// Copyright 2026 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package envruntime

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestResolveSandboxDirs(t *testing.T) {
	base := t.TempDir()
	rootDir := filepath.Join(base, "root")
	workDir := filepath.Join(rootDir, "proj")
	// create=false validates confinement without mutating disk (used before --dry-run).
	if _, _, err := ResolveSandboxDirs(rootDir, workDir, false); err != nil {
		t.Fatalf("ResolveSandboxDirs(non-existent, create=false) = %v, want nil", err)
	}
	if _, statErr := os.Stat(rootDir); !os.IsNotExist(statErr) {
		t.Errorf("ResolveSandboxDirs(create=false) unexpectedly created %q", rootDir)
	}
	gotRoot, gotWork, err := ResolveSandboxDirs(rootDir, workDir, true)
	if err != nil {
		t.Fatalf("ResolveSandboxDirs(create=true) failed: %v", err)
	}
	if !strings.HasPrefix(gotWork, gotRoot) {
		t.Errorf("gotWork %q does not reside inside gotRoot %q", gotWork, gotRoot)
	}

	outside := t.TempDir()
	if _, _, err := ResolveSandboxDirs(gotRoot, outside, false); err == nil {
		t.Error("ResolveSandboxDirs(outside workdir) = nil, want escape error")
	}

	symlinkRoot := filepath.Join(base, "sym-root")
	if err := os.Symlink(gotRoot, symlinkRoot); err == nil {
		canonRoot, canonWork, err := ResolveSandboxDirs(symlinkRoot, filepath.Join(symlinkRoot, "proj"), false)
		if err != nil || canonRoot != gotRoot || canonWork != gotWork {
			t.Errorf("ResolveSandboxDirs(symlink) = (%q, %q, %v), want (%q, %q, nil)", canonRoot, canonWork, err, gotRoot, gotWork)
		}
	}
}

func TestSandboxFSConfinementModesAndOperations(t *testing.T) {
	modes := []struct {
		name string
		mode ConfinementMode
	}{
		{name: "os_root", mode: ConfinementOSRoot},
		{name: "lexical", mode: ConfinementLexical},
	}

	for _, tc := range modes {
		t.Run(tc.name, func(t *testing.T) {
			rootDir := t.TempDir()
			workDir := filepath.Join(rootDir, "sub")
			if err := os.MkdirAll(workDir, 0o755); err != nil {
				t.Fatalf("MkdirAll failed: %v", err)
			}
			outsideDir := t.TempDir()
			outsideSecret := filepath.Join(outsideDir, "secret.txt")
			if err := os.WriteFile(outsideSecret, []byte("top-secret"), 0o600); err != nil {
				t.Fatalf("WriteFile(outsideSecret) failed: %v", err)
			}

			fs := NewSandboxFSWithConfig(SandboxFSConfig{
				RootDir: rootDir,
				WorkDir: workDir,
				Mode:    tc.mode,
			})
			if fs.Mode() != tc.mode {
				t.Errorf("fs.Mode() = %v, want %v", fs.Mode(), tc.mode)
			}
			if fs.RootDir() == "" || fs.WorkDir() == "" {
				t.Errorf("RootDir=%q WorkDir=%q, want non-empty", fs.RootDir(), fs.WorkDir())
			}

			// Valid parent traversal within rootDir (`../root_note.txt` from `rootDir/sub`).
			if _, err := fs.WriteRegularFile("../root_note.txt", "in-root\n", false, false); err != nil {
				t.Fatalf("WriteRegularFile(../root_note.txt) failed: %v", err)
			}
			if _, err := fs.WriteRegularFile("../root_note.txt", "dup", false, false); err == nil {
				t.Error("WriteRegularFile(overwrite=false existing) = nil, want PathErrAlreadyExists")
			} else {
				var pe *PathError
				if !errors.As(err, &pe) || pe.Kind != PathErrAlreadyExists {
					t.Errorf("existing file error = %v, want PathErrAlreadyExists", err)
				}
			}
			if _, err := fs.WriteRegularFile("../root_note.txt", "more\n", false, true); err != nil {
				t.Fatalf("WriteRegularFile(appendMode=true) failed: %v", err)
			}
			data, err := fs.ReadRegularFile("/root_note.txt")
			if err != nil || string(data) != "in-root\nmore\n" {
				t.Errorf("ReadRegularFile(/root_note.txt) = (%q, %v), want \"in-root\\nmore\\n\"", data, err)
			}

			// Relative traversal outside rootDir must fail with PathErrPermissionDenied.
			if _, err := fs.ReadRegularFile("../../escape.txt"); err == nil {
				t.Error("ReadRegularFile(../../escape.txt) succeeded, want confinement error")
			}
			if _, err := fs.WriteRegularFile("../../escape.txt", "x", true, false); err == nil {
				t.Error("WriteRegularFile(../../escape.txt) succeeded, want confinement error")
			}

			// Absolute paths outside rootDir are mapped into the virtual root inside rootDir, never touching host files.
			if _, err := fs.ReadRegularFile(outsideSecret); err == nil {
				t.Errorf("ReadRegularFile(%q) succeeded, want not-found inside virtual root", outsideSecret)
			}
			if _, err := fs.WriteRegularFile("/virtual_etc/config", "virtual", true, false); err != nil {
				t.Fatalf("WriteRegularFile(/virtual_etc/config) failed: %v", err)
			}
			if _, statErr := os.Stat(filepath.Join(fs.RootDir(), "virtual_etc", "config")); statErr != nil {
				t.Errorf("virtual absolute write did not land inside rootDir: %v", statErr)
			}

			// NUL byte rejected with PathErrPermissionDenied.
			if _, err := fs.ResolvePath("bad\x00name"); err == nil {
				t.Error("ResolvePath(NUL) = nil, want PathErrPermissionDenied")
			}

			// In ConfinementOSRoot mode, symlinks escaping rootDir are rejected for read, write, and nested leaf creation.
			if tc.mode == ConfinementOSRoot {
				escapeLink := filepath.Join(workDir, "escape_link")
				if err := os.Symlink(outsideDir, escapeLink); err == nil {
					if _, err := fs.ReadRegularFile("escape_link/secret.txt"); err == nil {
						t.Error("ReadRegularFile(escape symlink) succeeded, want error")
					}
					if _, err := fs.WriteRegularFile("escape_link/new.txt", "bad", true, false); err == nil {
						t.Error("WriteRegularFile(escape symlink) succeeded, want error")
					}
				}
			}

			// OpenWrite & OpenRead round-trip.
			wFile, err := fs.OpenWrite("streamed.txt", 0o644, false)
			if err != nil {
				t.Fatalf("OpenWrite(streamed.txt) failed: %v", err)
			}
			_, _ = wFile.Write([]byte("stream-payload"))
			_ = wFile.Close()
			if _, err := fs.OpenWrite("streamed.txt", 0o644, false); err == nil {
				t.Error("OpenWrite(overwrite=false existing) = nil, want error")
			}
			rFile, err := fs.OpenRead("streamed.txt")
			if err != nil {
				t.Fatalf("OpenRead(streamed.txt) failed: %v", err)
			}
			streamRead, _ := io.ReadAll(rFile)
			_ = rFile.Close()
			if string(streamRead) != "stream-payload" {
				t.Errorf("OpenRead(streamed.txt) = %q, want \"stream-payload\"", streamRead)
			}

			// CRLF ReadFileRange, Grep, FindFiles, Stat, Mkdir, Rename, ListEntries, Remove.
			crlfText := "alpha\r\nbeta = 42\r\ngamma\r\n"
			if _, err := fs.WriteRegularFile("cfg/app.ini", crlfText, true, false); err != nil {
				t.Fatalf("WriteRegularFile(cfg/app.ini) failed: %v", err)
			}
			ranged, err := fs.ReadFileRange("cfg/app.ini", 2, 3)
			if err != nil || ranged != "beta = 42\ngamma" {
				t.Errorf("ReadFileRange() = (%q, %v), want (\"beta = 42\\ngamma\", nil)", ranged, err)
			}
			if emptyRange, err := fs.ReadFileRange("cfg/app.ini", 3, 2); err != nil || emptyRange != "" {
				t.Errorf("ReadFileRange(start > end) = (%q, %v), want (\"\", nil)", emptyRange, err)
			}

			matches, truncated, err := fs.Grep(".", "BETA = 42$", true, true)
			if err != nil || truncated || len(matches) != 1 {
				t.Errorf("Grep() = (%v, %v, %v), want 1 non-truncated match", matches, truncated, err)
			}
			if _, _, err := fs.Grep(".", "[", false, true); err == nil {
				t.Error("Grep(invalid regex) = nil, want error")
			}
			if _, _, err := fs.Grep(".", "", false, false); err == nil {
				t.Error("Grep(empty query) = nil, want error")
			}

			found, _, err := fs.FindFiles(".", "*", 3, "INI")
			if err != nil || len(found) != 1 || found[0] != "cfg/app.ini" {
				t.Errorf("FindFiles(INI) = (%v, %v), want [cfg/app.ini]", found, err)
			}

			meta, err := fs.Stat("cfg/app.ini")
			if err != nil || meta.IsDir || meta.Kind != FileKindRegular {
				t.Errorf("Stat(cfg/app.ini) = (%+v, %v)", meta, err)
			}
			if err := fs.Mkdir("nested/a/b", 0o755, true); err != nil {
				t.Fatalf("Mkdir(recursive) failed: %v", err)
			}
			if err := fs.Rename("cfg/app.ini", "moved/app.ini"); err != nil {
				t.Fatalf("Rename() failed: %v", err)
			}
			entries, err := fs.ListEntries("moved")
			if err != nil || len(entries) != 1 || entries[0].(map[string]any)["name"] != "app.ini" {
				t.Errorf("ListEntries(moved) = (%v, %v), want [app.ini]", entries, err)
			}
			dirMetas, err := fs.ReadDir("moved")
			if err != nil || len(dirMetas) != 1 || dirMetas[0].Name != "app.ini" {
				t.Errorf("ReadDir(moved) = (%+v, %v)", dirMetas, err)
			}
			if err := fs.Remove("moved", false); err == nil {
				t.Error("Remove(non-empty dir, recursive=false) = nil, want error")
			}
			if err := fs.Remove("moved", true); err != nil {
				t.Errorf("Remove(moved, recursive=true) failed: %v", err)
			}
			if err := fs.Remove("..", true); err == nil {
				t.Error("Remove(..) = nil, want root removal protection error")
			}
		})
	}

	// Verify bounded vs UnlimitedRead behavior above MaxReadFileBytes.
	bigDir := t.TempDir()
	bigPayload := strings.Repeat("x", MaxReadFileBytes+128)
	if err := os.WriteFile(filepath.Join(bigDir, "big.bin"), []byte(bigPayload), 0o644); err != nil {
		t.Fatalf("WriteFile(big.bin) failed: %v", err)
	}
	boundedFS := NewSandboxFS(bigDir, bigDir)
	if _, err := boundedFS.ReadRegularFile("big.bin"); err == nil {
		t.Error("boundedFS.ReadRegularFile(>MaxReadFileBytes) = nil, want size limit error")
	}
	unlimitedFS := NewSandboxFSWithConfig(SandboxFSConfig{
		RootDir:       bigDir,
		WorkDir:       bigDir,
		Mode:          ConfinementLexical,
		UnlimitedRead: true,
	})
	gotBig, err := unlimitedFS.ReadRegularFile("big.bin")
	if err != nil || len(gotBig) != len(bigPayload) {
		t.Errorf("unlimitedFS.ReadRegularFile(big.bin) len=%d err=%v, want len=%d", len(gotBig), err, len(bigPayload))
	}

	// Verify ClassifyOSError mappings.
	if ClassifyOSError(nil, "p") != nil {
		t.Error("ClassifyOSError(nil) != nil")
	}
	if pe := ClassifyOSError(os.ErrNotExist, "missing"); pe.Kind != PathErrNotFound || !errors.Is(pe, os.ErrNotExist) || !strings.Contains(pe.Error(), "missing") {
		t.Errorf("ClassifyOSError(ErrNotExist) = %+v", pe)
	}
	if pe := ClassifyOSError(os.ErrExist, "dup"); pe.Kind != PathErrAlreadyExists {
		t.Errorf("ClassifyOSError(ErrExist) = %+v", pe)
	}
	if pe := ClassifyOSError(os.ErrPermission, "denied"); pe.Kind != PathErrPermissionDenied {
		t.Errorf("ClassifyOSError(ErrPermission) = %+v", pe)
	}
}

func TestSandboxShellEnvBuffersAndSubprocessKill(t *testing.T) {
	var capBuf CappedBuffer
	capBuf.MaxBytes = 5
	_, _ = capBuf.Write([]byte("123"))
	_, _ = capBuf.Write([]byte("456789"))
	_, _ = capBuf.Write([]byte("extra"))
	if got := capBuf.String(); !strings.HasPrefix(got, "12345") || !strings.Contains(got, "truncated") {
		t.Errorf("CappedBuffer = %q, want \"12345...[output truncated]\"", got)
	}

	allowEnv := BuildAllowlistEnv([]string{
		"PATH=/usr/bin",
		"COMPUTERNAME=WIN-NODE",
		"USERNAME=runner",
		"OS=Windows_NT",
		"SYSTEMDRIVE=C:",
		"PSMODULEPATH=C:\\Modules",
		"GEMINI_API_KEY=secret",
		"UNLISTED=drop",
	})
	if len(allowEnv) != 6 {
		t.Errorf("BuildAllowlistEnv() = %v, want 6 entries", allowEnv)
	}

	scrubbed := FilterScrubbedEnv([]string{
		"CUSTOM_SAFE=keep",
		"GEMINI_API_KEY=drop1",
		"GEMINI_ENVIRONMENT_KEY=drop2",
		"GOOGLE_API_KEY=drop3",
		"GEMINI_LEASE_TOKEN=drop4",
	}, "EXTRA_VAR=ok")
	joined := strings.Join(scrubbed, "\n")
	if !strings.Contains(joined, "CUSTOM_SAFE=keep") || !strings.Contains(joined, "EXTRA_VAR=ok") || strings.Contains(joined, "drop") {
		t.Errorf("FilterScrubbedEnv() = %v", scrubbed)
	}

	origPath := os.Getenv("PATH")
	t.Setenv("PATH", t.TempDir())
	if bin, args := ResolveShellCommand("windows", "dir"); bin != "cmd.exe" || len(args) != 2 || args[0] != "/C" {
		t.Errorf("ResolveShellCommand(windows, empty PATH) = (%q, %v), want (\"cmd.exe\", [\"/C\", \"dir\"])", bin, args)
	}
	if bin, _ := ResolveShellCommand("linux", "ls"); bin != "sh" {
		t.Errorf("ResolveShellCommand(linux, empty PATH) = %q, want sh", bin)
	}
	t.Setenv("PATH", origPath)
	if len(ShutdownSignals()) == 0 {
		t.Error("ShutdownSignals() returned empty slice")
	}

	workDir := filepath.Join(t.TempDir(), "auto-work")
	sh := NewSandboxShellWithConfig(SandboxShellConfig{
		WorkDir:           workDir,
		EnvPolicy:         EnvPolicyScrubCredentials,
		ExtraEnv:          []string{"INJECTED_FLAG=present"},
		AutoCreateWorkDir: true,
		UseBinSh:          true,
	})
	if sh.WorkDir() != workDir {
		t.Errorf("sh.WorkDir() = %q, want %q", sh.WorkDir(), workDir)
	}

	t.Setenv("GEMINI_API_KEY", "should-not-leak")
	stdout, stderr, exitCode, execErr := sh.ExecuteBash(t.Context(), `printf "%s|%s" "$INJECTED_FLAG" "$GEMINI_API_KEY"`, "", 5*time.Second)
	if execErr != nil || stdout != "present|" || stderr != "" || exitCode != 0 {
		t.Errorf("ExecuteBash(env check) = (%q, %q, %d, %v), want stdout=\"present|\" exitCode=0", stdout, stderr, exitCode, execErr)
	}

	_, failStderr, failCode, failErr := sh.ExecuteBash(t.Context(), "echo err >&2; exit 7", "", 5*time.Second)
	if failErr != nil || failCode != 7 || !strings.Contains(failStderr, "err") {
		t.Errorf("ExecuteBash(exit 7) = (stderr=%q, code=%d, err=%v)", failStderr, failCode, failErr)
	}

	// Verify timeout kills background grandchild holding stdout pipe without hanging.
	start := time.Now()
	_, _, toCode, toErr := sh.ExecuteBash(t.Context(), "(sleep 30) & sleep 30", "", 80*time.Millisecond)
	if toErr == nil || toCode != -1 || !strings.Contains(toErr.Error(), "timed out") {
		t.Errorf("ExecuteBash(timeout) = (code=%d, err=%v), want timed out error", toCode, toErr)
	}
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Errorf("ExecuteBash(timeout) took %v, subprocess group did not terminate promptly", elapsed)
	}
}

func TestToolDispatcherToolsAndExtendedFS(t *testing.T) {
	rootDir := t.TempDir()
	fs := NewSandboxFS(rootDir, rootDir)
	sh := NewSandboxShell(rootDir)

	disabled := NewToolDispatcher(ToolDispatcherConfig{
		FS:          fs,
		Shell:       sh,
		DisableBash: true,
	})
	if res, isErr := disabled.Dispatch(t.Context(), "execute_bash", map[string]any{"command": "echo hi"}); !isErr || !strings.Contains(res["error"].(string), "disabled") {
		t.Errorf("Dispatch(execute_bash disabled) = (%v, %v), want disabled error", res, isErr)
	}
	if _, isErr := disabled.Dispatch(t.Context(), "stat_file", map[string]any{"path": "."}); !isErr {
		t.Error("Dispatch(stat_file with EnableExtendedFSTools=false) = false, want error")
	}

	var gotTimeout time.Duration
	td := NewToolDispatcher(ToolDispatcherConfig{
		FS:    fs,
		Shell: sh,
		ShellExec: func(_ context.Context, cmd, cwd string, timeout time.Duration) (string, string, int, error) {
			gotTimeout = timeout
			return cmd + "@" + filepath.Base(cwd), "", 0, nil
		},
		CommandTimeout:              2 * time.Second,
		EnableExtendedFSTools:       true,
		DefaultWriteToFileOverwrite: true,
		RespectWaitMsBeforeAsync:    true,
	})

	bashRes, bashErr := td.Dispatch(t.Context(), "run_shell_command", map[string]any{
		"CommandLine":       "ls",
		"WaitMsBeforeAsync": float64(500),
	})
	if bashErr || gotTimeout != 500*time.Millisecond || !strings.HasPrefix(bashRes["stdout"].(string), "ls@") {
		t.Errorf("Dispatch(run_shell_command) = (%v, %v), timeout=%v", bashRes, bashErr, gotTimeout)
	}
	if _, escErr := td.Dispatch(t.Context(), "bash", map[string]any{"command": "pwd", "cwd": "../../outside"}); !escErr {
		t.Error("Dispatch(bash escaping cwd) = false, want error")
	}

	// File tools: write_to_file, view_file, replace_file_content, list_dir, grep_search, find_by_name, extended tools.
	if res, isErr := td.Dispatch(t.Context(), "write_to_file", map[string]any{
		"TargetFile":  "dir/code.py",
		"CodeContent": "line1\r\nline2\r\nline3\r\n",
	}); isErr {
		t.Fatalf("write_to_file failed: %v", res)
	}
	if res, isErr := td.Dispatch(t.Context(), "replace_file_content", map[string]any{
		"TargetFile":         "dir/code.py",
		"TargetContent":      "line2",
		"ReplacementContent": "line2_edited",
		"StartLine":          "2",
		"EndLine":            float64(2),
	}); isErr {
		t.Fatalf("replace_file_content failed: %v", res)
	}
	viewRes, viewErr := td.Dispatch(t.Context(), "view_file", map[string]any{"AbsolutePath": "dir/code.py"})
	if viewErr || viewRes["content"] != "line1\r\nline2_edited\r\nline3\r\n" {
		t.Errorf("view_file(full) = (%v, %v)", viewRes, viewErr)
	}
	rangeRes, rangeErr := td.Dispatch(t.Context(), "view_file", map[string]any{
		"AbsolutePath": "dir/code.py",
		"StartLine":    1,
		"EndLine":      2,
	})
	if rangeErr || rangeRes["content"] != "line1\nline2_edited" {
		t.Errorf("view_file(range) = (%v, %v)", rangeRes, rangeErr)
	}

	if res, isErr := td.Dispatch(t.Context(), "stat_file", map[string]any{"path": "dir/code.py"}); isErr || res["is_dir"] != false {
		t.Errorf("stat_file = (%v, %v)", res, isErr)
	}
	if res, isErr := td.Dispatch(t.Context(), "mkdir", map[string]any{"path": "newdir/sub", "recursive": "true"}); isErr {
		t.Errorf("mkdir = (%v, %v)", res, isErr)
	}
	if res, isErr := td.Dispatch(t.Context(), "rename_file", map[string]any{"old_path": "dir/code.py", "new_path": "newdir/code.py"}); isErr {
		t.Errorf("rename_file = (%v, %v)", res, isErr)
	}
	if res, isErr := td.Dispatch(t.Context(), "list_dir", map[string]any{"DirectoryPath": "newdir"}); isErr {
		t.Errorf("list_dir = (%v, %v)", res, isErr)
	}
	if res, isErr := td.Dispatch(t.Context(), "grep_search", map[string]any{"SearchPath": ".", "Query": "line2_edited"}); isErr {
		t.Errorf("grep_search = (%v, %v)", res, isErr)
	}
	if res, isErr := td.Dispatch(t.Context(), "find_by_name", map[string]any{"SearchDirectory": ".", "Extensions": "py,go"}); isErr {
		t.Errorf("find_by_name = (%v, %v)", res, isErr)
	}
	if res, isErr := td.Dispatch(t.Context(), "remove_file", map[string]any{"path": "newdir", "recursive": true}); isErr {
		t.Errorf("remove_file = (%v, %v)", res, isErr)
	}
	if _, isErr := td.Dispatch(t.Context(), "unknown_tool", nil); !isErr {
		t.Error("Dispatch(unknown_tool) = false, want error")
	}
}
