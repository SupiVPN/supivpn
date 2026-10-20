// Copyright (c) 2026 Stanislav Kazachkov (SupiVPN).
// Licensed under AGPL-3.0-only. See LICENSE and COPYRIGHT.md.
// SPDX-License-Identifier: AGPL-3.0-only

package logging

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

func fileConfig(t *testing.T) Config {
	t.Helper()
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	c, err := (&Config{File: filepath.Join(dir, "agent.jsonl")}).resolve("agent")
	if err != nil {
		t.Fatal(err)
	}
	return c
}
func openTestWriter(t *testing.T, c Config, out io.Writer) *fileWriter {
	t.Helper()
	w, err := newFileWriter(c, "agent", out)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(w.Close)
	return w
}
func archives(t *testing.T, w *fileWriter) []string {
	t.Helper()
	files, err := os.ReadDir(w.root.Name())
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, f := range files {
		if _, ok := w.archiveDate(f.Name()); ok {
			names = append(names, f.Name())
		}
	}
	return names
}
func TestFileDefaultsAndValidation(t *testing.T) {
	for _, component := range []string{"agent", "controller"} {
		c, err := (*Config)(nil).resolve(component)
		if err != nil || c.Output != "file" || c.File != "/var/log/supivpn/"+component+".jsonl" ||
			*c.RetentionDays != 7 || c.MaxSizeMB != 10 || c.MaxFiles != 10 {
			t.Fatal("unsafe file defaults")
		}
	}
	for _, component := range []string{"public", "agent_api", "recovery", "migrate", "profile"} {
		c, err := (*Config)(nil).resolve(component)
		if err != nil || c.Output != "stderr" {
			t.Fatal("ephemeral process should use stderr")
		}
		if (&Config{Output: "file"}).Validate(component) == nil {
			t.Fatal("file output accepted outside VM service")
		}
	}
	minus, zero, large := -1, 0, 3651
	for _, c := range []Config{{Output: "s3"}, {Output: "stderr", File: "/tmp/a.jsonl"},
		{Output: "stdout", MaxFiles: 2}, {Output: "stdout", RetentionDays: &zero},
		{File: "relative.jsonl"}, {File: "/tmp/../log.jsonl"}, {File: "/tmp/.log.jsonl"},
		{File: "/tmp/a.log"}, {File: "/tmp/a\nb.jsonl"}, {MaxSizeMB: -1}, {MaxSizeMB: 1025},
		{MaxFiles: -1}, {MaxFiles: 1001}, {RetentionDays: &minus}, {RetentionDays: &large}} {
		if c.Validate("agent") == nil {
			t.Fatalf("invalid log config accepted: %+v", c)
		}
	}
	c := Config{RetentionDays: &zero}
	if c.Validate("agent") != nil {
		t.Fatal("bounded size/count mode refused")
	}
}
func TestConcurrentFileRotationKeepsWholeJSONRecords(t *testing.T) {
	c := fileConfig(t)
	c.MaxFiles = 100
	w := openTestWriter(t, c, io.Discard)
	w.maxBytes = 700
	l := New(w, "agent")
	var wg sync.WaitGroup
	for i := range 100 {
		wg.Add(1)
		go func() { defer wg.Done(); l.Emit(context.Background(), "vpn.disconnected", slog.Int("cid", i)) }()
	}
	wg.Wait()
	w.Close()
	names := append(archives(t, w), w.name)
	seen := map[float64]bool{}
	for _, name := range names {
		b, err := os.ReadFile(filepath.Join(filepath.Dir(c.File), name))
		if err != nil {
			t.Fatal(err)
		}
		if len(b) > 700 {
			t.Fatal("size limit exceeded")
		}
		info, err := os.Stat(filepath.Join(filepath.Dir(c.File), name))
		if err != nil || info.Mode().Perm()&0027 != 0 {
			t.Fatal("log permissions widened")
		}
		for _, line := range strings.Split(strings.TrimSpace(string(b)), "\n") {
			if line == "" {
				continue
			}
			e := decode(t, line+"\n")
			cid := e["cid"].(float64)
			if seen[cid] {
				t.Fatal("duplicate record")
			}
			seen[cid] = true
		}
	}
	if len(seen) != 100 {
		t.Fatal("records lost during rotation", len(seen))
	}
}
func TestRetentionCountAgeAndIdleRotation(t *testing.T) {
	c := fileConfig(t)
	c.MaxFiles = 2
	w := openTestWriter(t, c, io.Discard)
	clock := time.Now().UTC()
	w.mu.Lock()
	w.now = func() time.Time { return clock }
	w.mu.Unlock()
	l := New(w, "agent")
	for range 4 {
		l.Emit(context.Background(), "vpn.disconnected")
		w.mu.Lock()
		clock = clock.Add(24 * time.Hour)
		err := w.maintain(clock)
		w.mu.Unlock()
		if err != nil {
			t.Fatal(err)
		}
	}
	if len(archives(t, w)) != 2 {
		t.Fatal("archive count not enforced")
	}
	unrelated := filepath.Join(filepath.Dir(c.File), "do-not-delete.jsonl")
	if err := os.WriteFile(unrelated, []byte("unrelated"), 0600); err != nil {
		t.Fatal(err)
	}
	w.mu.Lock()
	clock = clock.Add(7 * 24 * time.Hour)
	err := w.maintain(clock)
	w.mu.Unlock()
	if err != nil || len(archives(t, w)) != 0 {
		t.Fatal("idle age cleanup failed")
	}
	if _, err := os.Stat(unrelated); err != nil {
		t.Fatal("unrelated file removed")
	}
}
func TestRestartPrunesOldArchivesAndExcludesSecondWriter(t *testing.T) {
	c := fileConfig(t)
	w := openTestWriter(t, c, io.Discard)
	if other, err := newFileWriter(c, "agent", io.Discard); err == nil {
		other.Close()
		t.Fatal("two writers accepted")
	}
	New(w, "agent").Emit(context.Background(), "vpn.disconnected")
	w.mu.Lock()
	w.lastWrite = time.Now().Add(-8 * 24 * time.Hour)
	err := w.rotate(time.Now().Add(-8 * 24 * time.Hour))
	w.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	w.Close()
	next := openTestWriter(t, c, io.Discard)
	if len(archives(t, next)) != 0 {
		t.Fatal("restart did not prune expired archives")
	}
}
func TestUnsafeLogPathsRefusedWithoutChangingTargets(t *testing.T) {
	for _, kind := range []string{"symlink", "hardlink", "fifo", "public", "lock-symlink", "directory-symlink"} {
		t.Run(kind, func(t *testing.T) {
			c := fileConfig(t)
			target := filepath.Join(t.TempDir(), "untouched")
			original := []byte("do not change")
			if err := os.WriteFile(target, original, 0600); err != nil {
				t.Fatal(err)
			}
			var err error
			switch kind {
			case "symlink":
				err = os.Symlink(target, c.File)
			case "hardlink":
				err = os.Link(target, c.File)
			case "fifo":
				err = syscall.Mkfifo(c.File, 0600)
			case "public":
				err = os.WriteFile(c.File, original, 0644)
				if err == nil {
					err = os.Chmod(c.File, 0644)
				}
			case "lock-symlink":
				err = os.Symlink(target, filepath.Join(filepath.Dir(c.File), ".agent.jsonl.lock"))
			case "directory-symlink":
				alias := filepath.Join(t.TempDir(), "alias")
				err = os.Symlink(filepath.Dir(c.File), alias)
				c.File = filepath.Join(alias, "agent.jsonl")
			}
			if err != nil {
				t.Fatal(err)
			}
			if w, err := newFileWriter(c, "agent", io.Discard); err == nil {
				w.Close()
				t.Fatal("unsafe path accepted")
			}
			after, err := os.ReadFile(target)
			if err != nil || !bytes.Equal(after, original) {
				t.Fatal("target changed")
			}
		})
	}
}
func TestFileFailureFallsBackOnceAndDoesNotStopLogging(t *testing.T) {
	c := fileConfig(t)
	var fallback bytes.Buffer
	w := openTestWriter(t, c, &fallback)
	l := New(w, "agent")
	l.Emit(context.Background(), "vpn.disconnected", slog.Int("cid", 1))
	w.mu.Lock()
	w.file.Close()
	w.mu.Unlock()
	l.Emit(context.Background(), "vpn.disconnected", slog.Int("cid", 2))
	l.Emit(context.Background(), "vpn.disconnected", slog.Int("cid", 3))
	w.Close()
	lines := strings.Split(strings.TrimSpace(fallback.String()), "\n")
	if len(lines) != 3 {
		t.Fatal("missing fallback records or repeated warning")
	}
	if decode(t, lines[0]+"\n")["event"] != "logging.output_failed" {
		t.Fatal("missing sink failure signal")
	}
	for _, line := range lines {
		if !json.Valid([]byte(line)) {
			t.Fatal("fallback is not JSON")
		}
	}
	if strings.Contains(fallback.String(), c.File) {
		t.Fatal("raw path/error leaked")
	}
}
func TestSetupFileAndCleanupRestorePreviousLogger(t *testing.T) {
	c := fileConfig(t)
	prior := current.Load()
	closeLogs, err := Setup("agent", &c)
	if err != nil {
		t.Fatal(err)
	}
	Emit(context.Background(), "vpn.disconnected")
	closeLogs()
	closeLogs()
	if current.Load() != prior {
		t.Fatal("previous logger not restored")
	}
	b, err := os.ReadFile(c.File)
	if err != nil {
		t.Fatal(err)
	}
	if decode(t, string(b))["component"] != "agent" {
		t.Fatal("service output not configured")
	}
}

func TestRestartExpiresOldActiveFileWithoutResettingAge(t *testing.T) {
	c := fileConfig(t)
	w := openTestWriter(t, c, io.Discard)
	New(w, "agent").Emit(context.Background(), "vpn.disconnected")
	w.Close()
	old := time.Now().Add(-8 * 24 * time.Hour)
	if err := os.Chtimes(c.File, old, old); err != nil {
		t.Fatal(err)
	}
	next := openTestWriter(t, c, io.Discard)
	info, err := os.Stat(c.File)
	if err != nil || info.Size() != 0 || len(archives(t, next)) != 0 {
		t.Fatal("restart retained expired records")
	}
}

func TestFileAgeDisabledStillEnforcesArchiveCount(t *testing.T) {
	c := fileConfig(t)
	zero := 0
	c.RetentionDays = &zero
	c.MaxFiles = 1
	w := openTestWriter(t, c, io.Discard)
	New(w, "agent").Emit(context.Background(), "vpn.disconnected")
	w.mu.Lock()
	w.lastWrite = time.Now().Add(-30 * 24 * time.Hour)
	err := w.rotate(time.Now())
	w.mu.Unlock()
	if err != nil || len(archives(t, w)) != 1 {
		t.Fatal("age-disabled file was removed")
	}
	New(w, "agent").Emit(context.Background(), "vpn.disconnected")
	w.mu.Lock()
	err = w.rotate(time.Now())
	w.mu.Unlock()
	names := archives(t, w)
	if err != nil || len(names) != 1 {
		t.Fatal("count limit not enforced")
	}
	at, _ := w.archiveDate(names[0])
	if time.Since(at) > time.Minute {
		t.Fatal("newest archive not retained")
	}
}
