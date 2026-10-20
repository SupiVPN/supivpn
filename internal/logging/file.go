// Copyright (c) 2026 Stanislav Kazachkov (SupiVPN).
// Licensed under AGPL-3.0-only. See LICENSE and COPYRIGHT.md.
// SPDX-License-Identifier: AGPL-3.0-only

package logging

import (
	"context"
	"crypto/rand"
	"errors"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"
)

const archiveTime = "20060102T150405.000000000Z"

type fileWriter struct {
	mu             sync.Mutex
	root           *os.Root
	file, lock     *os.File
	name           string
	size, maxBytes int64
	day            time.Time
	lastWrite      time.Time
	days, maxFiles int
	now            func() time.Time
	fallback       io.Writer
	fallbackLogger *Logger
	failed, closed bool
	stop, done     chan struct{}
	once           sync.Once
}

func privateInfo(info os.FileInfo, dir bool) bool {
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok || int(st.Uid) != os.Geteuid() || info.Mode().Perm()&0027 != 0 {
		return false
	}
	if dir {
		return info.IsDir()
	}
	return info.Mode().IsRegular() && st.Nlink == 1 && info.Mode().Perm()&0111 == 0
}

func (w *fileWriter) open(name string, flags int) (*os.File, error) {
	// NONBLOCK prevents a special file from hanging startup before fstat.
	f, err := w.root.OpenFile(name, flags|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0640)
	if err != nil {
		return nil, err
	}
	info, err := f.Stat()
	if err != nil || !privateInfo(info, false) {
		f.Close()
		return nil, errors.New("unsafe log file")
	}
	return f, nil
}

func newFileWriter(c Config, component string, fallback io.Writer) (*fileWriter, error) {
	dir := filepath.Dir(c.File)
	info, err := os.Lstat(dir)
	if err != nil || !privateInfo(info, true) {
		return nil, errors.New("unsafe log directory")
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		return nil, err
	}
	w := &fileWriter{root: root, name: filepath.Base(c.File), maxBytes: int64(c.MaxSizeMB) << 20,
		days: *c.RetentionDays, maxFiles: c.MaxFiles, now: time.Now, fallback: fallback,
		fallbackLogger: New(fallback, component), stop: make(chan struct{}), done: make(chan struct{})}
	// Pin and recheck the directory, then hold a process lock across all rotations.
	pinned, err := root.Stat(".")
	if err == nil && (!os.SameFile(info, pinned) || !privateInfo(pinned, true)) {
		err = errors.New("log directory changed")
	}
	if err == nil {
		w.lock, err = w.open("."+w.name+".lock", os.O_CREATE|os.O_RDWR)
	}
	if err == nil {
		err = syscall.Flock(int(w.lock.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
	}
	if err == nil {
		err = w.openActive()
	}
	if err == nil {
		err = w.maintain(w.now())
	}
	if err != nil {
		if w.file != nil {
			w.file.Close()
		}
		if w.lock != nil {
			w.lock.Close()
		}
		root.Close()
		return nil, err
	}
	go w.run()
	return w, nil
}

func utcDay(t time.Time) time.Time {
	t = t.UTC()
	return time.Date(t.Year(), t.Month(), t.Day(), 0, 0, 0, 0, time.UTC)
}
func (w *fileWriter) openActive() error {
	f, err := w.open(w.name, os.O_CREATE|os.O_WRONLY|os.O_APPEND)
	if err != nil {
		return err
	}
	info, err := f.Stat()
	if err != nil {
		f.Close()
		return err
	}
	w.file = f
	w.size = info.Size()
	w.day = utcDay(info.ModTime())
	w.lastWrite = info.ModTime()
	return nil
}
func (w *fileWriter) rotate(now time.Time) error {
	if w.size == 0 {
		w.day = utcDay(now)
		return nil
	}
	if err := w.file.Close(); err != nil {
		return err
	}
	w.file = nil
	name := strings.TrimSuffix(w.name, ".jsonl") + "." + w.lastWrite.UTC().Format(archiveTime) + "." + rand.Text() + ".jsonl"
	// The private directory and exclusive writer lock protect this namespace.
	// Atomic rename avoids a crash window with multiply linked active files.
	if _, err := w.root.Lstat(name); !errors.Is(err, os.ErrNotExist) {
		return errors.New("log archive collision")
	}
	if err := w.root.Rename(w.name, name); err != nil {
		return err
	}
	if err := w.openActive(); err != nil {
		return err
	}
	w.day = utcDay(now)
	return w.prune(now)
}

func (w *fileWriter) archiveDate(name string) (time.Time, bool) {
	prefix := strings.TrimSuffix(w.name, ".jsonl") + "."
	if !strings.HasPrefix(name, prefix) || !strings.HasSuffix(name, ".jsonl") {
		return time.Time{}, false
	}
	body := strings.TrimSuffix(strings.TrimPrefix(name, prefix), ".jsonl")
	// Timestamp contains a decimal point; the suffix is crypto/rand.Text.
	if len(body) != len(archiveTime)+1+26 || body[len(archiveTime)] != '.' {
		return time.Time{}, false
	}
	suffix := body[len(archiveTime)+1:]
	for _, r := range suffix {
		if !(r >= 'A' && r <= 'Z' || r >= '2' && r <= '7') {
			return time.Time{}, false
		}
	}
	t, err := time.Parse(archiveTime, body[:len(archiveTime)])
	return t, err == nil
}
func (w *fileWriter) prune(now time.Time) error {
	dir, err := w.root.Open(".")
	if err != nil {
		return err
	}
	entries, err := dir.ReadDir(-1)
	dir.Close()
	if err != nil {
		return err
	}
	type archive struct {
		name string
		at   time.Time
	}
	var archives []archive
	for _, e := range entries {
		at, ok := w.archiveDate(e.Name())
		if !ok {
			continue
		}
		info, err := w.root.Lstat(e.Name())
		if err != nil {
			return err
		}
		if !privateInfo(info, false) {
			return errors.New("unsafe log archive")
		}
		archives = append(archives, archive{e.Name(), at})
	}
	sort.Slice(archives, func(i, j int) bool { return archives[i].name > archives[j].name })
	for i, a := range archives {
		if i >= w.maxFiles || w.days > 0 && !a.at.After(now.Add(-time.Duration(w.days)*24*time.Hour)) {
			if err := w.root.Remove(a.name); err != nil {
				return err
			}
		}
	}
	return nil
}
func (w *fileWriter) maintain(now time.Time) error {
	if w.size > 0 && (utcDay(now).After(w.day) || w.size >= w.maxBytes) {
		return w.rotate(now)
	}
	return w.prune(now)
}
func (w *fileWriter) fail() {
	if !w.failed {
		w.failed = true
		w.fallbackLogger.Emit(context.Background(), "logging.output_failed")
	}
}
func (w *fileWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.closed {
		return 0, os.ErrClosed
	}
	if !w.failed {
		now := w.now()
		if w.size > 0 && (w.size+int64(len(p)) > w.maxBytes || utcDay(now).After(w.day)) {
			if err := w.rotate(now); err != nil {
				w.fail()
			}
		}
		if !w.failed {
			n, err := w.file.Write(p)
			if err == nil && n == len(p) {
				w.size += int64(n)
				w.lastWrite = now
				return n, nil
			}
			// Preserve previous complete records where possible. Do not append
			// further records after an incomplete write or failed rotation.
			_ = w.file.Truncate(w.size)
			w.fail()
		}
	}
	return w.fallback.Write(p)
}
func (w *fileWriter) run() {
	defer close(w.done)
	tick := time.NewTicker(time.Minute)
	defer tick.Stop()
	for {
		select {
		case <-w.stop:
			return
		case <-tick.C:
			w.mu.Lock()
			if !w.failed {
				if err := w.maintain(w.now()); err != nil {
					w.fail()
				}
			}
			w.mu.Unlock()
		}
	}
}
func (w *fileWriter) Close() {
	w.once.Do(func() {
		close(w.stop)
		<-w.done
		w.mu.Lock()
		defer w.mu.Unlock()
		w.closed = true
		if w.file != nil {
			if err := w.file.Close(); err != nil {
				w.fail()
			}
		}
		w.lock.Close()
		w.root.Close()
	})
}
