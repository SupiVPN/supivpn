// Copyright (c) 2026 Stanislav Kazachkov (SupiVPN).
// Licensed under AGPL-3.0-only. See LICENSE and COPYRIGHT.md.
// SPDX-License-Identifier: AGPL-3.0-only

package logging

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// Config controls application logs only; OpenVPN and platform logs are separate.
type Config struct {
	Output        string `json:"output,omitempty"`
	File          string `json:"file,omitempty"`
	RetentionDays *int   `json:"retention_days,omitempty"`
	MaxSizeMB     int    `json:"max_size_mb,omitempty"`
	MaxFiles      int    `json:"max_files,omitempty"`
}

func (c *Config) resolve(component string) (Config, error) {
	v := Config{}
	if c != nil {
		v = *c
	}
	vm := component == "agent" || component == "controller"
	if v.Output == "" {
		v.Output = "stderr"
		if vm {
			v.Output = "file"
		}
	}
	if v.Output != "file" && v.Output != "stderr" && v.Output != "stdout" {
		return v, errors.New("logging.output must be file, stderr or stdout")
	}
	if v.Output != "file" {
		if v.File != "" || v.RetentionDays != nil || v.MaxSizeMB != 0 || v.MaxFiles != 0 {
			return v, errors.New("file retention settings require logging.output=file")
		}
		return v, nil
	}
	if !vm {
		return v, errors.New("file logging is supported only for VM services")
	}
	if v.File == "" {
		v.File = "/var/log/supivpn/" + component + ".jsonl"
	}
	base := filepath.Base(v.File)
	if !filepath.IsAbs(v.File) || filepath.Clean(v.File) != v.File || !strings.HasSuffix(base, ".jsonl") ||
		!identifier(base, 128) || strings.HasPrefix(base, ".") {
		return v, errors.New("logging.file must be an absolute clean path with a simple .jsonl filename")
	}
	if v.RetentionDays == nil {
		days := 7
		v.RetentionDays = &days
	}
	if v.MaxSizeMB == 0 {
		v.MaxSizeMB = 10
	}
	if v.MaxFiles == 0 {
		v.MaxFiles = 10
	}
	if *v.RetentionDays < 0 || *v.RetentionDays > 3650 || v.MaxSizeMB < 1 || v.MaxSizeMB > 1024 ||
		v.MaxFiles < 1 || v.MaxFiles > 1000 {
		return v, errors.New("logging limits: retention_days 0..3650, max_size_mb 1..1024, max_files 1..1000")
	}
	return v, nil
}

// Validate performs no filesystem operations.
func (c *Config) Validate(component string) error {
	_, err := c.resolve(component)
	return err
}

// Setup installs the service destination. Call cleanup after service goroutines
// stop. Startup/CLI errors before or after this lifetime remain on stderr.
func Setup(component string, c *Config) (func(), error) {
	v, err := c.resolve(component)
	if err != nil {
		return nil, err
	}
	var out io.Writer = os.Stderr
	var file *fileWriter
	if v.Output == "stdout" {
		out = os.Stdout
	}
	if v.Output == "file" {
		file, err = newFileWriter(v, component, os.Stderr)
		if err != nil {
			return nil, errors.New("cannot initialize private log file; check directory, permissions and exclusive ownership")
		}
		out = file
	}
	installed := New(out, component)
	previous := current.Swap(installed)
	return func() {
		current.CompareAndSwap(installed, previous)
		if file != nil {
			file.Close()
		}
	}, nil
}
