package main

import (
	"context"
	"os"
	"path/filepath"
	"time"
)

func dataDir() (string, error) {
	return xdgDir("XDG_DATA_HOME", ".local", "share")
}

func sockPath() (string, error) {
	dir, err := xdgDir("XDG_RUNTIME_DIR", ".local", "state")
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "sock"), nil
}

func xdgDir(env string, fallback ...string) (string, error) {
	dir, err := xdgPath(env, fallback...)
	if err != nil {
		return "", err
	}
	return dir, os.MkdirAll(dir, 0o700)
}

func waited(ctx context.Context, d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-t.C:
		return true
	case <-ctx.Done():
		return false
	}
}

// xdgPath returns the location without creating it.
func xdgPath(env string, fallback ...string) (string, error) {
	dir := os.Getenv(env)
	if dir == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", err
		}
		dir = filepath.Join(append([]string{home}, fallback...)...)
	}
	return filepath.Join(dir, "tp"), nil
}
