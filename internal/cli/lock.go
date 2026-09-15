package cli

import (
	"errors"
	"os"
	"path/filepath"
	"syscall"
)

// lockPath returns the per-user sync lock file. Tests swap it for a path
// under t.TempDir().
var lockPath = func() (string, error) {
	dir, err := os.UserCacheDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "envsec", "sync.lock"), nil
}

// acquireLock takes the exclusive, non-blocking sync lock. A lock held by
// another process is the fatal error sync_locked. The returned func releases
// the lock and is safe to call once.
func acquireLock() (release func(), err error) {
	path, err := lockPath()
	if err != nil {
		return nil, lockFailed("resolve lock path: " + err.Error())
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, lockFailed(err.Error())
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, lockFailed(err.Error())
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		_ = f.Close()
		if errors.Is(err, syscall.EWOULDBLOCK) || errors.Is(err, syscall.EAGAIN) {
			return nil, &ExitError{
				Code:   ExitFailure,
				Err:    "sync_locked",
				Detail: "another envsec sync holds " + path,
				Hint:   "wait for the other envsec sync to finish",
			}
		}
		return nil, lockFailed("flock " + path + ": " + err.Error())
	}
	return func() {
		_ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
		_ = f.Close()
	}, nil
}

func lockFailed(detail string) error {
	return &ExitError{Code: ExitFailure, Err: "lock_failed", Detail: detail, Hint: "check permissions on the cache directory"}
}
