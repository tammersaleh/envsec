//go:build integration

package keychain

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"os/exec"
	"testing"
	"time"
)

// TestIntegrationLoginKeychain exercises the real store against the login
// keychain under a throwaway service name and deletes the item afterwards.
// Every security call is bounded by a timeout; a killed security leaves its
// dialog on screen, so the test stays small.
func TestIntegrationLoginKeychain(t *testing.T) {
	suffix := make([]byte, 6)
	if _, err := rand.Read(suffix); err != nil {
		t.Fatal(err)
	}
	service := "envsec-test." + hex.EncodeToString(suffix)
	account := "bundle"

	s := New(Options{Service: service, Account: account, Timeout: 10 * time.Second})
	real := s.(*store)

	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		cmd := exec.CommandContext(ctx, real.opts.SecurityPath,
			"delete-generic-password", "-a", account, "-s", service, real.opts.KeychainPath,
		)
		cmd.Stdin = nil
		cmd.WaitDelay = 2 * time.Second
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Errorf("cleanup delete-generic-password: %v\n%s", err, out)
		}
	})

	ctx := context.Background()

	if _, err := s.Read(ctx); err != ErrNotFound {
		t.Fatalf("read before write: got %v, want ErrNotFound", err)
	}

	first := []byte("first")
	if err := s.Write(ctx, first); err != nil {
		t.Fatalf("first write: %v", err)
	}
	got, err := s.Read(ctx)
	if err != nil {
		t.Fatalf("read after first write: %v", err)
	}
	if !bytes.Equal(got, first) {
		t.Fatalf("read after first write: got %q, want %q", got, first)
	}

	// Overwrite via -U with a 2 KB base64 payload. 1534 raw bytes encode to
	// 2048 chars ending in "=="; the "+/" prefix guarantees both symbols.
	raw := make([]byte, 1534)
	if _, err := rand.Read(raw); err != nil {
		t.Fatal(err)
	}
	second := append([]byte("+/"), base64.StdEncoding.EncodeToString(raw)...)
	if len(second) < 2048 || !bytes.HasSuffix(second, []byte("==")) {
		t.Fatalf("payload shape wrong: len %d", len(second))
	}
	if err := s.Write(ctx, second); err != nil {
		t.Fatalf("overwrite: %v", err)
	}
	got, err = s.Read(ctx)
	if err != nil {
		t.Fatalf("read after overwrite: %v", err)
	}
	if !bytes.Equal(got, second) {
		t.Fatalf("read after overwrite: mismatch (len %d vs %d)", len(got), len(second))
	}
}
