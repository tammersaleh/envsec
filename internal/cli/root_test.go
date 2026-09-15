package cli

import (
	"bytes"
	"testing"
)

func TestVersion(t *testing.T) {
	var out, errb bytes.Buffer
	if err := Run([]string{"version"}, &out, &errb); err != nil {
		t.Fatal(err)
	}
	want := "{\"version\":\"dev\"}\n{\"_meta\":{\"has_more\":false}}\n"
	if out.String() != want {
		t.Fatalf("got %q, want %q", out.String(), want)
	}
}
