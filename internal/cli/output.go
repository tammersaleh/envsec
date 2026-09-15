package cli

import (
	"encoding/json"
	"io"
)

// Meta is the `_meta` trailer that ends every JSONL command. Field order is
// has_more, error_count, generated_at; absent optionals are omitted.
type Meta struct {
	HasMore     bool   `json:"has_more"`
	ErrorCount  *int   `json:"error_count,omitempty"`
	GeneratedAt string `json:"generated_at,omitempty"`
}

// jsonl writes one JSON object per line.
type jsonl struct {
	w io.Writer
}

// Row encodes v (a struct with snake_case json tags) as one line.
func (j jsonl) Row(v any) error {
	raw, err := json.Marshal(v)
	if err != nil {
		return err
	}
	_, err = j.w.Write(append(raw, '\n'))
	return err
}

// Meta writes the trailer.
func (j jsonl) Meta(m Meta) error {
	return j.Row(struct {
		Meta Meta `json:"_meta"`
	}{m})
}
