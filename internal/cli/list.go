package cli

import (
	"slices"
	"strings"
	"time"

	"github.com/tammersaleh/envsec/internal/bundle"
)

// ListCmd prints the bundle's provenance. Never prints values.
type ListCmd struct{}

type listRow struct {
	Var     string `json:"var"`
	Account string `json:"account"`
	ItemID  string `json:"item_id"`
	FieldID string `json:"field_id"`
}

func (ListCmd) Run(rc *runContext) error {
	b, err := readBundle(rc)
	if err != nil {
		return err
	}
	vars := slices.Clone(b.Vars)
	slices.SortFunc(vars, func(a, c bundle.Var) int { return strings.Compare(a.Name, c.Name) })
	out := jsonl{rc.stdout}
	for _, v := range vars {
		if err := out.Row(listRow{Var: v.Name, Account: v.AccountURL, ItemID: v.ItemID, FieldID: v.FieldID}); err != nil {
			return err
		}
	}
	return out.Meta(Meta{GeneratedAt: b.GeneratedAt.UTC().Format(time.RFC3339)})
}
