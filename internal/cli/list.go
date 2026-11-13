package cli

import (
	"slices"
	"strings"
	"time"

	"github.com/tammersaleh/envsec/internal/bundle"
)

// ListCmd prints the bundle's provenance: one row per var, then one row with
// status absent per trusted source that has no var. Never prints values and
// never calls op.
type ListCmd struct{}

type listRow struct {
	Var      string `json:"var"`
	Account  string `json:"account"`
	VaultID  string `json:"vault_id"`
	ItemID   string `json:"item_id"`
	FieldID  string `json:"field_id"`
	SourceID string `json:"source_id"`
}

// absentRow is a trusted source with no var: 1Password no longer has it, or
// has it in a form sync refuses. Its id is what trust --revoke takes.
type absentRow struct {
	Var         string `json:"var"`
	AccountUUID string `json:"account_uuid"`
	VaultID     string `json:"vault_id"`
	ItemID      string `json:"item_id"`
	FieldID     string `json:"field_id"`
	SourceID    string `json:"source_id"`
	Status      string `json:"status"`
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
		if err := out.Row(listRow{Var: v.Name, Account: v.AccountURL, VaultID: v.VaultID, ItemID: v.ItemID, FieldID: v.FieldID, SourceID: v.Source().ID()}); err != nil {
			return err
		}
	}
	// After the var rows: every trusted source that has no var.
	hasVar := make(map[bundle.Source]bool, len(vars))
	for _, v := range vars {
		hasVar[v.Source()] = true
	}
	var absent []absentRow
	for _, s := range b.TrustedSources {
		if !hasVar[s] {
			absent = append(absent, absentRow{Var: s.Name, AccountUUID: s.AccountUUID, VaultID: s.VaultID, ItemID: s.ItemID, FieldID: s.FieldID, SourceID: s.ID(), Status: "absent"})
		}
	}
	slices.SortFunc(absent, func(a, c absentRow) int {
		if d := strings.Compare(a.Var, c.Var); d != 0 {
			return d
		}
		return strings.Compare(a.SourceID, c.SourceID)
	})
	for _, row := range absent {
		if err := out.Row(row); err != nil {
			return err
		}
	}
	return out.Meta(Meta{GeneratedAt: b.GeneratedAt.UTC().Format(time.RFC3339)})
}
