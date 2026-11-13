package cli

import (
	"errors"
	"fmt"
	"maps"
	"slices"
	"strings"

	"github.com/tammersaleh/envsec/internal/bundle"
	"github.com/tammersaleh/envsec/internal/export"
	"github.com/tammersaleh/envsec/internal/trustpicker"
)

// Row statuses beyond the diff and compare ones in package bundle.
const (
	statusConflict  = "conflict"
	statusError     = "error"
	statusUntrusted = "untrusted"
	statusRevoked   = "revoked"
)

// statusRow is one line of sync, trust, or check output. It never carries a
// value. Account is always present: the var's account URL, or empty when the
// row stands for sources in more than one account or for a source known only
// from the stored trust list. The provenance fields from Vault to SourceID
// are set only when the row stands for exactly one source: an untrusted or
// revoked one. Vault and Item come from 1Password unescaped, so a row is
// written with the JSON encoder and nothing else.
type statusRow struct {
	Var      string `json:"var"`
	Account  string `json:"account"`
	Vault    string `json:"vault,omitempty"`
	VaultID  string `json:"vault_id,omitempty"`
	Item     string `json:"item,omitempty"`
	ItemID   string `json:"item_id,omitempty"`
	FieldID  string `json:"field_id,omitempty"`
	SourceID string `json:"source_id,omitempty"`
	Status   string `json:"status"`
	Detail   string `json:"detail,omitempty"`
}

// passing are the statuses that do not count in error_count.
var passing = map[string]bool{
	string(bundle.OK): true, string(bundle.Added): true, string(bundle.Unchanged): true,
	string(bundle.Changed): true, string(bundle.Removed): true, statusRevoked: true,
}

// originRow is the row for exactly one source, with its provenance.
func originRow(o export.Origin, status, detail string) statusRow {
	return statusRow{
		Var: o.Source.Name, Account: o.AccountURL,
		Vault: o.VaultName, VaultID: o.Source.VaultID,
		Item: o.ItemTitle, ItemID: o.Source.ItemID, FieldID: o.Source.FieldID,
		SourceID: o.Source.ID(), Status: status, Detail: detail,
	}
}

// noted is the detail each source adds to a row that stands for more than
// that one source, where the row's own fields cannot identify it.
func noted(origins []export.Origin, what string) []string {
	out := make([]string, len(origins))
	for i, o := range origins {
		out[i] = fmt.Sprintf("source %s %s (item %s field %s)", o.Source.ID(), what, o.Source.ItemID, o.Source.FieldID)
	}
	return out
}

// agreed returns the one account URL every origin shares, or "".
func agreed(urls []string) string {
	if len(urls) == 0 {
		return ""
	}
	for _, u := range urls[1:] {
		if u != urls[0] {
			return ""
		}
	}
	return urls[0]
}

func accountURLs(origins []export.Origin) []string {
	urls := make([]string, len(origins))
	for i, o := range origins {
		urls[i] = o.AccountURL
	}
	return urls
}

// problemRows folds p into one row per var name that has a conflict, a
// validation error, or an untrusted source. conflict wins over error, and
// error wins over untrusted. Detail joins every problem for the name with
// "; ": conflicts, then validation errors (trusted sources first), then
// untrusted sources. A name whose only problem is one untrusted source gets
// that source's provenance. Sources in skip are left out: trust passes the
// ones it revoked in this run. No candidate value is read.
func problemRows(p export.Partition, skip map[bundle.Source]bool) map[string]statusRow {
	type group struct {
		conflicts []string
		errs      []string
		errURLs   []string
		untrusted []export.Origin
	}
	groups := map[string]*group{}
	at := func(name string) *group {
		if groups[name] == nil {
			groups[name] = &group{}
		}
		return groups[name]
	}
	for _, c := range p.Conflicts {
		g := at(c.Name)
		g.conflicts = append(g.conflicts, c.Error())
	}
	for _, problems := range [][]*export.SelectError{p.TrustedProblems, p.UntrustedProblems} {
		for _, e := range problems {
			if skip[e.Source] {
				continue
			}
			g := at(e.Source.Name)
			g.errs = append(g.errs, e.Error())
			g.errURLs = append(g.errURLs, e.AccountURL)
		}
	}
	for _, c := range p.Untrusted {
		if skip[c.Source] {
			continue
		}
		g := at(c.Source.Name)
		g.untrusted = append(g.untrusted, c.Origin)
	}

	rows := make(map[string]statusRow, len(groups))
	for name, g := range groups {
		switch {
		case len(g.conflicts) > 0:
			detail := slices.Concat(g.conflicts, g.errs, noted(g.untrusted, "is not trusted"))
			rows[name] = statusRow{Var: name, Status: statusConflict, Detail: strings.Join(detail, "; ")}
		case len(g.errs) > 0:
			detail := slices.Concat(g.errs, noted(g.untrusted, "is not trusted"))
			rows[name] = statusRow{Var: name, Account: agreed(g.errURLs), Status: statusError, Detail: strings.Join(detail, "; ")}
		case len(g.untrusted) == 1:
			rows[name] = originRow(g.untrusted[0], statusUntrusted, "source is not trusted")
		default:
			rows[name] = statusRow{
				Var: name, Account: agreed(accountURLs(g.untrusted)), Status: statusUntrusted,
				Detail: strings.Join(noted(g.untrusted, "is not trusted"), "; "),
			}
		}
	}
	return rows
}

// mergeRows returns one row per var name: the problem row when the name has
// one, else its diff or compare row. A problem row wins for display only.
// The trusted value behind it is still written or compared.
func mergeRows(problems map[string]statusRow, compared []bundle.Row) map[string]statusRow {
	rows := maps.Clone(problems)
	for _, r := range compared {
		if _, bad := rows[r.Name]; !bad {
			rows[r.Name] = statusRow{Var: r.Name, Account: r.AccountURL, Status: string(r.Status)}
		}
	}
	return rows
}

// addRevoked reports the sources revoked in this run. A name that lost its
// var gets a revoked row in place of removed, with the source's provenance.
// A name that still has a row (another source now provides it, or it has a
// problem) keeps that row and the revoke is added to its detail.
func addRevoked(rows map[string]statusRow, revoked []export.Origin) {
	byName := map[string][]export.Origin{}
	for _, o := range revoked {
		byName[o.Source.Name] = append(byName[o.Source.Name], o)
	}
	for name, origins := range byName {
		cur, has := rows[name]
		switch {
		case has && cur.Status != string(bundle.Removed):
			details := noted(origins, "revoked")
			if cur.Detail != "" {
				details = slices.Insert(details, 0, cur.Detail)
			}
			cur.Detail = strings.Join(details, "; ")
			rows[name] = cur
		case len(origins) == 1:
			rows[name] = originRow(origins[0], statusRevoked, "trust revoked")
		default:
			rows[name] = statusRow{
				Var: name, Account: agreed(accountURLs(origins)), Status: statusRevoked,
				Detail: strings.Join(noted(origins, "revoked"), "; "),
			}
		}
	}
}

// untrustedNames lists the var names with a valid untrusted source, sorted.
// Names matched the label pattern at selection, so they are safe to print
// on stderr as they are.
func untrustedNames(p export.Partition, skip map[bundle.Source]bool) []string {
	var names []string
	for _, c := range p.Untrusted {
		if !skip[c.Source] {
			names = append(names, c.Source.Name)
		}
	}
	slices.Sort(names)
	return slices.Compact(names)
}

// emit prints rows sorted by var name, the trailer, and, when warn is not
// empty, the one stderr line naming the untrusted vars. It returns the
// silent exit-1 error for cmd when any row is a failure. Sync and trust call
// it only after the keychain write succeeded or when nothing is written.
func emit(rc *runContext, cmd string, rows map[string]statusRow, warn []string) error {
	out := jsonl{rc.stdout}
	failures := 0
	for _, name := range slices.Sorted(maps.Keys(rows)) {
		if !passing[rows[name].Status] {
			failures++
		}
		if err := out.Row(rows[name]); err != nil {
			return err
		}
	}
	if err := out.Meta(Meta{ErrorCount: &failures}); err != nil {
		return err
	}
	if len(warn) > 0 {
		_, _ = fmt.Fprintf(rc.stderr, "envsec: untrusted sources for %s; run envsec trust\n", strings.Join(warn, ", "))
	}
	if failures > 0 {
		return &ExitError{Code: ExitFailure, Err: cmd + "_failed", Silent: true}
	}
	return nil
}

// change is a resolution and the trust to judge it by, ready to write. It is
// the path sync and trust share once each has settled its trusted list.
type change struct {
	cmd string
	old bundle.Bundle
	res resolution
	// trusted becomes the bundle's trusted_sources, whole.
	trusted []bundle.Source
	// revoked are the sources trust dropped in this run.
	revoked []bundle.Source
}

// apply splits the resolution by c.trusted. A failure on a trusted source
// prints the problem rows and leaves the keychain untouched. Otherwise it
// writes the bundle once, with every trusted source kept whether or not
// 1Password still has it, and only then prints rows and the warning.
func (c change) apply(rc *runContext) error {
	skip := make(map[bundle.Source]bool, len(c.revoked))
	for _, s := range c.revoked {
		skip[s] = true
	}
	p := c.res.split(c.trusted)
	if p.Fatal() {
		return emit(rc, c.cmd, problemRows(p, skip), nil)
	}

	cur := bundle.Bundle{Schema: bundle.Schema, GeneratedAt: rc.deps.Now().UTC(), TrustedSources: c.trusted, Vars: p.Vars()}
	raw, err := bundle.Encode(cur)
	if err != nil {
		return err
	}
	if err := rc.deps.Keychain.Write(rc.ctx, raw); err != nil {
		e := asExit(err)
		if e.Code != ExitKeychain {
			e = &ExitError{Code: ExitKeychain, Err: "keychain_unavailable", Detail: err.Error()}
		}
		// A locked keychain already carries the unlock command as its hint.
		if e.Err != "keychain_locked" {
			e.Hint = "unlock the login keychain and rerun envsec " + c.cmd
		}
		return e
	}

	rows := mergeRows(problemRows(p, skip), bundle.Diff(c.old, cur))
	addRevoked(rows, c.origins(c.revoked))
	return emit(rc, c.cmd, rows, untrustedNames(p, skip))
}

// origins returns the display form of srcs. A source in this resolution has
// its account, vault, and item strings. One known only from the stored trust
// list has its tuple, plus the account URL when the old bundle held its var.
func (c change) origins(srcs []bundle.Source) []export.Origin {
	known := map[bundle.Source]export.Origin{}
	for _, v := range c.old.Vars {
		known[v.Source()] = export.Origin{Source: v.Source(), AccountURL: v.AccountURL}
	}
	for _, e := range c.res.Problems {
		known[e.Source] = e.Origin
	}
	for _, cand := range c.res.Candidates {
		known[cand.Source] = cand.Origin
	}
	out := make([]export.Origin, len(srcs))
	for i, s := range srcs {
		out[i] = export.Origin{Source: s}
		if o, ok := known[s]; ok {
			out[i] = o
		}
	}
	return out
}

// validOrigins returns every source that passed selection, once each,
// sorted by var name and otherwise in resolve order. These are the sources
// that can be trusted.
func (r resolution) validOrigins() []export.Origin {
	seen := map[bundle.Source]bool{}
	var out []export.Origin
	for _, c := range r.Candidates {
		if !seen[c.Source] {
			seen[c.Source] = true
			out = append(out, c.Origin)
		}
	}
	slices.SortStableFunc(out, func(a, b export.Origin) int { return strings.Compare(a.Source.Name, b.Source.Name) })
	return out
}

// pick shows origins in the picker, checked where checked says so, and
// returns the sources confirmed. Any failure is trust_cancelled and the
// caller writes nothing. The error text is fixed: a terminal error can hold
// anything.
func pick(rc *runContext, origins []export.Origin, checked func(bundle.Source) bool) ([]bundle.Source, error) {
	opts := make([]trustpicker.Option, len(origins))
	byID := make(map[string]bundle.Source, len(origins))
	for i, o := range origins {
		id := o.Source.ID()
		opts[i] = trustpicker.Option{
			ID: id, Var: o.Source.Name, Account: o.AccountURL, Vault: o.VaultName, Item: o.ItemTitle,
			Checked: checked(o.Source),
		}
		byID[id] = o.Source
	}
	cancelled := func(detail string) error {
		return &ExitError{Code: ExitFailure, Err: "trust_cancelled", Detail: detail + "; nothing was written", Hint: "envsec trust"}
	}
	ids, err := rc.deps.Picker.Pick(opts)
	if errors.Is(err, trustpicker.ErrCancelled) {
		return nil, cancelled("the trust picker was cancelled")
	}
	if err != nil {
		return nil, cancelled("the trust picker failed")
	}
	picked := make([]bundle.Source, 0, len(ids))
	for _, id := range ids {
		s, ok := byID[id]
		if !ok || slices.Contains(picked, s) {
			return nil, cancelled("the trust picker returned a source it was not given")
		}
		picked = append(picked, s)
	}
	return picked, nil
}
