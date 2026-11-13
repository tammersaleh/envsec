package cli

import (
	"fmt"
	"regexp"
	"slices"
	"strings"

	"github.com/tammersaleh/envsec/internal/bundle"
	"github.com/tammersaleh/envsec/internal/export"
)

// TrustCmd changes which sources sync may export, then writes the bundle as
// sync does. See SPEC.md "envsec trust". It takes sync's lock and runs
// sync's guards. It has no --forget-account and no --prune-all: when a guard
// refuses, the hint is the sync command that settles it. A --revoke is
// applied before the guards, so a source 1Password no longer has can still
// be revoked.
type TrustCmd struct {
	Revoke    bool     `help:"Revoke the named sources instead of trusting them. Their vars are removed."`
	SourceIDs []string `arg:"" optional:"" name:"source-id" help:"Source ids (src_...) from sync or check output. All apply or none. With none, pick from a list on the terminal."`
}

// sourceIDPattern is the shape of bundle.Source.ID.
var sourceIDPattern = regexp.MustCompile(`^src_[a-z2-7]{26}$`)

const sourceIDShape = "src_ plus 26 characters of a-z and 2-7"

func (c TrustCmd) Run(rc *runContext) error {
	// Everything that can be refused from the arguments alone is refused
	// before the lock and before 1Password, which may prompt.
	if err := c.checkArgs(rc); err != nil {
		return err
	}

	release, err := acquireLock()
	if err != nil {
		return err
	}
	defer release()

	res, err := resolve(rc, "trust")
	if err != nil {
		return err
	}
	old, err := readBundleOrEmpty(rc)
	if err != nil {
		return err
	}

	ch := change{cmd: "trust", old: old, res: res}
	var next bundle.Bundle
	switch {
	case c.Revoke:
		// An explicit revoke authorizes dropping that source and its var,
		// so the guards judge what is left: another vanished account, or a
		// zero-item resolution that would drop some other var, still needs
		// the sync flag.
		if ch.revoked, err = c.revoked(old); err != nil {
			return err
		}
		next = old.Revoke(ch.revoked...)
		err = guard(rc, next, res, nil, len(next.Vars) == 0)
	case len(c.SourceIDs) > 0:
		if err = guard(rc, old, res, nil, false); err != nil {
			return err
		}
		var added []bundle.Source
		added, err = c.added(old, res)
		next = old.Trust(added...)
	default:
		// Guards before the picker, as in sync.
		if err = guard(rc, old, res, nil, false); err != nil {
			return err
		}
		var picked []bundle.Source
		picked, ch.revoked, err = c.fromPicker(rc, old, res)
		next = old.Revoke(ch.revoked...).Trust(picked...)
	}
	if err != nil {
		return err
	}
	ch.trusted = next.TrustedSources
	return ch.apply(rc)
}

// checkArgs validates the ids as text. An argument that is not shaped like
// a source id is never echoed: it is named by position. Past this point
// every id is safe to print.
func (c TrustCmd) checkArgs(rc *runContext) error {
	if len(c.SourceIDs) == 0 {
		if c.Revoke {
			return &ExitError{Code: ExitFailure, Err: "usage", Detail: "--revoke needs at least one source id", Hint: "envsec trust --revoke <source-id>"}
		}
		if !rc.deps.Picker.Available() {
			return &ExitError{
				Code:   ExitFailure,
				Err:    "no_terminal",
				Detail: "envsec trust with no source id needs a terminal on stdin and stderr",
				Hint:   "envsec trust <source-id>",
			}
		}
		return nil
	}
	for i, id := range c.SourceIDs {
		if !sourceIDPattern.MatchString(id) {
			return &ExitError{
				Code:   ExitFailure,
				Err:    "invalid_source_id",
				Detail: fmt.Sprintf("argument %d is not a source id (%s)", i+1, sourceIDShape),
				Hint:   "envsec check",
			}
		}
	}
	var repeated []string
	for i, id := range c.SourceIDs {
		if slices.Contains(c.SourceIDs[:i], id) && !slices.Contains(repeated, id) {
			repeated = append(repeated, id)
		}
	}
	if len(repeated) > 0 {
		return refused("duplicate_source_id", "source id given more than once", repeated, "envsec trust <source-id>")
	}
	return nil
}

// refused is a fatal error that names source ids.
func refused(code, what string, ids []string, hint string) error {
	return &ExitError{Code: ExitFailure, Err: code, Detail: what + ": " + strings.Join(ids, ", "), Hint: hint}
}

// fromPicker shows every valid source, the trusted ones checked, and
// returns what was checked and what that revokes. A trusted source absent
// from 1Password is not shown and stays trusted. One that is present and
// not checked is revoked. That includes a trusted source that no longer
// passes validation: it cannot be shown, and keeping it would block every
// write.
func (c TrustCmd) fromPicker(rc *runContext, old bundle.Bundle, res resolution) (picked, revoked []bundle.Source, err error) {
	picked, err = pick(rc, res.validOrigins(), old.Trusts)
	if err != nil {
		return nil, nil, err
	}
	present := map[bundle.Source]bool{}
	for _, cand := range res.Candidates {
		present[cand.Source] = true
	}
	for _, e := range res.Problems {
		present[e.Source] = true
	}
	for _, s := range old.TrustedSources {
		if present[s] && !slices.Contains(picked, s) {
			revoked = append(revoked, s)
		}
	}
	return picked, revoked, nil
}

// added returns the sources the ids name that are not trusted yet. Each id
// must name one valid source in this resolution, and trusting them must not
// give any var name two trusted sources that are both present.
func (c TrustCmd) added(old bundle.Bundle, res resolution) ([]bundle.Source, error) {
	valid := map[string][]bundle.Source{}
	for _, o := range res.validOrigins() {
		valid[o.Source.ID()] = append(valid[o.Source.ID()], o.Source)
	}
	invalid := map[string]string{}
	for _, e := range res.Problems {
		// Reason is fixed text around the label, which matched the label
		// pattern. The item title is not in it.
		invalid[e.Source.ID()] = e.Reason
	}

	var added []bundle.Source
	var unknown, unusable []string
	for _, id := range c.SourceIDs {
		switch {
		case len(valid[id]) == 1:
			if s := valid[id][0]; !old.Trusts(s) {
				added = append(added, s)
			}
		case invalid[id] != "":
			unusable = append(unusable, id+" ("+invalid[id]+")")
		default:
			unknown = append(unknown, id)
		}
	}
	if len(unknown) > 0 {
		return nil, refused("unknown_source_id", "no valid source in 1Password has this id", unknown, "envsec check")
	}
	if len(unusable) > 0 {
		return nil, refused("source_invalid", "source cannot be trusted", unusable, "fix the field in 1Password")
	}

	// A conflict the new sources take part in is refused here, by id. One
	// that was already there is reported by apply as any sync would.
	var conflicts []string
	for _, conflict := range res.split(old.Trust(added...).TrustedSources).Conflicts {
		if !slices.ContainsFunc(conflict.Sources, func(o export.Origin) bool { return slices.Contains(added, o.Source) }) {
			continue
		}
		ids := make([]string, len(conflict.Sources))
		for i, o := range conflict.Sources {
			ids[i] = o.Source.ID()
		}
		conflicts = append(conflicts, conflict.Name+" would have more than one trusted source: "+strings.Join(ids, ", "))
	}
	if len(conflicts) > 0 {
		return nil, &ExitError{Code: ExitFailure, Err: "trust_conflict", Detail: strings.Join(conflicts, "; "), Hint: "envsec trust --revoke <source-id>"}
	}
	return added, nil
}

// revoked returns the stored sources the ids name. Each id must be in the
// stored trust list, whether or not 1Password still has the source.
// envsec list prints the id of every stored source.
func (c TrustCmd) revoked(old bundle.Bundle) ([]bundle.Source, error) {
	var revoked []bundle.Source
	var unknown []string
	for _, id := range c.SourceIDs {
		i := slices.IndexFunc(old.TrustedSources, func(s bundle.Source) bool { return s.ID() == id })
		if i < 0 {
			unknown = append(unknown, id)
			continue
		}
		revoked = append(revoked, old.TrustedSources[i])
	}
	if len(unknown) > 0 {
		return nil, refused("unknown_source_id", "no trusted source has this id", unknown, "envsec list")
	}
	return revoked, nil
}
