package cli

import (
	"bytes"
	"fmt"
	"slices"
	"strings"

	"github.com/tammersaleh/envsec/internal/bundle"
	"github.com/tammersaleh/envsec/internal/export"
)

// managedVar is the sentinel listing the names the last run exported.
const managedVar = "ENVSEC_MANAGED_VARS"

// EnvCmd prints shell for `eval "$(envsec env)"`. See SPEC.md "envsec env"
// and "Hardening rules for env". Never touches 1Password.
type EnvCmd struct{}

func (EnvCmd) Run(rc *runContext) error {
	b, err := readBundle(rc)
	if err != nil {
		e := asExit(err)
		_, _ = fmt.Fprintf(rc.stderr, "envsec: %s; run %s\n", e.Detail, hintSync)
		e.Silent = true
		return e
	}

	vars := slices.Clone(b.Vars)
	slices.SortFunc(vars, func(a, c bundle.Var) int { return strings.Compare(a.Name, c.Name) })

	var body bytes.Buffer
	var exported []string
	var rejected []string
	inBundle := map[string]bool{}
	for _, v := range vars {
		inBundle[v.Name] = true
		validName := export.LabelPattern.MatchString(v.Name)
		reason := ""
		switch {
		case !validName:
			reason = "invalid name"
		case export.Denied(v.Name):
			reason = "denylisted"
		default:
			if _, qerr := export.Quote(v.Value); qerr != nil {
				reason = qerr.Error()
			}
		}
		if reason != "" {
			rejected = append(rejected, fmt.Sprintf("%s (%s)", v.Name, reason))
			if validName {
				fmt.Fprintln(&body, export.UnsetLine(v.Name))
			}
			continue
		}
		line, lerr := export.ExportLine(v.Name, v.Value)
		if lerr != nil {
			return lerr
		}
		fmt.Fprintln(&body, line)
		exported = append(exported, v.Name)
	}

	// Inherited sentinel: unset names no longer in the bundle. Names are
	// validated so a tampered sentinel cannot inject shell or unset a
	// denylisted var.
	var stale []string
	for _, name := range strings.Fields(rc.deps.Env(managedVar)) {
		if !export.LabelPattern.MatchString(name) || export.Denied(name) || inBundle[name] {
			continue
		}
		stale = append(stale, name)
	}
	slices.Sort(stale)
	stale = slices.Compact(stale)

	var out bytes.Buffer
	for _, name := range stale {
		fmt.Fprintln(&out, export.UnsetLine(name))
	}
	out.Write(body.Bytes())
	sentinel, err := export.ExportLine(managedVar, strings.Join(exported, " "))
	if err != nil {
		return err
	}
	fmt.Fprintln(&out, sentinel)

	if _, err := rc.stdout.Write(out.Bytes()); err != nil {
		return err
	}
	if len(rejected) > 0 {
		_, _ = fmt.Fprintf(rc.stderr, "envsec: rejected %d var(s): %s\n", len(rejected), strings.Join(rejected, ", "))
		return &ExitError{Code: ExitFailure, Err: "vars_rejected", Silent: true}
	}
	return nil
}
