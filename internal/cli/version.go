package cli

// Version is set at build time via -ldflags (target: github.com/tammersaleh/envsec/internal/cli.Version).
var Version = "dev"

// VersionCmd prints the build version.
type VersionCmd struct{}

func (VersionCmd) Run(rc *runContext) error {
	out := jsonl{rc.stdout}
	if err := out.Row(struct {
		Version string `json:"version"`
	}{Version}); err != nil {
		return err
	}
	return out.Meta(Meta{})
}
