// Package preflight checks, before an audit, that what the audit needs
// offline is on this machine: the pinned gnark and gnark-crypto sources in
// the Go module cache (agents read gnark std there), the target's other
// requirements (type loading and PoCs run with GOPROXY=off), and a Go
// toolchain at least as new as the module's go directive and gnark's own.
// It reports what is missing and the exact commands that fetch it; it
// never runs them (the skill asks the user first).
package preflight

import (
	"fmt"
	"path/filepath"
	"strings"

	"github.com/shramee/zk-audit/plugins/zk-audit/skills/zk-audit/tools/gnark-inventory/internal/detect"
	"github.com/shramee/zk-audit/plugins/zk-audit/skills/zk-audit/tools/gnark-inventory/internal/gomod"
	"github.com/shramee/zk-audit/plugins/zk-audit/skills/zk-audit/tools/gnark-inventory/internal/modcache"
)

// Options are the machine facts; Check never runs the go command itself.
type Options struct {
	Cache   string // GOMODCACHE
	LocalGo string // version of the local go command, e.g. go1.24.7
	Out     string // audit output directory, used in the printed commands
}

// Report is the result.
type Report struct {
	Repo       string               `json:"repo"`
	ModCache   string               `json:"modcache"`
	LocalGo    string               `json:"local_go"`
	Modules    []ModuleCheck        `json:"modules"`
	Toolchains []modcache.Toolchain `json:"cached_toolchains"`
	Missing    []string             `json:"missing"`
	Commands   []Command            `json:"commands"`
	OK         bool                 `json:"ok"`
	Summary    string               `json:"summary"`
}

// ModuleCheck is the check of one go.mod.
type ModuleCheck struct {
	GoMod       string `json:"go_mod"`
	Module      string `json:"module"`
	GoDirective string `json:"go_directive,omitempty"`
	// NeedsGo is the newest go directive among the module, gnark and
	// gnark-crypto: the oldest Go that can build the target.
	NeedsGo   string `json:"needs_go,omitempty"`
	LocalGoOK bool   `json:"local_go_ok"`
	// UseGo is a cached toolchain's go binary to run instead of the local
	// one when the local Go is too old ("" when none is needed or cached).
	UseGo       string           `json:"use_go,omitempty"`
	Gnark       *modcache.Module `json:"gnark,omitempty"`
	GnarkCrypto *modcache.Module `json:"gnark_crypto,omitempty"`
	// Std is the absolute gnark std directory agents read, or "".
	Std string `json:"gnark_std,omitempty"`
	// Requirements counts the go.mod requirements and those whose download
	// is not in the cache.
	Requirements        int      `json:"requirements"`
	MissingRequirements []string `json:"missing_requirements"`
	Notes               []string `json:"notes"`
}

// Command is one command the user may approve.
type Command struct {
	Why     string `json:"why"`
	Command string `json:"command"`
	Network bool   `json:"network"`
}

const (
	gnarkModule  = "github.com/consensys/gnark"
	cryptoModule = "github.com/consensys/gnark-crypto"
)

// Check runs the pre-flight check for the stack detected in a repository.
func Check(st *detect.Stack, opt Options) *Report {
	out := opt.Out
	if out == "" {
		out = "<out>"
	}
	r := &Report{Repo: st.Repo, ModCache: opt.Cache, LocalGo: opt.LocalGo, Modules: []ModuleCheck{}, Missing: []string{}, Commands: []Command{}}
	r.Toolchains = modcache.Toolchains(opt.Cache)
	if r.Toolchains == nil {
		r.Toolchains = []modcache.Toolchain{}
	}
	var fetch []string // module@version for the std download command
	seenFetch := map[string]bool{}
	missingReqs := false
	toolchain := ""
	for _, m := range st.GoModules {
		if m.Gnark == "" && m.GnarkLocal == "" && m.GnarkCrypto == "" {
			continue
		}
		mc := ModuleCheck{GoMod: m.Path, Module: m.Module, GoDirective: m.Go, NeedsGo: m.Go, MissingRequirements: []string{}, Notes: []string{}}
		check := func(module, version string) *modcache.Module {
			if version == "" {
				return nil
			}
			x := modcache.Lookup(opt.Cache, module, version)
			if !x.SourcePresent || !x.DownloadPresent {
				r.Missing = append(r.Missing, fmt.Sprintf("%s: %s@%s is not in the module cache %s", m.Path, module, version, opt.Cache))
				if k := module + "@" + version; !seenFetch[k] {
					seenFetch[k] = true
					fetch = append(fetch, k)
				}
			}
			if x.GoDirective != "" && (mc.NeedsGo == "" || modcache.CompareGo(x.GoDirective, mc.NeedsGo) > 0) {
				mc.NeedsGo = x.GoDirective
				mc.Notes = append(mc.Notes, fmt.Sprintf("%s@%s needs go %s", module, version, x.GoDirective))
			}
			return &x
		}
		if m.GnarkLocal != "" {
			mc.Notes = append(mc.Notes, "gnark is replaced by "+m.GnarkLocal+": std is read from there, not from the module cache")
		}
		mc.Gnark = check(gnarkModule, m.Gnark)
		mc.GnarkCrypto = check(cryptoModule, m.GnarkCrypto)
		if mc.Gnark != nil && mc.Gnark.SourcePresent {
			mc.Std = filepath.Join(mc.Gnark.Source, "std")
		}
		// every other requirement: type loading and PoCs run offline
		if f, err := gomod.ParseFile(filepath.Join(st.Repo, filepath.FromSlash(m.Path))); err == nil {
			replaced := map[string]bool{}
			for _, rp := range f.Replace {
				replaced[rp.Old] = true
			}
			for _, rq := range f.Require {
				if replaced[rq.Path] {
					continue
				}
				mc.Requirements++
				if !modcache.Lookup(opt.Cache, rq.Path, rq.Version).DownloadPresent {
					mc.MissingRequirements = append(mc.MissingRequirements, rq.Path+"@"+rq.Version)
				}
			}
		}
		if n := len(mc.MissingRequirements); n > 0 {
			missingReqs = true
			r.Missing = append(r.Missing, fmt.Sprintf("%s: %d of %d requirements are not in the module cache (first: %s); typed loading falls back to syntax mode and PoCs cannot build offline", m.Path, n, mc.Requirements, mc.MissingRequirements[0]))
		}
		mc.LocalGoOK = mc.NeedsGo == "" || modcache.CompareGo(opt.LocalGo, mc.NeedsGo) >= 0
		if !mc.LocalGoOK {
			for _, tc := range r.Toolchains {
				if modcache.CompareGo(tc.Version, mc.NeedsGo) >= 0 {
					mc.UseGo = tc.GoBin
					break
				}
			}
			if mc.UseGo != "" {
				mc.Notes = append(mc.Notes, fmt.Sprintf("local %s is older than go %s; the cached toolchain %s works offline: use it as the go command (the sandbox keeps GOTOOLCHAIN=local)", opt.LocalGo, mc.NeedsGo, mc.UseGo))
			} else {
				r.Missing = append(r.Missing, fmt.Sprintf("%s: needs go %s, local is %s, and no newer toolchain is in the module cache", m.Path, mc.NeedsGo, opt.LocalGo))
				if t := toolchainName(mc.NeedsGo); toolchain == "" || modcache.CompareGo(t, toolchain) > 0 {
					toolchain = t
				}
			}
		}
		r.Modules = append(r.Modules, mc)
	}
	if len(fetch) > 0 {
		r.Commands = append(r.Commands, Command{
			Why:     "download the pinned gnark / gnark-crypto sources (std for the agents) into the module cache; runs outside the repository and changes no file in it",
			Command: "go -C " + out + " mod download " + strings.Join(fetch, " "),
			Network: true,
		})
	}
	if missingReqs {
		r.Commands = append(r.Commands, Command{
			Why:     "create the scratch worktree (Phase 4 creates it anyway) so the next command changes only its go.sum",
			Command: "git -C " + st.Repo + " worktree add --detach " + out + "/worktree HEAD",
		}, Command{
			Why:     "download every requirement of the target for typed loading and PoCs",
			Command: "go -C " + out + "/worktree mod download",
			Network: true,
		})
	}
	if toolchain != "" {
		r.Commands = append(r.Commands, Command{
			Why:     "download the Go toolchain the target needs into the module cache (proxy.golang.org); then run its bin/go (rerun preflight to print the path)",
			Command: "GOTOOLCHAIN=" + toolchain + " go -C " + out + " version",
			Network: true,
		})
	}
	r.OK = len(r.Missing) == 0
	switch {
	case len(r.Modules) == 0:
		r.Summary = "preflight: no go.mod pins gnark or gnark-crypto; nothing to fetch"
	case r.OK:
		r.Summary = fmt.Sprintf("preflight: ok (%s; module cache %s)", strings.Join(stdLines(r), "; "), opt.Cache)
	default:
		r.Summary = fmt.Sprintf("preflight: %d missing; ask the user before running the commands below (network)", len(r.Missing))
	}
	return r
}

func stdLines(r *Report) []string {
	var out []string
	for _, m := range r.Modules {
		s := m.GoMod + ": "
		if m.Std != "" {
			s += "gnark std " + m.Std
		} else {
			s += "no gnark std"
		}
		if m.UseGo != "" {
			s += ", go " + m.UseGo
		}
		out = append(out, s)
	}
	return out
}

// toolchainName turns a go directive into a toolchain name: "1.25" and
// "1.25.0" become go1.25.0.
func toolchainName(v string) string {
	v = strings.TrimPrefix(v, "go")
	if strings.Count(v, ".") == 1 && !strings.ContainsAny(v, "rcbeta") {
		v += ".0"
	}
	return "go" + v
}

// Text renders the report for the terminal.
func (r *Report) Text() string {
	var b strings.Builder
	fmt.Fprintln(&b, r.Summary)
	fmt.Fprintf(&b, "local go: %s · module cache: %s\n", r.LocalGo, r.ModCache)
	for _, m := range r.Modules {
		fmt.Fprintf(&b, "- %s (%s): go %s, needs go %s (local ok: %v)", m.GoMod, m.Module, dash(m.GoDirective), dash(m.NeedsGo), m.LocalGoOK)
		for _, x := range []*modcache.Module{m.Gnark, m.GnarkCrypto} {
			if x == nil {
				continue
			}
			st := "cached"
			if !x.SourcePresent || !x.DownloadPresent {
				st = "MISSING"
			}
			fmt.Fprintf(&b, "; %s@%s %s", strings.TrimPrefix(x.Path, "github.com/consensys/"), x.Version, st)
		}
		fmt.Fprintf(&b, "; requirements %d, missing %d\n", m.Requirements, len(m.MissingRequirements))
		if m.Std != "" {
			fmt.Fprintf(&b, "  gnark std: %s\n", m.Std)
		}
		for _, n := range m.Notes {
			fmt.Fprintf(&b, "  note: %s\n", n)
		}
	}
	for _, x := range r.Missing {
		fmt.Fprintf(&b, "missing: %s\n", x)
	}
	for _, c := range r.Commands {
		tag := "ask first"
		if c.Network {
			tag = "network, ask first"
		}
		fmt.Fprintf(&b, "command (%s): %s\n  why: %s\n", tag, c.Command, c.Why)
	}
	return b.String()
}

func dash(s string) string {
	if s == "" {
		return "–"
	}
	return s
}
