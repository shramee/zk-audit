// Package args parses a /zk-audit invocation ("quick circuits/vote.go
// --loop 2 --no-poc", "diff origin/main..HEAD", "recon") into a validated
// run configuration with defaults, so the orchestrator never parses flags by
// hand.
package args

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/shramee/zk-audit/plugins/zk-audit/skills/zk-audit/tools/gnark-inventory/internal/fsutil"
	"github.com/shramee/zk-audit/plugins/zk-audit/skills/zk-audit/tools/gnark-inventory/internal/profile"
)

// Modes a run can be in. Guidance mode is never reached through an explicit
// invocation, so it is not one of them.
var Modes = []string{"audit", "recon", "diff", "setup"}

// MaxLoop bounds --loop.
const MaxLoop = 10

// Run is the parsed invocation.
type Run struct {
	Mode            string    `json:"mode"`
	Profile         string    `json:"profile"`
	ProfileExplicit bool      `json:"profile_explicit"`
	Scope           []string  `json:"scope"`
	Local           bool      `json:"local"`
	Passes          int       `json:"passes"`
	Memory          bool      `json:"memory"`
	LoopExplicit    bool      `json:"loop_explicit"`
	PoC             bool      `json:"poc"`
	FileOutput      bool      `json:"file_output"`
	CheckOnly       bool      `json:"check_only,omitempty"`
	ReportCopy      string    `json:"report_copy,omitempty"`
	Repo            string    `json:"repo"`
	RepoName        string    `json:"repo_name"`
	RunID           string    `json:"run_id"`
	Out             string    `json:"out"`
	OutExplicit     bool      `json:"out_explicit"`
	Diff            *DiffArgs `json:"diff,omitempty"`
	Words           []string  `json:"words"`
	Warnings        []string  `json:"warnings"`
}

// DiffArgs is the commit range of diff mode.
type DiffArgs struct {
	Base string `json:"base"`
	Head string `json:"head"`
}

// Options are the caller's context.
type Options struct {
	Repo  string    // target repository (default ".")
	Home  string    // home directory for the default output path
	Now   time.Time // run id clock
	RunID string    // explicit run id (overrides Now)
	Mode  string    // forced mode (a /zk-audit:<mode> command); "" detects it
}

// Error lists every problem of an invalid invocation.
type Error struct{ Problems []string }

func (e *Error) Error() string { return strings.Join(e.Problems, "; ") }

// Split splits an invocation string into words with POSIX-shell-like quoting:
// single quotes, double quotes and backslash escapes.
func Split(s string) ([]string, error) {
	var words []string
	var cur strings.Builder
	inWord := false
	var quote rune
	esc := false
	for _, r := range s {
		switch {
		case esc:
			cur.WriteRune(r)
			esc = false
		case quote == '\'':
			if r == '\'' {
				quote = 0
			} else {
				cur.WriteRune(r)
			}
		case quote == '"':
			switch r {
			case '"':
				quote = 0
			case '\\':
				esc = true
			default:
				cur.WriteRune(r)
			}
		case r == '\\':
			esc, inWord = true, true
		case r == '\'' || r == '"':
			quote, inWord = r, true
		case r == ' ' || r == '\t' || r == '\n':
			if inWord {
				words = append(words, cur.String())
				cur.Reset()
				inWord = false
			}
		default:
			cur.WriteRune(r)
			inWord = true
		}
	}
	if quote != 0 {
		return nil, fmt.Errorf("unterminated %c quote", quote)
	}
	if esc {
		return nil, fmt.Errorf("trailing backslash")
	}
	if inWord {
		words = append(words, cur.String())
	}
	return words, nil
}

var reRunID = func(s string) bool {
	_, err := time.Parse("20060102-150405", s)
	return err == nil
}

// Parse validates words against the repository and fills in defaults.
func Parse(words []string, opt Options) (*Run, error) {
	set := profile.Load()
	var problems []string
	bad := func(f string, a ...any) { problems = append(problems, fmt.Sprintf(f, a...)) }
	repo := opt.Repo
	if repo == "" {
		repo = "."
	}
	root, err := filepath.Abs(repo)
	if err != nil {
		return nil, err
	}
	if st, err := os.Stat(root); err != nil || !st.IsDir() {
		return nil, fmt.Errorf("repository %s is not a directory", root)
	}
	if r, err := filepath.EvalSymlinks(root); err == nil {
		root = r
	}
	r := &Run{Repo: root, RepoName: filepath.Base(root), PoC: true, Scope: []string{}, Words: append([]string{}, words...), Warnings: []string{}}
	if r.Words == nil {
		r.Words = []string{}
	}
	r.Mode = opt.Mode
	rest := words
	if r.Mode == "" {
		r.Mode = "audit"
		if len(rest) > 0 {
			for _, m := range Modes {
				if rest[0] == m {
					r.Mode, rest = m, rest[1:]
					break
				}
			}
		}
	} else if !contains(Modes, r.Mode) {
		return nil, fmt.Errorf("unknown mode %q (want %s)", r.Mode, strings.Join(Modes, ", "))
	}
	loop, out := 0, ""
	var positional []string
	value := func(i *int, name string) (string, bool) {
		w := rest[*i]
		if v, ok := strings.CutPrefix(w, name+"="); ok {
			return v, true
		}
		if *i+1 >= len(rest) || strings.HasPrefix(rest[*i+1], "--") {
			bad("%s needs a value", name)
			return "", false
		}
		*i++
		return rest[*i], true
	}
	for i := 0; i < len(rest); i++ {
		w := rest[i]
		name := w
		if j := strings.IndexByte(w, '='); j > 0 && strings.HasPrefix(w, "--") {
			name = w[:j]
		}
		switch {
		case w == "--local":
			r.Local = true
		case w == "--no-poc":
			r.PoC = false
		case w == "--file-output":
			r.FileOutput = true
		case w == "--check-only":
			r.CheckOnly = true
		case name == "--loop":
			if v, ok := value(&i, "--loop"); ok {
				n, err := strconv.Atoi(v)
				if err != nil || n < 1 || n > MaxLoop {
					bad("--loop wants a whole number from 1 to %d, got %q", MaxLoop, v)
				} else {
					loop = n
				}
			}
		case name == "--out":
			if v, ok := value(&i, "--out"); ok {
				out = v
			}
		case name == "--profile":
			if v, ok := value(&i, "--profile"); ok {
				if _, ok := set.Profile(v); !ok {
					bad("unknown profile %q (want %s)", v, strings.Join(set.ProfileIDs(), ", "))
				} else {
					setProfile(r, v, bad)
				}
			}
		case strings.HasPrefix(w, "-"):
			bad("unknown flag %q (flags: --local, --loop N, --no-poc, --file-output, --out DIR, --profile P; setup: --check-only)", w)
		default:
			if _, ok := set.Profile(w); ok {
				setProfile(r, w, bad)
				continue
			}
			positional = append(positional, w)
		}
	}
	if !r.ProfileExplicit {
		r.Profile = set.Default().ID
	}
	p, _ := set.Profile(r.Profile)
	r.Passes, r.Memory = p.Passes, p.Memory
	if loop > 0 {
		r.Passes, r.LoopExplicit = loop, true
		r.Memory = loop > 1
	}

	switch r.Mode {
	case "diff":
		r.Diff = &DiffArgs{Base: "origin/main", Head: "HEAD"}
		if len(positional) > 0 && !isPath(root, positional[0]) {
			rng := positional[0]
			positional = positional[1:]
			base, head := rng, ""
			if b, h, ok := strings.Cut(rng, "..."); ok {
				base, head = b, h
			} else if b, h, ok := strings.Cut(rng, ".."); ok {
				base, head = b, h
			}
			if base != "" {
				r.Diff.Base = base
			}
			if head != "" {
				r.Diff.Head = head
			}
			for _, rev := range []string{r.Diff.Base, r.Diff.Head} {
				if strings.HasPrefix(rev, "-") || strings.ContainsAny(rev, " \t\n") {
					bad("diff: %q is not a revision", rev)
				}
			}
		}
	case "recon", "setup":
		if loop > 0 {
			bad("--loop applies to a full audit, not %s mode", r.Mode)
		}
		if r.ProfileExplicit {
			r.Warnings = append(r.Warnings, fmt.Sprintf("profile %s is ignored in %s mode", r.Profile, r.Mode))
		}
		if !r.PoC {
			r.Warnings = append(r.Warnings, fmt.Sprintf("--no-poc has no effect in %s mode (no PoCs run)", r.Mode))
		}
		if r.Mode == "setup" && (len(positional) > 0 || r.Local || r.FileOutput || out != "") {
			bad("setup mode takes no scope or flags")
		}
	}
	if r.CheckOnly && r.Mode != "setup" {
		bad("--check-only applies to setup mode only")
	}
	if r.Local && r.LoopExplicit && r.Passes > 1 {
		r.Warnings = append(r.Warnings, "--local with --loop runs every pass in this context, one lens at a time")
	}
	for _, p := range positional {
		rel, err := scopePath(root, p)
		if err != nil {
			bad("%v", err)
			continue
		}
		r.Scope = append(r.Scope, rel)
	}

	switch {
	case opt.RunID != "":
		if !reRunID(opt.RunID) {
			bad("run id %q is not YYYYMMDD-HHMMSS", opt.RunID)
		}
		r.RunID = opt.RunID
	default:
		now := opt.Now
		if now.IsZero() {
			now = time.Now()
		}
		r.RunID = now.Format("20060102-150405")
	}
	if out != "" {
		r.OutExplicit = true
		if strings.HasPrefix(out, "~/") && opt.Home != "" {
			out = filepath.Join(opt.Home, out[2:])
		}
		abs, err := filepath.Abs(out)
		if err != nil {
			bad("--out: %v", err)
		}
		r.Out = abs
	} else {
		if opt.Home == "" {
			bad("no home directory for the default output path; pass --out DIR")
		}
		r.Out = filepath.Join(opt.Home, ".zk-audit", r.RepoName, r.RunID)
	}
	if r.Out != "" && fsutil.Inside(r.Out, root) {
		bad("--out %s is inside the target repository; the output directory must be outside it (hard rule 2)", r.Out)
	}
	if r.FileOutput {
		r.ReportCopy = filepath.Join(root, "zk-audit-report-"+r.RunID+".md")
	}
	if len(problems) > 0 {
		return r, &Error{Problems: problems}
	}
	return r, nil
}

func setProfile(r *Run, p string, bad func(string, ...any)) {
	if r.ProfileExplicit && r.Profile != p {
		bad("two profiles given: %s and %s", r.Profile, p)
		return
	}
	r.Profile, r.ProfileExplicit = p, true
}

func contains(xs []string, x string) bool {
	for _, y := range xs {
		if y == x {
			return true
		}
	}
	return false
}

// isPath reports whether w names an existing file or directory of the repo.
func isPath(root, w string) bool {
	_, err := scopePath(root, w)
	return err == nil
}

// scopePath turns a scope word into a clean repo-relative slash path. It must
// exist and stay inside the repository after resolving symlinks.
func scopePath(root, w string) (string, error) {
	p := w
	if !filepath.IsAbs(p) {
		p = filepath.Join(root, p)
	}
	real, err := filepath.EvalSymlinks(p)
	if err != nil {
		return "", fmt.Errorf("scope %q does not exist in %s", w, root)
	}
	if !fsutil.Inside(real, root) {
		return "", fmt.Errorf("scope %q is outside the repository", w)
	}
	rel, err := filepath.Rel(root, real)
	if err != nil || rel == "." {
		return "", fmt.Errorf("scope %q is the whole repository; omit it", w)
	}
	return filepath.ToSlash(rel), nil
}
