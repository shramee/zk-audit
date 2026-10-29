package solidity

import (
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// ---------------------------------------------------------------- lexing

// stripComments blanks out comments but keeps newlines and string contents so
// that byte offsets and line numbers stay valid.
func stripComments(src string) string {
	b := []byte(src)
	out := make([]byte, len(b))
	copy(out, b)
	for i := 0; i < len(b); i++ {
		switch {
		case b[i] == '"' || b[i] == '\'':
			q := b[i]
			for i++; i < len(b) && b[i] != q && b[i] != '\n'; i++ {
				if b[i] == '\\' {
					i++
				}
			}
		case b[i] == '/' && i+1 < len(b) && b[i+1] == '/':
			for ; i < len(b) && b[i] != '\n'; i++ {
				out[i] = ' '
			}
		case b[i] == '/' && i+1 < len(b) && b[i+1] == '*':
			out[i], out[i+1] = ' ', ' '
			for i += 2; i < len(b); i++ {
				if b[i] == '*' && i+1 < len(b) && b[i+1] == '/' {
					out[i], out[i+1] = ' ', ' '
					i++
					break
				}
				if b[i] != '\n' {
					out[i] = ' '
				}
			}
		}
	}
	return string(out)
}

type lineIndex []int

func newLineIndex(s string) lineIndex {
	idx := lineIndex{0}
	for i, c := range s {
		if c == '\n' {
			idx = append(idx, i+1)
		}
	}
	return idx
}

func (l lineIndex) line(off int) int {
	return sort.Search(len(l), func(i int) bool { return l[i] > off })
}

// matchClose returns the index of the bracket closing the one at open.
func matchClose(s string, open int) int {
	o := s[open]
	var c byte
	switch o {
	case '{':
		c = '}'
	case '(':
		c = ')'
	case '[':
		c = ']'
	default:
		return -1
	}
	depth := 0
	for i := open; i < len(s); i++ {
		switch s[i] {
		case '"', '\'':
			q := s[i]
			for i++; i < len(s) && s[i] != q; i++ {
				if s[i] == '\\' {
					i++
				}
			}
		case o:
			depth++
		case c:
			depth--
			if depth == 0 {
				return i
			}
		}
	}
	return -1
}

// splitArgs splits a call's argument text on top-level commas.
func splitArgs(s string) []string {
	var out []string
	depth := 0
	start := 0
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '(', '[', '{':
			depth++
		case ')', ']', '}':
			depth--
		case ',':
			if depth == 0 {
				out = append(out, strings.TrimSpace(s[start:i]))
				start = i + 1
			}
		}
	}
	if t := strings.TrimSpace(s[start:]); t != "" {
		out = append(out, t)
	}
	return out
}

func squash(s string) string { return strings.Join(strings.Fields(s), " ") }

type stmt struct {
	off  int
	text string
}

func splitStatements(s string) []stmt {
	var out []stmt
	start := 0
	depth := 0
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '(', '[':
			depth++
		case ')', ']':
			depth--
		case ';':
			if depth == 0 {
				t := s[start:i]
				off := start + (len(t) - len(strings.TrimLeft(t, " \t\r\n")))
				out = append(out, stmt{off: off, text: strings.TrimSpace(t)})
				start = i + 1
			}
		case '{', '}':
			if depth == 0 {
				start = i + 1
			}
		}
	}
	return out
}

var reDeclName = regexp.MustCompile(`([A-Za-z_]\w*)\s*$`)

var reInit = regexp.MustCompile(`=[^>]`)

func stateVarName(text string) string {
	t := text + " "
	if loc := reInit.FindStringIndex(t); loc != nil {
		t = t[:loc[0]]
	}
	t = strings.TrimSpace(t)
	m := reDeclName.FindStringSubmatch(t)
	if m == nil {
		return ""
	}
	return m[1]
}

func stateKind(name, decl string) string {
	n := strings.ToLower(name)
	switch {
	case strings.Contains(n, "nullif") || strings.Contains(n, "spent") || (strings.Contains(n, "used") && strings.Contains(decl, "mapping")):
		return "nullifier"
	case strings.Contains(n, "root"):
		return "root"
	case strings.Contains(n, "commitment"):
		return "commitment"
	case strings.Contains(n, "verifier"):
		return "verifier"
	case strings.Contains(n, "vkey") || n == "vk" || strings.HasPrefix(n, "vk") || strings.HasSuffix(n, "vk") || strings.Contains(n, "vkhash"):
		return "vk"
	case strings.Contains(n, "nonce"):
		return "nonce"
	}
	return ""
}

func dedupAccess(res *Result) {
	seen := map[string]bool{}
	out := res.StateAccess[:0]
	for _, a := range res.StateAccess {
		k := a.File + "|" + strconv.Itoa(a.Line) + "|" + a.Name + "|" + a.Op
		if seen[k] {
			continue
		}
		seen[k] = true
		out = append(out, a)
	}
	res.StateAccess = out
}

func accessOp(st, name string) string {
	switch {
	case strings.HasPrefix(st, "delete ") && strings.Contains(st, name):
		return "delete"
	case regexp.MustCompile(`\b` + regexp.QuoteMeta(name) + `\s*\.\s*push\s*\(`).MatchString(st):
		return "push"
	case regexp.MustCompile(`\b` + regexp.QuoteMeta(name) + `\s*(\[[^\]]*\]\s*)*(=|\+=|-=|\+\+|--)[^=]`).MatchString(st + " "):
		return "write"
	case strings.HasPrefix(st, "require") || strings.HasPrefix(st, "if") || strings.HasPrefix(st, "assert") || strings.Contains(st, "revert"):
		return "check"
	}
	return ""
}

func lineBefore(s string, off int) string {
	i := strings.LastIndexByte(s[:off], '\n')
	return s[i+1 : off]
}

// statementAround returns the statement text containing [from, to).
func statementAround(s string, from, to int) string {
	a := strings.LastIndexAny(s[:from], ";{}") + 1
	b := to
	depth := 0
	for ; b < len(s); b++ {
		switch s[b] {
		case '(':
			depth++
		case ')':
			depth--
		case ';', '{', '}':
			if depth <= 0 {
				return strings.TrimSpace(s[a:b])
			}
		}
	}
	return strings.TrimSpace(s[a:])
}

// resultUsed reports whether the call's return value is consumed. callOff is
// the offset of the call inside st.
func resultUsed(st string, callOff int) bool {
	t := squash(st)
	for _, p := range []string{"require", "assert", "if", "return", "bool ", "while"} {
		if strings.HasPrefix(t, p) {
			return true
		}
	}
	if callOff > 0 && callOff <= len(st) {
		pre := st[:callOff]
		if strings.Contains(pre, "=") || strings.Contains(pre, "!") || strings.Contains(pre, "&&") || strings.Contains(pre, "||") || strings.Contains(pre, "(") {
			return true
		}
	}
	return false
}

// MentionsBinding reports which context values an expression mentions.
func MentionsBinding(expr string) []string {
	var out []string
	checks := []struct{ needle, tag string }{
		{"msg.sender", "sender"}, {"tx.origin", "origin"}, {"block.chainid", "chainid"},
		{"address(this)", "contract"}, {"nonce", "nonce"}, {"epoch", "epoch"},
		{"recipient", "recipient"}, {"deadline", "deadline"},
	}
	l := strings.ToLower(expr)
	for _, c := range checks {
		if strings.Contains(l, strings.ToLower(c.needle)) {
			out = append(out, c.tag)
		}
	}
	return out
}

// Idents returns identifiers in an expression (used to link inputs to state).
func Idents(expr string) []string { return reIdent.FindAllString(expr, -1) }

// IsNumber reports whether s is a decimal literal.
func IsNumber(s string) bool { return reNumber.MatchString(s) }

// blankStrings replaces the contents of string literals with spaces (quotes
// and newlines kept), so call patterns never match inside a string.
func blankStrings(s string) string {
	b := []byte(s)
	for i := 0; i < len(b); i++ {
		if b[i] != '"' && b[i] != '\'' {
			continue
		}
		q := b[i]
		for i++; i < len(b) && b[i] != q && b[i] != '\n'; i++ {
			if b[i] == '\\' && i+1 < len(b) {
				b[i] = ' '
				i++
			}
			b[i] = ' '
		}
	}
	return string(b)
}
