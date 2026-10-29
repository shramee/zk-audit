// Package gomod is a small go.mod reader: module path, go directive, require
// and replace lines. It avoids a dependency on golang.org/x/mod/modfile.
package gomod

import (
	"bufio"
	"io"
	"os"
	"strings"
)

// Require is one required module.
type Require struct {
	Path     string `json:"path"`
	Version  string `json:"version"`
	Indirect bool   `json:"indirect,omitempty"`
}

// Replace is one replace directive.
type Replace struct {
	Old        string `json:"old"`
	OldVersion string `json:"old_version,omitempty"`
	New        string `json:"new"`
	NewVersion string `json:"new_version,omitempty"`
}

// File is a parsed go.mod.
type File struct {
	Module    string    `json:"module"`
	Go        string    `json:"go,omitempty"`
	Toolchain string    `json:"toolchain,omitempty"`
	Require   []Require `json:"require"`
	Replace   []Replace `json:"replace,omitempty"`
}

// ParseFile reads and parses a go.mod file.
func ParseFile(path string) (*File, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return Parse(f)
}

// Parse parses go.mod content.
func Parse(r io.Reader) (*File, error) {
	out := &File{}
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 1024*1024), 1024*1024)
	block := ""
	for sc.Scan() {
		line := sc.Text()
		indirect := strings.Contains(line, "// indirect")
		if i := strings.Index(line, "//"); i >= 0 {
			line = line[:i]
		}
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if block != "" {
			if line == ")" {
				block = ""
				continue
			}
			out.add(block, strings.Fields(line), indirect)
			continue
		}
		fields := strings.Fields(line)
		if len(fields) >= 2 && fields[1] == "(" {
			block = fields[0]
			continue
		}
		if len(fields) == 0 {
			continue
		}
		out.add(fields[0], fields[1:], indirect)
	}
	return out, sc.Err()
}

func unquote(s string) string { return strings.Trim(s, "\"`") }

func (f *File) add(verb string, args []string, indirect bool) {
	switch verb {
	case "module":
		if len(args) > 0 {
			f.Module = unquote(args[0])
		}
	case "go":
		if len(args) > 0 {
			f.Go = args[0]
		}
	case "toolchain":
		if len(args) > 0 {
			f.Toolchain = args[0]
		}
	case "require":
		if len(args) >= 2 {
			f.Require = append(f.Require, Require{Path: unquote(args[0]), Version: args[1], Indirect: indirect})
		}
	case "replace":
		// old [v] => new [v]
		arrow := -1
		for i, a := range args {
			if a == "=>" {
				arrow = i
			}
		}
		if arrow < 1 || arrow+1 >= len(args) {
			return
		}
		r := Replace{Old: unquote(args[0]), New: unquote(args[arrow+1])}
		if arrow == 2 {
			r.OldVersion = args[1]
		}
		if arrow+2 < len(args) {
			r.NewVersion = args[arrow+2]
		}
		f.Replace = append(f.Replace, r)
	}
}

// Version returns the effective version of module path, applying replace
// directives. A replacement by a local path returns ("", replacedPath).
func (f *File) Version(path string) (version string, replacedBy string, ok bool) {
	for _, r := range f.Require {
		if r.Path == path {
			version, ok = r.Version, true
		}
	}
	for _, r := range f.Replace {
		if r.Old != path || (r.OldVersion != "" && r.OldVersion != version) {
			continue
		}
		if r.NewVersion == "" {
			return "", r.New, true
		}
		if r.New == path {
			return r.NewVersion, "", true
		}
		return r.NewVersion, r.New, true
	}
	return version, "", ok
}
