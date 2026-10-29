package main

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/shramee/zk-audit/plugins/zk-audit/skills/zk-audit/tools/gnark-inventory/internal/advisory"
	"github.com/shramee/zk-audit/plugins/zk-audit/skills/zk-audit/tools/gnark-inventory/internal/fixture"
)

// osvReplay serves OSV responses recorded on 2026-10-29 from
// testdata/osv: query-<module>-<version>.json for POST /v1/query and
// vuln-<id>.json for GET /v1/vulns/<id> (404 when no file exists). No test
// touches the network.
func osvReplay(t *testing.T) (*httptest.Server, *[]string) {
	t.Helper()
	dir := fixture.Dir(t, "osv")
	var log []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/v1/query":
			var q struct {
				Package struct{ Name, Ecosystem string }
				Version string
			}
			b, _ := io.ReadAll(r.Body)
			if err := json.Unmarshal(b, &q); err != nil || q.Package.Ecosystem != "Go" {
				http.Error(w, "bad query", http.StatusBadRequest)
				return
			}
			name := "query-" + strings.TrimPrefix(q.Package.Name, "github.com/consensys/") + "-" + q.Version + ".json"
			log = append(log, "query "+q.Package.Name+"@"+q.Version)
			body, err := os.ReadFile(filepath.Join(dir, name))
			if err != nil {
				t.Errorf("no recorded OSV response %s", name)
				http.Error(w, "unrecorded", http.StatusInternalServerError)
				return
			}
			w.Write(body)
		case r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/v1/vulns/"):
			id := strings.TrimPrefix(r.URL.Path, "/v1/vulns/")
			log = append(log, "get "+id)
			body, err := os.ReadFile(filepath.Join(dir, "vuln-"+id+".json"))
			if err != nil || bytes.Contains(body, []byte(`"code":5`)) {
				w.WriteHeader(http.StatusNotFound)
				w.Write([]byte(`{"code":5,"message":"Vulnerability not found"}`))
				return
			}
			w.Write(body)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	return srv, &log
}

func TestAdvisoriesOSVFreshness(t *testing.T) {
	srv, log := osvReplay(t)
	var out bytes.Buffer
	code := run([]string{"advisories", "--version", "v0.10.0", "--crypto-version", "v0.19.0", "--osv", "--osv-url", srv.URL, "--json"}, &out, os.Stderr)
	if code != 0 {
		t.Fatalf("exit %d: %s", code, out.String())
	}
	var f advisory.Freshness
	if err := json.Unmarshal(out.Bytes(), &f); err != nil {
		t.Fatal(err)
	}
	if f.TableAsOf == "" || !strings.Contains(f.Summary, "advisory table as of "+f.TableAsOf) {
		t.Errorf("summary %q lacks the table date", f.Summary)
	}
	if len(f.New) != 0 {
		t.Errorf("recorded OSV has nothing the table lacks, got new %+v", f.New)
	}
	// GO-2025-3929 (the Go vulnerability database) has no lower bound while
	// the GHSA record and the table start at v0.12.0
	if len(f.Changed) != 1 || f.Changed[0].ID != "GHSA-9fvj-xqr2-xwg8" || f.Changed[0].OSVID != "GO-2025-3929" || f.Changed[0].OSV != "< v0.13.0" {
		t.Errorf("changed = %+v", f.Changed)
	}
	var notIn []string
	for _, n := range f.NotInOSV {
		notIn = append(notIn, n.ID)
	}
	if strings.Join(notIn, ",") != "GHSA-3mvx-pp85-pm65,GHSA-7fx8-hmgc-82jp,GHSA-fwf3-jmp7-gmrj" {
		t.Errorf("not in OSV = %v", notIn)
	}
	if len(f.Queried) != 2 || f.Queried[1].Package != advisory.GnarkCrypto || strings.Join(f.Queried[1].OSVIDs, ",") != "GHSA-fj2x-735w-74vq,GO-2025-4087" {
		t.Errorf("queried = %+v", f.Queried)
	}
	if !strings.Contains(strings.Join(*log, "\n"), "get GHSA-7fx8-hmgc-82jp") {
		t.Errorf("rows OSV did not return must be looked up by id: %v", *log)
	}
}

func TestAdvisoriesOSVReportsNewIDs(t *testing.T) {
	srv, _ := osvReplay(t)
	tab, err := advisory.Load()
	if err != nil {
		t.Fatal(err)
	}
	// a table that lacks GHSA-95v9 (and its aliases): OSV's record must
	// come back as new for v0.12.0
	var kept []advisory.Advisory
	for _, a := range tab.Advisories {
		if a.ID != "GHSA-95v9-hv42-pwrj" {
			kept = append(kept, a)
		}
	}
	tab.Advisories = kept
	c := advisory.NewOSV(srv.URL)
	vulns, err := c.Query(t.Context(), advisory.Gnark, "v0.12.0")
	if err != nil {
		t.Fatal(err)
	}
	f := &advisory.Freshness{TableAsOf: tab.AsOf}
	if err := tab.CompareOSV(f, advisory.Gnark, "v0.12.0", vulns, func(id string) (*advisory.OSVVuln, bool, error) { return c.Get(t.Context(), id) }); err != nil {
		t.Fatal(err)
	}
	var ids []string
	for _, n := range f.New {
		ids = append(ids, n.ID+" "+n.Affected)
	}
	if strings.Join(ids, ";") != "GHSA-95v9-hv42-pwrj < v0.14.0;GO-2025-3912 < v0.14.0" {
		t.Errorf("new = %v", ids)
	}
	if len(f.Changed) != 0 {
		t.Errorf("changed = %+v", f.Changed)
	}
}

func TestAdvisoriesOfflineByDefault(t *testing.T) {
	var out, errb bytes.Buffer
	if code := run([]string{"advisories", "--repo", fixture.Dir(t, "pool")}, &out, &errb); code != 0 {
		t.Fatalf("exit %d: %s", code, errb.String())
	}
	got := out.String()
	for _, want := range []string{"advisory table as of ", "go.mod: gnark v0.14.0: 3 advisories", "go.mod: gnark-crypto v0.19.0: 1 advisories", "GHSA-fj2x-735w-74vq affected"} {
		if !strings.Contains(got, want) {
			t.Errorf("missing %q in\n%s", want, got)
		}
	}
	if code := run([]string{"advisories", "--osv"}, &out, &errb); code != 2 {
		t.Errorf("--osv without versions should be a usage error, got %d", code)
	}
}
