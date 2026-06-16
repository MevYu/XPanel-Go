package docker

import (
	"net/http"
	"strings"
	"testing"
)

// --- 容器:stats / pause / unpause / rename / exec / update ---

func TestContainerStatsParsesJSON(t *testing.T) {
	run := &mockRunner{out: `{"Name":"web","CPUPerc":"0.50%","MemUsage":"10MiB / 1GiB"}`}
	m, _ := newTestModule(t, "operator", run)
	rec := do(m, "GET", "/containers/stats", "", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d: %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "CPUPerc") {
		t.Errorf("expected stats json, got %s", rec.Body.String())
	}
	args := run.last()
	if strings.Join(args, " ") != "stats --no-stream --format {{json .}}" {
		t.Errorf("unexpected stats args: %v", args)
	}
}

func TestContainerPauseUnpause(t *testing.T) {
	for _, verb := range []string{"pause", "unpause"} {
		run := &mockRunner{out: "ok"}
		m, audited := newTestModule(t, "operator", run)
		rec := do(m, "POST", "/containers/web/"+verb, "", nil)
		if rec.Code != http.StatusOK {
			t.Fatalf("%s status %d: %s", verb, rec.Code, rec.Body.String())
		}
		if *audited != 1 {
			t.Errorf("%s should audit once, got %d", verb, *audited)
		}
		args := run.last()
		if len(args) != 2 || args[0] != verb || args[1] != "web" {
			t.Errorf("expected %s web, got %v", verb, args)
		}
	}
}

func TestContainerRenameValidatesAndAudits(t *testing.T) {
	run := &mockRunner{out: "ok"}
	m, audited := newTestModule(t, "operator", run)
	rec := do(m, "POST", "/containers/web/rename", `{"name":"web2"}`, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d: %s", rec.Code, rec.Body.String())
	}
	if *audited != 1 {
		t.Errorf("rename should audit, got %d", *audited)
	}
	args := run.last()
	if len(args) != 3 || args[0] != "rename" || args[1] != "web" || args[2] != "web2" {
		t.Errorf("expected rename web web2, got %v", args)
	}
}

func TestContainerRenameRejectsBadName(t *testing.T) {
	run := &mockRunner{}
	m, _ := newTestModule(t, "operator", run)
	rec := do(m, "POST", "/containers/web/rename", `{"name":"bad name;rm"}`, nil)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("bad name should 400, got %d", rec.Code)
	}
	if len(run.calls) != 0 {
		t.Error("docker must not run for invalid name")
	}
}

func TestContainerRenameRequiresOperator(t *testing.T) {
	run := &mockRunner{out: "ok"}
	m, _ := newTestModule(t, "viewer", run)
	rec := do(m, "POST", "/containers/web/rename", `{"name":"web2"}`, nil)
	if rec.Code != http.StatusForbidden {
		t.Errorf("viewer rename should 403, got %d", rec.Code)
	}
}

func TestContainerExecRunsArgArray(t *testing.T) {
	run := &mockRunner{out: "hello"}
	m, audited := newTestModule(t, "operator", run)
	rec := do(m, "POST", "/containers/web/exec", `{"cmd":["echo","hello"]}`, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d: %s", rec.Code, rec.Body.String())
	}
	if rec.Body.String() != "hello" {
		t.Errorf("expected exec output, got %q", rec.Body.String())
	}
	if *audited != 1 {
		t.Errorf("exec should audit, got %d", *audited)
	}
	args := run.last()
	if strings.Join(args, " ") != "exec web echo hello" {
		t.Errorf("expected 'exec web echo hello', got %v", args)
	}
}

func TestContainerExecRejectsEmptyCmd(t *testing.T) {
	run := &mockRunner{}
	m, _ := newTestModule(t, "operator", run)
	rec := do(m, "POST", "/containers/web/exec", `{"cmd":[]}`, nil)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("empty cmd should 400, got %d", rec.Code)
	}
	if len(run.calls) != 0 {
		t.Error("docker must not run for empty cmd")
	}
}

func TestContainerExecRejectsControlChars(t *testing.T) {
	run := &mockRunner{}
	m, _ := newTestModule(t, "operator", run)
	rec := do(m, "POST", "/containers/web/exec", "{\"cmd\":[\"echo\",\"a\\nb\"]}", nil)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("control-char arg should 400, got %d", rec.Code)
	}
	if len(run.calls) != 0 {
		t.Error("docker must not run for control-char arg")
	}
}

func TestContainerUpdateDangerAndArgs(t *testing.T) {
	run := &mockRunner{out: "web"}
	// operator + confirm → still admin-only → 403
	m, _ := newTestModule(t, "operator", run)
	rec := do(m, "POST", "/containers/web/update", `{"memory":"512m"}`,
		map[string]string{"X-Confirm-Danger": "y"})
	if rec.Code != http.StatusForbidden {
		t.Errorf("operator update should 403, got %d", rec.Code)
	}

	// admin without confirm → 428
	m2, _ := newTestModule(t, "admin", run)
	rec = do(m2, "POST", "/containers/web/update", `{"memory":"512m"}`, nil)
	if rec.Code != http.StatusPreconditionRequired {
		t.Errorf("missing confirm should 428, got %d", rec.Code)
	}

	// admin + confirm → ok
	m3, audited := newTestModule(t, "admin", run)
	rec = do(m3, "POST", "/containers/web/update", `{"memory":"512m","cpus":"1.5"}`,
		map[string]string{"X-Confirm-Danger": "y"})
	if rec.Code != http.StatusOK {
		t.Fatalf("admin+confirm should 200, got %d: %s", rec.Code, rec.Body.String())
	}
	if *audited != 1 {
		t.Errorf("update should audit, got %d", *audited)
	}
	args := run.last()
	if strings.Join(args, " ") != "update --memory 512m --cpus 1.5 web" {
		t.Errorf("unexpected update args: %v", args)
	}
}

func TestContainerUpdateRejectsBadValues(t *testing.T) {
	run := &mockRunner{}
	m, _ := newTestModule(t, "admin", run)
	hdr := map[string]string{"X-Confirm-Danger": "y"}
	for _, body := range []string{`{"memory":"lots"}`, `{"cpus":"-1"}`, `{}`} {
		rec := do(m, "POST", "/containers/web/update", body, hdr)
		if rec.Code != http.StatusBadRequest {
			t.Errorf("body %s should 400, got %d", body, rec.Code)
		}
	}
	if len(run.calls) != 0 {
		t.Error("docker must not run for invalid update")
	}
}

// --- 镜像:history / tag / prune ---

func TestImageHistoryParsesJSON(t *testing.T) {
	run := &mockRunner{out: `{"ID":"abc","CreatedBy":"RUN x"}`}
	m, _ := newTestModule(t, "operator", run)
	rec := do(m, "GET", "/images/nginx/history", "", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d: %s", rec.Code, rec.Body.String())
	}
	args := run.last()
	if args[0] != "history" || args[len(args)-1] != "nginx" {
		t.Errorf("unexpected history args: %v", args)
	}
}

func TestImageTagValidatesAndAudits(t *testing.T) {
	run := &mockRunner{out: ""}
	m, audited := newTestModule(t, "operator", run)
	rec := do(m, "POST", "/images/nginx/tag", `{"target":"myrepo/nginx:1.0"}`, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d: %s", rec.Code, rec.Body.String())
	}
	if *audited != 1 {
		t.Errorf("tag should audit, got %d", *audited)
	}
	args := run.last()
	if strings.Join(args, " ") != "tag nginx myrepo/nginx:1.0" {
		t.Errorf("unexpected tag args: %v", args)
	}
}

func TestImageTagRejectsBadTarget(t *testing.T) {
	run := &mockRunner{}
	m, _ := newTestModule(t, "operator", run)
	rec := do(m, "POST", "/images/nginx/tag", `{"target":"bad;rm"}`, nil)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("bad target should 400, got %d", rec.Code)
	}
	if len(run.calls) != 0 {
		t.Error("docker must not run for bad target")
	}
}

func TestImagePruneDanger(t *testing.T) {
	run := &mockRunner{out: "reclaimed"}
	// operator → 403 even with confirm
	m, _ := newTestModule(t, "operator", run)
	rec := do(m, "POST", "/images/prune", "", map[string]string{"X-Confirm-Danger": "y"})
	if rec.Code != http.StatusForbidden {
		t.Errorf("operator prune should 403, got %d", rec.Code)
	}
	// admin no confirm → 428
	m2, _ := newTestModule(t, "admin", run)
	rec = do(m2, "POST", "/images/prune", "", nil)
	if rec.Code != http.StatusPreconditionRequired {
		t.Errorf("missing confirm should 428, got %d", rec.Code)
	}
	// admin + confirm → ok
	m3, audited := newTestModule(t, "admin", run)
	rec = do(m3, "POST", "/images/prune", "", map[string]string{"X-Confirm-Danger": "y"})
	if rec.Code != http.StatusOK {
		t.Fatalf("admin+confirm should 200, got %d", rec.Code)
	}
	if *audited != 1 {
		t.Errorf("prune should audit, got %d", *audited)
	}
	if strings.Join(run.last(), " ") != "image prune -f" {
		t.Errorf("unexpected prune args: %v", run.last())
	}
}

// --- compose:config / logs / restart ---

func TestComposeConfigUsesProjectDir(t *testing.T) {
	run := &mockRunner{out: "services: {}"}
	m, _ := newTestModule(t, "operator", run)
	rec := do(m, "GET", "/compose/web/config", "", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d: %s", rec.Code, rec.Body.String())
	}
	joined := strings.Join(run.last(), " ")
	if !strings.Contains(joined, "compose --project-directory "+defaultComposeDir+"/web -p web config") {
		t.Errorf("unexpected config args: %v", run.last())
	}
}

func TestComposeLogsClampsTail(t *testing.T) {
	run := &mockRunner{out: "logs"}
	m, _ := newTestModule(t, "operator", run)
	rec := do(m, "GET", "/compose/web/logs?tail=10", "", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d", rec.Code)
	}
	joined := strings.Join(run.last(), " ")
	if !strings.Contains(joined, "logs --no-color --tail 10") {
		t.Errorf("unexpected logs args: %v", run.last())
	}
}

func TestComposeRestartAudits(t *testing.T) {
	run := &mockRunner{out: "restarted"}
	m, audited := newTestModule(t, "operator", run)
	rec := do(m, "POST", "/compose/web/restart", "", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d: %s", rec.Code, rec.Body.String())
	}
	if *audited != 1 {
		t.Errorf("restart should audit, got %d", *audited)
	}
	if !strings.Contains(strings.Join(run.last(), " "), "-p web restart") {
		t.Errorf("unexpected restart args: %v", run.last())
	}
}

// --- 网络:create / inspect / remove ---

func TestNetworkCreateValidates(t *testing.T) {
	run := &mockRunner{out: "netid"}
	m, audited := newTestModule(t, "operator", run)
	rec := do(m, "POST", "/networks", `{"name":"mynet"}`, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d: %s", rec.Code, rec.Body.String())
	}
	if *audited != 1 {
		t.Errorf("create should audit, got %d", *audited)
	}
	if strings.Join(run.last(), " ") != "network create mynet" {
		t.Errorf("unexpected args: %v", run.last())
	}

	m2, _ := newTestModule(t, "operator", &mockRunner{})
	rec = do(m2, "POST", "/networks", `{"name":"bad/name"}`, nil)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("bad name should 400, got %d", rec.Code)
	}
}

func TestNetworkInspect(t *testing.T) {
	run := &mockRunner{out: "[{}]"}
	m, _ := newTestModule(t, "operator", run)
	rec := do(m, "GET", "/networks/bridge/inspect", "", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d", rec.Code)
	}
	if strings.Join(run.last(), " ") != "network inspect bridge" {
		t.Errorf("unexpected args: %v", run.last())
	}
}

func TestNetworkRemoveDanger(t *testing.T) {
	run := &mockRunner{out: "removed"}
	m, _ := newTestModule(t, "admin", run)
	rec := do(m, "DELETE", "/networks/mynet", "", nil)
	if rec.Code != http.StatusPreconditionRequired {
		t.Errorf("missing confirm should 428, got %d", rec.Code)
	}
	rec = do(m, "DELETE", "/networks/mynet", "", map[string]string{"X-Confirm-Danger": "y"})
	if rec.Code != http.StatusOK {
		t.Fatalf("admin+confirm should 200, got %d", rec.Code)
	}
	if strings.Join(run.last(), " ") != "network rm mynet" {
		t.Errorf("unexpected args: %v", run.last())
	}
}

// --- 卷:create / inspect / remove ---

func TestVolumeCreateInspectRemove(t *testing.T) {
	run := &mockRunner{out: "ok"}
	m, _ := newTestModule(t, "operator", run)
	rec := do(m, "POST", "/volumes", `{"name":"data"}`, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("create status %d: %s", rec.Code, rec.Body.String())
	}
	if strings.Join(run.last(), " ") != "volume create data" {
		t.Errorf("unexpected create args: %v", run.last())
	}

	rec = do(m, "GET", "/volumes/data/inspect", "", nil)
	if rec.Code != http.StatusOK || strings.Join(run.last(), " ") != "volume inspect data" {
		t.Errorf("inspect failed: %d %v", rec.Code, run.last())
	}

	// remove danger
	adm, _ := newTestModule(t, "admin", run)
	rec = do(adm, "DELETE", "/volumes/data", "", nil)
	if rec.Code != http.StatusPreconditionRequired {
		t.Errorf("missing confirm should 428, got %d", rec.Code)
	}
	rec = do(adm, "DELETE", "/volumes/data", "", map[string]string{"X-Confirm-Danger": "y"})
	if rec.Code != http.StatusOK || strings.Join(run.last(), " ") != "volume rm data" {
		t.Errorf("remove failed: %d %v", rec.Code, run.last())
	}
}

// --- 镜像仓库:login / list / remove ---

func TestRegistryLoginEncryptsAndMasks(t *testing.T) {
	run := &mockRunner{out: "Login Succeeded"}
	m, audited := newTestModule(t, "admin", run)
	body := `{"name":"ghcr","server":"ghcr.io","username":"alice","password":"s3cret"}`
	rec := do(m, "POST", "/registries", body, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("login status %d: %s", rec.Code, rec.Body.String())
	}
	if *audited != 1 {
		t.Errorf("login should audit, got %d", *audited)
	}
	// password fed via stdin, not args
	args := run.last()
	if strings.Join(args, " ") != "login ghcr.io --username alice --password-stdin" {
		t.Errorf("unexpected login args: %v", args)
	}
	if run.stdin[len(run.stdin)-1] != "s3cret" {
		t.Errorf("password should be passed via stdin, got %q", run.stdin[len(run.stdin)-1])
	}
	for _, a := range args {
		if strings.Contains(a, "s3cret") {
			t.Errorf("password leaked into args: %v", args)
		}
	}
	// response must not contain password
	if strings.Contains(rec.Body.String(), "s3cret") {
		t.Errorf("password leaked in response: %s", rec.Body.String())
	}

	// list must not return password, and ciphertext stored != plaintext
	rec = do(m, "GET", "/registries", "", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("list status %d", rec.Code)
	}
	if strings.Contains(rec.Body.String(), "s3cret") {
		t.Errorf("password leaked in list: %s", rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "ghcr") {
		t.Errorf("registry not listed: %s", rec.Body.String())
	}

	// verify stored ciphertext is not plaintext
	var stored string
	if err := m.ss.db.QueryRow(`SELECT password FROM docker_registries WHERE name = ?`, "ghcr").Scan(&stored); err != nil {
		t.Fatal(err)
	}
	if stored == "" || stored == "s3cret" || strings.Contains(stored, "s3cret") {
		t.Errorf("stored password not encrypted: %q", stored)
	}
}

func TestRegistryLoginRequiresAdmin(t *testing.T) {
	run := &mockRunner{out: "ok"}
	m, _ := newTestModule(t, "operator", run)
	rec := do(m, "POST", "/registries", `{"name":"x","server":"r.io","username":"u","password":"p"}`, nil)
	if rec.Code != http.StatusForbidden {
		t.Errorf("operator login should 403, got %d", rec.Code)
	}
	if len(run.calls) != 0 {
		t.Error("docker must not run for non-admin")
	}
}

func TestRegistryLoginValidates(t *testing.T) {
	run := &mockRunner{out: "ok"}
	m, _ := newTestModule(t, "admin", run)
	bad := []string{
		`{"name":"bad/name","server":"r.io","username":"u","password":"p"}`,
		`{"name":"x","server":"r.io;rm","username":"u","password":"p"}`,
		`{"name":"x","server":"r.io","username":"","password":"p"}`,
		`{"name":"x","server":"r.io","username":"u","password":""}`,
	}
	for _, b := range bad {
		rec := do(m, "POST", "/registries", b, nil)
		if rec.Code != http.StatusBadRequest {
			t.Errorf("body %s should 400, got %d", b, rec.Code)
		}
	}
	if len(run.calls) != 0 {
		t.Error("docker must not run for invalid registry input")
	}
}

func TestRegistryLoginFailureMasked(t *testing.T) {
	run := &mockRunner{err: http.ErrNotSupported, out: "/secret/path denied"}
	m, _ := newTestModule(t, "admin", run)
	rec := do(m, "POST", "/registries",
		`{"name":"x","server":"r.io","username":"u","password":"p"}`, nil)
	if rec.Code != http.StatusBadGateway {
		t.Fatalf("login failure should 502, got %d", rec.Code)
	}
	if strings.Contains(rec.Body.String(), "/secret/path") {
		t.Errorf("internal output leaked: %s", rec.Body.String())
	}
	// failed login must not persist a record
	var n int
	m.ss.db.QueryRow(`SELECT COUNT(*) FROM docker_registries`).Scan(&n)
	if n != 0 {
		t.Errorf("failed login should not store credential, got %d rows", n)
	}
}

func TestRegistryRemove(t *testing.T) {
	run := &mockRunner{out: "Login Succeeded"}
	m, _ := newTestModule(t, "admin", run)
	do(m, "POST", "/registries", `{"name":"ghcr","server":"ghcr.io","username":"u","password":"p"}`, nil)
	rec := do(m, "DELETE", "/registries/ghcr", "", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("remove status %d: %s", rec.Code, rec.Body.String())
	}
	// gone now → 404
	rec = do(m, "DELETE", "/registries/ghcr", "", nil)
	if rec.Code != http.StatusNotFound {
		t.Errorf("removing missing registry should 404, got %d", rec.Code)
	}
}

func TestRegistryRemoveRequiresAdmin(t *testing.T) {
	m, _ := newTestModule(t, "operator", &mockRunner{})
	rec := do(m, "DELETE", "/registries/ghcr", "", nil)
	if rec.Code != http.StatusForbidden {
		t.Errorf("operator remove should 403, got %d", rec.Code)
	}
}

func TestInstallSecretStableAndEncryptRoundTrips(t *testing.T) {
	m, _ := newTestModule(t, "admin", &mockRunner{})
	s1, err := m.ss.installSecret()
	if err != nil || s1 == "" {
		t.Fatalf("installSecret: %q %v", s1, err)
	}
	s2, _ := m.ss.installSecret()
	if s1 != s2 {
		t.Errorf("install secret must be stable, got %q then %q", s1, s2)
	}
	c, err := m.cryptor()
	if err != nil {
		t.Fatal(err)
	}
	enc, _ := c.encrypt("hunter2")
	if dec, _ := c.decrypt(enc); dec != "hunter2" {
		t.Errorf("round-trip failed: %q", dec)
	}
}
