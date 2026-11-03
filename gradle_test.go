package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// gradleDistSHA256 is the published SHA-256 of the distribution
// testdata/gradle's wrapper names, from its .sha256 beside it on
// services.gradle.org.
const (
	gradleDist       = "gradle-9.8.0-bin.zip"
	gradleDistSHA256 = "bafd5ce9cfaea0fbccfdc8439a1ac42fbd4cd9c89dc9a988228d8a2639a58e6c"
)

// The trust store the Gradle client setting in docs/configuration.md names.
const gradleTrustScript = `set -e
cp "$JAVA_HOME/lib/security/cacerts" /tmp/trust.p12
keytool -importcert -noprompt -alias via-maris-maven -file /ca.crt -keystore /tmp/trust.p12 -storepass changeit >/dev/null
printf 'systemProp.javax.net.ssl.trustStore=/tmp/trust.p12\nsystemProp.javax.net.ssl.trustStorePassword=changeit\n' > "$GRADLE_USER_HOME/gradle.properties"
exec ./gradlew --no-daemon --console=plain --no-configuration-cache "$@"
`

type gradleRig struct {
	t       *testing.T
	image   string
	addr    string
	project string
	ca      string
}

func (r *gradleRig) run(home string, args ...string) (string, error) {
	r.t.Helper()
	create := []string{"create"}
	for _, h := range []string{"repo.maven.apache.org", "dl.google.com", "services.gradle.org"} {
		create = append(create, "--add-host", h+":"+r.addr)
	}
	create = append(create, "-v", home+":/gradle-home", "-e", "GRADLE_USER_HOME=/gradle-home", "-w", "/project",
		"--entrypoint", "sh", r.image, "-c", gradleTrustScript, "sh")
	out, err := exec.Command("docker", append(create, args...)...).Output()
	if err != nil {
		r.t.Fatalf("docker create: %v", err)
	}
	id := strings.TrimSpace(string(out))
	defer exec.Command("docker", "rm", "-f", id).Run()
	for _, cp := range [][2]string{{r.project + "/.", id + ":/project"}, {r.ca, id + ":/ca.crt"}} {
		if out, err := exec.Command("docker", "cp", cp[0], cp[1]).CombinedOutput(); err != nil {
			r.t.Fatalf("docker cp %s: %v %s", cp[0], err, out)
		}
	}
	b, err := exec.Command("docker", "start", "-a", id).CombinedOutput()
	r.t.Logf("./gradlew %s\n%s", strings.Join(args, " "), b)
	return string(b), err
}

func (r *gradleRig) volume() string {
	r.t.Helper()
	out, err := exec.Command("docker", "volume", "create").Output()
	if err != nil {
		r.t.Fatalf("docker volume create: %v", err)
	}
	name := strings.TrimSpace(string(out))
	r.t.Cleanup(func() { exec.Command("docker", "volume", "rm", "-f", name).Run() })
	return name
}

func gradleRecords(t *testing.T, b *bytes.Buffer, g *gateway) []record {
	t.Helper()
	g.records.mu.Lock()
	defer g.records.mu.Unlock()
	var out []record
	sc := bufio.NewScanner(bytes.NewReader(b.Bytes()))
	for sc.Scan() {
		var r record
		if err := json.Unmarshal(sc.Bytes(), &r); err != nil {
			t.Fatalf("record %q: %v", sc.Text(), err)
		}
		out = append(out, r)
	}
	b.Reset()
	return out
}

// TestGradleBuildThroughTheMavenNames is the test docs/configuration.md
// describes under "Maven and pinned files by their own names".
func TestGradleBuildThroughTheMavenNames(t *testing.T) {
	image := os.Getenv("VIA_MARIS_GRADLE_IMAGE")
	if image == "" {
		t.Skip("VIA_MARIS_GRADLE_IMAGE is not set")
	}
	addr := os.Getenv("VIA_MARIS_GRADLE_HOST")
	if addr == "" {
		addr = "host-gateway"
	}
	props, err := os.ReadFile("testdata/gradle/gradle/wrapper/gradle-wrapper.properties")
	if err != nil {
		t.Fatal(err)
	}
	distURL := "https://services.gradle.org/distributions/" + gradleDist
	if !strings.Contains(string(props), "distributionUrl="+strings.Replace(distURL, ":", "\\:", 1)+"\n") {
		t.Fatalf("the wrapper no longer names %s; pin the distribution it names in gradleDist and gradleDistSHA256", distURL)
	}

	t.Setenv("TEST_KEY_ID", "test-key")
	t.Setenv("TEST_SECRET", "test-secret")
	_, storeSrv := newFakeStore(t)
	store := Store{Endpoint: storeSrv.URL, Region: "test", Bucket: "bucket", AccessKeyIDEnv: "TEST_KEY_ID", SecretAccessKeyEnv: "TEST_SECRET"}
	names := []string{"repo.maven.apache.org", "dl.google.com", "services.gradle.org"}
	ca := newTestCA(t, append(names, "plugins.gradle.org", "pypi.org", "files.pythonhosted.org")...)
	certs, pypiCerts := t.TempDir(), t.TempDir()
	ca.writeLeaf(t, certs, 2, 30*day, names...)
	ca.writeLeaf(t, pypiCerts, 3, 30*day, "pypi.org", "files.pythonhosted.org")

	// The hold ends between kotlin-stdlib 2.4.21-RC, published 2026-09-30,
	// and 2.4.21, published 2026-10-08, whenever the test runs.
	hold := time.Since(time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)).Round(time.Hour)
	cfg := &Config{Listen: ":0", Upstreams: []Upstream{
		{Name: "pypi", Ecosystem: "PyPI", URL: "https://pypi.org", Files: "https://files.pythonhosted.org", Hold: Duration{hold}, Advisories: "malicious"},
		{Name: "central", Ecosystem: "Maven", URL: "https://repo.maven.apache.org/maven2", Hold: Duration{hold}, Advisories: "malicious"},
		{Name: "google", Ecosystem: "Maven", URL: "https://dl.google.com/dl/android/maven2", Hold: Duration{hold}, Advisories: "malicious"},
		{Name: "gradle", Ecosystem: "files", Held: t.TempDir(), Pinned: []PinnedFile{{Name: gradleDist, URL: distURL, SHA256: gradleDistSHA256}}},
	}}
	cfg.Advisories.Source = "https://osv-vulnerabilities.storage.googleapis.com"
	cfg.Advisories.Refresh = Duration{time.Hour}
	cfg.Advisories.MaxAge = Duration{2 * time.Hour}
	cfg.InUse.Store, cfg.InUse.Object = store, "in-use.json"
	cfg.InUse.Refresh, cfg.InUse.MaxAge = Duration{time.Hour}, Duration{2 * time.Hour}
	cfg.Records.Store, cfg.Records.Prefix = store, "records/"
	cfg.Records.Interval, cfg.Records.MaxUnshipped = Duration{time.Second}, Duration{time.Hour}
	cfg.ByName = &ByName{Listen: ":443", Upstream: "pypi",
		Cert: filepath.Join(pypiCerts, "tls.crt"), Key: filepath.Join(pypiCerts, "tls.key"), CA: filepath.Join(pypiCerts, "ca.crt"),
		Maven: &MavenByName{Upstreams: []string{"google", "central"}, Files: "gradle", Listings: []string{"https://dl.google.com/android/repository"},
			Cert: filepath.Join(certs, "tls.crt"), Key: filepath.Join(certs, "tls.key"), CA: filepath.Join(certs, "ca.crt")}}
	if err := cfg.validate(); err != nil {
		t.Fatal(err)
	}
	var records bytes.Buffer
	g, err := newGateway(cfg, &http.Client{Transport: &http.Transport{Proxy: http.ProxyFromEnvironment, ResponseHeaderTimeout: time.Minute}}, &records)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	if err := g.db.load(ctx, "Maven"); err != nil {
		t.Fatal(err)
	}
	g.held["gradle"].fetchMissing(ctx)
	if n := g.held["gradle"].unheld(); n != 0 {
		t.Fatalf("%s was not held", gradleDist)
	}
	ln, err := net.Listen("tcp", ":443")
	if err != nil {
		t.Fatal(err)
	}
	go g.byName.serveTLS(ln)
	t.Cleanup(func() { g.byName.srv.Close() })

	rig := &gradleRig{t: t, image: image, addr: addr, project: "testdata/gradle", ca: filepath.Join(certs, "ca.crt")}
	home := rig.volume()

	t.Run("the wrapper and a build resolve through the check", func(t *testing.T) {
		out, err := rig.run(home, "probe", "-PprobeDeps=org.jetbrains.kotlin:kotlin-stdlib:2.4.+,androidx.core:core-ktx:1.19.1,junit:junit:4.13.2")
		if err != nil {
			t.Fatalf("%v\n%s", err, out)
		}
		wantContains(t, out,
			"Downloading "+distURL,
			"resolved org.jetbrains.kotlin:kotlin-stdlib:2.4.21-RC kotlin-stdlib-2.4.21-RC.jar",
			"resolved androidx.core:core-ktx:1.19.1 core-ktx-1.19.1.aar",
			"resolved junit:junit:4.13.2 junit-4.13.2.jar")
		served := map[string]bool{}
		for _, r := range gradleRecords(t, &records, g) {
			if r.Kind == "artifact" && r.Served {
				served[r.Package+"@"+r.Version] = true
			}
			if r.Kind == "metadata" && r.Package == "org.jetbrains.kotlin:kotlin-stdlib" && r.Upstream == "central" && strings.HasPrefix(r.Reason, "0 of") {
				t.Errorf("the kotlin-stdlib listing refused nothing: %+v", r)
			}
		}
		for _, want := range []string{
			gradleDist + "@sha256:" + gradleDistSHA256,
			"org.jetbrains.kotlin:kotlin-stdlib@2.4.21-RC",
			"androidx.core:core-ktx@1.19.1",
			"junit:junit@4.13.2",
		} {
			if !served[want] {
				t.Errorf("no served record of %s in %v", want, served)
			}
		}
	})

	t.Run("a version inside the hold is refused with its reason as the reason phrase", func(t *testing.T) {
		out, err := rig.run(home, "probe", "-PprobeDeps=org.jetbrains.kotlin:kotlin-stdlib:2.4.21")
		if err == nil {
			t.Fatalf("the build passed\n%s", out)
		}
		wantContains(t, out, "Received status code 403 from server: via-maris refused org.jetbrains.kotlin:kotlin-stdlib@2.4.21: published 2026-10-08T07:57:54Z, inside the "+hold.String()+" release-age hold until ")
		var refused bool
		for _, r := range gradleRecords(t, &records, g) {
			refused = refused || r.Package == "org.jetbrains.kotlin:kotlin-stdlib" && r.Version == "2.4.21" && !r.Served && r.Published == "2026-10-08T07:57:54Z"
		}
		if !refused {
			t.Error("no record of the refusal")
		}
	})

	t.Run("a version the upstreams lack is answered with their 404", func(t *testing.T) {
		out, err := rig.run(home, "probe", "-PprobeDeps=junit:junit:99.0.0")
		if err == nil {
			t.Fatalf("the build passed\n%s", out)
		}
		wantContains(t, out, "Could not find junit:junit:99.0.0.",
			"https://dl.google.com/dl/android/maven2/junit/junit/99.0.0/junit-99.0.0.pom",
			"https://repo.maven.apache.org/maven2/junit/junit/99.0.0/junit-99.0.0.pom")
		for _, r := range gradleRecords(t, &records, g) {
			if !r.Served {
				t.Errorf("a missing version was refused rather than passed on as missing: %+v", r)
			}
		}
	})

	t.Run("a distribution that does not match its pin is never served", func(t *testing.T) {
		up := upstreamNamed(g, "gradle")
		up.Pinned[0].SHA256 = strings.Repeat("0", 64)
		h := newHeldFiles(g, up)
		g.held["gradle"], g.byName.maven.held = h, h
		h.fetchMissing(ctx)
		out, err := rig.run(rig.volume(), "help")
		if err == nil {
			t.Fatalf("the wrapper ran\n%s", out)
		}
		wantContains(t, out, "Downloading "+distURL)
		var refused bool
		for _, r := range gradleRecords(t, &records, g) {
			refused = refused || r.Package == gradleDist && !r.Served && strings.Contains(r.Reason, "its bytes hash to sha256:"+gradleDistSHA256)
		}
		if !refused {
			t.Errorf("no refusal naming the digest the bytes hash to\n%s", out)
		}
	})
}
