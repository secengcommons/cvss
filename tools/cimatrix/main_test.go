package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (function roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return function(request)
}

type failingReader struct{}

func (failingReader) Read([]byte) (int, error) {
	return 0, errors.New("read failed")
}

type failingWriter struct{}

func (failingWriter) Write([]byte) (int, error) {
	return 0, errors.New("write failed")
}

type failingCloser struct {
	io.Reader
}

func (failingCloser) Close() error {
	return errors.New("close failed")
}

func TestReleaseHTTPClient(t *testing.T) {
	t.Parallel()

	client := releaseHTTPClient()
	if client.Timeout != requestTimeout {
		t.Fatalf("timeout = %s", client.Timeout)
	}
	for url, allowed := range map[string]bool{
		"https://go.dev/dl/":    true,
		"http://go.dev/dl/":     false,
		"https://example.test/": false,
	} {
		request, err := http.NewRequest(http.MethodGet, url, nil)
		if err != nil {
			t.Fatal(err)
		}
		if err := client.CheckRedirect(request, nil); (err == nil) != allowed {
			t.Fatalf("redirect %s = %v", url, err)
		}
	}
}

func TestCompatibilityMatrix(t *testing.T) {
	t.Parallel()

	module := filepath.Join(t.TempDir(), "go.mod")
	if err := os.WriteFile(module, []byte("module example.test/project\n\ngo 1.24.0\ntoolchain go1.26.6\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	client := responseClient(http.StatusOK, `[
		{"version":"go1.26.6","stable":true},
		{"version":"go1.25.2","stable":true},
		{"version":"go1.24.0","stable":true},
		{"version":"go1.27rc1","stable":false},
		{"version":"go1.23.9","stable":true}
	]`)
	result, err := compatibilityMatrix(filepath.Dir(module), releaseIndex, client)
	if err != nil {
		t.Fatal(err)
	}
	want := []matrixEntry{{Version: "1.24.0"}, {Version: "1.25.2"}, {Version: "1.26.6"}}
	if !equalEntries(result.Include, want) {
		t.Fatalf("entries = %#v", result.Include)
	}
}

func TestCompatibilityMatrixRejectsUnavailableAndFailedSources(t *testing.T) {
	t.Parallel()

	missing := filepath.Join(t.TempDir(), "missing")
	if _, err := compatibilityMatrix(missing, releaseIndex, responseClient(http.StatusOK, `[]`)); err == nil {
		t.Fatal("missing module accepted")
	}
	if _, err := compatibilityMatrix(t.TempDir(), releaseIndex, responseClient(http.StatusOK, `[]`)); err == nil {
		t.Fatal("directory without module accepted")
	}
	module := filepath.Join(t.TempDir(), "go.mod")
	if err := os.WriteFile(module, []byte("go 1.24.0\ntoolchain go1.26.6\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := compatibilityMatrix(filepath.Dir(module), releaseIndex, responseClient(http.StatusBadGateway, "failed")); err == nil {
		t.Fatal("failed release index accepted")
	}
	invalidMedia := responseClient(http.StatusOK, `[]`)
	invalidMedia.Transport = roundTripFunc(func(request *http.Request) (*http.Response, error) {
		response, err := responseClient(http.StatusOK, `[]`).Transport.RoundTrip(request)
		response.Header.Set("Content-Type", "text/plain")
		return response, err
	})
	if _, err := compatibilityMatrix(filepath.Dir(module), releaseIndex, invalidMedia); err == nil {
		t.Fatal("non-JSON release index accepted")
	}
	closeClient := responseClient(http.StatusOK, `[{"version":"go1.24.0","stable":true},{"version":"go1.26.6","stable":true}]`)
	closeClient.Transport = roundTripFunc(func(request *http.Request) (*http.Response, error) {
		response, err := responseClient(http.StatusOK, `[{"version":"go1.24.0","stable":true},{"version":"go1.26.6","stable":true}]`).Transport.RoundTrip(request)
		response.Body = failingCloser{Reader: response.Body}
		return response, err
	})
	if _, err := compatibilityMatrix(filepath.Dir(module), releaseIndex, closeClient); err == nil || !strings.Contains(err.Error(), "close failed") {
		t.Fatalf("close error = %v", err)
	}
	client := &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		return nil, errors.New("request failed")
	})}
	if _, err := compatibilityMatrix(filepath.Dir(module), releaseIndex, client); err == nil {
		t.Fatal("request failure accepted")
	}
	if _, err := compatibilityMatrix(filepath.Dir(module), "://invalid", client); err == nil {
		t.Fatal("invalid endpoint accepted")
	}
	invalidModule := filepath.Join(t.TempDir(), "go.mod")
	if err := os.WriteFile(invalidModule, []byte("go 1.24\ntoolchain go1.26.6\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := compatibilityMatrix(filepath.Dir(invalidModule), releaseIndex, client); err == nil {
		t.Fatal("invalid module accepted")
	}
}

func TestModuleVersions(t *testing.T) {
	t.Parallel()

	lower, upper, err := moduleVersions([]byte("module example.test/project\n\ngo 1.24.0\ntoolchain go1.26.6\n"))
	if err != nil || lower != (version{major: 1, minor: 24}) || upper != (version{major: 1, minor: 26, patch: 6}) {
		t.Fatalf("versions = (%#v, %#v, %v)", lower, upper, err)
	}
	for _, source := range []string{
		"go 1.24\ntoolchain go1.26.6\n",
		"go 1.24.0\ngo 1.25.0\ntoolchain go1.26.6\n",
		"go 1.24.0\ntoolchain 1.26.6\n",
		"go 1.24.0\ntoolchain go1.26\n",
		"go 1.24.0\ntoolchain go1.26.6\ntoolchain go1.26.7\n",
		"go 1.27.0\ntoolchain go1.26.6\n",
		"go 1.24.0\n",
	} {
		if _, _, err := moduleVersions([]byte(source)); err == nil {
			t.Fatalf("accepted %q", source)
		}
	}
	if _, _, err := moduleVersions([]byte(strings.Repeat("x", 65537))); err == nil {
		t.Fatal("overlong module line accepted")
	}
}

func TestParseVersion(t *testing.T) {
	t.Parallel()

	for _, value := range []string{"", "1.24", "1.24.0.1", "1.024.0", "1.x.0", "-1.24.0", strings.Repeat("1", tokenLimit+1)} {
		if _, ok := parseVersion(value); ok {
			t.Fatalf("accepted %q", value)
		}
	}
	if value, ok := parseVersion("2.0.1"); !ok || formatVersion(value) != "2.0.1" {
		t.Fatalf("parse = (%#v, %t)", value, ok)
	}
	if compareVersion(version{major: 2}, version{major: 1}) <= 0 ||
		compareVersion(version{major: 1, minor: 2}, version{major: 1, minor: 1}) <= 0 ||
		compareVersion(version{major: 1, minor: 1, patch: 2}, version{major: 1, minor: 1, patch: 1}) <= 0 ||
		compareVersion(version{major: 1}, version{major: 1}) != 0 {
		t.Fatal("version ordering failed")
	}
}

func TestDecodeReleasesRejectsInvalidMaterial(t *testing.T) {
	t.Parallel()

	lower := version{major: 1, minor: 24}
	upper := version{major: 1, minor: 26, patch: 6}
	for name, source := range map[string]string{
		"malformed":       `{`,
		"trailing":        `[] {}`,
		"missing lower":   `[{"version":"go1.26.6","stable":true}]`,
		"missing upper":   `[{"version":"go1.24.0","stable":true}]`,
		"duplicate":       `[{"version":"go1.24.0","stable":true},{"version":"go1.24.0","stable":true},{"version":"go1.26.6","stable":true}]`,
		"invalid version": `[{"version":"release","stable":true},{"version":"go1.24.0","stable":true}]`,
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := decodeReleases(strings.NewReader(source), lower, upper); err == nil {
				t.Fatal("invalid releases accepted")
			}
		})
	}
	if _, err := decodeReleases(strings.NewReader(strings.Repeat(" ", responseLimit+1)), lower, upper); err == nil {
		t.Fatal("oversized response accepted")
	}
	tooMany := make([]release, matrixLimit+1)
	for index := range tooMany {
		tooMany[index] = release{Version: "go1.0." + strconv.Itoa(index), Stable: true}
	}
	encoded, err := json.Marshal(tooMany)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := decodeReleases(bytes.NewReader(encoded), version{major: 1}, version{major: 1, patch: matrixLimit}); err == nil {
		t.Fatal("oversized release matrix accepted")
	}
}

func TestPortMatrix(t *testing.T) {
	t.Parallel()

	result, err := portMatrix(strings.NewReader(`[{"GOOS":"windows","GOARCH":"amd64"},{"GOOS":"aix","GOARCH":"ppc64"}]`))
	if err != nil {
		t.Fatal(err)
	}
	want := []matrixEntry{
		{Name: "aix-ppc64", GOOS: "aix", GOARCH: "ppc64", Runner: "ubuntu-24.04", CGO: "0"},
		{Name: "windows-amd64", GOOS: "windows", GOARCH: "amd64", Runner: "ubuntu-24.04", CGO: "0"},
	}
	if !equalEntries(result.Include, want) {
		t.Fatalf("entries = %#v", result.Include)
	}
}

func TestPortMatrixRejectsInvalidMaterial(t *testing.T) {
	t.Parallel()

	for _, source := range []string{"[]", `{}`, `[{"GOOS":"","GOARCH":"amd64"}]`, `[{"GOOS":"linux-${{x}}","GOARCH":"amd64"}]`, `[{"GOOS":"aix","GOARCH":"ppc64"},{"GOOS":"aix","GOARCH":"ppc64"}]`, `[{"GOOS":"aix","GOARCH":"ppc64"}] {}`} {
		if _, err := portMatrix(strings.NewReader(source)); err == nil {
			t.Fatalf("accepted %q", source)
		}
	}
	if _, err := portMatrix(strings.NewReader(strings.Repeat(" ", responseLimit+1))); err == nil {
		t.Fatal("oversized port inventory accepted")
	}
	if _, err := portMatrix(failingReader{}); err == nil {
		t.Fatal("port read failure accepted")
	}
}

func TestPortMatrixRejectsTooManyEntries(t *testing.T) {
	t.Parallel()

	tooMany := make([]port, matrixLimit+1)
	for index := range tooMany {
		tooMany[index] = port{GOOS: "os" + strconv.Itoa(index), GOARCH: "amd64"}
	}
	encoded, err := json.Marshal(tooMany)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := portMatrix(bytes.NewReader(encoded)); err == nil {
		t.Fatal("oversized matrix accepted")
	}
}

func TestPortMatrixSelectsIOSRunners(t *testing.T) {
	t.Parallel()

	ios, err := portMatrix(strings.NewReader(`[{"GOOS":"ios","GOARCH":"arm64","CgoSupported":true}]`))
	if err != nil || ios.Include[0].Runner != "macos-15" || ios.Include[0].CGO != "1" {
		t.Fatalf("iOS entry = (%#v, %v)", ios.Include, err)
	}
	if _, err := portMatrix(strings.NewReader(`[{"GOOS":"ios","GOARCH":"arm64"}]`)); err == nil {
		t.Fatal("iOS without cgo support accepted")
	}
	iosIntel, err := portMatrix(strings.NewReader(`[{"GOOS":"ios","GOARCH":"amd64","CgoSupported":true}]`))
	if err != nil || iosIntel.Include[0].Runner != "macos-15-intel" {
		t.Fatalf("Intel iOS entry = (%#v, %v)", iosIntel.Include, err)
	}
}

func TestRun(t *testing.T) {
	t.Parallel()

	var output bytes.Buffer
	if err := run([]string{"ports", "unused"}, strings.NewReader(`[{"GOOS":"linux","GOARCH":"amd64"}]`), &output, http.DefaultClient); err != nil {
		t.Fatal(err)
	}
	if got := output.String(); got != "{\"include\":[{\"name\":\"linux-amd64\",\"goos\":\"linux\",\"goarch\":\"amd64\",\"runner\":\"ubuntu-24.04\",\"cgo\":\"0\"}]}\n" {
		t.Fatalf("output = %q", got)
	}
	for _, arguments := range [][]string{nil, {"unknown", "unused"}, {"ports"}, {"ports", "unused", "extra"}} {
		if err := run(arguments, strings.NewReader("[]"), io.Discard, http.DefaultClient); err == nil {
			t.Fatalf("arguments %#v accepted", arguments)
		}
	}
	if err := run([]string{"ports", "unused"}, nil, io.Discard, http.DefaultClient); err == nil {
		t.Fatal("nil input accepted")
	}
	if err := run([]string{"ports", "unused"}, strings.NewReader("[]"), nil, http.DefaultClient); err == nil {
		t.Fatal("nil output accepted")
	}
	if err := run([]string{"ports", "unused"}, strings.NewReader("[]"), io.Discard, nil); err == nil {
		t.Fatal("nil client accepted")
	}
	if err := run([]string{"ports", "unused"}, strings.NewReader(`[{"GOOS":"linux","GOARCH":"amd64"}]`), failingWriter{}, http.DefaultClient); err == nil {
		t.Fatal("write failure accepted")
	}
	if err := run([]string{"ports", "unused"}, strings.NewReader("[]"), io.Discard, http.DefaultClient); err == nil {
		t.Fatal("invalid port inventory accepted")
	}
}

func TestRunCompatibility(t *testing.T) {
	t.Parallel()

	module := filepath.Join(t.TempDir(), "go.mod")
	if err := os.WriteFile(module, []byte("go 1.24.0\ntoolchain go1.26.6\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	client := responseClient(http.StatusOK, `[{"version":"go1.24.0","stable":true},{"version":"go1.26.6","stable":true}]`)
	var output bytes.Buffer
	if err := run([]string{"compatibility", filepath.Dir(module)}, strings.NewReader(""), &output, client); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(output.String(), `"version":"1.26.6"`) {
		t.Fatalf("output = %q", output.String())
	}
}

func TestRunMain(t *testing.T) {
	t.Parallel()

	var output, errorOutput bytes.Buffer
	if code := runMain([]string{"ports", "unused"}, strings.NewReader(`[{"GOOS":"linux","GOARCH":"amd64"}]`), &output, &errorOutput, http.DefaultClient); code != 0 {
		t.Fatalf("code = %d", code)
	}
	if code := runMain(nil, strings.NewReader(""), &output, &errorOutput, http.DefaultClient); code != 1 || !strings.Contains(errorOutput.String(), "cimatrix:") {
		t.Fatalf("failure = (%d, %q)", code, errorOutput.String())
	}
	if code := runMain(nil, strings.NewReader(""), &output, failingWriter{}, http.DefaultClient); code != 1 {
		t.Fatalf("diagnostic write code = %d", code)
	}
}

func TestMain(t *testing.T) {
	originalArguments := os.Args
	originalExit := exitProcess
	t.Cleanup(func() {
		os.Args = originalArguments
		exitProcess = originalExit
	})
	os.Args = []string{"cimatrix"}
	code := -1
	exitProcess = func(value int) { code = value }
	main()
	if code != 1 {
		t.Fatalf("code = %d", code)
	}
}

func TestReadBounded(t *testing.T) {
	t.Parallel()

	if value, err := readBounded(strings.NewReader("value"), 5); err != nil || string(value) != "value" {
		t.Fatalf("read = (%q, %v)", value, err)
	}
	if _, err := readBounded(strings.NewReader("value"), 4); err == nil {
		t.Fatal("oversized input accepted")
	}
	if _, err := readBounded(failingReader{}, 4); err == nil {
		t.Fatal("read failure accepted")
	}
}

func responseClient(status int, body string) *http.Client {
	return &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		if request.URL.String() != releaseIndex || request.Header.Get("Accept") != "application/json" {
			return nil, errors.New("unexpected request")
		}
		response := &http.Response{
			StatusCode: status,
			Status:     http.StatusText(status),
			Body:       io.NopCloser(strings.NewReader(body)),
			Header:     make(http.Header),
			Request:    request,
		}
		response.Header.Set("Content-Type", "application/json")
		return response, nil
	})}
}

func equalEntries(left, right []matrixEntry) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

func TestValidToken(t *testing.T) {
	t.Parallel()

	for value, valid := range map[string]bool{
		"linux":                           true,
		"arm64":                           true,
		"":                                false,
		"ARM64":                           false,
		"a-b":                             false,
		strings.Repeat("a", tokenLimit+1): false,
	} {
		if validToken(value) != valid {
			t.Fatalf("validToken(%q) = %t", value, !valid)
		}
	}
}
