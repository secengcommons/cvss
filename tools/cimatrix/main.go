package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"os"
	"slices"
	"strconv"
	"strings"
	"time"
)

const releaseIndex = "https://go.dev/dl/?mode=json&include=all"
const responseLimit = 4 << 20
const moduleLimit = 64 << 10
const matrixLimit = 256
const tokenLimit = 32
const requestTimeout = 30 * time.Second

var errInvalidInput = errors.New("invalid CI matrix input")
var exitProcess = os.Exit

type version struct {
	major int
	minor int
	patch int
}

type release struct {
	Version string `json:"version"`
	Stable  bool   `json:"stable"`
}

type port struct {
	GOOS         string
	GOARCH       string
	CgoSupported bool
}

type matrixEntry struct {
	Name    string `json:"name,omitempty"`
	Version string `json:"version,omitempty"`
	GOOS    string `json:"goos,omitempty"`
	GOARCH  string `json:"goarch,omitempty"`
	Runner  string `json:"runner,omitempty"`
	CGO     string `json:"cgo,omitempty"`
}

type matrix struct {
	Include []matrixEntry `json:"include"`
}

func main() {
	exitProcess(runMain(os.Args[1:], os.Stdin, os.Stdout, os.Stderr, releaseHTTPClient()))
}

func releaseHTTPClient() *http.Client {
	return &http.Client{
		Timeout: requestTimeout,
		CheckRedirect: func(request *http.Request, _ []*http.Request) error {
			if request.URL.Scheme != "https" || request.URL.Host != "go.dev" {
				return errInvalidInput
			}
			return nil
		},
	}
}

func runMain(arguments []string, input io.Reader, output, errorOutput io.Writer, client *http.Client) int {
	if err := run(arguments, input, output, client); err != nil {
		if _, writeErr := fmt.Fprintln(errorOutput, "cimatrix:", err); writeErr != nil {
			return 1
		}
		return 1
	}
	return 0
}

func run(arguments []string, input io.Reader, output io.Writer, client *http.Client) error {
	if len(arguments) != 2 || input == nil || output == nil || client == nil {
		return errInvalidInput
	}
	var result matrix
	var err error
	switch arguments[0] {
	case "compatibility":
		result, err = compatibilityMatrix(arguments[1], releaseIndex, client)
	case "ports":
		result, err = portMatrix(input)
	default:
		return errInvalidInput
	}
	if err != nil {
		return err
	}
	encoder := json.NewEncoder(output)
	encoder.SetEscapeHTML(false)
	return encoder.Encode(result)
}

func compatibilityMatrix(moduleRoot, endpoint string, client *http.Client) (result matrix, resultErr error) {
	source, err := readModuleFile(moduleRoot)
	if err != nil {
		return matrix{}, err
	}
	lower, upper, err := moduleVersions(source)
	if err != nil {
		return matrix{}, err
	}
	request, err := http.NewRequest(http.MethodGet, endpoint, nil)
	if err != nil {
		return matrix{}, err
	}
	request.Header.Set("Accept", "application/json")
	response, err := client.Do(request)
	if err != nil {
		return matrix{}, err
	}
	defer func() { resultErr = errors.Join(resultErr, response.Body.Close()) }()
	if response.StatusCode != http.StatusOK {
		return matrix{}, fmt.Errorf("go release index returned %s", response.Status)
	}
	mediaType, _, err := mime.ParseMediaType(response.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/json" {
		return matrix{}, errInvalidInput
	}
	return decodeReleases(response.Body, lower, upper)
}

func readModuleFile(path string) (value []byte, resultErr error) {
	root, err := os.OpenRoot(path)
	if err != nil {
		return nil, err
	}
	defer func() { resultErr = errors.Join(resultErr, root.Close()) }()
	file, err := root.Open("go.mod")
	if err != nil {
		return nil, err
	}
	defer func() { resultErr = errors.Join(resultErr, file.Close()) }()
	return readBounded(file, moduleLimit)
}

func readBounded(reader io.Reader, limit int64) ([]byte, error) {
	value, err := io.ReadAll(io.LimitReader(reader, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(value)) > limit {
		return nil, errInvalidInput
	}
	return value, nil
}

func moduleVersions(source []byte) (version, version, error) {
	var lower, upper version
	var haveLower, haveUpper bool
	scanner := bufio.NewScanner(io.LimitReader(bytes.NewReader(source), moduleLimit))
	scanner.Buffer(make([]byte, 1024), int(moduleLimit))
	for scanner.Scan() {
		if err := acceptModuleDirective(strings.Fields(scanner.Text()), &lower, &upper, &haveLower, &haveUpper); err != nil {
			return version{}, version{}, err
		}
	}
	if err := scanner.Err(); err != nil {
		return version{}, version{}, err
	}
	if !haveLower || !haveUpper || compareVersion(lower, upper) > 0 {
		return version{}, version{}, errInvalidInput
	}
	return lower, upper, nil
}

func acceptModuleDirective(fields []string, lower, upper *version, haveLower, haveUpper *bool) error {
	if len(fields) != 2 {
		return nil
	}
	switch fields[0] {
	case "go":
		if *haveLower {
			return errInvalidInput
		}
		parsed, ok := parseVersion(fields[1])
		if !ok {
			return errInvalidInput
		}
		*lower, *haveLower = parsed, true
	case "toolchain":
		if *haveUpper || !strings.HasPrefix(fields[1], "go") {
			return errInvalidInput
		}
		parsed, ok := parseVersion(strings.TrimPrefix(fields[1], "go"))
		if !ok {
			return errInvalidInput
		}
		*upper, *haveUpper = parsed, true
	}
	return nil
}

func parseVersion(value string) (version, bool) {
	if len(value) > tokenLimit {
		return version{}, false
	}
	parts := strings.Split(value, ".")
	if len(parts) != 3 {
		return version{}, false
	}
	values := [3]int{}
	for index, part := range parts {
		if part == "" || (len(part) > 1 && part[0] == '0') {
			return version{}, false
		}
		parsed, err := strconv.Atoi(part)
		if err != nil || parsed < 0 {
			return version{}, false
		}
		values[index] = parsed
	}
	return version{major: values[0], minor: values[1], patch: values[2]}, true
}

func compareVersion(left, right version) int {
	if left.major != right.major {
		return left.major - right.major
	}
	if left.minor != right.minor {
		return left.minor - right.minor
	}
	return left.patch - right.patch
}

func formatVersion(value version) string {
	return strconv.Itoa(value.major) + "." + strconv.Itoa(value.minor) + "." + strconv.Itoa(value.patch)
}

func decodeReleases(reader io.Reader, lower, upper version) (matrix, error) {
	source, err := readBounded(reader, responseLimit)
	if err != nil {
		return matrix{}, err
	}
	decoder := json.NewDecoder(bytes.NewReader(source))
	var releases []release
	if err := decoder.Decode(&releases); err != nil {
		return matrix{}, errInvalidInput
	}
	if err := requireEOF(decoder); err != nil {
		return matrix{}, err
	}
	versions, seen, err := selectedVersions(releases, lower, upper)
	if err != nil {
		return matrix{}, err
	}
	if len(versions) > matrixLimit {
		return matrix{}, errInvalidInput
	}
	if _, found := seen[lower]; !found {
		return matrix{}, errInvalidInput
	}
	if _, found := seen[upper]; !found {
		return matrix{}, errInvalidInput
	}
	slices.SortFunc(versions, compareVersion)
	entries := make([]matrixEntry, len(versions))
	for index, candidate := range versions {
		entries[index] = matrixEntry{Version: formatVersion(candidate)}
	}
	return matrix{Include: entries}, nil
}

func selectedVersions(releases []release, lower, upper version) ([]version, map[version]struct{}, error) {
	versions := make([]version, 0, len(releases))
	seen := make(map[version]struct{}, len(releases))
	for _, candidate := range releases {
		parsed, selected := selectedVersion(candidate, lower, upper)
		if !selected {
			continue
		}
		if _, found := seen[parsed]; found {
			return nil, nil, errInvalidInput
		}
		seen[parsed] = struct{}{}
		versions = append(versions, parsed)
	}
	return versions, seen, nil
}

func selectedVersion(candidate release, lower, upper version) (version, bool) {
	if !candidate.Stable || !strings.HasPrefix(candidate.Version, "go") {
		return version{}, false
	}
	parsed, ok := parseVersion(strings.TrimPrefix(candidate.Version, "go"))
	return parsed, ok && compareVersion(parsed, lower) >= 0 && compareVersion(parsed, upper) <= 0
}

func requireEOF(decoder *json.Decoder) error {
	var trailing json.RawMessage
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return errInvalidInput
	}
	return nil
}

func portMatrix(input io.Reader) (matrix, error) {
	source, err := readBounded(input, responseLimit)
	if err != nil {
		return matrix{}, err
	}
	decoder := json.NewDecoder(bytes.NewReader(source))
	var ports []port
	if err := decoder.Decode(&ports); err != nil || len(ports) == 0 {
		return matrix{}, errInvalidInput
	}
	if len(ports) > matrixLimit {
		return matrix{}, errInvalidInput
	}
	if err := requireEOF(decoder); err != nil {
		return matrix{}, err
	}
	entries, err := portEntries(ports)
	if err != nil {
		return matrix{}, err
	}
	return matrix{Include: entries}, nil
}

func portEntries(ports []port) ([]matrixEntry, error) {
	entries := make([]matrixEntry, len(ports))
	seen := make(map[string]struct{}, len(ports))
	for index, candidate := range ports {
		if !validToken(candidate.GOOS) || !validToken(candidate.GOARCH) {
			return nil, errInvalidInput
		}
		name := candidate.GOOS + "-" + candidate.GOARCH
		if _, found := seen[name]; found {
			return nil, errInvalidInput
		}
		seen[name] = struct{}{}
		runner := "ubuntu-24.04"
		cgo := "0"
		if candidate.GOOS == "ios" {
			if !candidate.CgoSupported {
				return nil, errInvalidInput
			}
			if candidate.GOARCH == "amd64" {
				runner = "macos-15-intel"
			} else {
				runner = "macos-15"
			}
			cgo = "1"
		}
		entries[index] = matrixEntry{Name: name, GOOS: candidate.GOOS, GOARCH: candidate.GOARCH, Runner: runner, CGO: cgo}
	}
	slices.SortFunc(entries, func(left, right matrixEntry) int { return strings.Compare(left.Name, right.Name) })
	return entries, nil
}

func validToken(value string) bool {
	if value == "" || len(value) > tokenLimit {
		return false
	}
	for _, character := range value {
		if (character < 'a' || character > 'z') && (character < '0' || character > '9') {
			return false
		}
	}
	return true
}
