package hosts

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func marked(iface, block string) string {
	return beginMarker(iface) + "\n" + block + endMarker(iface) + "\n"
}

func TestRewriteMultipleNetworks(t *testing.T) {
	first := marked("tincan0", "10.42.0.1\talice.work\n")
	second := marked("tincan1", "10.43.0.1\talice.home\n")
	content := "before\n" + first + "between\n" + second + "after\n"
	for _, tc := range []struct {
		name, iface, block, want string
	}{
		{"update first", "tincan0", "new\n", "before\n" + marked("tincan0", "new\n") + "between\n" + second + "after\n"},
		{"update second", "tincan1", "new\n", "before\n" + first + "between\n" + marked("tincan1", "new\n") + "after\n"},
		{"remove first", "tincan0", "", "before\nbetween\n" + second + "after\n"},
		{"remove second", "tincan1", "", "before\n" + first + "between\nafter\n"},
		{"remove absent", "other", "", content},
		{"add third", "other", "new\n", content + "\n" + marked("other", "new\n")},
		{"unchanged", "tincan1", "10.43.0.1\talice.home\n", content},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, changed, err := Rewrite([]byte(content), tc.iface, tc.block)
			if err != nil || string(got) != tc.want || changed != (tc.want != content) {
				t.Fatalf("Rewrite: changed=%v err=%v\ngot: %q\nwant: %q", changed, err, got, tc.want)
			}
		})
	}
}

func TestRewriteLegacyBelongsToTincan0(t *testing.T) {
	legacy := legacyBeginMarker + "\nold\n" + legacyEndMarker + "\n"
	other := marked("tincan2", "10.44.0.1\talice.other\n")
	content := "before\n" + legacy + other + "after\n"
	for _, tc := range []struct {
		name, iface, block, want string
	}{
		{"migrate", "tincan0", "old\n", "before\n" + marked("tincan0", "old\n") + other + "after\n"},
		{"remove", "tincan0", "", "before\n" + other + "after\n"},
		{"other add", "tincan1", "new\n", content + "\n" + marked("tincan1", "new\n")},
		{"other remove", "tincan1", "", content},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, changed, err := Rewrite([]byte(content), tc.iface, tc.block)
			if err != nil || string(got) != tc.want || changed != (tc.want != content) {
				t.Fatalf("Rewrite: changed=%v err=%v\ngot: %q\nwant: %q", changed, err, got, tc.want)
			}
			_, changed, err = Rewrite(got, tc.iface, tc.block)
			if err != nil || changed {
				t.Fatalf("not idempotent: changed=%v err=%v", changed, err)
			}
		})
	}
}

func TestRewriteRejectsAmbiguousNetworkMarkers(t *testing.T) {
	for name, content := range map[string]string{
		"missing end":                   beginMarker("tincan1") + "\n",
		"orphan end":                    endMarker("tincan1") + "\n",
		"mismatch":                      beginMarker("tincan0") + "\n" + endMarker("tincan1") + "\n",
		"nested":                        beginMarker("tincan0") + "\n" + marked("tincan1", "other\n") + endMarker("tincan0") + "\n",
		"duplicate":                     marked("tincan1", "first\n") + marked("tincan1", "second\n"),
		"legacy and labelled duplicate": legacyBeginMarker + "\nold\n" + legacyEndMarker + "\n" + marked("tincan0", "new\n"),
	} {
		t.Run(name, func(t *testing.T) {
			for _, iface := range []string{"tincan0", "tincan1", "unrelated"} {
				if _, _, err := Rewrite([]byte(content), iface, "new\n"); !errors.Is(err, ErrMalformedMarkers) {
					t.Fatalf("%s: err=%v, want ErrMalformedMarkers", iface, err)
				}
			}
		})
	}
}

func TestApplyConcurrentNetworks(t *testing.T) {
	path := filepath.Join(t.TempDir(), "hosts")
	const operator = "127.0.0.1 localhost\n"
	if err := os.WriteFile(path, []byte(operator), 0o640); err != nil {
		t.Fatal(err)
	}
	const networks = 24
	start := make(chan struct{})
	errs := make(chan error, networks)
	for i := range networks {
		go func() {
			<-start
			iface := fmt.Sprintf("tincan%d", i)
			_, err := Apply(path, iface, fmt.Sprintf("10.42.%d.1\talice.net%d\n", i, i))
			errs <- err
		}()
	}
	close(start)
	for range networks {
		if err := <-errs; err != nil {
			t.Fatal(err)
		}
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(string(data), operator) {
		t.Fatalf("lost operator content: %s", data)
	}
	for i := range networks {
		iface := fmt.Sprintf("tincan%d", i)
		block := fmt.Sprintf("10.42.%d.1\talice.net%d\n", i, i)
		if _, changed, err := Rewrite(data, iface, block); err != nil || changed {
			t.Fatalf("lost %s block: changed=%v err=%v\n%s", iface, changed, err, data)
		}
	}
	st, err := os.Stat(path)
	if err != nil || st.Mode().Perm() != 0o640 {
		t.Fatalf("mode not preserved: stat=%v err=%v", st, err)
	}
}

func TestApplyMalformedLeavesFileUntouched(t *testing.T) {
	path := filepath.Join(t.TempDir(), "hosts")
	original := "127.0.0.1 localhost\n" + beginMarker("tincan1") + "\noperator content\n"
	if err := os.WriteFile(path, []byte(original), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Apply(path, "tincan0", "new\n"); !errors.Is(err, ErrMalformedMarkers) {
		t.Fatalf("err=%v, want ErrMalformedMarkers", err)
	}
	got, err := os.ReadFile(path)
	if err != nil || string(got) != original {
		t.Fatalf("file changed: err=%v\n%s", err, got)
	}
}
