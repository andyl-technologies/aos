// These tests exercise source-selected observer inputs only. They open no
// database or provider connection and establish no deployed collector custody.
package main

import (
	"encoding/json"
	"os"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

func syntheticConfiguration() configuration {
	return configuration{Version: 1, ConnectionName: "synthetic-project:synthetic-region:synthetic-database",
		IPType:   "private",
		Database: "synthetic_database", Role: "synthetic_reader", Deployment: "synthetic-deployment",
		Checkpoints: json.RawMessage(`[]`), QuerySHA256: strings.Repeat("a", 64),
		CutoffUnixNanos:  strconv.FormatInt(time.Now().Add(time.Minute).UnixNano(), 10),
		MaximumWorkNanos: strconv.FormatInt(int64(time.Second), 10)}
}

func TestObservationOriginalCutoffAndResourceRefusal(t *testing.T) {
	selected := syntheticConfiguration()
	ctx, cancel, err := observationContext(selected, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	defer cancel()
	if ctx.Err() != nil {
		t.Fatal("fresh synthetic observation unexpectedly expired")
	}
	for _, mutate := range []func(*configuration){
		func(value *configuration) { value.ConnectionName = "https://unselected.example" },
		func(value *configuration) { value.Role = "reader;DELETE" },
		func(value *configuration) { value.Version = 2 },
		func(value *configuration) { value.CutoffUnixNanos = "01" },
		func(value *configuration) { value.CutoffUnixNanos = "1" },
		func(value *configuration) { value.MaximumWorkNanos = strconv.FormatInt(int64(maxWork)+1, 10) },
	} {
		changed := selected
		mutate(&changed)
		if _, cancel, err := observationContext(changed, time.Now()); err == nil {
			cancel()
			t.Fatal("invalid synthetic resource or cutoff admitted")
		}
	}
}

func TestClosedConfigurationRefusesTrailingAndUnknownFields(t *testing.T) {
	raw, err := json.Marshal(syntheticConfiguration())
	if err != nil {
		t.Fatal(err)
	}
	for _, changed := range [][]byte{
		append(append([]byte{}, raw...), []byte(` {}`)...),
		[]byte(strings.TrimSuffix(string(raw), "}") + `,"sql":"DELETE FROM unknown"}`),
		[]byte(`{"version":true}`),
		[]byte(strings.TrimSuffix(string(raw), "}") + `,"version":1}`),
	} {
		if decode(changed, &configuration{}) == nil {
			t.Fatal("unsupported configuration admitted")
		}
	}
}

func TestPrivateDescriptorBoundAndOwnerMode(t *testing.T) {
	file, err := os.CreateTemp(t.TempDir(), "synthetic-input")
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	if _, err := file.WriteString("fixture"); err != nil {
		t.Fatal(err)
	}
	duplicate := func() string {
		fd, err := syscall.Dup(int(file.Fd()))
		if err != nil {
			t.Fatal(err)
		}
		return strconv.Itoa(fd)
	}
	if raw, err := privateDescriptor(duplicate(), 7); err != nil || string(raw) != "fixture" {
		t.Fatalf("exact private fixture refused: %v", err)
	}
	if _, err := privateDescriptor(duplicate(), 6); err == nil {
		t.Fatal("growing or over-bound fixture admitted")
	}
	if err := file.Chmod(0644); err != nil {
		t.Fatal(err)
	}
	if _, err := privateDescriptor(duplicate(), 7); err == nil {
		t.Fatal("publicly readable credential input admitted")
	}
}

func TestPrivateUninstalledSourceCannotSelectQuery(t *testing.T) {
	path := t.TempDir() + "/synthetic-query-source.py"
	if err := os.WriteFile(path, []byte("raise Exception('not installed')"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := installed(path, 1<<20); err == nil {
		t.Fatal("private supplied source admitted as installed query generator")
	}
}
