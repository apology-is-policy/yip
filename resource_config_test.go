package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func customConfig() ResourceConfig {
	return ResourceConfig{Version: 1, Resources: []Resource{{Name: "builder", Desc: "shared build host", Machine: "machine-one"}}}
}
func TestResourceConfigMigrationPreservesLeaseAndQueue(t *testing.T) {
	resTestRoot(t)
	if got, _, _, e := TryAcquire("mac", "owner", "build", time.Hour, nil); !got || e != nil {
		t.Fatal(got, e)
	}
	Request("mac", "waiter", "next", time.Hour, nil)
	beforeLease, _ := os.ReadFile(leasePath("mac"))
	beforeQueue, _ := os.ReadFile(queuePath("mac", "waiter"))
	if e := initializeResourceConfig(true); e != nil {
		t.Fatal(e)
	}
	afterLease, _ := os.ReadFile(leasePath("mac"))
	afterQueue, _ := os.ReadFile(queuePath("mac", "waiter"))
	if !bytes.Equal(beforeLease, afterLease) || !bytes.Equal(beforeQueue, afterQueue) {
		t.Fatal("migration altered live ownership/queue")
	}
	c, _ := LoadResourceConfig()
	if len(c.Resources) != 2 || c.Resources[0].Name != "mac" {
		t.Fatal(c)
	}
	c.Resources[0].Desc = "clearer wording"
	if e := saveResourceConfig(c); e != nil {
		t.Fatal(e)
	}
	c.Resources[0].Machine = "different"
	if e := saveResourceConfig(c); e == nil {
		t.Fatal("changed held machine")
	}
	c.Resources = c.Resources[1:]
	if e := saveResourceConfig(c); e == nil {
		t.Fatal("removed held resource")
	}
	afterLease, _ = os.ReadFile(leasePath("mac"))
	afterQueue, _ = os.ReadFile(queuePath("mac", "waiter"))
	if !bytes.Equal(beforeLease, afterLease) || !bytes.Equal(beforeQueue, afterQueue) {
		t.Fatal("rejected edit altered state")
	}
}
func TestCustomResourcesFlowAndHistoryProtection(t *testing.T) {
	resTestRoot(t)
	if e := initializeResourceConfig(false); e != nil {
		t.Fatal(e)
	}
	if e := saveResourceConfig(customConfig()); e != nil {
		t.Fatal(e)
	}
	if got, _, _, e := Request("builder", "owner", "test", time.Hour, nil); !got || e != nil {
		t.Fatal(got, e)
	}
	if got, _, _, e := Request("builder", "waiter", "next", time.Hour, nil); got || e != nil {
		t.Fatal(got, e)
	}
	Release("builder", "owner")
	if got, _, _, e := Request("builder", "waiter", "next", time.Hour, nil); !got || e != nil {
		t.Fatal(got, e)
	}
	Release("builder", "waiter")
	c := customConfig()
	c.Resources[0].Disabled = true
	if e := saveResourceConfig(c); e != nil {
		t.Fatal(e)
	}
	if got, _, _, e := TryAcquire("builder", "new", "test", time.Hour, nil); got || e == nil {
		t.Fatal("disabled grant", got, e)
	}
	if !strings.Contains(ResourcesText(""), "DISABLED") {
		t.Fatal(ResourcesText(""))
	}
	if e := saveResourceConfig(ResourceConfig{Version: 1, Resources: []Resource{}}); e == nil {
		t.Fatal("deleted history-bearing name")
	}
	files, _ := filepath.Glob(filepath.Join(Root(), "config-history", "*.json"))
	if len(files) < 2 {
		t.Fatal("missing restoration records")
	}
}
func TestResourceConfigFailsClosed(t *testing.T) {
	resTestRoot(t)
	for _, input := range []string{`null`, `{"version":2,"resources":[]}`, `{"version":1,"resources":[],"typo":true}`, `{"version":1,"resources":[{"name":"../mac","description":"x","machine":"m"}]}`, `{"version":1,"resources":[{"name":"a","description":"x","machine":"m"},{"name":"b","description":"x","machine":"m"}]}`} {
		if _, e := decodeResourceConfig([]byte(input)); e == nil {
			t.Fatal("accepted invalid", input)
		}
	}
	os.WriteFile(resourceConfigPath(), []byte(`{"version":2,"resources":[{"name":"mac","description":"bad","machine":"x"}]}`), 0600)
	if got, _, _, e := TryAcquire("mac", "a", "test", time.Hour, nil); got || e == nil {
		t.Fatal("bad config granted", got, e)
	}
	if len(resourceList()) != 0 || !strings.Contains(ResourcesText(""), "CONFIGURATION ERROR") {
		t.Fatal("invalid config displayed resources")
	}
	if _, e := os.Stat(leasePath("mac")); !os.IsNotExist(e) {
		t.Fatal(e)
	}
}
func TestDiskAdmissionAndNoWeakening(t *testing.T) {
	resTestRoot(t)
	host, _ := os.Hostname()
	c := customConfig()
	c.Resources[0].Host = host
	c.Resources[0].DiskPath = t.TempDir()
	c.Resources[0].MinFreeGiB = 1e12
	if e := saveResourceConfig(c); e != nil {
		t.Fatal(e)
	}
	if got, _, _, e := TryAcquire("builder", "a", "test", time.Hour, nil); got || e == nil || !strings.Contains(e.Error(), "admission refused") {
		t.Fatal(got, e)
	}
	c.Resources[0].MinFreeGiB = 8
	if e := saveResourceConfig(c); e == nil {
		t.Fatal("weakened guard")
	}
	c.Resources[0].MinFreeGiB = 1e12
	c.Resources[0].DiskPath = "/another/path"
	if e := saveResourceConfig(c); e == nil {
		t.Fatal("redirected guard")
	}
}
func TestConfigUpdateWaitsForResourceTransaction(t *testing.T) {
	resTestRoot(t)
	unlock, e := resourceGuard("mac")
	if e != nil {
		t.Fatal(e)
	}
	done := make(chan error, 1)
	go func() { done <- saveResourceConfig(customConfig()) }()
	select {
	case e := <-done:
		unlock()
		t.Fatal("config raced transaction", e)
	case <-time.After(30 * time.Millisecond):
	}
	unlock()
	select {
	case e := <-done:
		if e != nil {
			t.Fatal(e)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("config lock stuck")
	}
	if _, ok := KnownResource("builder"); !ok {
		t.Fatal("new config not visible")
	}
}
func TestInitRefusesExistingStateAndApplyRequiresBoundary(t *testing.T) {
	resTestRoot(t)
	TryAcquire("mac", "a", "test", time.Hour, nil)
	if e := initializeResourceConfig(false); e == nil {
		t.Fatal("empty init hid existing resource")
	}
	if e := ResourceConfigCLI([]string{"migrate"}); e == nil {
		t.Fatal("missing client boundary accepted")
	}
}
