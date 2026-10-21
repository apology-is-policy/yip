package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

// Configuration contains definitions, never ownership or queue state.
type ResourceConfig struct {
	Version   int        `json:"version"`
	Resources []Resource `json:"resources"`
}

func resourceConfigPath() string { return filepath.Join(Root(), "resources.json") }
func decodeResourceConfig(data []byte) (ResourceConfig, error) {
	var c ResourceConfig
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&c); err != nil {
		return c, err
	}
	if err := dec.Decode(new(any)); err != io.EOF {
		return c, fmt.Errorf("configuration must contain exactly one JSON object")
	}
	return c, validateResourceConfig(c)
}
func validateResourceConfig(c ResourceConfig) error {
	if c.Version != 1 || c.Resources == nil {
		return fmt.Errorf("require version 1 and a resources array (empty is allowed)")
	}
	names, machines := map[string]bool{}, map[string]bool{}
	for _, r := range c.Resources {
		if !validComponent(r.Name) || strings.ToLower(r.Name) != r.Name || names[r.Name] {
			return fmt.Errorf("invalid or duplicate resource name %q (use lowercase safe names)", r.Name)
		}
		names[r.Name] = true
		if strings.TrimSpace(r.Desc) == "" || strings.TrimSpace(r.Machine) == "" {
			return fmt.Errorf("%s needs description and machine identity", r.Name)
		}
		if machines[r.Machine] {
			return fmt.Errorf("machine %q has multiple resource names; use one contention class", r.Machine)
		}
		machines[r.Machine] = true
		if r.MinFreeGiB < 0 || math.IsNaN(r.MinFreeGiB) || math.IsInf(r.MinFreeGiB, 0) {
			return fmt.Errorf("invalid disk floor for %s", r.Name)
		}
		if (r.MinFreeGiB > 0) != (r.DiskPath != "") {
			return fmt.Errorf("%s needs both min_free_gib and disk_path", r.Name)
		}
		if r.DiskPath != "" && (!filepath.IsAbs(r.DiskPath) || r.Host == "") {
			return fmt.Errorf("%s disk guard requires absolute disk_path and exact host name", r.Name)
		}
	}
	return nil
}
func LoadResourceConfig() (ResourceConfig, error) {
	data, e := os.ReadFile(resourceConfigPath())
	if os.IsNotExist(e) {
		return ResourceConfig{Version: 1, Resources: append([]Resource{}, legacyResources...)}, nil
	}
	if e != nil {
		return ResourceConfig{}, e
	}
	c, e := decodeResourceConfig(data)
	if e != nil {
		return c, fmt.Errorf("resource configuration: %w", e)
	}
	return c, nil
}
func resourceList() []Resource {
	c, e := LoadResourceConfig()
	if e != nil {
		return nil
	}
	return c.Resources
}

// Config edits take EX, resource operations SH, always before a resource lock.
// An old client does not participate: operators must restart clients at migration.
func registryGuard(exclusive bool) (func(), error) {
	if e := os.MkdirAll(Root(), 0700); e != nil {
		return nil, e
	}
	f, e := os.OpenFile(resourceConfigPath()+".lock", os.O_CREATE|os.O_RDWR, 0600)
	if e != nil {
		return nil, e
	}
	mode := syscall.LOCK_SH
	if exclusive {
		mode = syscall.LOCK_EX
	}
	if e = syscall.Flock(int(f.Fd()), mode); e != nil {
		f.Close()
		return nil, e
	}
	return func() { _ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN); _ = f.Close() }, nil
}
func resourceHasState(name string, activeOnly bool) (bool, error) {
	paths := []string{leasePath(name), queueDir(name)}
	if !activeOnly {
		paths = append(paths, filepath.Join(resourcesDir(), name+".history"), filepath.Join(resourcesDir(), name+".events"))
	}
	for _, path := range paths {
		st, e := os.Stat(path)
		if os.IsNotExist(e) {
			continue
		}
		if e != nil {
			return false, e
		}
		if !st.IsDir() {
			return true, nil
		}
		entries, e := os.ReadDir(path)
		if e != nil {
			return false, e
		}
		for _, entry := range entries {
			if entry.Name() == ".tmp" && entry.IsDir() {
				staged, err := os.ReadDir(filepath.Join(path, ".tmp"))
				if err != nil {
					return false, err
				}
				if len(staged) == 0 {
					continue
				}
			}
			return true, nil
		}
	}
	return false, nil
}
func validateConfigTransition(old, next ResourceConfig) error {
	proposed := map[string]Resource{}
	for _, r := range next.Resources {
		proposed[r.Name] = r
	}
	for _, r := range old.Resources {
		n, exists := proposed[r.Name]
		if !exists {
			used, e := resourceHasState(r.Name, false)
			if e != nil {
				return e
			}
			if used {
				return fmt.Errorf("%s has recorded state; retain its name (disable it after leases/queues clear)", r.Name)
			}
			continue
		}
		if n.MinFreeGiB < r.MinFreeGiB || (r.DiskPath != "" && (n.DiskPath != r.DiskPath || n.Host != r.Host)) {
			return fmt.Errorf("refusing to weaken or redirect %s disk guard", r.Name)
		}
		structural := r.Machine != n.Machine || r.Host != n.Host || r.DiskPath != n.DiskPath || r.MinFreeGiB != n.MinFreeGiB || r.Disabled != n.Disabled
		if structural {
			used, e := resourceHasState(r.Name, true)
			if e != nil {
				return e
			}
			if used {
				return fmt.Errorf("%s has a lease or queued request; only its description may change", r.Name)
			}
			used, e = resourceHasState(r.Name, false)
			if e != nil {
				return e
			}
			if used && r.Machine != n.Machine {
				return fmt.Errorf("%s has historical state; its machine identity is immutable", r.Name)
			}
		}
	}
	// Never silently adopt state belonging to an unknown/removed historical name.
	prior := map[string]bool{}
	for _, r := range old.Resources {
		prior[r.Name] = true
	}
	for _, r := range next.Resources {
		if !prior[r.Name] {
			used, e := resourceHasState(r.Name, false)
			if e != nil {
				return e
			}
			if used {
				return fmt.Errorf("%s already has unregistered state; restore its previous definition", r.Name)
			}
		}
	}
	return nil
}
func saveResourceConfig(next ResourceConfig) error {
	if e := validateResourceConfig(next); e != nil {
		return e
	}
	unlock, e := registryGuard(true)
	if e != nil {
		return e
	}
	defer unlock()
	old, e := LoadResourceConfig()
	if e != nil {
		return e
	}
	if e = validateConfigTransition(old, next); e != nil {
		return e
	}
	// Immutable before/after record is also a restoration source for implicit
	// legacy config. Creating evidence must succeed before the active rename.
	record := struct {
		At     string         `json:"at"`
		Before ResourceConfig `json:"before"`
		After  ResourceConfig `json:"after"`
	}{now(), old, next}
	path := filepath.Join(Root(), "config-history", requestID()+".json")
	if e = writeState(path, record); e != nil {
		return e
	}
	return writeState(resourceConfigPath(), next)
}
func initializeResourceConfig(migrate bool) error {
	unlock, e := registryGuard(true)
	if e != nil {
		return e
	}
	defer unlock()
	if _, e = os.Stat(resourceConfigPath()); e == nil {
		return fmt.Errorf("configuration already exists; use show/validate/apply")
	} else if !os.IsNotExist(e) {
		return e
	}
	c := ResourceConfig{Version: 1, Resources: []Resource{}}
	if migrate {
		c.Resources = append(c.Resources, legacyResources...)
	} else {
		entries, e := os.ReadDir(resourcesDir())
		if e != nil && !os.IsNotExist(e) {
			return e
		}
		if len(entries) > 0 {
			return fmt.Errorf("resource state exists; use config migrate to preserve legacy definitions")
		}
	}
	return writeState(resourceConfigPath(), c)
}
func checkResourceAdmission(name string) error {
	r, ok := KnownResource(name)
	if !ok {
		return fmt.Errorf("unknown resource %q", name)
	}
	if r.Disabled {
		return fmt.Errorf("resource %s is disabled", name)
	}
	if r.MinFreeGiB == 0 {
		return nil
	}
	host, e := os.Hostname()
	if e != nil {
		return e
	}
	if r.Host != host {
		return fmt.Errorf("%s disk admission requires host %q; this host is %q", name, r.Host, host)
	}
	var st syscall.Statfs_t
	if e = syscall.Statfs(r.DiskPath, &st); e != nil {
		return fmt.Errorf("disk admission unknown: %w", e)
	}
	free := float64(st.Bavail) * float64(st.Bsize) / (1 << 30)
	if free < r.MinFreeGiB {
		return fmt.Errorf("%s admission refused: %.2f GiB free, %.2f GiB required at %s", name, free, r.MinFreeGiB, r.DiskPath)
	}
	return nil
}
func ResourceConfigCLI(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("config show | validate FILE | init --clients-restarted | migrate --clients-restarted | apply FILE --clients-restarted")
	}
	switch args[0] {
	case "show":
		if len(args) != 1 {
			return fmt.Errorf("show takes no arguments")
		}
		c, e := LoadResourceConfig()
		if e != nil {
			return e
		}
		b, _ := json.MarshalIndent(c, "", "  ")
		fmt.Println(string(b))
		return nil
	case "validate":
		if len(args) != 2 {
			return fmt.Errorf("validate FILE")
		}
		b, e := os.ReadFile(args[1])
		if e != nil {
			return e
		}
		_, e = decodeResourceConfig(b)
		if e == nil {
			fmt.Println("valid schema; apply also checks current leases, queues and history")
		}
		return e
	case "init", "migrate":
		if len(args) != 2 || args[1] != "--clients-restarted" {
			return fmt.Errorf("restart all line clients first, then use %s --clients-restarted", args[0])
		}
		return initializeResourceConfig(args[0] == "migrate")
	case "apply":
		if len(args) != 3 || args[2] != "--clients-restarted" {
			return fmt.Errorf("apply FILE --clients-restarted (all line clients must support resource config)")
		}
		b, e := os.ReadFile(args[1])
		if e != nil {
			return e
		}
		c, e := decodeResourceConfig(b)
		if e != nil {
			return e
		}
		return saveResourceConfig(c)
	}
	return fmt.Errorf("unknown config command")
}
