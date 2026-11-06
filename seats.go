package main

// A SEAT is a line identity that is not keyed by a checkout path.
//
// Path membership (members.json) answers "who works in this checkout" for
// runtimes whose hooks resolve identity by path, and for a human at the CLI.
// A path can only answer one way. So a second agent working in the SAME
// checkout -- a Codex reviewer opened beside a Claude session -- or an agent
// with no checkout of its own -- a Codex profile started anywhere -- cannot be
// a path member without evicting whoever already is.
//
// A seat's runtime configuration names it explicitly (--as/--line in its MCP
// arguments and hook commands), so nothing has to be inferred from where it
// runs. This file only records that the seat exists, so that it is a known
// recipient, its name cannot be claimed twice, and operators can see it.
//
// Seats live in their own file rather than inside members.json: a binary that
// predates seats rewrites members.json whole, and would silently drop them.

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
)

type Seat struct {
	Agent   string `json:"agent"`
	Runtime string `json:"runtime"`
	// Workdir is the checkout the seat shares, when it has one. It is where the
	// seat's config lives and what its revision stamps observe; it is NOT an
	// identity key, and the checkout's path member is unaffected by it.
	Workdir string `json:"workdir,omitempty"`
	// Profile names the Codex profile layer holding the seat's config, for a
	// seat that has no checkout and can be started from any directory.
	Profile string `json:"profile,omitempty"`
	Created string `json:"created"`
}

type Seats struct {
	Version int             `json:"version"`
	Seats   map[string]Seat `json:"seats"`
}

func seatsPath() string { return filepath.Join(Root(), "seats.json") }

// loadSeatsStrict fails closed on corruption; anything that writes uses it.
func loadSeatsStrict() (Seats, error) {
	s := Seats{Version: 1, Seats: map[string]Seat{}}
	if err := readState(seatsPath(), &s); err != nil {
		return s, err
	}
	if s.Version != 1 {
		return s, fmt.Errorf("%s: unsupported seats version %d", seatsPath(), s.Version)
	}
	if s.Seats == nil {
		s.Seats = map[string]Seat{}
	}
	return s, nil
}

// LoadSeats is for observers (rendering, recipient lists). A corrupt file
// shows no seats rather than breaking a view; writers use loadSeatsStrict.
func LoadSeats() Seats {
	s, err := loadSeatsStrict()
	if err != nil {
		return Seats{Version: 1, Seats: map[string]Seat{}}
	}
	return s
}

// saveSeats must be called while holding the members guard, which serialises
// every identity change on a line (names are unique across both files).
func saveSeats(s Seats) error {
	if err := EnsureRoot(); err != nil {
		return err
	}
	s.Version = 1
	if len(s.Seats) == 0 {
		if err := os.Remove(seatsPath()); err != nil && !os.IsNotExist(err) {
			return err
		}
		return nil
	}
	return writeState(seatsPath(), s)
}

// At lists the seats sharing a checkout, sorted.
func (s Seats) At(root string) []string {
	var out []string
	for name, seat := range s.Seats {
		if seat.Workdir != "" && seat.Workdir == root {
			out = append(out, name)
		}
	}
	sort.Strings(out)
	return out
}

// LineNames is everyone on the line: path members and seats. Use it wherever
// a recipient or participant list is needed; Members.Names() alone misses
// agents that do not own a checkout.
func LineNames() []string {
	seen := map[string]bool{}
	var out []string
	for _, n := range LoadMembers().Names() {
		if !seen[n] {
			seen[n] = true
			out = append(out, n)
		}
	}
	for n := range LoadSeats().Seats {
		if !seen[n] {
			seen[n] = true
			out = append(out, n)
		}
	}
	sort.Strings(out)
	return out
}

// seatDescription is a one-line, human-readable location for a seat.
func seatDescription(s Seat) string {
	switch {
	case s.Profile != "":
		return fmt.Sprintf("%s seat, profile %s (no checkout of its own)", s.Runtime, s.Profile)
	case s.Workdir != "":
		return fmt.Sprintf("%s seat sharing %s", s.Runtime, s.Workdir)
	}
	return s.Runtime + " seat"
}
