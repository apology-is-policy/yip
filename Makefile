# yip -- build, install, test.
#
# `install` is rm-then-copy, and that is not a style choice.
#
# MEASURED on macOS/arm64: overwriting this binary IN PLACE while a process is
# running from it can leave that path permanently SIGKILL-on-exec -- valid on
# disk, valid to `codesign -v`, dead at every exec, and it does NOT clear when
# the holder exits. 3 of 4 attempts poisoned the path that way; 0 of 2 did with
# rm-then-copy. (The likely cause is a stale per-vnode signature cache, but
# that is a conjecture. The measurement is the reason for this target's shape.)
#
# `go build -o $(BIN) .` is exactly the unsafe form, so no target here does it,
# and the README points at `make install` rather than at go build.
#
# The dangerous condition is the NORMAL one for anyone using yip over MCP:
# `yip serve` runs from the installed path for the whole session, so a rebuild
# onto that path always has a live holder.
#
# Not hypothetical -- it happened to a live agent mid-merge. The hook died with
# `Killed: 9`, nothing in the message named yip, and the peer lost its
# heartbeat, its Stop-block and its MCP server at once.

BIN ?= $(HOME)/.local/bin/yip
GO  ?= go

# The version is the tree, not a constant. `git describe --always --dirty`
# gives every build a distinct name (tag or short sha, "-dirty" if uncommitted),
# and `yip doctor` compares the WIRED binary's answer against its own, so a
# checkout still pointing at a stale install fails loudly instead of "ok".
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo unknown)
LDFLAGS  = -ldflags "-X main.serverVersion=$(VERSION)"

.PHONY: all build install uninstall test clean

all: build

build:
	$(GO) build $(LDFLAGS) -o yip .

install: build
	@mkdir -p $(dir $(BIN))
	rm -f $(BIN)
	cp yip $(BIN)
	@# Verify the INSTALLED path, not the build output. An exit >= 128 means a
	@# signal killed it -- the exact failure this target exists to prevent --
	@# and it must fail loudly rather than leave a dead hook behind. Any other
	@# exit code means the binary RAN, which is all that is being asked here.
	@$(BIN) whoami >/dev/null 2>&1; rc=$$?; \
	 if [ $$rc -ge 128 ]; then \
	   echo "FAIL: $(BIN) died with signal $$(($$rc - 128)) -- the install did not take"; \
	   exit 1; \
	 fi
	@echo "installed $(BIN) ($$($(BIN) version))"

test:
	$(GO) test ./...
	@# e2e.sh runs /tmp/yiptest. Building it HERE is not a convenience: without
	@# it the suite silently exercises whatever stale binary was left there,
	@# which is a green run that proves nothing about this tree.
	$(GO) build $(LDFLAGS) -o /tmp/yiptest .
	./e2e.sh

clean:
	rm -f yip
