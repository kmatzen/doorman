# Tier 1 packaging: build a release binary for the host platform and bundle
# it into a tar.gz alongside docs, the example config, and the appropriate
# service file (systemd unit on Linux, launchd plist on macOS).
#
# To produce both a Linux and a macOS artifact, run `make release` on each
# host. Cross-compilation is intentionally out of scope for tier 1.

VERSION    := $(shell awk -F'"' '/^version *= *"/ {print $$2; exit}' Cargo.toml)
TARGET     := $(shell rustc -vV | awk '/^host:/ {print $$2}')
INSTALL_AS := /usr/local/bin/doormand
NAME       := doorman-$(VERSION)-$(TARGET)
DIST       := dist/$(NAME)

.PHONY: release
release: clean-dist
	cargo build --release
	@mkdir -p $(DIST)
	cp target/release/doormand $(DIST)/
	-strip $(DIST)/doormand 2>/dev/null || true
	cp README.md plan.md $(DIST)/
	cp -r examples $(DIST)/
	@if echo "$(TARGET)" | grep -q darwin; then \
		sed "s|__BIN_PATH__|$(INSTALL_AS)|g" share/com.doorman.doormand.plist.in > $(DIST)/com.doorman.doormand.plist; \
	else \
		sed "s|__BIN_PATH__|$(INSTALL_AS)|g" share/doormand.service.in > $(DIST)/doormand.service; \
	fi
	cd dist && tar -czf $(NAME).tar.gz $(NAME)
	@echo
	@echo "Built dist/$(NAME).tar.gz"
	@ls -lh dist/$(NAME).tar.gz

.PHONY: clean-dist
clean-dist:
	rm -rf dist

.PHONY: clean
clean: clean-dist
	cargo clean
