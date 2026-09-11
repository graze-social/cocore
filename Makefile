.PHONY: lex-validate lex-codegen lex-codegen-check \
        provider-build provider-test \
        sdk-test \
        appview-build appview-test \
        console-build console-test \
        exchange-build exchange-test \
        services-test \
        enclave-build shell-build \
        stack-up stack-down stack-smoke stack-logs \
        mac-installer mac-release mac-install mac-uninstall \
        register-cdhash \
        build test e2e clean

lex-validate:
	@for f in lexicons/dev/cocore/*/*.json; do \
		python3 -c "import json,sys; json.load(open('$$f'))" && echo "ok  $$f" || exit 1; \
	done

lex-codegen:
	node --experimental-strip-types scripts/lex-codegen.ts

# CI hook: re-run codegen, fail if the on-disk types.gen.ts no
# longer matches. Anyone editing a lexicon must rerun lex-codegen.
lex-codegen-check:
	node --experimental-strip-types scripts/lex-codegen.ts --check

provider-build:
	cd provider && cargo build

provider-test:
	cd provider && cargo test

sdk-test:
	cd packages/sdk && aube run test

appview-build:
	cd packages/appview && aube run build

appview-test:
	cd packages/appview && aube run test

console-build:
	cd packages/console && aube run build

console-test:
	cd packages/console && aube run test

exchange-build:
	cd packages/exchange && aube run build

exchange-test:
	cd packages/exchange && aube run test

services-test:
	cd infra/services && aube run test

# Swift packages: build only on macOS (Apple Silicon menu bar app +
# Secure Enclave FFI). On Linux these targets no-op so `make build`
# stays green in CI.
enclave-build:
	@if [ "$$(uname)" = "Darwin" ]; then cd provider/enclave && swift build -c release; \
	 else echo "skipping enclave-build (not macOS)"; fi

shell-build:
	@if [ "$$(uname)" = "Darwin" ]; then cd provider-shell && swift build; \
	 else echo "skipping shell-build (not macOS)"; fi

build: provider-build appview-build console-build exchange-build enclave-build shell-build

test: lex-validate provider-test sdk-test appview-test console-test exchange-test services-test

# Local docker-compose stack (cocore-services + console + mock provider).
# Requires a running Docker daemon. See infra/README.md for the
# `node`-only fallback if you don't have Docker.
stack-up:
	cd infra && docker compose up -d --build

stack-down:
	cd infra && docker compose down -v

stack-logs:
	cd infra && docker compose logs -f --tail=200

stack-smoke:
	node --experimental-strip-types infra/smoke.ts

# macOS provider installer.
#
# `make mac-install` runs the installer in-place against this checkout:
# preflight + cargo build --release + install to ~/.local/bin + pair +
# load LaunchAgent. Idempotent.
#
# `make mac-installer` produces a distributable tarball at
# dist/cocore-mac-arm64.tar.gz containing a prebuilt binary plus
# the install script + LaunchAgent plist template, so you can copy it
# to a fresh Mac Mini that doesn't have a checkout. Builds are gated
# to macOS hosts because we link Apple-only frameworks at release.
#
# `make mac-uninstall` reverses an in-place install.
mac-install:
	@if [ "$$(uname)" != "Darwin" ]; then \
	  echo "mac-install requires macOS; detected $$(uname)" >&2; exit 1; \
	fi
	./scripts/install-mac-provider.sh

mac-uninstall:
	@if [ "$$(uname)" != "Darwin" ]; then \
	  echo "mac-uninstall requires macOS; detected $$(uname)" >&2; exit 1; \
	fi
	./scripts/uninstall-mac-provider.sh

mac-installer:
	@if [ "$$(uname)" != "Darwin" ]; then \
	  echo "mac-installer requires macOS; detected $$(uname)" >&2; exit 1; \
	fi
	@echo "==> building release binary"
	cd provider && cargo build --release --locked
	@echo "==> staging dist/cocore-mac-arm64"
	rm -rf dist/cocore-mac-arm64
	mkdir -p dist/cocore-mac-arm64/bin dist/cocore-mac-arm64/scripts
	cp provider/target/release/cocore           dist/cocore-mac-arm64/bin/cocore
	cp scripts/install-mac-provider.sh          dist/cocore-mac-arm64/scripts/
	cp scripts/uninstall-mac-provider.sh        dist/cocore-mac-arm64/scripts/
	cp scripts/dev.cocore.provider.plist.template dist/cocore-mac-arm64/scripts/
	cp scripts/install-from-tarball.sh          dist/cocore-mac-arm64/install.sh
	chmod 755 dist/cocore-mac-arm64/install.sh
	@if [ -d provider-shell/build/cocore.app ]; then \
	  echo "==> bundling cocore.app (menu-bar app — the default experience)"; \
	  rm -rf dist/cocore-mac-arm64/cocore.app; \
	  cp -R provider-shell/build/cocore.app dist/cocore-mac-arm64/cocore.app; \
	else \
	  echo "==> note: no cocore.app to bundle — run 'make mac-release' (or scripts/build-mac-app.sh) to include the tray app"; \
	fi
	@echo "==> tar"
	tar -C dist -czf dist/cocore-mac-arm64.tar.gz cocore-mac-arm64
	@echo "==> built dist/cocore-mac-arm64.tar.gz"
	@ls -lh dist/cocore-mac-arm64.tar.gz

# `make mac-release` is the full distributable build: it builds + Developer-ID-
# signs the menu-bar app, notarizes + staples it (needs COCORE_NOTARY_PROFILE),
# then produces both the curl|sh installer tarball (with the app bundled) and a
# standalone cocore.app.zip. Upload both as GitHub release assets; the console's
# github-releases proxy serves the tarball to `curl …/agent | sh`.
mac-release:
	@if [ "$$(uname)" != "Darwin" ]; then \
	  echo "mac-release requires macOS; detected $$(uname)" >&2; exit 1; \
	fi
	@echo "==> build + Developer ID sign cocore.app"
	./scripts/build-mac-app.sh
	@if [ -n "$$COCORE_NOTARY_PROFILE" ]; then \
	  echo "==> notarize + staple"; \
	  ./scripts/notarize-mac-app.sh "$$COCORE_NOTARY_PROFILE"; \
	else \
	  echo "==> WARNING: COCORE_NOTARY_PROFILE unset — app is signed but NOT notarized (Gatekeeper will warn on other Macs)"; \
	fi
	@echo "==> standalone cocore.app.zip"
	mkdir -p dist; rm -f dist/cocore.app.zip
	/usr/bin/ditto -c -k --keepParent provider-shell/build/cocore.app dist/cocore.app.zip
	@$(MAKE) mac-installer
	@echo "==> SHA256SUMS (verifiable binary hashes)"
	@# Publish the hashes of the EXACT shipped binaries so a verifier can
	@# confirm a provider's attested `binaryHash` matches a known-good
	@# release. The app-embedded cocore is Developer-ID-signed (its bytes
	@# differ from the raw build); the tarball cocore is the raw build — so
	@# we publish BOTH. A provider's binaryHash matches one or the other
	@# depending on install type (app-supervised vs headless tarball).
	@rm -f dist/SHA256SUMS
	@cd dist && shasum -a 256 cocore.app.zip cocore-mac-arm64.tar.gz cocore-mac-arm64/bin/cocore >> SHA256SUMS
	@shasum -a 256 provider-shell/build/cocore.app/Contents/MacOS/cocore \
	  | awk '{print $$1 "  cocore.app/Contents/MacOS/cocore"}' >> dist/SHA256SUMS
	@echo "   dist/SHA256SUMS:"; cat dist/SHA256SUMS
	@echo "==> release artifacts:"
	@ls -lh dist/cocore.app.zip dist/cocore-mac-arm64.tar.gz dist/SHA256SUMS
	@# Surface (and optionally register) the confidential cdHash so the
	@# advisor's known-good set tracks this release. Print-only by default;
	@# set COCORE_AUTO_REGISTER_CDHASH=1 to push it to Railway automatically.
	@$(MAKE) register-cdhash

# The Developer-ID-signed confidential worker nested inside cocore.app. Its
# cdHash is what the confidential tier trusts (COCORE_KNOWN_GOOD_CDHASHES) —
# extracted from the LOCAL notarized build (CI only ad-hoc signs, so the CI
# cdHash is not the distributable one).
WORKER_BIN := provider-shell/build/cocore.app/Contents/CoCoreProvider.app/Contents/MacOS/cocore-provider

# `make register-cdhash` extracts the confidential worker's cdHash from the
# built app and registers it in the advisor's known-good set. Print-only unless
# COCORE_AUTO_REGISTER_CDHASH=1 (then it sets the Railway var + redeploys, only
# ever APPENDING — see scripts/register-known-good.sh). No-op for a build that
# didn't nest the confidential worker.
register-cdhash:
	@if [ ! -f "$(WORKER_BIN)" ]; then \
	  echo "==> no confidential worker at $(WORKER_BIN) — skipping cdHash registration (non-confidential build)"; \
	else \
	  echo "==> extract + register confidential cdHash"; \
	  mkdir -p dist; \
	  ./scripts/extract-cdhash.sh "$(WORKER_BIN)" | tee dist/cdhash.json >/dev/null; \
	  if [ "$$COCORE_AUTO_REGISTER_CDHASH" = "1" ]; then \
	    ./scripts/register-known-good.sh --apply dist/cdhash.json; \
	  else \
	    ./scripts/register-known-good.sh dist/cdhash.json; \
	    echo "   (COCORE_AUTO_REGISTER_CDHASH=1 make register-cdhash  → apply to Railway automatically)"; \
	  fi; \
	fi

e2e:
	@echo "M2: live pair flow"
	@cd packages/console && PORT=3001 aube exec vite dev --host 127.0.0.1 --port 3001 & \
	  pid=$$!; \
	  trap "kill $$pid" EXIT; \
	  for i in 1 2 3 4 5 6 7 8 9 10; do \
	    curl -sf http://localhost:3001/ > /dev/null && break; sleep 1; \
	  done; \
	  CONSOLE=http://localhost:3001 node --experimental-strip-types packages/console/scripts/e2e-pair.ts && \
	  cd provider && COCORE_CONSOLE_URL=http://localhost:3001 cargo test --test oauth_pair_live -- --ignored

clean:
	cd provider && cargo clean
	rm -rf node_modules
	rm -rf packages/sdk/node_modules
	rm -rf packages/appview/node_modules packages/appview/dist
	rm -rf packages/console/node_modules packages/console/.next packages/console/.output packages/console/dist packages/console/.tanstack
	rm -rf packages/exchange/node_modules packages/exchange/dist
	rm -rf infra/services/node_modules
	rm -rf infra/mock-provider/node_modules
	rm -rf provider/enclave/.build provider-shell/.build
