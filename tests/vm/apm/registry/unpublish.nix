# Registry VM checks for unpublish workflows.
{
  testing,
  pkgs,
  fixtures,
  setupNixPublishEnv,
  closureLeafTool,
  closureRootTool,
  retireDepTool,
  retireTool,
  closureWorkflowDeps,
}: {
  # -------------------------------------------------------------------------
  # registry-unpublish — Selectively remove versions and platforms
  # -------------------------------------------------------------------------
  registry-unpublish = testing.mkVMTest {
    name = "apm-registry-unpublish";
    rootfsDeps =
      closureWorkflowDeps
      ++ [
        pkgs.iproute2
        pkgs.jq
        pkgs.python3
        pkgs.zstd
      ];
    memory = 1024;
    testScript = ''
      ${fixtures.setupPreamble}
      ${setupNixPublishEnv}

      echo "==> Test: selectively unpublish package versions and platforms"

      LEAF_STORE="${closureLeafTool}"
      ROOT_STORE="${closureRootTool}"
      RETIRE_DEP_STORE="${retireDepTool}"
      RETIRE_STORE="${retireTool}"
      RETIRE_DEP_HASH=$(basename "$RETIRE_DEP_STORE" | cut -d- -f1)
      RETIRE_HASH=$(basename "$RETIRE_STORE" | cut -d- -f1)
      MAINTAINER_HOME=/tmp
      CONSUMER_HOME=/tmp/unpublish-consumer
      PROFILE="/var/lib/profiles/per-user/unpublishuser"

      as_maintainer() {
        export HOME="$MAINTAINER_HOME"
        export USER=root
      }

      as_consumer() {
        export HOME="$CONSUMER_HOME"
        export USER=unpublishuser
        mkdir -p "$HOME"
      }

      assert_file_not_contains() {
        if grep -q "$2" "$1" 2>/dev/null; then
          fail "$3 (pattern '$2' unexpectedly found in $1)"
          cat "$1" 2>/dev/null || true
        else
          pass "$3"
        fi
      }

      assert_store_valid() {
        path="$1"
        label="$2"
        if nix-store --check-validity "$path" > "/tmp/unpublish-valid-$label.out" 2>&1; then
          pass "$label valid in store"
        else
          cat "/tmp/unpublish-valid-$label.out"
          fail "$label should be valid in store"
        fi
      }

      assert_store_missing() {
        path="$1"
        label="$2"
        if nix-store --check-validity "$path" > "/tmp/unpublish-missing-$label.out" 2>&1; then
          cat "/tmp/unpublish-missing-$label.out"
          fail "$label should be missing from store"
        else
          pass "$label missing from store"
        fi
      }

      delete_store_path() {
        path="$1"
        label="$2"
        if nix-store --delete --ignore-liveness "$path" > "/tmp/unpublish-delete-$label.out" 2>&1; then
          pass "$label deleted before apm download"
        else
          cat "/tmp/unpublish-delete-$label.out"
          fail "$label should be deletable before apm download"
          return 1
        fi
        assert_store_missing "$path" "$label"
      }

      wait_for_cache_server() {
        for _i in 1 2 3 4 5 6 7 8 9 10; do
          if curl -sf http://127.0.0.1:18109/nix-cache-info >/dev/null; then
            return 0
          fi
          sleep 1
        done
        return 1
      }

      # Create registry and publish a package
      as_maintainer
      $APR create test-reg
      REG_DIR="$REG_STORAGE/test-reg"
      DEFAULT_BRANCH=$(git -C "$REG_DIR" symbolic-ref --short HEAD)

      $APR publish "$LEAF_STORE" \
        --name removepkg \
        --version 1.0.0 \
        --platform x86_64-linux \
        --description "Published v1 for unpublish workflow" \
        --license MIT \
        --maintainer test \
        --registry test-reg
      $APR publish "$ROOT_STORE" \
        --name removepkg \
        --version 2.0.0 \
        --platform x86_64-linux \
        --previous 1.0.0 \
        --description "Published v2 for unpublish workflow" \
        --license MIT \
        --maintainer test \
        --registry test-reg
      $APR publish "$ROOT_STORE" \
        --name removepkg \
        --version 2.0.0 \
        --platform aarch64-linux \
        --previous 1.0.0 \
        --description "Published v2 for unpublish workflow" \
        --license MIT \
        --maintainer test \
        --registry test-reg
      $APR publish "$RETIRE_DEP_STORE" \
        --name retire-dep \
        --version 1.0.0 \
        --platform x86_64-linux \
        --description "Dependency that remains after retire-tool is unpublished" \
        --license MIT \
        --maintainer test \
        --registry test-reg
      $APR publish "$RETIRE_STORE" \
        --name retire-tool \
        --version 1.0.0 \
        --platform x86_64-linux \
        --description "Installed package retired by unpublish workflow" \
        --license MIT \
        --maintainer test \
        --registry test-reg

      # Verify package exists
      assert_file_exists "$REG_DIR/packages/r/removepkg.toml" \
        "package TOML exists before unpublish"
      assert_file_exists "$REG_DIR/packages/r/retire-tool.toml" \
        "consumer package TOML exists before unpublish"
      assert_file_contains "$REG_DIR/store/$(printf %.2s "$RETIRE_HASH")/$RETIRE_HASH" "$RETIRE_DEP_HASH" \
        "consumer package store record lists dependency edge"
      $APR show removepkg --registry test-reg --raw > /tmp/unpublish-before.toml 2>&1 || {
        cat /tmp/unpublish-before.toml
        fail "apr show --raw reports initial multi-version package"
      }
      assert_file_contains /tmp/unpublish-before.toml 'version = "1.0.0"' \
        "initial package contains v1"
      assert_file_contains /tmp/unpublish-before.toml 'version = "2.0.0"' \
        "initial package contains v2"
      assert_file_contains /tmp/unpublish-before.toml 'x86_64-linux' \
        "initial package contains x86_64 platform"
      assert_file_contains /tmp/unpublish-before.toml 'aarch64-linux' \
        "initial package contains aarch64 platform"
      $APR packages --registry test-reg --platform aarch64-linux \
        > /tmp/unpublish-packages-aarch64-before.out 2>&1 || {
        cat /tmp/unpublish-packages-aarch64-before.out
        fail "apr packages --platform sees aarch64 package before unpublish"
      }
      assert_file_contains /tmp/unpublish-packages-aarch64-before.out \
        "removepkg 2.0.0" \
        "aarch64 platform filter sees v2 before unpublish"

      $APR cache generate \
        --registry test-reg \
        --output /tmp/unpublish-cache \
        --cache-url http://127.0.0.1:18109 \
        --priority 53 \
        --no-commit > /tmp/unpublish-cache-generate.out 2>&1 || {
        cat /tmp/unpublish-cache-generate.out
        fail "apr cache generate writes consumer unpublish cache"
      }
      cat /tmp/unpublish-cache-generate.out
      assert_file_exists "/tmp/unpublish-cache/$RETIRE_HASH.narinfo" \
        "static cache has retire-tool narinfo"
      assert_file_exists "/tmp/unpublish-cache/$RETIRE_DEP_HASH.narinfo" \
        "static cache has retire-dep narinfo"
      git -C "$REG_DIR" add -A
      git -C "$REG_DIR" commit -m "registry: publish unpublish consumer cache"
      git init --bare --object-format=sha256 /tmp/unpublish-origin.git
      git -C "$REG_DIR" remote add origin /tmp/unpublish-origin.git
      git -C "$REG_DIR" push origin "$DEFAULT_BRANCH"

      ${pkgs.iproute2}/sbin/ip link set lo up || true
      ${pkgs.iproute2}/sbin/ip addr add 127.0.0.1/8 dev lo 2>/dev/null || true
      PYTHONUNBUFFERED=1 python3 -m http.server 18109 --bind 127.0.0.1 \
        --directory /tmp/unpublish-cache > /tmp/unpublish-cache-http.log 2>&1 &
      CACHE_PID=$!
      if wait_for_cache_server; then
        pass "static cache HTTP server started"
      else
        cat /tmp/unpublish-cache-http.log || true
        fail "static cache HTTP server started"
      fi

      echo "==> Consumer: install package before maintainer unpublishes it"
      as_consumer
      # The unpublish producer registry is unsigned (created without a trust
      # key); signed metadata is now required by default on sync, so opt this
      # consumer out of signature verification with --no-verify.
      $APM registry add file:///tmp/unpublish-origin.git \
        --name test-reg \
        --branch "$DEFAULT_BRANCH" \
        --no-verify > /tmp/unpublish-registry-add.out 2>&1 || {
        cat /tmp/unpublish-registry-add.out
        fail "apm registry add syncs unpublish registry"
      }
      cat /tmp/unpublish-registry-add.out
      delete_store_path "$RETIRE_STORE" "retire-tool"
      delete_store_path "$RETIRE_DEP_STORE" "retire-dep"
      rm -rf "$HOME/.cache/apm"
      mkdir -p "$HOME/.cache/apm"
      $APM install retire-tool --registry test-reg --yes \
        > /tmp/unpublish-install-retire-tool.out 2>&1 || {
        cat /tmp/unpublish-install-retire-tool.out
        fail "apm install downloads retire-tool before unpublish"
      }
      cat /tmp/unpublish-install-retire-tool.out
      assert_file_contains /tmp/unpublish-install-retire-tool.out "Downloading" \
        "apm install downloads retire-tool closure"
      assert_store_valid "$RETIRE_STORE" "retire-tool"
      assert_store_valid "$RETIRE_DEP_STORE" "retire-dep"
      "$PROFILE/current/bin/retire-tool" > /tmp/unpublish-retire-tool-run-before.out
      assert_file_contains /tmp/unpublish-retire-tool-run-before.out \
        "^retire-tool 1.0.0 via retire-dep 1.0.0$" \
        "installed retire-tool executable runs before unpublish"
      $APM list --installed > /tmp/unpublish-installed-before.out 2>&1 || {
        cat /tmp/unpublish-installed-before.out
        fail "apm list --installed sees retire-tool before unpublish"
      }
      assert_file_contains /tmp/unpublish-installed-before.out "retire-tool/test-reg 1.0.0" \
        "installed list reports retire-tool before unpublish"

      as_maintainer

      if $APR unpublish removepkg 9.9.9 --registry test-reg --no-commit \
        > /tmp/unpublish-missing-version.out 2>&1; then
        cat /tmp/unpublish-missing-version.out
        fail "apr unpublish should reject a missing version"
      else
        cat /tmp/unpublish-missing-version.out
        pass "apr unpublish rejects a missing version"
      fi
      assert_file_contains /tmp/unpublish-missing-version.out \
        "does not contain version '9.9.9'" \
        "missing-version unpublish error names requested version"

      if $APR unpublish removepkg 2.0.0 --platform riscv64-linux \
        --registry test-reg --no-commit > /tmp/unpublish-missing-platform.out 2>&1; then
        cat /tmp/unpublish-missing-platform.out
        fail "apr unpublish should reject a missing platform"
      else
        cat /tmp/unpublish-missing-platform.out
        pass "apr unpublish rejects a missing platform"
      fi
      assert_file_contains /tmp/unpublish-missing-platform.out \
        "version '2.0.0' does not contain platform 'riscv64-linux'" \
        "missing-platform unpublish error names requested platform"

      HEAD_BEFORE_NO_COMMIT=$(git -C "$REG_DIR" rev-parse HEAD)
      $APR --json unpublish removepkg 2.0.0 --platform aarch64-linux \
        --registry test-reg --no-commit > /tmp/unpublish-aarch64.json 2>&1 || {
        cat /tmp/unpublish-aarch64.json
        fail "apr unpublish --platform --no-commit removes one platform"
      }
      ${pkgs.jq}/bin/jq -e --arg head "$HEAD_BEFORE_NO_COMMIT" \
        '.action == "unpublish"
          and .registry == "test-reg"
          and .package == "removepkg"
          and .version == "2.0.0"
          and .platform == "aarch64-linux"
          and .status == "updated"
          and .package_file == "packages/r/removepkg.toml"
          and .package_file_removed == false
          and .committed == false
          and .commit_message == null
          and .current == "stable"
          and .head == $head' \
        /tmp/unpublish-aarch64.json >/dev/null || {
        cat /tmp/unpublish-aarch64.json
        fail "apr --json unpublish --no-commit reports staged platform removal"
      }
      pass "apr --json unpublish --no-commit reports staged platform removal"
      HEAD_AFTER_NO_COMMIT=$(git -C "$REG_DIR" rev-parse HEAD)
      if [ "$HEAD_BEFORE_NO_COMMIT" = "$HEAD_AFTER_NO_COMMIT" ]; then
        pass "apr unpublish --no-commit leaves HEAD unchanged"
      else
        fail "apr unpublish --no-commit should not create a commit"
      fi
      git -C "$REG_DIR" status --short --untracked-files=all \
        > /tmp/unpublish-status-after-no-commit.out
      assert_file_contains /tmp/unpublish-status-after-no-commit.out \
        "packages/r/removepkg.toml" \
        "apr unpublish --no-commit leaves package metadata dirty"

      $APR show removepkg --registry test-reg --version 2.0.0 --raw \
        > /tmp/unpublish-v2-after-aarch64.toml 2>&1 || {
        cat /tmp/unpublish-v2-after-aarch64.toml
        fail "apr show reports v2 after platform unpublish"
      }
      assert_file_contains /tmp/unpublish-v2-after-aarch64.toml 'x86_64-linux' \
        "v2 keeps x86_64 platform after aarch64 unpublish"
      assert_file_not_contains /tmp/unpublish-v2-after-aarch64.toml 'aarch64-linux' \
        "v2 drops aarch64 platform after unpublish"
      $APR packages --registry test-reg --platform aarch64-linux \
        > /tmp/unpublish-packages-aarch64-after.out 2>&1 || {
        cat /tmp/unpublish-packages-aarch64-after.out
        fail "apr packages --platform succeeds after aarch64 unpublish"
      }
      assert_file_not_contains /tmp/unpublish-packages-aarch64-after.out \
        "removepkg" \
        "aarch64 platform filter hides package after unpublish"

      $APR unpublish removepkg 1.0.0 \
        --registry test-reg \
        --message "registry: retire removepkg 1.0.0 and aarch64" \
        > /tmp/unpublish-v1.out 2>&1 || {
        cat /tmp/unpublish-v1.out
        fail "apr unpublish with custom message commits pending removals"
      }
      cat /tmp/unpublish-v1.out
      assert_file_contains /tmp/unpublish-v1.out \
        "registry: retire removepkg 1.0.0 and aarch64" \
        "apr unpublish reports custom commit message"
      git -C "$REG_DIR" log --oneline -1 > /tmp/unpublish-custom-log.out
      assert_file_contains /tmp/unpublish-custom-log.out \
        "registry: retire removepkg 1.0.0 and aarch64" \
        "git log records custom unpublish message"

      if $APR show removepkg --registry test-reg --version 1.0.0 \
        > /tmp/unpublish-show-v1.out 2>&1; then
        cat /tmp/unpublish-show-v1.out
        fail "apr show should not find unpublished v1"
      else
        cat /tmp/unpublish-show-v1.out
        pass "apr show rejects unpublished v1"
      fi
      assert_file_contains /tmp/unpublish-show-v1.out \
        "does not contain version '1.0.0'" \
        "apr show reports v1 was removed"
      $APR show removepkg --registry test-reg --version 2.0.0 \
        > /tmp/unpublish-show-v2.out 2>&1 || {
        cat /tmp/unpublish-show-v2.out
        fail "apr show still finds remaining v2"
      }
      assert_file_contains /tmp/unpublish-show-v2.out "Version: 2.0.0" \
        "apr show reports remaining v2"

      $APR --json unpublish removepkg 2.0.0 --platform x86_64-linux \
        --registry test-reg \
        --message "registry: remove final removepkg platform" \
        > /tmp/unpublish-final-platform.json 2>&1 || {
        cat /tmp/unpublish-final-platform.json
        fail "apr unpublish removes final platform and package file"
      }
      ${pkgs.jq}/bin/jq -e \
        '.action == "unpublish"
          and .registry == "test-reg"
          and .package == "removepkg"
          and .version == "2.0.0"
          and .platform == "x86_64-linux"
          and .status == "removed"
          and .package_file == "packages/r/removepkg.toml"
          and .package_file_removed == true
          and .committed == true
          and .commit_message == "registry: remove final removepkg platform"
          and .current == "stable"
          and (.head | length == 64)' \
        /tmp/unpublish-final-platform.json >/dev/null || {
        cat /tmp/unpublish-final-platform.json
        fail "apr --json unpublish reports committed final platform removal"
      }
      pass "apr --json unpublish reports committed final platform removal"

      # Verify TOML file removed
      assert_file_not_exists "$REG_DIR/packages/r/removepkg.toml" \
        "package TOML removed after final platform unpublish"
      $APR unpublish retire-tool \
        --registry test-reg \
        --message "registry: retire installed consumer package" \
        > /tmp/unpublish-retire-tool.out 2>&1 || {
        cat /tmp/unpublish-retire-tool.out
        fail "apr unpublish removes installed consumer package from registry"
      }
      cat /tmp/unpublish-retire-tool.out
      assert_file_not_exists "$REG_DIR/packages/r/retire-tool.toml" \
        "consumer package TOML removed by unpublish"
      git -C "$REG_DIR" rm -f "store/$(printf %.2s "$RETIRE_HASH")/$RETIRE_HASH" \
        > /tmp/unpublish-retire-tool-closure-rm.out 2>&1 || {
        cat /tmp/unpublish-retire-tool-closure-rm.out
        fail "maintainer prunes retired package store record"
      }
      git -C "$REG_DIR" commit -m "registry: prune retired consumer closure" \
        > /tmp/unpublish-retire-tool-closure-commit.out 2>&1 || {
        cat /tmp/unpublish-retire-tool-closure-commit.out
        fail "maintainer commits retired package closure pruning"
      }
      assert_file_not_exists "$REG_DIR/store/$(printf %.2s "$RETIRE_HASH")/$RETIRE_HASH" \
        "retired package store record pruned"
      $APR packages --registry test-reg > /tmp/unpublish-packages-final.out 2>&1 || {
        cat /tmp/unpublish-packages-final.out
        fail "apr packages succeeds after final unpublish"
      }
      assert_file_not_contains /tmp/unpublish-packages-final.out "removepkg" \
        "apr packages hides fully unpublished package"
      assert_file_not_contains /tmp/unpublish-packages-final.out "retire-tool" \
        "apr packages hides retired consumer package"
      assert_file_contains /tmp/unpublish-packages-final.out "retire-dep" \
        "apr packages keeps dependency that remains published"

      # Verify git log shows removal commit
      cd "$REG_DIR"
      assert_cmd_output_contains "git log --oneline -2" \
        "registry: retire installed consumer package" \
        "git log shows consumer package retirement commit"
      cd /tmp
      $APR verify --registry test-reg > /tmp/unpublish-verify-final.out 2>&1 || {
        cat /tmp/unpublish-verify-final.out
        fail "apr verify accepts registry after unpublish workflow"
      }
      assert_file_contains /tmp/unpublish-verify-final.out "no errors" \
        "apr verify reports no errors after unpublish workflow"

      git -C "$REG_DIR" push origin "$DEFAULT_BRANCH"

      echo "==> Consumer: update after maintainer unpublishes installed package"
      as_consumer
      $APM update --registry test-reg > /tmp/unpublish-consumer-update.out 2>&1 || {
        cat /tmp/unpublish-consumer-update.out
        fail "apm update syncs unpublish changeset"
      }
      cat /tmp/unpublish-consumer-update.out
      assert_file_contains /tmp/unpublish-consumer-update.out "removed" \
        "apm update reports package metadata removal"
      $APM list --installed > /tmp/unpublish-installed-after.out 2>&1 || {
        cat /tmp/unpublish-installed-after.out
        fail "apm list --installed succeeds after installed package is unpublished"
      }
      cat /tmp/unpublish-installed-after.out
      assert_file_contains /tmp/unpublish-installed-after.out "retire-tool/test-reg 1.0.0" \
        "installed list keeps installed package after registry unpublish"
      assert_file_contains /tmp/unpublish-installed-after.out "unavailable" \
        "installed list marks unpublished installed package unavailable"
      $APM search retire-tool --registry test-reg --names-only \
        > /tmp/unpublish-search-after.out 2>&1 || {
        cat /tmp/unpublish-search-after.out
        fail "apm search succeeds after package is unpublished"
      }
      assert_file_not_contains /tmp/unpublish-search-after.out "retire-tool" \
        "default search hides package after registry unpublish"
      $APM search retire-tool --installed > /tmp/unpublish-search-installed-after.out 2>&1 || {
        cat /tmp/unpublish-search-installed-after.out
        fail "apm search --installed succeeds after package is unpublished"
      }
      cat /tmp/unpublish-search-installed-after.out
      assert_file_contains /tmp/unpublish-search-installed-after.out \
        "retire-tool/test-reg 1.0.0" \
        "installed search keeps installed package after registry unpublish"
      assert_file_contains /tmp/unpublish-search-installed-after.out "unavailable" \
        "installed search marks unpublished package unavailable"
      $APM --json search retire-tool --installed \
        > /tmp/unpublish-search-installed-after.json || {
        cat /tmp/unpublish-search-installed-after.json
        fail "apm --json search --installed succeeds after package is unpublished"
      }
      assert_file_contains /tmp/unpublish-search-installed-after.json "retire-tool" \
        "installed search JSON keeps unpublished package"
      assert_file_contains /tmp/unpublish-search-installed-after.json "unavailable" \
        "installed search JSON marks unpublished package unavailable"
      $APM policy retire-tool > /tmp/unpublish-policy-after.out 2>&1 || {
        cat /tmp/unpublish-policy-after.out
        fail "apm policy succeeds after installed package is unpublished"
      }
      cat /tmp/unpublish-policy-after.out
      assert_file_contains /tmp/unpublish-policy-after.out "Installed: 1.0.0" \
        "policy reports installed version after registry unpublish"
      assert_file_contains /tmp/unpublish-policy-after.out "Candidate: (none)" \
        "policy reports no candidate after registry unpublish"
      assert_file_contains /tmp/unpublish-policy-after.out "test-reg (installed, unavailable)" \
        "policy marks unpublished installed version unavailable"
      $APM show retire-tool > /tmp/unpublish-show-installed-after.out 2>&1 || {
        cat /tmp/unpublish-show-installed-after.out
        fail "apm show succeeds from installed metadata after registry unpublish"
      }
      cat /tmp/unpublish-show-installed-after.out
      assert_file_contains /tmp/unpublish-show-installed-after.out "Package: retire-tool" \
        "show reports unpublished installed package name"
      assert_file_contains /tmp/unpublish-show-installed-after.out "Version: 1.0.0" \
        "show reports unpublished installed package version"
      assert_file_contains /tmp/unpublish-show-installed-after.out \
        "Status: installed, unavailable in registry" \
        "show marks unpublished installed package unavailable"
      assert_file_contains /tmp/unpublish-show-installed-after.out "Dependencies:.*retire-dep" \
        "show resolves installed dependency after registry unpublish"
      $APM --json show retire-tool > /tmp/unpublish-show-installed-after.json || {
        cat /tmp/unpublish-show-installed-after.json
        fail "apm --json show succeeds from installed metadata after registry unpublish"
      }
      assert_file_contains /tmp/unpublish-show-installed-after.json '"name":"retire-tool"' \
        "show JSON reports unpublished installed package name"
      assert_file_contains /tmp/unpublish-show-installed-after.json '"unavailable":true' \
        "show JSON marks unpublished installed package unavailable"
      assert_file_contains /tmp/unpublish-show-installed-after.json '"retire-dep"' \
        "show JSON resolves installed dependency after registry unpublish"
      $APM depends retire-tool > /tmp/unpublish-depends-after.out 2>&1 || {
        cat /tmp/unpublish-depends-after.out
        fail "apm depends succeeds from installed closure after registry unpublish"
      }
      cat /tmp/unpublish-depends-after.out
      assert_file_contains /tmp/unpublish-depends-after.out "retire-tool (1.0.0)" \
        "depends reports unpublished installed package root"
      assert_file_contains /tmp/unpublish-depends-after.out "retire-dep (1.0.0)" \
        "depends resolves installed dependency after registry unpublish"
      assert_file_contains /tmp/unpublish-depends-after.out \
        "unique store paths in installed dependency tree" \
        "depends reports installed dependency tree summary"
      $APM rdepends retire-dep > /tmp/unpublish-rdepends-after.out 2>&1 || {
        cat /tmp/unpublish-rdepends-after.out
        fail "apm rdepends succeeds from installed closure after dependency metadata prune"
      }
      cat /tmp/unpublish-rdepends-after.out
      assert_file_contains /tmp/unpublish-rdepends-after.out \
        "retire-dep (1.0.0) is required by:" \
        "rdepends reports dependents for retained dependency"
      assert_file_contains /tmp/unpublish-rdepends-after.out "retire-tool (1.0.0)" \
        "rdepends finds unpublished installed dependent via local store closure"
      "$PROFILE/current/bin/retire-tool" > /tmp/unpublish-retire-tool-run-after.out
      assert_file_contains /tmp/unpublish-retire-tool-run-after.out \
        "^retire-tool 1.0.0 via retire-dep 1.0.0$" \
        "installed retire-tool executable still runs after registry unpublish"
      if $APM verify retire-tool > /tmp/unpublish-retire-tool-verify.out 2>&1; then
        cat /tmp/unpublish-retire-tool-verify.out
        fail "apm verify should fail once installed package is unpublished"
      else
        cat /tmp/unpublish-retire-tool-verify.out
        pass "apm verify fails for unpublished installed package"
      fi
      assert_file_contains /tmp/unpublish-retire-tool-verify.out \
        "not present in registry 'test-reg'" \
        "verify error explains installed package is absent from registry"
      $APM upgrade retire-tool --yes > /tmp/unpublish-retire-tool-upgrade.out 2>&1 || {
        cat /tmp/unpublish-retire-tool-upgrade.out
        fail "apm upgrade handles unpublished installed package"
      }
      assert_file_contains /tmp/unpublish-retire-tool-upgrade.out \
        "All packages are up to date" \
        "upgrade does not invent a candidate for unpublished installed package"

      $APM remove retire-tool --autoremove --yes > /tmp/unpublish-remove-retired.out 2>&1 || {
        cat /tmp/unpublish-remove-retired.out
        fail "apm remove --autoremove removes unpublished installed package"
      }
      cat /tmp/unpublish-remove-retired.out
      assert_file_contains /tmp/unpublish-remove-retired.out "retire-tool" \
        "remove lists retired explicit package"
      assert_file_contains /tmp/unpublish-remove-retired.out "retire-dep" \
        "autoremove lists retired package dependency"
      assert_file_contains /tmp/unpublish-remove-retired.out "Removed 2 package" \
        "remove reports retired package and orphan removal"
      assert_file_not_exists "$PROFILE/meta/$RETIRE_HASH.json" \
        "remove deletes retired package metadata"
      assert_file_not_exists "$PROFILE/meta/$RETIRE_DEP_HASH.json" \
        "autoremove deletes retired dependency metadata"
      if [ -e "$PROFILE/current/bin/retire-tool" ]; then
        fail "retired package executable should be absent after remove"
      else
        pass "retired package executable absent after remove"
      fi
      $APM list --installed > /tmp/unpublish-installed-after-remove.out 2>&1 || {
        cat /tmp/unpublish-installed-after-remove.out
        fail "apm list --installed succeeds after retired package removal"
      }
      assert_file_not_contains /tmp/unpublish-installed-after-remove.out "retire-tool" \
        "installed list omits retired package after remove"
      assert_file_not_contains /tmp/unpublish-installed-after-remove.out "retire-dep" \
        "installed list omits retired dependency after autoremove"

      $APM rollback > /tmp/unpublish-rollback-after-remove.out 2>&1 || {
        cat /tmp/unpublish-rollback-after-remove.out
        fail "apm rollback restores retired package generation"
      }
      cat /tmp/unpublish-rollback-after-remove.out
      assert_file_contains /tmp/unpublish-rollback-after-remove.out "Rolled back to generation 1" \
        "rollback returns to retired package generation"
      "$PROFILE/current/bin/retire-tool" > /tmp/unpublish-retire-tool-run-rollback.out
      assert_file_contains /tmp/unpublish-retire-tool-run-rollback.out \
        "^retire-tool 1.0.0 via retire-dep 1.0.0$" \
        "rolled-back retired package executable runs"
      assert_file_exists "$PROFILE/meta/$RETIRE_HASH.json" \
        "rollback restores retired package metadata snapshot"
      assert_file_exists "$PROFILE/meta/$RETIRE_DEP_HASH.json" \
        "rollback restores retired dependency metadata snapshot"
      $APM list --installed > /tmp/unpublish-installed-after-rollback.out 2>&1 || {
        cat /tmp/unpublish-installed-after-rollback.out
        fail "apm list --installed succeeds after retired package rollback"
      }
      cat /tmp/unpublish-installed-after-rollback.out
      assert_file_contains /tmp/unpublish-installed-after-rollback.out "retire-tool/test-reg 1.0.0" \
        "installed list sees retired package after rollback"
      assert_file_contains /tmp/unpublish-installed-after-rollback.out "retire-dep/test-reg 1.0.0" \
        "installed list sees retired dependency after rollback"
      assert_file_contains /tmp/unpublish-installed-after-rollback.out "unavailable" \
        "installed list keeps retired package unavailable after rollback"
      $APM show retire-tool > /tmp/unpublish-show-after-rollback.out 2>&1 || {
        cat /tmp/unpublish-show-after-rollback.out
        fail "apm show works after rolling back retired package"
      }
      assert_file_contains /tmp/unpublish-show-after-rollback.out \
        "Status: installed, unavailable in registry" \
        "show uses restored retired metadata after rollback"

      if kill "$CACHE_PID" 2>/dev/null; then
        pass "static cache HTTP server stopped"
      fi
      wait "$CACHE_PID" 2>/dev/null || true

      check_fail
    '';
  };
}
