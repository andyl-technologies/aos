# Packages VM checks for rollback workflows.
{
  testing,
  pkgs,
  fixtures,
  rollbackToolV1,
  rollbackToolV2,
  rollbackToolV3,
  realRollbackDeps,
  setupNixEnv,
}: {
  # -------------------------------------------------------------------------
  # 11. rollback-package — Roll back to previous generation
  # -------------------------------------------------------------------------
  rollback-package = testing.mkVMTest {
    name = "apm-rollback-package";
    rootfsDeps = realRollbackDeps;
    memory = 1024;
    testScript = ''
      ${fixtures.setupPreamble}
      ${setupNixEnv}

      echo "==> Test: real apm rollback generation workflow"

      ROLLBACK_V1_STORE="${rollbackToolV1}"
      ROLLBACK_V2_STORE="${rollbackToolV2}"
      ROLLBACK_V3_STORE="${rollbackToolV3}"
      ROLLBACK_V1_HASH=$(basename "$ROLLBACK_V1_STORE" | cut -d- -f1)
      ROLLBACK_V2_HASH=$(basename "$ROLLBACK_V2_STORE" | cut -d- -f1)
      ROLLBACK_V3_HASH=$(basename "$ROLLBACK_V3_STORE" | cut -d- -f1)
      PROFILE="/var/lib/profiles/per-user/rollbackuser"
      JQ="${pkgs.jq}/bin/jq"
      PROFILE_BIN="$PROFILE/current/bin/rollback-tool"

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
        if nix-store --check-validity "$path" > "/tmp/rollback-valid-$label.out" 2>&1; then
          pass "$label valid in store"
        else
          cat "/tmp/rollback-valid-$label.out"
          fail "$label should be valid in store"
        fi
      }

      assert_store_missing() {
        path="$1"
        label="$2"
        if nix-store --check-validity "$path" > "/tmp/rollback-missing-$label.out" 2>&1; then
          cat "/tmp/rollback-missing-$label.out"
          fail "$label should be missing from store"
        else
          pass "$label missing from store"
        fi
      }

      delete_store_path() {
        path="$1"
        label="$2"
        if nix-store --delete --ignore-liveness "$path" > "/tmp/rollback-delete-$label.out" 2>&1; then
          pass "$label deleted before apm download"
        else
          cat "/tmp/rollback-delete-$label.out"
          fail "$label should be deletable before apm download"
          return 1
        fi
        assert_store_missing "$path" "$label"
      }

      assert_current_generation() {
        expected="$1"
        label="$2"
        current=$(readlink "$PROFILE/current")
        if [ "$current" = "gen-$expected" ]; then
          pass "$label"
        else
          fail "$label (current=$current)"
        fi
      }

      assert_generation_exists() {
        generation="$1"
        label="$2"
        if [ -d "$PROFILE/gen-$generation" ]; then
          pass "$label"
        else
          fail "$label (missing $PROFILE/gen-$generation)"
        fi
      }

      assert_generation_missing() {
        generation="$1"
        label="$2"
        if [ ! -e "$PROFILE/gen-$generation" ]; then
          pass "$label"
        else
          fail "$label ($PROFILE/gen-$generation should be pruned)"
        fi
      }

      assert_current_tool_version() {
        version="$1"
        "$PROFILE_BIN" > "/tmp/rollback-run-$version.out"
        assert_file_contains "/tmp/rollback-run-$version.out" \
          "^rollback-tool $version$" "profile executable runs rollback-tool $version"
      }

      assert_list_marks_current() {
        generation="$1"
        file="$2"
        if grep -q "gen-$generation: .*rollback-tool .* (current)" "$file"; then
          pass "rollback list marks generation $generation current"
        else
          cat "$file"
          fail "rollback list should mark generation $generation current"
        fi
      }

      wait_for_cache_server() {
        for _i in 1 2 3 4 5 6 7 8 9 10; do
          if curl -sf http://127.0.0.1:18104/nix-cache-info >/dev/null; then
            return 0
          fi
          sleep 1
        done
        return 1
      }

      publish_rollback_tool() {
        version="$1"
        store="$2"
        $APR publish "$store" \
          --name rollback-tool \
          --version "$version" \
          --description "Executable rollback workflow fixture" \
          --license MIT \
          --maintainer rollback-workflow@example.invalid \
          --registry rollback-reg \
          --no-commit
      }

      generate_cache() {
        $APR cache generate \
          --registry rollback-reg \
          --output /tmp/rollback-cache \
          --cache-url http://127.0.0.1:18104 \
          --priority 44 \
          --no-commit
      }

      commit_and_push() {
        message="$1"
        git -C "$REG_DIR" add -A
        git -C "$REG_DIR" commit -m "$message"
        git -C "$REG_DIR" push origin "$DEFAULT_BRANCH"
      }

      mount -o remount,rw / || true
      assert_store_valid "$ROLLBACK_V1_STORE" "rollback-tool-v1"
      assert_store_valid "$ROLLBACK_V2_STORE" "rollback-tool-v2"
      assert_store_valid "$ROLLBACK_V3_STORE" "rollback-tool-v3"

      echo "==> Maintainer: publish rollback-tool 1.0.0 and static cache"
      $APR create rollback-reg
      REG_DIR="$REG_STORAGE/rollback-reg"
      DEFAULT_BRANCH=$(git -C "$REG_DIR" symbolic-ref --short HEAD)
      publish_rollback_tool 1.0.0 "$ROLLBACK_V1_STORE"
      assert_file_contains "$REG_DIR/packages/r/rollback-tool.toml" \
        "$ROLLBACK_V1_HASH" "published rollback v1 metadata records store hash"
      generate_cache
      assert_file_exists "/tmp/rollback-cache/$ROLLBACK_V1_HASH.narinfo" \
        "static cache has rollback-tool v1 narinfo"
      assert_file_contains "$REG_DIR/registry.toml" \
        "http://127.0.0.1:18104" "registry records rollback cache URL"

      git init --bare --object-format=sha256 /tmp/rollback-origin.git
      git -C "$REG_DIR" remote add origin /tmp/rollback-origin.git
      commit_and_push "release: rollback-tool 1.0.0"

      ${pkgs.iproute2}/sbin/ip link set lo up || true
      ${pkgs.iproute2}/sbin/ip addr add 127.0.0.1/8 dev lo 2>/dev/null || true
      PYTHONUNBUFFERED=1 python3 -m http.server 18104 --bind 127.0.0.1 \
        --directory /tmp/rollback-cache > /tmp/rollback-cache-http.log 2>&1 &
      CACHE_PID=$!
      if wait_for_cache_server; then
        pass "static cache HTTP server started"
      else
        cat /tmp/rollback-cache-http.log || true
        fail "static cache HTTP server started"
      fi

      echo "==> Consumer: install rollback-tool 1.0.0"
      export HOME=/tmp/rollback-consumer
      export USER=rollbackuser
      mkdir -p "$HOME"
      $APM registry add --no-verify file:///tmp/rollback-origin.git \
        --name rollback-reg \
        --branch "$DEFAULT_BRANCH" > /tmp/rollback-registry-add.out 2>&1 || {
        cat /tmp/rollback-registry-add.out
        fail "apm registry add syncs rollback registry"
      }
      cat /tmp/rollback-registry-add.out

      $APM clean --generations --keep 1 > /tmp/rollback-empty-clean-generations.out 2>&1 || {
        cat /tmp/rollback-empty-clean-generations.out
        fail "clean generations succeeds before any package is installed"
      }
      cat /tmp/rollback-empty-clean-generations.out
      assert_file_contains /tmp/rollback-empty-clean-generations.out "No old generations to remove" \
        "empty clean generations reports no stale generations"
      if [ ! -e "$PROFILE" ]; then
        pass "empty clean generations leaves profile directory absent"
      else
        find "$PROFILE" -maxdepth 2 -print
        fail "empty clean generations should not initialize profile state"
      fi

      if $APM rollback > /tmp/rollback-empty.out 2>&1; then
        cat /tmp/rollback-empty.out
        fail "rollback should fail when no profile generation is active"
      else
        cat /tmp/rollback-empty.out
        pass "rollback fails before any package is installed"
      fi
      assert_file_contains /tmp/rollback-empty.out "no active generation" \
        "empty rollback reports missing active generation"
      if [ ! -e "$PROFILE" ]; then
        pass "empty rollback leaves profile directory absent"
      else
        find "$PROFILE" -maxdepth 2 -print
        fail "empty rollback should not initialize profile state"
      fi

      if $APM rollback --dry-run > /tmp/rollback-empty-dry-run.out 2>&1; then
        cat /tmp/rollback-empty-dry-run.out
        fail "rollback dry-run should fail when no profile generation is active"
      else
        cat /tmp/rollback-empty-dry-run.out
        pass "rollback dry-run fails before any package is installed"
      fi
      assert_file_contains /tmp/rollback-empty-dry-run.out "no active generation" \
        "empty rollback dry-run reports missing active generation"
      if [ ! -e "$PROFILE" ]; then
        pass "empty rollback dry-run leaves profile directory absent"
      else
        find "$PROFILE" -maxdepth 2 -print
        fail "empty rollback dry-run should not initialize profile state"
      fi

      delete_store_path "$ROLLBACK_V1_STORE" "rollback-tool-v1"
      rm -rf "$HOME/.cache/apm"
      mkdir -p "$HOME/.cache/apm"
      $APM install rollback-tool --registry rollback-reg --yes \
        > /tmp/rollback-install-v1.out 2>&1 || {
        cat /tmp/rollback-install-v1.out
        fail "apm installs rollback-tool v1"
      }
      cat /tmp/rollback-install-v1.out
      assert_file_contains /tmp/rollback-install-v1.out "Downloading" \
        "apm install downloads rollback-tool v1"
      assert_file_contains /tmp/rollback-install-v1.out "Installed 1 package" \
        "apm install creates rollback generation 1"
      assert_store_valid "$ROLLBACK_V1_STORE" "rollback-tool-v1"
      assert_current_generation 1 "rollback profile current is generation 1"
      assert_current_tool_version 1.0.0

      $APM rollback --list > /tmp/rollback-list-v1.out 2>&1 || {
        cat /tmp/rollback-list-v1.out
        fail "apm rollback --list shows package generations"
      }
      cat /tmp/rollback-list-v1.out
      assert_file_contains /tmp/rollback-list-v1.out "Profile generations" \
        "rollback --list uses package profile generations"
      assert_file_not_contains /tmp/rollback-list-v1.out "System generations" \
        "rollback --list does not route to system generations without --system"
      assert_file_contains /tmp/rollback-list-v1.out "gen-1: rollback-tool 1.0.0" \
        "rollback --list shows generation 1 package version"
      assert_list_marks_current 1 /tmp/rollback-list-v1.out

      echo "==> Maintainer: publish rollback-tool 2.0.0"
      export HOME=/tmp
      export USER=root
      publish_rollback_tool 2.0.0 "$ROLLBACK_V2_STORE"
      assert_file_contains "$REG_DIR/packages/r/rollback-tool.toml" \
        "$ROLLBACK_V2_HASH" "published rollback v2 metadata records store hash"
      generate_cache
      assert_file_exists "/tmp/rollback-cache/$ROLLBACK_V2_HASH.narinfo" \
        "static cache has rollback-tool v2 narinfo"
      commit_and_push "release: rollback-tool 2.0.0"

      echo "==> Consumer: upgrade to rollback-tool 2.0.0"
      export HOME=/tmp/rollback-consumer
      export USER=rollbackuser
      delete_store_path "$ROLLBACK_V2_STORE" "rollback-tool-v2"
      rm -rf "$HOME/.cache/apm"
      mkdir -p "$HOME/.cache/apm"
      $APM update --registry rollback-reg > /tmp/rollback-update-v2.out 2>&1 || {
        cat /tmp/rollback-update-v2.out
        fail "apm update fetches rollback-tool v2 metadata"
      }
      $APM upgrade rollback-tool --yes > /tmp/rollback-upgrade-v2.out 2>&1 || {
        cat /tmp/rollback-upgrade-v2.out
        fail "apm upgrades rollback-tool to v2"
      }
      cat /tmp/rollback-upgrade-v2.out
      assert_file_contains /tmp/rollback-upgrade-v2.out "Downloading" \
        "apm upgrade downloads rollback-tool v2"
      assert_file_contains /tmp/rollback-upgrade-v2.out "Upgraded 1 package" \
        "apm upgrade creates rollback generation 2"
      assert_current_generation 2 "rollback profile current is generation 2"
      assert_current_tool_version 2.0.0

      echo "==> Maintainer: publish rollback-tool 3.0.0"
      export HOME=/tmp
      export USER=root
      publish_rollback_tool 3.0.0 "$ROLLBACK_V3_STORE"
      assert_file_contains "$REG_DIR/packages/r/rollback-tool.toml" \
        "$ROLLBACK_V3_HASH" "published rollback v3 metadata records store hash"
      generate_cache
      assert_file_exists "/tmp/rollback-cache/$ROLLBACK_V3_HASH.narinfo" \
        "static cache has rollback-tool v3 narinfo"
      commit_and_push "release: rollback-tool 3.0.0"

      echo "==> Consumer: upgrade to rollback-tool 3.0.0"
      export HOME=/tmp/rollback-consumer
      export USER=rollbackuser
      delete_store_path "$ROLLBACK_V3_STORE" "rollback-tool-v3"
      rm -rf "$HOME/.cache/apm"
      mkdir -p "$HOME/.cache/apm"
      $APM update --registry rollback-reg > /tmp/rollback-update-v3.out 2>&1 || {
        cat /tmp/rollback-update-v3.out
        fail "apm update fetches rollback-tool v3 metadata"
      }
      $APM upgrade rollback-tool --yes > /tmp/rollback-upgrade-v3.out 2>&1 || {
        cat /tmp/rollback-upgrade-v3.out
        fail "apm upgrades rollback-tool to v3"
      }
      cat /tmp/rollback-upgrade-v3.out
      assert_file_contains /tmp/rollback-upgrade-v3.out "Downloading" \
        "apm upgrade downloads rollback-tool v3"
      assert_file_contains /tmp/rollback-upgrade-v3.out "Upgraded 1 package" \
        "apm upgrade creates rollback generation 3"
      assert_current_generation 3 "rollback profile current is generation 3"
      assert_current_tool_version 3.0.0

      $APM rollback --list > /tmp/rollback-list-v3.out 2>&1 || {
        cat /tmp/rollback-list-v3.out
        fail "apm rollback --list shows all package generations"
      }
      cat /tmp/rollback-list-v3.out
      assert_file_contains /tmp/rollback-list-v3.out "gen-1: rollback-tool 1.0.0" \
        "rollback --list shows generation 1 version"
      assert_file_contains /tmp/rollback-list-v3.out "gen-2: rollback-tool 2.0.0" \
        "rollback --list shows generation 2 version"
      assert_file_contains /tmp/rollback-list-v3.out "gen-3: rollback-tool 3.0.0" \
        "rollback --list shows generation 3 version"
      assert_list_marks_current 3 /tmp/rollback-list-v3.out

      echo "==> Consumer: rollback explicitly to generation 1"
      $APM --json rollback --generation 1 > /tmp/rollback-to-gen1.json 2>&1 || {
        cat /tmp/rollback-to-gen1.json
        fail "apm rollback --generation 1 succeeds"
      }
      "$JQ" -e \
        --arg restored "$ROLLBACK_V1_STORE" \
        --arg removed "$ROLLBACK_V3_STORE" \
        '.action == "rollback"
          and .status == "rolled_back"
          and .requested_generation == 1
          and .from_generation == 3
          and .to_generation == 1
          and .dry_run == false
          and .generation == 1
          and (.restored | length == 1)
          and .restored[0].store_path == $restored
          and .restored[0].registry == "rollback-reg"
          and .restored[0].package.name == "rollback-tool"
          and .restored[0].package.version == "1.0.0"
          and (.removed | length == 1)
          and .removed[0].store_path == $removed
          and .removed[0].registry == "rollback-reg"
          and .removed[0].package.name == "rollback-tool"
          and .removed[0].package.version == "3.0.0"
          and (.current_roots | any(.store_path == $removed
            and .package.name == "rollback-tool"
            and .package.version == "3.0.0"))
          and (.target_roots | any(.store_path == $restored
            and .package.name == "rollback-tool"
            and .package.version == "1.0.0"))' \
        /tmp/rollback-to-gen1.json >/dev/null || {
        cat /tmp/rollback-to-gen1.json
        fail "apm --json rollback reports explicit generation transition"
      }
      assert_current_generation 1 "rollback profile current is generation 1 after explicit rollback"
      assert_current_tool_version 1.0.0
      $APM list --installed > /tmp/rollback-installed-gen1.out 2>&1 || {
        cat /tmp/rollback-installed-gen1.out
        fail "apm list --installed succeeds after generation 1 rollback"
      }
      assert_file_contains /tmp/rollback-installed-gen1.out "rollback-tool" \
        "installed list names rollback-tool after generation 1 rollback"
      assert_file_contains /tmp/rollback-installed-gen1.out "1.0.0" \
        "installed metadata follows generation 1 rollback"
      assert_file_contains /tmp/rollback-installed-gen1.out "upgradable: 3.0.0" \
        "installed list reports generation 3 as an upgrade candidate after generation 1 rollback"

      $APM rollback --list > /tmp/rollback-list-gen1-current.out 2>&1 || {
        cat /tmp/rollback-list-gen1-current.out
        fail "apm rollback --list works after generation 1 rollback"
      }
      assert_list_marks_current 1 /tmp/rollback-list-gen1-current.out

      echo "==> Consumer: explicit rollback target can switch back to generation 3"
      $APM rollback --generation 3 > /tmp/rollback-to-gen3.out 2>&1 || {
        cat /tmp/rollback-to-gen3.out
        fail "apm rollback --generation 3 succeeds"
      }
      cat /tmp/rollback-to-gen3.out
      assert_current_generation 3 "rollback profile current is generation 3 after explicit target"
      assert_current_tool_version 3.0.0

      echo "==> Consumer: dry-run rollback does not switch generation"
      $APM --json rollback --dry-run > /tmp/rollback-dry-run.json 2>&1 || {
        cat /tmp/rollback-dry-run.json
        fail "apm rollback --dry-run succeeds"
      }
      "$JQ" -e \
        --arg restored "$ROLLBACK_V2_STORE" \
        --arg removed "$ROLLBACK_V3_STORE" \
        '.action == "rollback"
          and .status == "planned"
          and .requested_generation == null
          and .from_generation == 3
          and .to_generation == 2
          and .dry_run == true
          and .generation == null
          and (.restored | length == 1)
          and .restored[0].store_path == $restored
          and .restored[0].registry == "rollback-reg"
          and .restored[0].package.name == "rollback-tool"
          and .restored[0].package.version == "2.0.0"
          and (.removed | length == 1)
          and .removed[0].store_path == $removed
          and .removed[0].registry == "rollback-reg"
          and .removed[0].package.name == "rollback-tool"
          and .removed[0].package.version == "3.0.0"
          and (.current_roots | any(.store_path == $removed
            and .package.name == "rollback-tool"
            and .package.version == "3.0.0"))
          and (.target_roots | any(.store_path == $restored
            and .package.name == "rollback-tool"
            and .package.version == "2.0.0"))' \
        /tmp/rollback-dry-run.json >/dev/null || {
        cat /tmp/rollback-dry-run.json
        fail "apm --json rollback --dry-run reports planned previous-generation transition"
      }
      assert_current_generation 3 "rollback dry-run keeps generation 3 active"
      assert_current_tool_version 3.0.0

      echo "==> Consumer: plain rollback selects previous generation"
      $APM --json rollback > /tmp/rollback-plain.json 2>&1 || {
        cat /tmp/rollback-plain.json
        fail "plain apm rollback succeeds"
      }
      "$JQ" -e \
        --arg restored "$ROLLBACK_V2_STORE" \
        --arg removed "$ROLLBACK_V3_STORE" \
        '.action == "rollback"
          and .status == "rolled_back"
          and .requested_generation == null
          and .from_generation == 3
          and .to_generation == 2
          and .dry_run == false
          and .generation == 2
          and (.restored | length == 1)
          and .restored[0].store_path == $restored
          and .restored[0].registry == "rollback-reg"
          and .restored[0].package.name == "rollback-tool"
          and .restored[0].package.version == "2.0.0"
          and (.removed | length == 1)
          and .removed[0].store_path == $removed
          and .removed[0].registry == "rollback-reg"
          and .removed[0].package.name == "rollback-tool"
          and .removed[0].package.version == "3.0.0"
          and (.current_roots | any(.store_path == $removed
            and .package.name == "rollback-tool"
            and .package.version == "3.0.0"))
          and (.target_roots | any(.store_path == $restored
            and .package.name == "rollback-tool"
            and .package.version == "2.0.0"))' \
        /tmp/rollback-plain.json >/dev/null || {
        cat /tmp/rollback-plain.json
        fail "apm --json rollback reports previous-generation transition"
      }
      assert_current_generation 2 "rollback profile current is generation 2 after plain rollback"
      assert_current_tool_version 2.0.0

      echo "==> Consumer: clean generations keeps rolled-back current generation"
      $APM --json clean --generations --keep 1 > /tmp/rollback-clean-generations.json 2>&1 || {
        cat /tmp/rollback-clean-generations.json
        fail "apm clean --generations succeeds after rollback"
      }
      "$JQ" -e \
        '.action == "clean"
          and .mode == "generations"
          and .status == "cleaned"
          and .keep == 1
          and .current_generation == 2
          and .generations_before == [1, 2, 3]
          and .generations_after == [2, 3]
          and .removed_generations == [1]
          and .removed == 1' \
        /tmp/rollback-clean-generations.json >/dev/null || {
        cat /tmp/rollback-clean-generations.json
        fail "apm --json clean --generations reports pruned rollback generation"
      }
      assert_generation_missing 1 "clean generations prunes generation 1"
      assert_generation_exists 2 "clean generations keeps rolled-back current generation"
      assert_generation_exists 3 "clean generations keeps latest generation"
      assert_current_generation 2 "clean generations leaves generation 2 current"
      assert_current_tool_version 2.0.0
      $APM rollback --list > /tmp/rollback-list-after-clean.out 2>&1 || {
        cat /tmp/rollback-list-after-clean.out
        fail "apm rollback --list works after generation cleanup"
      }
      cat /tmp/rollback-list-after-clean.out
      assert_file_not_contains /tmp/rollback-list-after-clean.out "gen-1:" \
        "rollback list no longer shows pruned generation"
      assert_file_contains /tmp/rollback-list-after-clean.out "gen-2: rollback-tool 2.0.0" \
        "rollback list keeps current generation after cleanup"
      assert_file_contains /tmp/rollback-list-after-clean.out "gen-3: rollback-tool 3.0.0" \
        "rollback list keeps latest generation after cleanup"
      assert_list_marks_current 2 /tmp/rollback-list-after-clean.out
      $APM list --installed > /tmp/rollback-installed-after-clean.out 2>&1 || {
        cat /tmp/rollback-installed-after-clean.out
        fail "apm list --installed works after generation cleanup"
      }
      assert_file_contains /tmp/rollback-installed-after-clean.out "rollback-tool" \
        "installed list names rollback-tool after generation cleanup"
      assert_file_contains /tmp/rollback-installed-after-clean.out "2.0.0" \
        "installed metadata follows rolled-back current generation after cleanup"

      if $APM rollback --generation 99 > /tmp/rollback-missing.out 2>&1; then
        cat /tmp/rollback-missing.out
        fail "rollback to missing generation should fail"
      else
        pass "rollback to missing generation fails"
      fi
      assert_file_contains /tmp/rollback-missing.out "generation 99 not found" \
        "rollback missing generation reports target"
      assert_current_generation 2 "failed rollback keeps generation 2 active"

      kill "$CACHE_PID" 2>/dev/null || true
      wait "$CACHE_PID" 2>/dev/null || true

      check_fail
    '';
  };
}
