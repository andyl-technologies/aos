# Registry VM checks for static origin workflows.
{
  testing,
  pkgs,
  fixtures,
  maintainerWorkflowDeps,
  setupNixPublishEnv,
  closureLeafTool,
  closureRootTool,
  closureRootSourceTool,
  closureLeafToolV2,
  closureRootToolV2,
  closureRootSourceToolV2,
}: {
  # -------------------------------------------------------------------------
  # registry-release-static-origin-closure — Release-uploaded origin + closure
  # -------------------------------------------------------------------------
  registry-release-static-origin-closure = testing.mkVMTest {
    name = "apm-registry-release-static-origin-closure";
    rootfsDeps =
      maintainerWorkflowDeps
      ++ [
        pkgs.jq
        closureLeafTool
        closureRootTool
        closureRootSourceTool
        closureLeafToolV2
        closureRootToolV2
        closureRootSourceToolV2
      ];
    memory = 2048;
    testScript = ''
      ${fixtures.setupPreamble}
      ${setupNixPublishEnv}

      echo "==> Test: release upload serves a complete closure to a fresh consumer"

      LEAF_STORE="${closureLeafTool}"
      ROOT_STORE="${closureRootTool}"
      ROOT_SOURCE_STORE="${closureRootSourceTool}"
      LEAF_V2_STORE="${closureLeafToolV2}"
      ROOT_V2_STORE="${closureRootToolV2}"
      ROOT_V2_SOURCE_STORE="${closureRootSourceToolV2}"
      LEAF_HASH=$(basename "$LEAF_STORE" | cut -d- -f1)
      ROOT_HASH=$(basename "$ROOT_STORE" | cut -d- -f1)
      ROOT_SOURCE_HASH=$(basename "$ROOT_SOURCE_STORE" | cut -d- -f1)
      LEAF_V2_HASH=$(basename "$LEAF_V2_STORE" | cut -d- -f1)
      ROOT_V2_HASH=$(basename "$ROOT_V2_STORE" | cut -d- -f1)
      ROOT_V2_SOURCE_HASH=$(basename "$ROOT_V2_SOURCE_STORE" | cut -d- -f1)
      PROFILE="/var/lib/profiles/per-user/staticreleaseuser"

      assert_store_valid() {
        path="$1"
        label="$2"
        if nix-store --check-validity "$path" > "/tmp/static-release-valid-$label.out" 2>&1; then
          pass "$label valid in store"
        else
          cat "/tmp/static-release-valid-$label.out"
          fail "$label should be valid in store"
        fi
      }

      assert_store_missing() {
        path="$1"
        label="$2"
        if nix-store --check-validity "$path" > "/tmp/static-release-missing-$label.out" 2>&1; then
          cat "/tmp/static-release-missing-$label.out"
          fail "$label should be missing from store"
        else
          pass "$label missing from store"
        fi
      }

      assert_file_not_contains() {
        if grep -q "$2" "$1" 2>/dev/null; then
          fail "$3 (pattern '$2' unexpectedly found in $1)"
          cat "$1" 2>/dev/null || true
        else
          pass "$3"
        fi
      }

      delete_store_path() {
        path="$1"
        label="$2"
        if nix-store --delete --ignore-liveness "$path" > "/tmp/static-release-delete-$label.out" 2>&1; then
          pass "$label deleted from store"
        else
          cat "/tmp/static-release-delete-$label.out"
          fail "$label should be deletable from store"
          return 1
        fi
        assert_store_missing "$path" "$label"
      }

      cache_nar_count() {
        find "$HOME/.cache/apm" -type f -name '*.nar.zst' 2>/dev/null | wc -l | tr -d ' '
      }

      cache_nar_http_get_count() {
        grep -E 'GET /nar/.*\.nar\.zst HTTP/' /tmp/static-release-http.log 2>/dev/null | wc -l | tr -d ' '
      }

      generation_count() {
        if [ -d "$PROFILE" ]; then
          find "$PROFILE" -maxdepth 1 -type d -name 'gen-*' | wc -l | tr -d ' '
        else
          printf '0'
        fi
      }

      wait_for_static_origin() {
        for _i in 1 2 3 4 5 6 7 8 9 10; do
          if curl -sf http://127.0.0.1:18120/HEAD >/dev/null \
            && curl -sf http://127.0.0.1:18120/nix-cache-info >/dev/null; then
            return 0
          fi
          sleep 1
        done
        return 1
      }

      mount -o remount,rw / || true
      assert_store_valid "$LEAF_STORE" "closure-leaf"
      assert_store_valid "$ROOT_STORE" "closure-root"
      nix-store -q --references "$ROOT_STORE" > /tmp/static-release-root-refs.out
      assert_file_contains /tmp/static-release-root-refs.out "$LEAF_STORE" \
        "release root has a real Nix reference to closure-leaf"

      ssh-keygen -q -t ed25519 -N "" -f /tmp/static-release-key
      STATIC_RELEASE_PUBLIC=$(cut -d ' ' -f2 < /tmp/static-release-key.pub)
      STATIC_RELEASE_TRUST_KEY="static-release-reg:Ed25519:$STATIC_RELEASE_PUBLIC"
      $APR create static-release-reg \
        --trust-key "$STATIC_RELEASE_TRUST_KEY" \
        --key /tmp/static-release-key
      REG_DIR="$REG_STORAGE/static-release-reg"
      DEFAULT_BRANCH=$(git -C "$REG_DIR" symbolic-ref --short HEAD)
      assert_file_contains "$REG_DIR/keys.toml" "$STATIC_RELEASE_TRUST_KEY" \
        "registry records static release trust key"
      nix --extra-experimental-features nix-command key generate-secret \
        --key-name static-release-cache > /tmp/static-release-cache.sec
      TRUSTED_PUBLIC_KEY=$(nix --extra-experimental-features nix-command \
        key convert-secret-to-public < /tmp/static-release-cache.sec)

      $APR release 1.0.0 \
        --registry static-release-reg \
        --store-path "$ROOT_STORE" \
        --name static-closure \
        --description "Static release closure fixture" \
        --license MIT \
        --maintainer static-release@example.invalid \
        --source-drv "$ROOT_SOURCE_STORE" \
        --key /tmp/static-release-key \
        --cache-key /tmp/static-release-cache.sec \
        --cache-url http://127.0.0.1:18120 \
        --upload-url file:///tmp/static-release-origin \
        > /tmp/static-release.out 2>&1 || {
        cat /tmp/static-release.out
        fail "apr release uploads static origin and cache"
      }
      cat /tmp/static-release.out
      assert_file_contains /tmp/static-release.out "Created signed tag '1.0.0'" \
        "apr release creates signed tag for uploaded origin"
      assert_file_contains /tmp/static-release.out "Generated static cache" \
        "apr release generates a static cache"
      assert_file_contains /tmp/static-release.out "Uploaded" \
        "apr release uploads static origin files"
      assert_file_contains /tmp/static-release.out "Released static-release-reg 1.0.0" \
        "apr release completes uploaded static origin workflow"
      assert_file_contains /tmp/static-release.out "Source drv: $ROOT_SOURCE_STORE" \
        "apr release reports explicit source provenance"
      assert_file_contains "$REG_DIR/packages/s/static-closure.toml" \
        "source_drv = \"$ROOT_SOURCE_STORE\"" \
        "release metadata records v1 source provenance"
      assert_file_contains "$REG_DIR/packages/s/static-closure.toml" \
        'source_nar_hash = "sha256:' "release metadata records v1 source NAR hash"

      assert_file_exists "/tmp/static-release-origin/$ROOT_HASH.narinfo" \
        "release cache has root narinfo"
      assert_file_exists "/tmp/static-release-origin/$LEAF_HASH.narinfo" \
        "release cache has unpublished dependency narinfo"
      assert_file_exists "/tmp/static-release-origin/$ROOT_SOURCE_HASH.narinfo" \
        "release cache has explicit source narinfo"
      assert_file_exists "/tmp/static-release-origin/HEAD" \
        "uploaded static origin has HEAD"
      assert_file_exists "/tmp/static-release-origin/info/refs" \
        "uploaded static origin has dumb HTTP refs"
      assert_file_exists "/tmp/static-release-origin/releases/1/0/0/objects/info/packs" \
        "uploaded static origin has release pack metadata"
      assert_file_exists "/tmp/static-release-origin/nix-cache-info" \
        "uploaded static origin includes cache info"
      assert_file_exists "/tmp/static-release-origin/$ROOT_HASH.narinfo" \
        "uploaded static origin has root narinfo"
      assert_file_exists "/tmp/static-release-origin/$LEAF_HASH.narinfo" \
        "uploaded static origin has dependency narinfo"
      assert_file_exists "/tmp/static-release-origin/$ROOT_SOURCE_HASH.narinfo" \
        "uploaded static origin has source narinfo"
      assert_file_contains "/tmp/static-release-origin/$ROOT_HASH.narinfo" \
        "Sig: static-release-cache:" \
        "uploaded static origin signs root narinfo"
      assert_file_contains "/tmp/static-release-origin/$LEAF_HASH.narinfo" \
        "Sig: static-release-cache:" \
        "uploaded static origin signs dependency narinfo"
      assert_file_contains "/tmp/static-release-origin/$ROOT_SOURCE_HASH.narinfo" \
        "Sig: static-release-cache:" \
        "uploaded static origin signs source narinfo"

      ${pkgs.iproute2}/sbin/ip link set lo up || true
      ${pkgs.iproute2}/sbin/ip addr add 127.0.0.1/8 dev lo 2>/dev/null || true
      PYTHONUNBUFFERED=1 python3 -m http.server 18120 --bind 127.0.0.1 \
        --directory /tmp/static-release-origin > /tmp/static-release-http.log 2>&1 &
      ORIGIN_PID=$!
      if wait_for_static_origin; then
        pass "uploaded static origin HTTP server started"
      else
        cat /tmp/static-release-http.log || true
        fail "uploaded static origin HTTP server started"
      fi

      echo "==> Stock Nix: copy signed release closure from uploaded origin"
      delete_store_path "$ROOT_SOURCE_STORE" "closure-root-source-stock-nix"
      delete_store_path "$ROOT_STORE" "closure-root-stock-nix"
      delete_store_path "$LEAF_STORE" "closure-leaf-stock-nix"
      nix --extra-experimental-features nix-command \
        --option require-sigs true \
        --option trusted-public-keys "$TRUSTED_PUBLIC_KEY" \
        copy --from http://127.0.0.1:18120 "$ROOT_STORE" \
        > /tmp/static-release-stock-nix-copy.out 2>&1 || {
        cat /tmp/static-release-stock-nix-copy.out
        fail "stock Nix imports signed release closure from uploaded origin"
      }
      cat /tmp/static-release-stock-nix-copy.out
      assert_store_valid "$ROOT_STORE" "closure-root-stock-nix"
      assert_store_valid "$LEAF_STORE" "closure-leaf-stock-nix"
      "$ROOT_STORE/bin/closure-root" > /tmp/static-release-stock-nix-run.out
      assert_file_contains /tmp/static-release-stock-nix-run.out \
        "^closure-root 1.0.0 via closure-leaf 1.0.0$" \
        "stock Nix imported release closure executes with its dependency"

      export HOME=/tmp/static-release-consumer
      export USER=staticreleaseuser
      mkdir -p "$HOME"
      $APM registry add http://127.0.0.1:18120 \
        --name static-release-reg \
        --trust-key "$STATIC_RELEASE_TRUST_KEY" \
        --branch "$DEFAULT_BRANCH" > /tmp/static-release-add.out 2>&1 || {
        cat /tmp/static-release-add.out
        fail "apm registry add syncs uploaded static origin"
      }
      cat /tmp/static-release-add.out
      assert_file_contains /tmp/static-release-add.out "Signing.*trusted key.*pinned" \
        "consumer pins static release registry signing key"
      assert_file_contains "$HOME/.local/share/apm/registries/static-release-reg/registry.toml" \
        "http://127.0.0.1:18120" \
        "consumer synced cache endpoint from uploaded origin"
      $APM search static-closure --registry static-release-reg \
        > /tmp/static-release-search.out 2>&1 || {
        cat /tmp/static-release-search.out
        fail "apm search sees uploaded release package"
      }
      assert_file_contains /tmp/static-release-search.out "static-closure" \
        "consumer sees package from uploaded static origin"

      delete_store_path "$ROOT_STORE" "closure-root"
      delete_store_path "$LEAF_STORE" "closure-leaf"
      assert_store_missing "$ROOT_SOURCE_STORE" "closure-root-source"
      rm -rf "$HOME/.cache/apm"
      mkdir -p "$HOME/.cache/apm"

      echo "==> Consumer: no-deps refuses an unpublished missing closure reference"
      if $APM install static-closure \
        --registry static-release-reg \
        --no-deps \
        --yes > /tmp/static-release-no-deps-missing.out 2>&1; then
        cat /tmp/static-release-no-deps-missing.out
        fail "apm install --no-deps should fail when anonymous closure dependency is absent"
      else
        cat /tmp/static-release-no-deps-missing.out
        pass "apm install --no-deps fails before downloading anonymous closure dependency"
      fi
      assert_file_contains /tmp/static-release-no-deps-missing.out \
        "no-deps requested but dependency store path" \
        "failed no-deps install reports missing anonymous dependency"
      assert_file_not_contains /tmp/static-release-no-deps-missing.out "Downloading" \
        "failed no-deps install does not download NAR bodies"
      if [ "$(cache_nar_count)" = "0" ]; then
        pass "failed no-deps install leaves NAR cache empty"
      else
        fail "failed no-deps install should not cache release NARs"
      fi
      assert_store_missing "$ROOT_STORE" "closure-root"
      assert_store_missing "$LEAF_STORE" "closure-leaf"
      assert_store_missing "$ROOT_SOURCE_STORE" "closure-root-source"
      if [ "$(generation_count)" = "0" ] && [ ! -e "$PROFILE/current" ]; then
        pass "failed no-deps install creates no profile generation"
      else
        fail "failed no-deps install should not create a profile generation"
      fi

      echo "==> Consumer: JSON download-only fetches anonymous closure without importing"
      NAR_GETS_BEFORE_JSON_DOWNLOAD_ONLY=$(cache_nar_http_get_count)
      $APM --json install static-closure \
        --registry static-release-reg \
        --download-only \
        --yes > /tmp/static-release-download-only-json.out 2>&1 || {
        cat /tmp/static-release-download-only-json.out
        fail "apm --json install --download-only downloads anonymous release closure"
      }
      if ${pkgs.jq}/bin/jq -e --arg root "$ROOT_STORE" --arg leaf "$LEAF_STORE" \
        '[.downloads.paths[].store_path] as $downloaded_paths
        | .action == "install"
          and .status == "downloaded"
          and .download_only == true
          and .dry_run == false
          and .generation == null
          and .downloads.planned == 2
          and .downloads.downloaded == 2
          and .downloads.imported == 0
          and (.roots | length == 1)
          and .roots[0].name == "static-closure"
          and (.closure | length == 1)
          and ($downloaded_paths | index($root) != null)
          and ($downloaded_paths | index($leaf) != null)' \
        /tmp/static-release-download-only-json.out >/dev/null; then
        pass "apm --json install --download-only reports downloaded anonymous closure"
      else
        cat /tmp/static-release-download-only-json.out
        fail "apm --json install --download-only reports downloaded anonymous closure"
      fi
      assert_file_not_contains /tmp/static-release-download-only-json.out "Downloading" \
        "apm --json install --download-only emits clean JSON while downloading"
      if [ "$(cache_nar_count)" = "2" ]; then
        pass "json download-only leaves root and dependency NARs in user cache"
      else
        fail "json download-only should cache exactly two release NARs"
      fi
      EXPECTED_NAR_GETS_AFTER_JSON_DOWNLOAD_ONLY=$((NAR_GETS_BEFORE_JSON_DOWNLOAD_ONLY + 2))
      if [ "$(cache_nar_http_get_count)" = "$EXPECTED_NAR_GETS_AFTER_JSON_DOWNLOAD_ONLY" ]; then
        pass "json download-only fetches exactly two release NAR bodies"
      else
        cat /tmp/static-release-http.log || true
        fail "json download-only should fetch exactly two release NAR bodies"
      fi
      assert_store_missing "$ROOT_STORE" "closure-root"
      assert_store_missing "$LEAF_STORE" "closure-leaf"
      assert_store_missing "$ROOT_SOURCE_STORE" "closure-root-source"
      if [ "$(generation_count)" = "0" ] && [ ! -e "$PROFILE/current" ]; then
        pass "json download-only creates no profile generation"
      else
        fail "json download-only should not create a profile generation"
      fi
      rm -rf "$HOME/.cache/apm"
      mkdir -p "$HOME/.cache/apm"

      echo "==> Consumer: download-only fetches anonymous closure without importing"
      NAR_GETS_BEFORE_DOWNLOAD_ONLY=$(cache_nar_http_get_count)
      $APM install static-closure \
        --registry static-release-reg \
        --download-only \
        --yes > /tmp/static-release-download-only.out 2>&1 || {
        cat /tmp/static-release-download-only.out
        fail "apm install --download-only downloads anonymous release closure"
      }
      cat /tmp/static-release-download-only.out
      assert_file_contains /tmp/static-release-download-only.out "Downloading 2 NAR" \
        "download-only downloads root and anonymous dependency NARs"
      assert_file_contains /tmp/static-release-download-only.out "no profile changes made" \
        "download-only reports no profile mutation"
      assert_file_not_contains /tmp/static-release-download-only.out "Importing packages" \
        "download-only does not import release closure"
      assert_file_not_contains /tmp/static-release-download-only.out "Updating profile" \
        "download-only does not update profile"
      if [ "$(cache_nar_count)" = "2" ]; then
        pass "download-only leaves root and dependency NARs in user cache"
      else
        fail "download-only should cache exactly two release NARs"
      fi
      EXPECTED_NAR_GETS_AFTER_DOWNLOAD_ONLY=$((NAR_GETS_BEFORE_DOWNLOAD_ONLY + 2))
      if [ "$(cache_nar_http_get_count)" = "$EXPECTED_NAR_GETS_AFTER_DOWNLOAD_ONLY" ]; then
        pass "download-only fetches exactly two release NAR bodies"
      else
        cat /tmp/static-release-http.log || true
        fail "download-only should fetch exactly two release NAR bodies"
      fi
      assert_store_missing "$ROOT_STORE" "closure-root"
      assert_store_missing "$LEAF_STORE" "closure-leaf"
      assert_store_missing "$ROOT_SOURCE_STORE" "closure-root-source"
      if [ "$(generation_count)" = "0" ] && [ ! -e "$PROFILE/current" ]; then
        pass "download-only creates no profile generation"
      else
        fail "download-only should not create a profile generation"
      fi

      echo "==> Consumer: normal install reuses cached anonymous closure and activates"
      NAR_GETS_BEFORE_INSTALL=$(cache_nar_http_get_count)
      $APM install static-closure --registry static-release-reg --yes \
        > /tmp/static-release-install.out 2>&1 || {
        cat /tmp/static-release-install.out
        fail "apm install downloads anonymous closure from uploaded origin"
      }
      cat /tmp/static-release-install.out
      assert_file_contains /tmp/static-release-install.out "Downloading" \
        "apm install downloads release closure NARs"
      assert_file_contains /tmp/static-release-install.out "Installed 1 package" \
        "apm install activates static release package"
      if [ "$(cache_nar_http_get_count)" = "$NAR_GETS_BEFORE_INSTALL" ]; then
        pass "normal install reuses cached anonymous closure NAR bodies"
      else
        cat /tmp/static-release-http.log || true
        fail "normal install should not refetch cached anonymous closure NAR bodies"
      fi
      if [ "$(cache_nar_count)" = "2" ]; then
        pass "download cache contains the root and dependency NARs"
      else
        fail "download cache should contain exactly two NARs"
      fi
      assert_store_valid "$ROOT_STORE" "closure-root"
      assert_store_valid "$LEAF_STORE" "closure-leaf"
      assert_store_missing "$ROOT_SOURCE_STORE" "closure-root-source"

      "$PROFILE/current/bin/closure-root" > /tmp/static-release-run.out
      assert_file_contains /tmp/static-release-run.out \
        "^closure-root 1.0.0 via closure-leaf 1.0.0$" \
        "installed release closure executes with its dependency"
      if [ -L "$PROFILE/current/src/$ROOT_SOURCE_HASH" ]; then
        pass "installed release closure roots v1 source provenance"
      else
        fail "installed release closure should root v1 source provenance"
      fi
      $APM source static-closure --verify \
        > /tmp/static-release-source-verify.out 2>&1 || {
        cat /tmp/static-release-source-verify.out
        fail "apm source --verify validates release-published source provenance"
      }
      cat /tmp/static-release-source-verify.out
      assert_file_contains /tmp/static-release-source-verify.out "Downloading 1 NAR" \
        "apm source --verify fetches missing v1 source path"
      assert_file_contains /tmp/static-release-source-verify.out "$ROOT_SOURCE_STORE" \
        "apm source --verify uses v1 release source path"
      assert_file_contains /tmp/static-release-source-verify.out "matches installed binary" \
        "apm source --verify compares v1 release source with installed binary"
      assert_store_valid "$ROOT_SOURCE_STORE" "closure-root-source"

      echo "==> Maintainer: release v2 with a new anonymous closure dependency"
      export HOME=/tmp
      export USER=root
      assert_store_valid "$LEAF_V2_STORE" "closure-leaf-v2"
      assert_store_valid "$ROOT_V2_STORE" "closure-root-v2"
      assert_store_valid "$ROOT_V2_SOURCE_STORE" "closure-root-source-v2"
      nix-store -q --references "$ROOT_V2_STORE" > /tmp/static-release-root-v2-refs.out
      assert_file_contains /tmp/static-release-root-v2-refs.out "$LEAF_V2_STORE" \
        "release root v2 has a real Nix reference to closure-leaf v2"
      $APR release 2.0.0 \
        --registry static-release-reg \
        --store-path "$ROOT_V2_STORE" \
        --name static-closure \
        --description "Static release closure fixture" \
        --license MIT \
        --maintainer static-release@example.invalid \
        --previous 1.0.0 \
        --source-drv "$ROOT_V2_SOURCE_STORE" \
        --key /tmp/static-release-key \
        --cache-key /tmp/static-release-cache.sec \
        --cache-url http://127.0.0.1:18120 \
        --upload-url file:///tmp/static-release-origin \
        > /tmp/static-release-v2.out 2>&1 || {
        cat /tmp/static-release-v2.out
        fail "apr release uploads static origin and cache for v2"
      }
      cat /tmp/static-release-v2.out
      assert_file_contains /tmp/static-release-v2.out "Created signed tag '2.0.0'" \
        "apr release creates signed v2 tag for uploaded origin"
      assert_file_contains /tmp/static-release-v2.out "Uploaded" \
        "apr release uploads v2 static origin files"
      assert_file_contains /tmp/static-release-v2.out "Source drv: $ROOT_V2_SOURCE_STORE" \
        "apr release reports v2 explicit source provenance"
      assert_file_contains "$REG_DIR/packages/s/static-closure.toml" \
        "source_drv = \"$ROOT_V2_SOURCE_STORE\"" \
        "release metadata records v2 source provenance"
      assert_file_exists "/tmp/static-release-origin/$ROOT_V2_HASH.narinfo" \
        "uploaded static origin has v2 root narinfo"
      assert_file_exists "/tmp/static-release-origin/$LEAF_V2_HASH.narinfo" \
        "uploaded static origin has v2 dependency narinfo"
      assert_file_exists "/tmp/static-release-origin/$ROOT_V2_SOURCE_HASH.narinfo" \
        "uploaded static origin has v2 source narinfo"
      assert_file_contains "/tmp/static-release-origin/$ROOT_V2_HASH.narinfo" \
        "Sig: static-release-cache:" \
        "uploaded static origin signs v2 root narinfo"
      assert_file_contains "/tmp/static-release-origin/$LEAF_V2_HASH.narinfo" \
        "Sig: static-release-cache:" \
        "uploaded static origin signs v2 dependency narinfo"
      assert_file_contains "/tmp/static-release-origin/$ROOT_V2_SOURCE_HASH.narinfo" \
        "Sig: static-release-cache:" \
        "uploaded static origin signs v2 source narinfo"

      echo "==> Consumer: upgrade from uploaded static origin downloads anonymous v2 closure"
      export HOME=/tmp/static-release-consumer
      export USER=staticreleaseuser
      delete_store_path "$ROOT_V2_SOURCE_STORE" "closure-root-source-v2"
      delete_store_path "$ROOT_V2_STORE" "closure-root-v2"
      delete_store_path "$LEAF_V2_STORE" "closure-leaf-v2"
      rm -rf "$HOME/.cache/apm"
      mkdir -p "$HOME/.cache/apm"
      $APM update --registry static-release-reg > /tmp/static-release-update-v2.out 2>&1 || {
        cat /tmp/static-release-update-v2.out
        fail "apm update syncs uploaded static origin v2"
      }
      cat /tmp/static-release-update-v2.out
      $APM list --upgradable > /tmp/static-release-upgradable-v2.out 2>&1 || {
        cat /tmp/static-release-upgradable-v2.out
        fail "apm list --upgradable sees static release v2"
      }
      assert_file_contains /tmp/static-release-upgradable-v2.out "static-closure" \
        "upgradable list names static release package"
      assert_file_contains /tmp/static-release-upgradable-v2.out "2.0.0" \
        "upgradable list reports static release v2"

      echo "==> Consumer: JSON dry-run upgrade reports anonymous v2 closure without downloading"
      NAR_GETS_BEFORE_UPGRADE_DRY_RUN=$(cache_nar_http_get_count)
      $APM --json upgrade static-closure --dry-run \
        > /tmp/static-release-upgrade-v2-dry-run-json.out 2>&1 || {
        cat /tmp/static-release-upgrade-v2-dry-run-json.out
        fail "apm --json upgrade --dry-run plans anonymous v2 closure from uploaded origin"
      }
      if ${pkgs.jq}/bin/jq -e --arg root "$ROOT_V2_STORE" --arg leaf "$LEAF_V2_STORE" \
        '[.downloads.paths[].store_path] as $downloaded_paths
        | .action == "upgrade"
          and .status == "planned"
          and .dry_run == true
          and .generation == null
          and .requested == ["static-closure"]
          and .downloads.planned == 2
          and .downloads.downloaded == 0
          and .downloads.imported == 0
          and (.upgrades | length == 1)
          and .upgrades[0].name == "static-closure"
          and .upgrades[0].old_version == "1.0.0"
          and .upgrades[0].new_version == "2.0.0"
          and .upgrades[0].new_store_path == $root
          and ($downloaded_paths | index($root) != null)
          and ($downloaded_paths | index($leaf) != null)' \
        /tmp/static-release-upgrade-v2-dry-run-json.out >/dev/null; then
        pass "apm --json upgrade --dry-run reports anonymous v2 closure"
      else
        cat /tmp/static-release-upgrade-v2-dry-run-json.out
        fail "apm --json upgrade --dry-run reports anonymous v2 closure"
      fi
      assert_file_not_contains /tmp/static-release-upgrade-v2-dry-run-json.out "Downloading" \
        "apm --json upgrade --dry-run emits clean JSON while planning"
      if [ "$(cache_nar_http_get_count)" = "$NAR_GETS_BEFORE_UPGRADE_DRY_RUN" ]; then
        pass "json upgrade dry-run fetches no v2 release NAR bodies"
      else
        cat /tmp/static-release-http.log || true
        fail "json upgrade dry-run should not fetch v2 release NAR bodies"
      fi
      if [ "$(cache_nar_count)" = "0" ]; then
        pass "json upgrade dry-run leaves NAR cache empty"
      else
        fail "json upgrade dry-run should not cache release NARs"
      fi
      assert_store_missing "$ROOT_V2_STORE" "closure-root-v2"
      assert_store_missing "$LEAF_V2_STORE" "closure-leaf-v2"
      assert_store_missing "$ROOT_V2_SOURCE_STORE" "closure-root-source-v2"
      if [ "$(generation_count)" = "1" ]; then
        pass "json upgrade dry-run creates no new profile generation"
      else
        fail "json upgrade dry-run should not create a profile generation"
      fi

      echo "==> Consumer: JSON upgrade from uploaded static origin downloads anonymous v2 closure"
      NAR_GETS_BEFORE_UPGRADE=$(cache_nar_http_get_count)
      $APM --json upgrade static-closure --yes \
        > /tmp/static-release-upgrade-v2-json.out 2>&1 || {
        cat /tmp/static-release-upgrade-v2-json.out
        fail "apm --json upgrade downloads anonymous v2 closure from uploaded origin"
      }
      if ${pkgs.jq}/bin/jq -e --arg root "$ROOT_V2_STORE" --arg leaf "$LEAF_V2_STORE" \
        '[.downloads.paths[].store_path] as $downloaded_paths
        | .action == "upgrade"
          and .status == "upgraded"
          and .dry_run == false
          and .generation == 2
          and .requested == ["static-closure"]
          and .downloads.planned == 2
          and .downloads.downloaded == 2
          and .downloads.imported == 2
          and (.upgrades | length == 1)
          and .upgrades[0].name == "static-closure"
          and .upgrades[0].old_version == "1.0.0"
          and .upgrades[0].new_version == "2.0.0"
          and .upgrades[0].new_store_path == $root
          and ($downloaded_paths | index($root) != null)
          and ($downloaded_paths | index($leaf) != null)' \
        /tmp/static-release-upgrade-v2-json.out >/dev/null; then
        pass "apm --json upgrade reports downloaded anonymous v2 closure"
      else
        cat /tmp/static-release-upgrade-v2-json.out
        fail "apm --json upgrade reports downloaded anonymous v2 closure"
      fi
      assert_file_not_contains /tmp/static-release-upgrade-v2-json.out "Downloading" \
        "apm --json upgrade emits clean JSON while downloading"
      assert_file_not_contains /tmp/static-release-upgrade-v2-json.out "Importing packages" \
        "apm --json upgrade emits clean JSON while importing"
      assert_file_not_contains /tmp/static-release-upgrade-v2-json.out "Updating profile" \
        "apm --json upgrade emits clean JSON while switching profile"
      EXPECTED_NAR_GETS_AFTER_UPGRADE=$((NAR_GETS_BEFORE_UPGRADE + 2))
      if [ "$(cache_nar_http_get_count)" = "$EXPECTED_NAR_GETS_AFTER_UPGRADE" ]; then
        pass "upgrade fetches exactly two v2 release NAR bodies"
      else
        cat /tmp/static-release-http.log || true
        fail "upgrade should fetch exactly two v2 release NAR bodies"
      fi
      if [ "$(cache_nar_count)" = "2" ]; then
        pass "upgrade leaves root and dependency v2 NARs in user cache"
      else
        fail "upgrade should cache exactly two v2 release NARs"
      fi
      assert_store_valid "$ROOT_V2_STORE" "closure-root-v2"
      assert_store_valid "$LEAF_V2_STORE" "closure-leaf-v2"
      assert_store_missing "$ROOT_V2_SOURCE_STORE" "closure-root-source-v2"
      "$PROFILE/current/bin/closure-root" > /tmp/static-release-run-v2.out
      assert_file_contains /tmp/static-release-run-v2.out \
        "^closure-root 2.0.0 via closure-leaf 2.0.0$" \
        "upgraded release closure executes with its v2 dependency"
      if [ ! -L "$PROFILE/current/src/$ROOT_SOURCE_HASH" ]; then
        pass "source root for v1 release is removed after upgrade"
      else
        fail "source root for v1 release should be removed after upgrade"
      fi
      if [ -L "$PROFILE/current/src/$ROOT_V2_SOURCE_HASH" ]; then
        pass "upgraded release closure roots v2 source provenance"
      else
        fail "upgraded release closure should root v2 source provenance"
      fi
      $APM source static-closure --verify \
        > /tmp/static-release-source-verify-v2.out 2>&1 || {
        cat /tmp/static-release-source-verify-v2.out
        fail "apm source --verify validates upgraded release source provenance"
      }
      cat /tmp/static-release-source-verify-v2.out
      assert_file_contains /tmp/static-release-source-verify-v2.out "Downloading 1 NAR" \
        "apm source --verify fetches missing v2 source path"
      assert_file_contains /tmp/static-release-source-verify-v2.out "$ROOT_V2_SOURCE_STORE" \
        "apm source --verify uses v2 release source path"
      assert_file_contains /tmp/static-release-source-verify-v2.out "matches installed binary" \
        "apm source --verify compares v2 release source with installed binary"
      assert_store_valid "$ROOT_V2_SOURCE_STORE" "closure-root-source-v2"

      kill "$ORIGIN_PID" 2>/dev/null || true
      wait "$ORIGIN_PID" 2>/dev/null || true
      check_fail
    '';
  };
}
