# Packages VM checks for command surface workflows.
{
  testing,
  pkgs,
  fixtures,
  surfaceLeafTool,
  surfaceTool,
  surfaceUpgradeV1,
  surfaceUpgradeV2,
  sourcefulV1,
  sourcefulV2,
  sourcefulSourceV1,
  sourcefulSourceV2,
  sourceClosureRuntime,
  sourceClosureSourceDep,
  sourceClosureSourceRoot,
  realCommandSurfaceDeps,
  setupNixEnv,
}: {
  # -------------------------------------------------------------------------
  # 15. command-surface — Real APM command surface workflow
  # -------------------------------------------------------------------------
  command-surface = testing.mkVMTest {
    name = "apm-command-surface";
    rootfsDeps = realCommandSurfaceDeps;
    memory = 2048;
    testScript = ''
      ${fixtures.setupPreamble}
      ${setupNixEnv}

      echo "==> Test: real APM command surface workflow"

      SURFACE_STORE="${surfaceTool}"
      LEAF_STORE="${surfaceLeafTool}"
      UPGRADE_V1_STORE="${surfaceUpgradeV1}"
      UPGRADE_V2_STORE="${surfaceUpgradeV2}"
      SOURCE_V1_STORE="${sourcefulV1}"
      SOURCE_V2_STORE="${sourcefulV2}"
      SOURCE_V1_SRC_STORE="${sourcefulSourceV1}"
      SOURCE_V2_SRC_STORE="${sourcefulSourceV2}"
      SOURCE_CLOSURE_STORE="${sourceClosureRuntime}"
      SOURCE_CLOSURE_SRC_STORE="${sourceClosureSourceRoot}"
      SOURCE_CLOSURE_DEP_STORE="${sourceClosureSourceDep}"
      SURFACE_HASH=$(basename "$SURFACE_STORE" | cut -d- -f1)
      LEAF_HASH=$(basename "$LEAF_STORE" | cut -d- -f1)
      UPGRADE_V1_HASH=$(basename "$UPGRADE_V1_STORE" | cut -d- -f1)
      UPGRADE_V2_HASH=$(basename "$UPGRADE_V2_STORE" | cut -d- -f1)
      SOURCE_V1_HASH=$(basename "$SOURCE_V1_STORE" | cut -d- -f1)
      SOURCE_V2_HASH=$(basename "$SOURCE_V2_STORE" | cut -d- -f1)
      SOURCE_V1_SRC_HASH=$(basename "$SOURCE_V1_SRC_STORE" | cut -d- -f1)
      SOURCE_V2_SRC_HASH=$(basename "$SOURCE_V2_SRC_STORE" | cut -d- -f1)
      SOURCE_CLOSURE_HASH=$(basename "$SOURCE_CLOSURE_STORE" | cut -d- -f1)
      SOURCE_CLOSURE_SRC_HASH=$(basename "$SOURCE_CLOSURE_SRC_STORE" | cut -d- -f1)
      SOURCE_CLOSURE_DEP_HASH=$(basename "$SOURCE_CLOSURE_DEP_STORE" | cut -d- -f1)
      PROFILE="/var/lib/profiles/per-user/surfaceuser"
      SURFACE_BIN="$PROFILE/current/bin/surfacepkg"
      LEAF_BIN="$PROFILE/current/bin/surface-leaf"
      UPGRADE_BIN="$PROFILE/current/bin/upgradeface"
      SOURCE_BIN="$PROFILE/current/bin/sourceful"
      JQ="${pkgs.jq}/bin/jq"

      assert_file_not_contains() {
        if grep -q "$2" "$1" 2>/dev/null; then
          fail "$3 (pattern '$2' unexpectedly found in $1)"
          cat "$1" 2>/dev/null || true
        else
          pass "$3"
        fi
      }

      assert_symlink_exists() {
        if [ -L "$1" ]; then
          pass "$2"
        else
          fail "$2 (symlink not found: $1)"
        fi
      }

      assert_symlink_not_exists() {
        if [ -L "$1" ]; then
          fail "$2 (symlink should not exist: $1)"
        else
          pass "$2"
        fi
      }

      assert_store_valid() {
        path="$1"
        label="$2"
        if nix-store --check-validity "$path" > "/tmp/surface-valid-$label.out" 2>&1; then
          pass "$label valid in store"
        else
          cat "/tmp/surface-valid-$label.out"
          fail "$label should be valid in store"
        fi
      }

      assert_store_missing() {
        path="$1"
        label="$2"
        if nix-store --check-validity "$path" > "/tmp/surface-missing-$label.out" 2>&1; then
          cat "/tmp/surface-missing-$label.out"
          fail "$label should be missing from store"
        else
          pass "$label missing from store"
        fi
      }

      delete_store_path() {
        path="$1"
        label="$2"
        if nix-store --delete --ignore-liveness "$path" > "/tmp/surface-delete-$label.out" 2>&1; then
          pass "$label deleted before apm download"
        else
          cat "/tmp/surface-delete-$label.out"
          fail "$label should be deletable before apm download"
          return 1
        fi
        assert_store_missing "$path" "$label"
      }

      generation_count() {
        find "$PROFILE" -maxdepth 1 -type d -name 'gen-*' | wc -l | tr -d ' '
      }

      wait_for_cache_server() {
        for _i in 1 2 3 4 5 6 7 8 9 10; do
          if curl -sf http://127.0.0.1:18105/nix-cache-info >/dev/null; then
            return 0
          fi
          sleep 1
        done
        return 1
      }

      publish_surface_package() {
        $APR publish "$SURFACE_STORE" \
          --name surfacepkg \
          --version 1.0.0 \
          --description "Surface command fixture" \
          --homepage https://example.invalid/surfacepkg \
          --license MIT \
          --maintainer surface@example.invalid \
          --registry surface-reg \
          --no-commit > /tmp/surface-publish-surfacepkg.out 2>&1 || {
          cat /tmp/surface-publish-surfacepkg.out
          fail "apr publish surfacepkg succeeds"
          return 1
        }
        cat /tmp/surface-publish-surfacepkg.out
      }

      publish_leaf_package() {
        $APR publish "$LEAF_STORE" \
          --name surface-leaf \
          --version 1.0.0 \
          --description "Surface dependency fixture" \
          --license MIT \
          --maintainer surface@example.invalid \
          --registry surface-reg \
          --no-commit > /tmp/surface-publish-leaf.out 2>&1 || {
          cat /tmp/surface-publish-leaf.out
          fail "apr publish surface-leaf succeeds"
          return 1
        }
        cat /tmp/surface-publish-leaf.out
      }

      publish_upgradeface() {
        version="$1"
        store="$2"
        label="$3"
        $APR publish "$store" \
          --name upgradeface \
          --version "$version" \
          --description "Upgradable command fixture" \
          --license MIT \
          --maintainer surface@example.invalid \
          --registry surface-reg \
          --no-commit > "/tmp/surface-publish-upgradeface-$label.out" 2>&1 || {
          cat "/tmp/surface-publish-upgradeface-$label.out"
          fail "apr publish upgradeface $version succeeds"
          return 1
        }
        cat "/tmp/surface-publish-upgradeface-$label.out"
      }

      publish_sourceful() {
        version="$1"
        store="$2"
        source_store="$3"
        label="$4"
        $APR publish "$store" \
          --name sourceful \
          --version "$version" \
          --description "Source derivation command fixture" \
          --license MIT \
          --maintainer surface@example.invalid \
          --source-drv "$source_store" \
          --registry surface-reg \
          --no-commit > "/tmp/surface-publish-sourceful-$label.out" 2>&1 || {
          cat "/tmp/surface-publish-sourceful-$label.out"
          fail "apr publish sourceful $version succeeds"
          return 1
        }
        cat "/tmp/surface-publish-sourceful-$label.out"
        assert_file_contains "/tmp/surface-publish-sourceful-$label.out" "$source_store" \
          "apr publish sourceful $version reports explicit source metadata"
      }

      publish_sourceclosure() {
        $APR publish "$SOURCE_CLOSURE_STORE" \
          --name sourceclosure \
          --version 1.0.0 \
          --description "Source closure command fixture" \
          --license MIT \
          --maintainer surface@example.invalid \
          --source-drv "$SOURCE_CLOSURE_SRC_STORE" \
          --registry surface-reg \
          --no-commit > /tmp/surface-publish-sourceclosure.out 2>&1 || {
          cat /tmp/surface-publish-sourceclosure.out
          fail "apr publish sourceclosure succeeds"
          return 1
        }
        cat /tmp/surface-publish-sourceclosure.out
        assert_file_contains /tmp/surface-publish-sourceclosure.out "$SOURCE_CLOSURE_SRC_STORE" \
          "apr publish sourceclosure reports explicit source metadata"
      }

      generate_surface_cache() {
        label="$1"
        $APR cache generate \
          --registry surface-reg \
          --output /tmp/surface-cache \
          --cache-url http://127.0.0.1:18105 \
          --priority 65 \
          --no-commit > "/tmp/surface-cache-generate-$label.out" 2>&1 || {
          cat "/tmp/surface-cache-generate-$label.out"
          fail "apr cache generate $label succeeds"
          return 1
        }
        cat "/tmp/surface-cache-generate-$label.out"
      }

      commit_surface_registry() {
        message="$1"
        git -C "$REG_DIR" add -A
        git -C "$REG_DIR" commit -m "$message" > /tmp/surface-git-commit.out 2>&1 || {
          cat /tmp/surface-git-commit.out
          fail "registry commit succeeds: $message"
          return 1
        }
        cat /tmp/surface-git-commit.out
      }

      run_ok() {
        label="$1"
        shift
        if "$@" > "/tmp/surface-$label.out" 2>&1; then
          pass "$label exits 0"
        else
          cat "/tmp/surface-$label.out"
          fail "$label should exit 0"
        fi
      }

      run_fail() {
        label="$1"
        shift
        if "$@" > "/tmp/surface-$label.out" 2>&1; then
          cat "/tmp/surface-$label.out"
          fail "$label should fail"
        else
          pass "$label fails as expected"
        fi
      }

      mount -o remount,rw / || true
      assert_store_valid "$SURFACE_STORE" "surfacepkg"
      assert_store_valid "$LEAF_STORE" "surface-leaf"
      assert_store_valid "$UPGRADE_V1_STORE" "upgradeface-v1"
      assert_store_valid "$UPGRADE_V2_STORE" "upgradeface-v2"
      assert_store_valid "$SOURCE_V1_STORE" "sourceful-v1"
      assert_store_valid "$SOURCE_V2_STORE" "sourceful-v2"
      assert_store_valid "$SOURCE_V1_SRC_STORE" "sourceful-source-v1"
      assert_store_valid "$SOURCE_V2_SRC_STORE" "sourceful-source-v2"
      assert_store_valid "$SOURCE_CLOSURE_STORE" "sourceclosure-runtime"
      assert_store_valid "$SOURCE_CLOSURE_SRC_STORE" "sourceclosure-source-root"
      assert_store_valid "$SOURCE_CLOSURE_DEP_STORE" "sourceclosure-source-helper"
      nix-store -q --references "$SURFACE_STORE" > /tmp/surface-refs.out
      assert_file_contains /tmp/surface-refs.out "$LEAF_STORE" \
        "surfacepkg has a real Nix reference to surface-leaf"

      echo "==> Maintainer: publish initial command-surface packages"
      $APR create surface-reg
      REG_DIR="$REG_STORAGE/surface-reg"
      DEFAULT_BRANCH=$(git -C "$REG_DIR" symbolic-ref --short HEAD)
      publish_leaf_package
      publish_surface_package
      publish_upgradeface 1.0.0 "$UPGRADE_V1_STORE" v1
      publish_sourceful 1.0.0 "$SOURCE_V1_STORE" "$SOURCE_V1_SRC_STORE" v1
      publish_sourceclosure
      assert_file_contains "$REG_DIR/packages/s/surfacepkg.toml" \
        "$SURFACE_HASH" "published surfacepkg metadata records store hash"
      assert_file_contains "$REG_DIR/packages/s/surface-leaf.toml" \
        "$LEAF_HASH" "published surface-leaf metadata records store hash"
      assert_file_contains "$REG_DIR/packages/s/sourceful.toml" \
        "$SOURCE_V1_HASH" "published sourceful metadata records store hash"
      assert_file_contains "$REG_DIR/packages/s/sourceful.toml" \
        "$SOURCE_V1_SRC_STORE" "published sourceful metadata records distinct source path"
      assert_file_contains "$REG_DIR/packages/s/sourceclosure.toml" \
        "$SOURCE_CLOSURE_SRC_STORE" "published sourceclosure metadata records source root"
      assert_file_contains "$REG_DIR/store/$(printf %.2s "$SURFACE_HASH")/$SURFACE_HASH" \
        "$LEAF_HASH" "published surfacepkg closure records dependency"
      nix-store -q --references "$SOURCE_CLOSURE_SRC_STORE" > /tmp/surface-sourceclosure-refs.out
      assert_file_contains /tmp/surface-sourceclosure-refs.out "$SOURCE_CLOSURE_DEP_STORE" \
        "sourceclosure source root has a real source-only dependency reference"

      generate_surface_cache initial
      assert_file_exists "/tmp/surface-cache/$SURFACE_HASH.narinfo" \
        "static cache has surfacepkg narinfo"
      assert_file_exists "/tmp/surface-cache/$LEAF_HASH.narinfo" \
        "static cache has surface-leaf narinfo"
      assert_file_exists "/tmp/surface-cache/$UPGRADE_V1_HASH.narinfo" \
        "static cache has upgradeface v1 narinfo"
      assert_file_exists "/tmp/surface-cache/$SOURCE_V1_HASH.narinfo" \
        "static cache has sourceful v1 narinfo"
      assert_file_exists "/tmp/surface-cache/$SOURCE_V1_SRC_HASH.narinfo" \
        "static cache has sourceful v1 source narinfo"
      assert_file_exists "/tmp/surface-cache/$SOURCE_CLOSURE_HASH.narinfo" \
        "static cache has sourceclosure runtime narinfo"
      assert_file_exists "/tmp/surface-cache/$SOURCE_CLOSURE_SRC_HASH.narinfo" \
        "static cache has sourceclosure source root narinfo"
      assert_file_exists "/tmp/surface-cache/$SOURCE_CLOSURE_DEP_HASH.narinfo" \
        "static cache has sourceclosure source-only dependency narinfo"
      assert_file_contains "$REG_DIR/registry.toml" \
        "http://127.0.0.1:18105" "registry records command-surface cache URL"

      commit_surface_registry "release: command surface initial packages"
      git init --bare --object-format=sha256 /tmp/surface-origin.git
      git -C "$REG_DIR" remote add origin /tmp/surface-origin.git
      git -C "$REG_DIR" push origin "$DEFAULT_BRANCH"

      ${pkgs.iproute2}/sbin/ip link set lo up || true
      ${pkgs.iproute2}/sbin/ip addr add 127.0.0.1/8 dev lo 2>/dev/null || true
      PYTHONUNBUFFERED=1 python3 -m http.server 18105 --bind 127.0.0.1 \
        --directory /tmp/surface-cache > /tmp/surface-cache-http.log 2>&1 &
      CACHE_PID=$!
      if wait_for_cache_server; then
        pass "static cache HTTP server started"
      else
        cat /tmp/surface-cache-http.log || true
        fail "static cache HTTP server started"
      fi

      echo "==> Consumer: install command-surface packages through apm"
      export HOME=/tmp/surface-consumer
      export USER=surfaceuser
      APM_CONFIG="$HOME/.config/apm"
      mkdir -p "$HOME"
      $APM registry add --no-verify file:///tmp/surface-origin.git \
        --name surface-reg \
        --branch "$DEFAULT_BRANCH" > /tmp/surface-registry-add.out 2>&1 || {
        cat /tmp/surface-registry-add.out
        fail "apm registry add syncs command-surface registry"
      }
      cat /tmp/surface-registry-add.out

      delete_store_path "$SURFACE_STORE" "surfacepkg"
      delete_store_path "$LEAF_STORE" "surface-leaf"
      delete_store_path "$UPGRADE_V1_STORE" "upgradeface-v1"
      delete_store_path "$SOURCE_V1_STORE" "sourceful-v1"
      delete_store_path "$SOURCE_V1_SRC_STORE" "sourceful-source-v1"
      delete_store_path "$SOURCE_CLOSURE_SRC_STORE" "sourceclosure-source-root"
      delete_store_path "$SOURCE_CLOSURE_DEP_STORE" "sourceclosure-source-helper"
      rm -rf "$HOME/.cache/apm"
      mkdir -p "$HOME/.cache/apm"

      $APM --json install surfacepkg --registry surface-reg --yes > /tmp/surface-install.json 2>&1 || {
        cat /tmp/surface-install.json
        fail "apm install downloads surfacepkg closure"
      }
      "$JQ" -e \
        --arg surface "$SURFACE_STORE" \
        --arg leaf "$LEAF_STORE" \
        '.action == "install"
          and .status == "installed"
          and .requested == ["surfacepkg"]
          and .reinstall == false
          and .download_only == false
          and .no_deps == false
          and .dry_run == false
          and .generation == 1
          and (.roots | length == 1)
          and .roots[0].name == "surfacepkg"
          and .roots[0].registry == "surface-reg"
          and .roots[0].store_path == $surface
          and .roots[0].explicit == true
          and (.closure | any(.name == "surfacepkg" and .store_path == $surface and .explicit == true))
          and (.closure | any(.name == "surface-leaf" and .store_path == $leaf and .explicit == false))
          and (.downloads.planned >= 2)
          and (.downloads.downloaded >= 2)
          and (.downloads.imported >= 2)' \
        /tmp/surface-install.json >/dev/null || {
        cat /tmp/surface-install.json
        fail "apm --json install reports real dependency install"
      }
      pass "apm --json install reports real dependency install"
      assert_store_valid "$SURFACE_STORE" "surfacepkg"
      assert_store_valid "$LEAF_STORE" "surface-leaf"
      "$SURFACE_BIN" > /tmp/surface-run.out
      assert_file_contains /tmp/surface-run.out "^surfacepkg 1.0.0 via surface-leaf 1.0.0$" \
        "installed surfacepkg executable runs from profile"
      "$LEAF_BIN" > /tmp/surface-leaf-run.out
      assert_file_contains /tmp/surface-leaf-run.out "^surface-leaf 1.0.0$" \
        "installed dependency executable runs from profile"
      assert_file_contains "$PROFILE/meta/$SURFACE_HASH.json" '"explicit": true' \
        "surfacepkg metadata is explicit"
      assert_file_contains "$PROFILE/meta/$LEAF_HASH.json" '"explicit": false' \
        "surface-leaf metadata is automatic"

      $APM install upgradeface --registry surface-reg --yes > /tmp/surface-install-upgradeface.out 2>&1 || {
        cat /tmp/surface-install-upgradeface.out
        fail "apm install downloads upgradeface v1"
      }
      cat /tmp/surface-install-upgradeface.out
      assert_store_valid "$UPGRADE_V1_STORE" "upgradeface-v1"
      "$UPGRADE_BIN" > /tmp/surface-upgradeface-v1-run.out
      assert_file_contains /tmp/surface-upgradeface-v1-run.out "^upgradeface 1.0.0$" \
        "installed upgradeface v1 executable runs from profile"

      $APM install sourceful --registry surface-reg --yes > /tmp/surface-install-sourceful.out 2>&1 || {
        cat /tmp/surface-install-sourceful.out
        fail "apm install downloads sourceful v1"
      }
      cat /tmp/surface-install-sourceful.out
      assert_file_contains /tmp/surface-install-sourceful.out "Downloading 1 NAR" \
        "sourceful install downloads v1 NAR"
      assert_file_contains /tmp/surface-install-sourceful.out "Installed 1 package" \
        "sourceful install creates profile generation"
      assert_store_valid "$SOURCE_V1_STORE" "sourceful-v1"
      "$SOURCE_BIN" > /tmp/surface-sourceful-v1-run.out
      assert_file_contains /tmp/surface-sourceful-v1-run.out "^sourceful 1.0.0$" \
        "installed sourceful v1 executable runs from profile"
      assert_file_contains "$PROFILE/meta/$SOURCE_V1_HASH.json" \
        "$SOURCE_V1_SRC_STORE" "sourceful metadata records v1 source root"
      assert_symlink_exists "$PROFILE/current/src/$SOURCE_V1_SRC_HASH" \
        "sourceful v1 source root is active after install"
      assert_store_missing "$SOURCE_V1_SRC_STORE" \
        "sourceful v1 source root before explicit fetch"
      assert_file_contains "$PROFILE/meta/$SOURCE_V1_HASH.json" '"explicit": true' \
        "sourceful metadata is explicit"

      run_ok search-desc "$APM" search Surface
      assert_file_contains /tmp/surface-search-desc.out "surfacepkg" "apm search finds descriptions"
      run_ok search-names "$APM" search surface --names-only
      assert_file_contains /tmp/surface-search-names.out "surfacepkg" "apm search --names-only finds package names"
      run_ok search-installed "$APM" search surface --installed
      assert_file_contains /tmp/surface-search-installed.out "surfacepkg" "apm search --installed filters through profile metadata"
      run_ok search-installed-json "$APM" --json search surface --installed
      "$JQ" -e \
        'map(select(.name == "surfacepkg" and .registry == "surface-reg" and .version == "1.0.0")) | length == 1' \
        /tmp/surface-search-installed-json.out >/dev/null

      run_ok show "$APM" show surfacepkg
      assert_file_contains /tmp/surface-show.out "Surface command fixture" "apm show prints package details"
      assert_file_contains /tmp/surface-show.out "Installed.*yes" "apm show sees installed profile metadata"
      assert_file_contains /tmp/surface-show.out "surface-leaf" "apm show resolves real dependency names"
      run_ok show-json "$APM" --json show surfacepkg
      "$JQ" -e --arg store "$SURFACE_STORE" \
        '.name == "surfacepkg"
          and .registry == "surface-reg"
          and .version == "1.0.0"
          and .installed == true
          and .store_path == $store
          and (.dependencies | index("surface-leaf"))' \
        /tmp/surface-show-json.out >/dev/null
      run_ok info "$APM" info surfacepkg
      assert_file_contains /tmp/surface-info.out "Surface command fixture" \
        "apm info prints real package metadata"
      run_ok info-permissions "$APM" info surfacepkg --permissions
      assert_file_contains /tmp/surface-info-permissions.out "surfacepkg" \
        "apm info --permissions resolves the real package"
      run_ok info-json "$APM" --json info surfacepkg
      "$JQ" -e --arg store "$SURFACE_STORE" \
        '.name == "surfacepkg" and .version == "1.0.0" and .store_path == $store' \
        /tmp/surface-info-json.out >/dev/null
      run_ok list "$APM" list
      assert_file_contains /tmp/surface-list.out "surfacepkg/surface-reg" "apm list includes registry package"
      run_ok list-installed "$APM" list --installed
      assert_file_contains /tmp/surface-list-installed.out "surfacepkg/surface-reg" \
        "apm list --installed reports surfacepkg"
      assert_file_contains /tmp/surface-list-installed.out "upgradeface/surface-reg" \
        "apm list --installed reports upgradeface"
      assert_file_contains /tmp/surface-list-installed.out "sourceful/surface-reg" \
        "apm list --installed reports sourceful"
      run_ok list-installed-json "$APM" --json list --installed
      "$JQ" -e \
        'map(.name) as $names
          | ($names | index("surfacepkg"))
          and ($names | index("surface-leaf"))
          and ($names | index("upgradeface"))
          and ($names | index("sourceful"))
          and (map(select(.name == "surfacepkg" and .status == "installed")) | length == 1)' \
        /tmp/surface-list-installed-json.out >/dev/null

      $APM --json hold surfacepkg > /tmp/surface-hold.json 2>&1 || {
        cat /tmp/surface-hold.json
        fail "apm hold succeeds for real installed package"
      }
      "$JQ" -e --arg store "$SURFACE_STORE" \
        '.action == "hold"
          and .status == "held"
          and .package == "surfacepkg"
          and .name == "surfacepkg"
          and .version == "1.0.0"
          and .registry == "surface-reg"
          and .store_path == $store
          and .held == true' \
        /tmp/surface-hold.json >/dev/null || {
        cat /tmp/surface-hold.json
        fail "apm --json hold reports real installed package"
      }
      run_ok list-held "$APM" list --held
      assert_file_contains /tmp/surface-list-held.out "surfacepkg/surface-reg" \
        "apm list --held reports held package"
      run_ok list-held-json "$APM" --json list --held
      "$JQ" -e \
        'length == 1
          and .[0].name == "surfacepkg"
          and .[0].registry == "surface-reg"
          and (.[0].status | contains("installed"))
          and (.[0].status | contains("held"))' \
        /tmp/surface-list-held-json.out >/dev/null
      run_ok held-json "$APM" --json held
      "$JQ" -e \
        'length == 1
          and .[0].name == "surfacepkg"
          and .[0].registry == "surface-reg"
          and .[0].version == "1.0.0"
          and (.[0].store_path | contains("surfacepkg-1.0.0"))' \
        /tmp/surface-held-json.out >/dev/null

      run_ok depends "$APM" depends surfacepkg
      assert_file_contains /tmp/surface-depends.out "surface-leaf" \
        "apm depends resolves real published dependency"
      run_ok depends-json "$APM" --json depends surfacepkg
      "$JQ" -e \
        '.package == "surfacepkg"
          and .installed == true
          and .registry == "surface-reg"
          and .tree.name == "surfacepkg"
          and (.tree.children | any(.name == "surface-leaf"))' \
        /tmp/surface-depends-json.out >/dev/null
      run_ok rdepends "$APM" rdepends surface-leaf
      assert_file_contains /tmp/surface-rdepends.out "surfacepkg" \
        "apm rdepends finds real installed reverse dependency"
      run_ok rdepends-json "$APM" --json rdepends surface-leaf
      "$JQ" -e \
        '.package == "surface-leaf"
          and .target_versions == "1.0.0"
          and (.dependents | any(.name == "surfacepkg" and .version == "1.0.0"))' \
        /tmp/surface-rdepends-json.out >/dev/null
      run_ok policy-surface "$APM" policy surfacepkg
      assert_file_contains /tmp/surface-policy-surface.out "Candidate: 1.0.0" \
        "apm policy reports current surfacepkg candidate"
      assert_file_contains /tmp/surface-policy-surface.out "Installed: 1.0.0" \
        "apm policy reports installed surfacepkg version"
      run_ok policy-surface-json "$APM" --json policy surfacepkg
      "$JQ" -e \
        '.package == "surfacepkg"
          and .installed == "1.0.0"
          and .candidate == "1.0.0"
          and (.versions | any(.version == "1.0.0" and .registry == "surface-reg" and .installed == true))' \
        /tmp/surface-policy-surface-json.out >/dev/null

      run_ok files "$APM" files surfacepkg
      assert_file_contains /tmp/surface-files.out "bin/surfacepkg" \
        "apm files walks installed store path"
      run_ok files-json "$APM" --json files surfacepkg
      "$JQ" -e 'index("bin/surfacepkg") != null' \
        /tmp/surface-files-json.out >/dev/null
      run_fail source-default "$APM" source surfacepkg
      assert_file_contains /tmp/surface-source-default.out "no source derivation recorded" \
        "apm source reports APR-published packages without source drv"
      run_fail source-fetch "$APM" source surfacepkg --fetch
      assert_file_contains /tmp/surface-source-fetch.out "no source derivation recorded" \
        "apm source --fetch reports missing source drv"
      assert_store_missing "$SOURCE_CLOSURE_SRC_STORE" \
        "sourceclosure source root before explicit fetch"
      assert_store_missing "$SOURCE_CLOSURE_DEP_STORE" \
        "sourceclosure source-only dependency before explicit fetch"
      run_ok sourceclosure-source "$APM" source sourceclosure
      assert_file_contains /tmp/surface-sourceclosure-source.out "$SOURCE_CLOSURE_SRC_STORE" \
        "apm source reports registry candidate source closure root"
      run_ok sourceclosure-fetch "$APM" source sourceclosure --fetch
      assert_file_contains /tmp/surface-sourceclosure-fetch.out "Downloading 2 NAR" \
        "apm source --fetch downloads source root and source-only dependency"
      assert_file_contains /tmp/surface-sourceclosure-fetch.out "Source realised: $SOURCE_CLOSURE_SRC_STORE" \
        "apm source --fetch realises registry candidate source closure root"
      assert_store_valid "$SOURCE_CLOSURE_SRC_STORE" "sourceclosure-source-root"
      assert_store_valid "$SOURCE_CLOSURE_DEP_STORE" "sourceclosure-source-helper"
      "$SOURCE_CLOSURE_SRC_STORE/bin/sourceclosure-source" > /tmp/surface-sourceclosure-run.out
      assert_file_contains /tmp/surface-sourceclosure-run.out \
        "^sourceclosure source 1.0.0 via sourceclosure-source-helper 1.0.0$" \
        "fetched source closure executes with its source-only dependency"
      run_ok source-sourceful "$APM" source sourceful
      assert_file_contains /tmp/surface-source-sourceful.out "$SOURCE_V1_SRC_STORE" \
        "apm source reports sourceful v1 source path"
      assert_file_contains /tmp/surface-source-sourceful.out "Source NAR hash" \
        "apm source reports sourceful source NAR hash"
      run_ok source-sourceful-json "$APM" --json source sourceful
      "$JQ" -e --arg source "$SOURCE_V1_SRC_STORE" --arg store "$SOURCE_V1_STORE" \
        '.package == "sourceful"
          and .registry == "surface-reg"
          and .source_drv == $source
          and .installed == true
          and .installed_store_path == $store
          and (.source_nar_hash | startswith("sha256:"))' \
        /tmp/surface-source-sourceful-json.out >/dev/null
      run_ok source-sourceful-show-drv "$APM" source sourceful --show-drv
      assert_file_contains /tmp/surface-source-sourceful-show-drv.out "$SOURCE_V1_SRC_STORE" \
        "apm source --show-drv reports sourceful v1 source path"
      run_ok source-sourceful-show-drv-json "$APM" --json source sourceful --show-drv
      "$JQ" -e --arg source "$SOURCE_V1_SRC_STORE" --arg store "$SOURCE_V1_STORE" \
        '.package == "sourceful"
          and .registry == "surface-reg"
          and .source_drv == $source
          and .installed == true
          and .installed_store_path == $store
          and (.source_nar_hash | startswith("sha256:"))' \
        /tmp/surface-source-sourceful-show-drv-json.out >/dev/null
      run_ok source-sourceful-fetch-json-missing "$APM" --json source sourceful --fetch
      "$JQ" -e --arg source "$SOURCE_V1_SRC_STORE" --arg store "$SOURCE_V1_STORE" \
        '.package == "sourceful"
          and .registry == "surface-reg"
          and .source_drv == $source
          and .installed == true
          and .installed_store_path == $store
          and .realised_path == $source
          and (.source_nar_hash | startswith("sha256:"))' \
        /tmp/surface-source-sourceful-fetch-json-missing.out >/dev/null
      assert_file_not_contains /tmp/surface-source-sourceful-fetch-json-missing.out "Fetching source" \
        "apm --json source --fetch emits clean JSON while downloading source"
      assert_store_valid "$SOURCE_V1_SRC_STORE" "sourceful-source-v1-json-fetch"
      delete_store_path "$SOURCE_V1_SRC_STORE" "sourceful-source-v1-after-json-fetch"
      rm -rf "$HOME/.cache/apm"
      mkdir -p "$HOME/.cache/apm"
      run_ok source-sourceful-fetch "$APM" source sourceful --fetch
      assert_file_contains /tmp/surface-source-sourceful-fetch.out "Downloading 1 NAR" \
        "apm source --fetch downloads missing sourceful v1 source NAR"
      assert_file_contains /tmp/surface-source-sourceful-fetch.out "Source realised: $SOURCE_V1_SRC_STORE" \
        "apm source --fetch realises sourceful v1 derivation"
      assert_store_valid "$SOURCE_V1_SRC_STORE" "sourceful-source-v1"
      run_ok source-sourceful-fetch-json "$APM" --json source sourceful --fetch
      "$JQ" -e --arg source "$SOURCE_V1_SRC_STORE" --arg store "$SOURCE_V1_STORE" \
        '.package == "sourceful"
          and .registry == "surface-reg"
          and .source_drv == $source
          and .installed == true
          and .installed_store_path == $store
          and .realised_path == $source
          and (.source_nar_hash | startswith("sha256:"))' \
        /tmp/surface-source-sourceful-fetch-json.out >/dev/null
      run_ok source-sourceful-verify "$APM" source sourceful --verify
      assert_file_contains /tmp/surface-source-sourceful-verify.out "$SOURCE_V1_SRC_STORE" \
        "apm source --verify uses sourceful v1 source path"
      assert_file_contains /tmp/surface-source-sourceful-verify.out "matches installed binary" \
        "apm source --verify compares sourceful rebuild with installed binary"
      delete_store_path "$SOURCE_V1_SRC_STORE" "sourceful-source-v1-before-json-verify"
      rm -rf "$HOME/.cache/apm"
      mkdir -p "$HOME/.cache/apm"
      run_ok source-sourceful-verify-json "$APM" --json source sourceful --verify
      "$JQ" -e --arg source "$SOURCE_V1_SRC_STORE" --arg store "$SOURCE_V1_STORE" \
        '.package == "sourceful"
          and .registry == "surface-reg"
          and .source_drv == $source
          and .installed == true
          and .installed_store_path == $store
          and .built_path == $source
          and .verified == true
          and (.expected_nar_hash | startswith("sha256:"))
          and (.actual_nar_hash | startswith("sha256:"))' \
        /tmp/surface-source-sourceful-verify-json.out >/dev/null
      assert_file_not_contains /tmp/surface-source-sourceful-verify-json.out "Rebuilding" \
        "apm --json source --verify emits clean JSON while downloading source"
      assert_store_valid "$SOURCE_V1_SRC_STORE" "sourceful-source-v1-json-verify"
      rm -rf "$HOME/.cache/apm"
      mkdir -p "$HOME/.cache/apm"
      $APM reinstall sourceful --yes > /tmp/surface-reinstall-sourceful.out 2>&1 || {
        cat /tmp/surface-reinstall-sourceful.out
        fail "apm reinstall downloads and rewrites sourceful v1"
      }
      cat /tmp/surface-reinstall-sourceful.out
      assert_file_contains /tmp/surface-reinstall-sourceful.out "Downloading 1 NAR" \
        "sourceful reinstall downloads v1 NAR"
      assert_file_contains /tmp/surface-reinstall-sourceful.out "Reinstalled 1 package" \
        "sourceful reinstall creates profile generation"
      "$SOURCE_BIN" > /tmp/surface-sourceful-v1-run-after-reinstall.out
      assert_file_contains /tmp/surface-sourceful-v1-run-after-reinstall.out "^sourceful 1.0.0$" \
        "sourceful v1 executable runs after reinstall"
      assert_symlink_exists "$PROFILE/current/src/$SOURCE_V1_SRC_HASH" \
        "sourceful reinstall keeps v1 source root active"
      assert_file_contains "$PROFILE/meta/$SOURCE_V1_HASH.json" \
        "$SOURCE_V1_SRC_STORE" "sourceful reinstall preserves v1 source metadata"
      run_ok verify "$APM" verify surfacepkg
      assert_file_contains /tmp/surface-verify.out "integrity verified" \
        "apm verify validates real installed NAR hash"
      run_ok verify-json "$APM" --json verify surfacepkg
      "$JQ" -e --arg store "$SURFACE_STORE" \
        '.package == "surfacepkg"
          and .registry == "surface-reg"
          and .version == "1.0.0"
          and .store_path == $store
          and .verified == true
          and (.expected_nar_hash | startswith("sha256:"))
          and (.actual_nar_hash | startswith("sha256:"))' \
        /tmp/surface-verify-json.out >/dev/null

      echo "==> Maintainer: publish command-surface upgrade candidate"
      export HOME=/tmp
      export USER=root
      APM_CONFIG="$HOME/.config/apm"
      publish_upgradeface 2.0.0 "$UPGRADE_V2_STORE" v2
      assert_file_contains "$REG_DIR/packages/u/upgradeface.toml" \
        "$UPGRADE_V2_HASH" "published upgradeface v2 metadata records store hash"
      generate_surface_cache upgrade
      assert_file_exists "/tmp/surface-cache/$UPGRADE_V2_HASH.narinfo" \
        "static cache has upgradeface v2 narinfo"
      commit_surface_registry "release: command surface upgradeface 2.0.0"
      git -C "$REG_DIR" push origin "$DEFAULT_BRANCH"

      echo "==> Consumer: query and apply real command-surface upgrade"
      export HOME=/tmp/surface-consumer
      export USER=surfaceuser
      APM_CONFIG="$HOME/.config/apm"
      delete_store_path "$UPGRADE_V2_STORE" "upgradeface-v2"

      $APM --json update --registry surface-reg > /tmp/surface-update.json 2>&1 || {
        cat /tmp/surface-update.json
        fail "apm update fetches command-surface upgrade"
      }
      "$JQ" -e \
        '.registry == "surface-reg"
          and .updated == 1
          and (.registries | length == 1)
          and .registries[0].registry == "surface-reg"
          and .registries[0].status == "updated"
          and .registries[0].packages >= 1
          and .registries[0].updated >= 1
          and .registries[0].added == 0
          and .registries[0].removed == 0
          and (.registries[0].commit | length == 64)' \
        /tmp/surface-update.json >/dev/null || {
        cat /tmp/surface-update.json
        fail "apm --json update reports command-surface upgrade sync"
      }
      pass "apm --json update reports command-surface upgrade sync"
      run_ok list-upgradable "$APM" list --upgradable
      assert_file_contains /tmp/surface-list-upgradable.out "upgradeface/surface-reg" \
        "apm list --upgradable includes upgradable package"
      assert_file_contains /tmp/surface-list-upgradable.out "upgradable: 2.0.0" \
        "apm list --upgradable reports candidate"
      assert_file_not_contains /tmp/surface-list-upgradable.out "surface-leaf" \
        "apm list --upgradable does not advertise automatic dependency"
      run_ok list-upgradable-json "$APM" --json list --upgradable
      "$JQ" -e \
        'length == 1
          and .[0].name == "upgradeface"
          and .[0].registry == "surface-reg"
          and .[0].version == "1.0.0"
          and (.[0].status | contains("installed"))
          and (.[0].status | contains("upgradable: 2.0.0"))' \
        /tmp/surface-list-upgradable-json.out >/dev/null
      run_ok policy-upgrade "$APM" policy upgradeface
      assert_file_contains /tmp/surface-policy-upgrade.out "Candidate: 2.0.0" \
        "apm policy reports upgrade candidate"
      assert_file_contains /tmp/surface-policy-upgrade.out "Installed: 1.0.0" \
        "apm policy reports installed upgradeface version"

      run_ok reinstall-dry-run "$APM" reinstall surfacepkg --dry-run
      assert_file_contains /tmp/surface-reinstall-dry-run.out "packages will be reinstalled" \
        "apm reinstall dry-run resolves installed real package"
      assert_file_contains /tmp/surface-reinstall-dry-run.out "Dry run -- no changes made" \
        "apm reinstall dry-run avoids profile mutation"
      run_ok full-upgrade-dry-run "$APM" --json full-upgrade --dry-run
      "$JQ" -e --arg store "$UPGRADE_V2_STORE" \
        '.action == "upgrade"
          and .status == "planned"
          and .requested == []
          and .exclude == []
          and .dry_run == true
          and .generation == null
          and .upgraded == 1
          and .held_back == []
          and (.upgrades | length == 1)
          and .upgrades[0].name == "upgradeface"
          and .upgrades[0].registry == "surface-reg"
          and .upgrades[0].old_version == "1.0.0"
          and .upgrades[0].new_version == "2.0.0"
          and .upgrades[0].new_store_path == $store
          and .downloads.planned == 1
          and .downloads.downloaded == 0
          and .downloads.imported == 0' \
        /tmp/surface-full-upgrade-dry-run.out >/dev/null || {
        cat /tmp/surface-full-upgrade-dry-run.out
        fail "apm --json full-upgrade dry-run reports planned upgrade"
      }
      "$UPGRADE_BIN" > /tmp/surface-upgradeface-before-full-upgrade.out
      assert_file_contains /tmp/surface-upgradeface-before-full-upgrade.out "^upgradeface 1.0.0$" \
        "dry-run leaves upgradeface v1 active"

      rm -rf "$HOME/.cache/apm"
      mkdir -p "$HOME/.cache/apm"
      $APM --json full-upgrade --yes > /tmp/surface-full-upgrade.out 2>&1 || {
        cat /tmp/surface-full-upgrade.out
        fail "apm full-upgrade downloads and activates upgradeface v2"
      }
      "$JQ" -e --arg store "$UPGRADE_V2_STORE" \
        '.action == "upgrade"
          and .status == "upgraded"
          and .requested == []
          and .exclude == []
          and .dry_run == false
          and .generation == 5
          and .upgraded == 1
          and .held_back == []
          and (.upgrades | length == 1)
          and .upgrades[0].name == "upgradeface"
          and .upgrades[0].registry == "surface-reg"
          and .upgrades[0].old_version == "1.0.0"
          and .upgrades[0].new_version == "2.0.0"
          and .upgrades[0].new_store_path == $store
          and (.downloads.planned >= 1)
          and (.downloads.downloaded >= 1)
          and (.downloads.imported >= 1)' \
        /tmp/surface-full-upgrade.out >/dev/null || {
        cat /tmp/surface-full-upgrade.out
        fail "apm --json full-upgrade reports activated upgrade"
      }
      assert_store_valid "$UPGRADE_V2_STORE" "upgradeface-v2"
      "$UPGRADE_BIN" > /tmp/surface-upgradeface-v2-run.out
      assert_file_contains /tmp/surface-upgradeface-v2-run.out "^upgradeface 2.0.0$" \
        "full-upgraded executable runs from profile"
      run_ok rollback-list-json "$APM" --json rollback --list
      "$JQ" -e \
        'map(select(.current == true)) as $current
          | ($current | length == 1)
          and ($current[0].roots | map(.package.name) | index("surfacepkg"))
          and ($current[0].roots | map(.package.name) | index("upgradeface"))
          and ($current[0].roots | map(.package.name) | index("sourceful"))' \
        /tmp/surface-rollback-list-json.out >/dev/null

      echo "==> Maintainer: publish newer sourceful candidate"
      export HOME=/tmp
      export USER=root
      APM_CONFIG="$HOME/.config/apm"
      publish_sourceful 2.0.0 "$SOURCE_V2_STORE" "$SOURCE_V2_SRC_STORE" v2
      assert_file_contains "$REG_DIR/packages/s/sourceful.toml" \
        "$SOURCE_V2_HASH" "published sourceful v2 metadata records store hash"
      assert_file_contains "$REG_DIR/packages/s/sourceful.toml" \
        "$SOURCE_V2_SRC_STORE" "published sourceful v2 metadata records distinct source path"
      generate_surface_cache source-v2
      assert_file_exists "/tmp/surface-cache/$SOURCE_V2_HASH.narinfo" \
        "static cache has sourceful v2 narinfo"
      assert_file_exists "/tmp/surface-cache/$SOURCE_V2_SRC_HASH.narinfo" \
        "static cache has sourceful v2 source narinfo"
      commit_surface_registry "release: command surface sourceful 2.0.0"
      git -C "$REG_DIR" push origin "$DEFAULT_BRANCH"

      echo "==> Consumer: source verification follows installed sourceful metadata"
      export HOME=/tmp/surface-consumer
      export USER=surfaceuser
      APM_CONFIG="$HOME/.config/apm"
      delete_store_path "$SOURCE_V2_STORE" "sourceful-v2"
      $APM update --registry surface-reg > /tmp/surface-update-sourceful.out 2>&1 || {
        cat /tmp/surface-update-sourceful.out
        fail "apm update fetches sourceful v2 metadata"
      }
      cat /tmp/surface-update-sourceful.out
      run_ok list-upgradable-sourceful "$APM" list --upgradable
      assert_file_contains /tmp/surface-list-upgradable-sourceful.out "sourceful/surface-reg" \
        "apm list --upgradable includes sourceful v2 candidate"
      assert_file_contains /tmp/surface-list-upgradable-sourceful.out "upgradable: 2.0.0" \
        "apm list --upgradable reports sourceful candidate version"
      run_ok source-sourceful-installed "$APM" source sourceful
      assert_file_contains /tmp/surface-source-sourceful-installed.out "$SOURCE_V1_SRC_STORE" \
        "apm source uses installed sourceful v1 source path after v2 appears"
      assert_file_not_contains /tmp/surface-source-sourceful-installed.out "$SOURCE_V2_SRC_STORE" \
        "apm source does not use latest uninstalled sourceful v2 source path"
      run_ok source-sourceful-show-drv-installed "$APM" source sourceful --show-drv
      assert_file_contains /tmp/surface-source-sourceful-show-drv-installed.out "$SOURCE_V1_SRC_STORE" \
        "apm source --show-drv uses installed sourceful v1 source path after v2 appears"
      assert_file_not_contains /tmp/surface-source-sourceful-show-drv-installed.out "$SOURCE_V2_SRC_STORE" \
        "apm source --show-drv does not use latest uninstalled sourceful v2 source path"
      run_ok source-sourceful-fetch-installed "$APM" source sourceful --fetch
      assert_file_contains /tmp/surface-source-sourceful-fetch-installed.out "Source realised: $SOURCE_V1_SRC_STORE" \
        "apm source --fetch realises installed sourceful v1 source path after v2 appears"
      assert_file_not_contains /tmp/surface-source-sourceful-fetch-installed.out "$SOURCE_V2_SRC_STORE" \
        "apm source --fetch does not realise latest uninstalled sourceful v2 source path"
      run_ok source-sourceful-verify-installed "$APM" source sourceful --verify
      assert_file_contains /tmp/surface-source-sourceful-verify-installed.out "$SOURCE_V1_SRC_STORE" \
        "apm source --verify uses installed sourceful v1 source path after v2 appears"
      assert_file_not_contains /tmp/surface-source-sourceful-verify-installed.out "$SOURCE_V2_SRC_STORE" \
        "apm source --verify does not use latest uninstalled sourceful v2 source path"
      assert_file_contains /tmp/surface-source-sourceful-verify-installed.out "matches installed binary" \
        "apm source --verify still validates installed sourceful v1"
      "$SOURCE_BIN" > /tmp/surface-sourceful-still-v1-run.out
      assert_file_contains /tmp/surface-sourceful-still-v1-run.out "^sourceful 1.0.0$" \
        "sourceful remains v1 until explicitly upgraded"

      echo "==> Consumer: upgrade sourceful and replace source roots"
      $APM upgrade sourceful --yes > /tmp/surface-upgrade-sourceful.out 2>&1 || {
        cat /tmp/surface-upgrade-sourceful.out
        fail "apm upgrade downloads and activates sourceful v2"
      }
      cat /tmp/surface-upgrade-sourceful.out
      assert_file_contains /tmp/surface-upgrade-sourceful.out "Downloading" \
        "sourceful upgrade downloads v2 NAR"
      assert_file_contains /tmp/surface-upgrade-sourceful.out "Upgraded 1 package" \
        "sourceful upgrade creates profile generation"
      assert_store_valid "$SOURCE_V2_STORE" "sourceful-v2"
      "$SOURCE_BIN" > /tmp/surface-sourceful-v2-run.out
      assert_file_contains /tmp/surface-sourceful-v2-run.out "^sourceful 2.0.0$" \
        "sourceful v2 executable runs after upgrade"
      assert_symlink_not_exists "$PROFILE/current/src/$SOURCE_V1_SRC_HASH" \
        "sourceful upgrade removes old v1 source root from current generation"
      assert_symlink_exists "$PROFILE/current/src/$SOURCE_V2_SRC_HASH" \
        "sourceful upgrade activates v2 source root"
      assert_file_contains "$PROFILE/meta/$SOURCE_V2_HASH.json" \
        "$SOURCE_V2_SRC_STORE" "sourceful metadata records v2 source root"

      run_ok clean "$APM" --json clean
      "$JQ" -e \
        '.action == "clean"
          and .mode == "cache"
          and .status == "cleaned"
          and .files_removed >= 1
          and .freed_bytes > 0
          and (.freed | length > 0)' \
        /tmp/surface-clean.out >/dev/null || {
        cat /tmp/surface-clean.out
        fail "apm --json clean reports removed NAR cache files"
      }
      if find "$HOME/.cache/apm" -name '*.nar.zst' | grep -q .; then
        fail "apm clean should remove cached NAR files"
      else
        pass "apm clean removed cached NAR files"
      fi
      run_ok clean-generations "$APM" --json clean --generations --keep 1
      "$JQ" -e \
        '.action == "clean"
          and .mode == "generations"
          and .status == "cleaned"
          and .keep == 1
          and .removed >= 1
          and (.removed_generations | length >= 1)
          and .generations_after_count <= 1' \
        /tmp/surface-clean-generations.out >/dev/null || {
        cat /tmp/surface-clean-generations.out
        fail "apm --json clean --generations reports pruned command-surface generations"
      }
      if [ "$(generation_count)" -le 1 ]; then
        pass "apm clean --generations keeps at most one old generation"
      else
        fail "apm clean --generations should prune old generations"
      fi
      run_ok gc-help "$APM" gc --help
      assert_file_contains /tmp/surface-gc-help.out "garbage collection" \
        "apm gc command surface is present without mutating the VM store"

      echo "==> Consumer: disable and re-enable registry with real installed packages"
      SURFACE_REG_CONFIG="$APM_CONFIG/registries.d/surface-reg.toml"
      $APM --json registry disable surface-reg > /tmp/surface-registry-disable.json 2>&1 || {
        cat /tmp/surface-registry-disable.json
        fail "apm registry disable succeeds for command-surface registry"
      }
      "$JQ" -e \
        --arg config "$SURFACE_REG_CONFIG" \
        '.action == "registry_disable"
          and .status == "disabled"
          and .registry == "surface-reg"
          and .enabled == false
          and .previous_enabled == true
          and .changed == true
          and .config == $config
          and .packages >= 4' \
        /tmp/surface-registry-disable.json >/dev/null || {
        cat /tmp/surface-registry-disable.json
        fail "apm --json registry disable reports command-surface registry state"
      }
      pass "apm --json registry disable reports command-surface registry state"
      assert_file_contains "$SURFACE_REG_CONFIG" "enabled = false" \
        "apm registry disable persists command-surface disabled state"
      $APM --json registry disable surface-reg > /tmp/surface-registry-disable-again.json 2>&1 || {
        cat /tmp/surface-registry-disable-again.json
        fail "apm registry disable is idempotent for command-surface registry"
      }
      "$JQ" -e \
        --arg config "$SURFACE_REG_CONFIG" \
        '.action == "registry_disable"
          and .status == "unchanged"
          and .registry == "surface-reg"
          and .enabled == false
          and .previous_enabled == false
          and .changed == false
          and .config == $config
          and .packages >= 4' \
        /tmp/surface-registry-disable-again.json >/dev/null || {
        cat /tmp/surface-registry-disable-again.json
        fail "idempotent apm --json registry disable reports unchanged state"
      }
      pass "idempotent apm --json registry disable reports unchanged state"
      run_ok registry-disable-text-again "$APM" registry disable surface-reg
      assert_file_contains /tmp/surface-registry-disable-text-again.out "already disabled" \
        "idempotent text-mode registry disable reports unchanged state"
      run_ok registry-list-disabled "$APM" registry list
      assert_file_contains /tmp/surface-registry-list-disabled.out "disabled" \
        "apm registry list reports command-surface registry disabled"
      run_ok search-disabled "$APM" --json search surfacepkg --registry surface-reg
      "$JQ" -e 'length == 0' /tmp/surface-search-disabled.out >/dev/null || {
        cat /tmp/surface-search-disabled.out
        fail "disabled registry search hides registry packages"
      }
      run_ok search-installed-disabled "$APM" --json search surfacepkg --installed --registry surface-reg
      "$JQ" -e \
        'length == 1
          and .[0].name == "surfacepkg"
          and .[0].registry == "surface-reg"
          and .[0].version == "1.0.0"
          and .[0].description == "installed package unavailable in registry"' \
        /tmp/surface-search-installed-disabled.out >/dev/null || {
        cat /tmp/surface-search-installed-disabled.out
        fail "disabled registry installed search uses profile metadata"
      }
      pass "disabled registry installed search uses profile metadata"
      if $APM --json update --registry surface-reg > /tmp/surface-update-disabled.json 2>&1; then
        cat /tmp/surface-update-disabled.json
        fail "apm update should reject disabled command-surface registry"
      else
        pass "apm update rejects disabled command-surface registry"
      fi
      assert_file_contains /tmp/surface-update-disabled.json "registry 'surface-reg' is not enabled" \
        "disabled registry update failure names disabled registry"
      run_ok orphans-disabled "$APM" orphans
      assert_file_contains /tmp/surface-orphans-disabled.out "No orphaned packages" \
        "disabled configured registry does not orphan command-surface packages"
      "$SURFACE_BIN" > /tmp/surface-run-while-disabled.out
      assert_file_contains /tmp/surface-run-while-disabled.out "^surfacepkg 1.0.0 via surface-leaf 1.0.0$" \
        "installed surfacepkg executable still runs while registry is disabled"

      $APM --json registry enable surface-reg > /tmp/surface-registry-enable.json 2>&1 || {
        cat /tmp/surface-registry-enable.json
        fail "apm registry enable succeeds for command-surface registry"
      }
      "$JQ" -e \
        --arg config "$SURFACE_REG_CONFIG" \
        '.action == "registry_enable"
          and .status == "enabled"
          and .registry == "surface-reg"
          and .enabled == true
          and .previous_enabled == false
          and .changed == true
          and .config == $config
          and .packages >= 4' \
        /tmp/surface-registry-enable.json >/dev/null || {
        cat /tmp/surface-registry-enable.json
        fail "apm --json registry enable reports command-surface registry state"
      }
      pass "apm --json registry enable reports command-surface registry state"
      assert_file_contains "$SURFACE_REG_CONFIG" "enabled = true" \
        "apm registry enable persists command-surface enabled state"
      run_ok registry-enable-text-again "$APM" registry enable surface-reg
      assert_file_contains /tmp/surface-registry-enable-text-again.out "already enabled" \
        "idempotent text-mode registry enable reports unchanged state"
      $APM --json update --registry surface-reg > /tmp/surface-update-reenabled.json 2>&1 || {
        cat /tmp/surface-update-reenabled.json
        fail "apm update succeeds after command-surface registry re-enable"
      }
      "$JQ" -e \
        '.registry == "surface-reg"
          and (.registries | length == 1)
          and .registries[0].registry == "surface-reg"
          and (.registries[0].status == "updated" or .registries[0].status == "current")
          and .registries[0].packages >= 4' \
        /tmp/surface-update-reenabled.json >/dev/null || {
        cat /tmp/surface-update-reenabled.json
        fail "apm --json update reports re-enabled command-surface registry"
      }
      pass "apm --json update reports re-enabled command-surface registry"
      run_ok verify-after-registry-enable "$APM" verify surfacepkg
      assert_file_contains /tmp/surface-verify-after-registry-enable.out "integrity verified" \
        "apm verify validates package after registry re-enable"

      run_ok orphans-none "$APM" orphans
      assert_file_contains /tmp/surface-orphans-none.out "No orphaned packages" \
        "apm orphans reports clean state while registry is configured"
      assert_dir_exists "$HOME/.local/share/apm/registries/surface-reg" \
        "local registry clone exists before registry remove"
      $APM registry remove surface-reg --keep-local > /tmp/surface-registry-remove.out 2>&1 || {
        cat /tmp/surface-registry-remove.out
        fail "apm registry remove --keep-local succeeds after real installs"
      }
      cat /tmp/surface-registry-remove.out
      assert_file_contains /tmp/surface-registry-remove.out "Registry 'surface-reg' removed" \
        "apm registry remove reports removed registry"
      assert_file_contains /tmp/surface-registry-remove.out "now orphaned" \
        "apm registry remove reports installed packages become orphans"
      assert_file_not_exists "$APM_CONFIG/registries.d/surface-reg.toml" \
        "apm registry remove deletes registry config"
      assert_dir_exists "$HOME/.local/share/apm/registries/surface-reg" \
        "apm registry remove --keep-local keeps local clone"
      run_ok orphans-removed "$APM" orphans
      assert_file_contains /tmp/surface-orphans-removed.out "surfacepkg" \
        "apm orphans lists package from removed registry"
      assert_file_contains /tmp/surface-orphans-removed.out "surface-leaf" \
        "apm orphans lists automatic dependency from removed registry"
      assert_file_contains /tmp/surface-orphans-removed.out "upgradeface" \
        "apm orphans lists additional package from removed registry"
      assert_file_contains /tmp/surface-orphans-removed.out "sourceful" \
        "apm orphans lists sourceful package from removed registry"
      assert_file_contains /tmp/surface-orphans-removed.out "removed registry 'surface-reg'" \
        "apm orphans names the removed registry"
      run_ok orphans-removed-json "$APM" --json orphans
      "$JQ" -e \
        'map(.name) as $names
          | ($names | index("surfacepkg"))
          and ($names | index("surface-leaf"))
          and ($names | index("upgradeface"))
          and ($names | index("sourceful"))
          and (map(select(.name == "surface-leaf" and .explicit == false)) | length == 1)
          and (map(select(.registry == "surface-reg")) | length == 4)' \
        /tmp/surface-orphans-removed-json.out >/dev/null

      run_ok source-sourceful-verify-after-registry-remove "$APM" source sourceful --verify
      assert_file_contains /tmp/surface-source-sourceful-verify-after-registry-remove.out \
        "$SOURCE_V2_SRC_STORE" \
        "apm source --verify uses installed source metadata after registry removal"
      assert_file_contains /tmp/surface-source-sourceful-verify-after-registry-remove.out \
        "matches installed binary" \
        "apm source --verify validates orphaned installed sourceful package"

      echo "==> Consumer: remove orphaned sourceful package and source root"
      $APM remove sourceful --yes > /tmp/surface-remove-sourceful.out 2>&1 || {
        cat /tmp/surface-remove-sourceful.out
        fail "apm remove sourceful succeeds after registry removal"
      }
      cat /tmp/surface-remove-sourceful.out
      assert_file_contains /tmp/surface-remove-sourceful.out "Removed 1 package" \
        "apm remove reports sourceful removal"
      if [ -e "$SOURCE_BIN" ]; then
        fail "sourceful executable should be absent after removal"
      else
        pass "sourceful executable absent after removal"
      fi
      assert_symlink_not_exists "$PROFILE/current/src/$SOURCE_V2_SRC_HASH" \
        "sourceful remove drops v2 source root from current generation"
      assert_file_not_exists "$PROFILE/meta/$SOURCE_V2_HASH.json" \
        "sourceful metadata removed after sourceful removal"

      if kill "$CACHE_PID" 2>/dev/null; then
        pass "static cache HTTP server stopped"
      fi
      wait "$CACHE_PID" 2>/dev/null || true
      check_fail
    '';
  };
}
