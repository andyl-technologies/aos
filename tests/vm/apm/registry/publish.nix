# Registry VM checks for publish workflows.
{
  testing,
  pkgs,
  aosPkg,
  fixtures,
  publishDeps,
  publishSysrootImage,
  publishSysrootDisk,
  publishSysrootInfo,
  publishSysrootUki,
  setupNixPublishEnv,
  setupAltNixPublishEnv,
}: {
  # -------------------------------------------------------------------------
  # registry-publish — Publish a package entry to the registry
  # -------------------------------------------------------------------------
  registry-publish = testing.mkVMTest {
    name = "apm-registry-publish";
    rootfsDeps = publishDeps ++ [pkgs.jq];
    memory = 512;
    testScript = ''
      ${fixtures.setupPreamble}
      ${setupNixPublishEnv}

      echo "==> Test: publish a package to registry"

      REG_DIR="$REG_STORAGE/test-reg"
      $APR --json create test-reg > /tmp/create-test-reg.json 2>&1 || {
        cat /tmp/create-test-reg.json
        fail "apr --json create initializes registry"
      }
      ${pkgs.jq}/bin/jq -e --arg reg "$REG_DIR" \
        '.action == "create"
          and .registry == "test-reg"
          and .path == $reg
          and .remote == null
          and .trust_key_id == null
          and .current == "stable"
          and (.head | length == 64)
          and (.branches | any(.name == "stable" and .current == true))' \
        /tmp/create-test-reg.json >/dev/null || {
        cat /tmp/create-test-reg.json
        fail "apr --json create reports initialized registry"
      }
      pass "apr --json create reports initialized registry"

      $APR --json publish ${aosPkg} \
        --name testpkg \
        --version 1.0.0 \
        --description "Published by the APR VM workflow" \
        --license MIT \
        --maintainer test \
        --registry test-reg > /tmp/publish-testpkg-v1.json 2>&1 || {
        cat /tmp/publish-testpkg-v1.json
        fail "apr --json publish creates package metadata"
      }
      if ${pkgs.jq}/bin/jq -e --arg store "${aosPkg}" \
        '.action == "publish"
          and .registry == "test-reg"
          and .package == "testpkg"
          and .version == "1.0.0"
          and .platform == "x86_64-linux"
          and .store_path == $store
          and (.nar_hash | startswith("sha256:"))
          and (.nar_size > 0)
          and (.closure_size > 0)
          and .sysroot == false
          and .previous == null
          and .images == []
          and .package_file == "packages/t/testpkg.toml"
          and .committed == true
          and .commit_message == "publish testpkg 1.0.0 (x86_64-linux)"
          and .current == "stable"
          and (.head | length == 64)' \
        /tmp/publish-testpkg-v1.json >/dev/null; then
        pass "apr --json publish reports committed package metadata"
      else
        cat /tmp/publish-testpkg-v1.json
        fail "apr --json publish reports committed package metadata"
      fi

      # Verify packages/t/testpkg.toml exists
      assert_file_exists "$REG_DIR/packages/t/testpkg.toml" \
        "package TOML file exists"

      # Verify TOML has required fields
      assert_file_contains "$REG_DIR/packages/t/testpkg.toml" \
        "store_path" "TOML has store_path"
      assert_file_contains "$REG_DIR/packages/t/testpkg.toml" \
        "nar_hash" "TOML has nar_hash"

      STORE_HASH=$(basename ${aosPkg} | cut -d- -f1)
      assert_file_exists "$REG_DIR/store/$(printf %.2s "$STORE_HASH")/$STORE_HASH" \
        "apr publish writes store realisation record"
      # References no longer live in the package TOML (RFC-0005): the per-path
      # store record carries them as `ia:` dependency edges instead.
      assert_file_contains "$REG_DIR/store/$(printf %.2s "$STORE_HASH")/$STORE_HASH" \
        "ia:sha256:" "store record lists dependency edges"

      # Verify git log shows the publish commit
      cd "$REG_DIR"
      assert_cmd_output_contains "git log --oneline" "publish testpkg" \
        "git log shows publish commit"
      cd /tmp

      $APR publish ${pkgs.curl} \
        --name testpkg \
        --version 2.0.0 \
        --description "Published by the APR VM workflow" \
        --license MIT \
        --maintainer test \
        --registry test-reg

      CURL_HASH=$(basename ${pkgs.curl} | cut -d- -f1)
      assert_file_exists "$REG_DIR/store/$(printf %.2s "$CURL_HASH")/$CURL_HASH" \
        "apr publish writes v2 store realisation record"

      $APR packages --registry test-reg > /tmp/packages.out 2>&1 || {
        cat /tmp/packages.out
        fail "apr packages lists published packages"
      }
      cat /tmp/packages.out
      assert_file_contains /tmp/packages.out "testpkg 2.0.0" \
        "apr packages reports latest published version"
      if grep -q "testpkg 1.0.0" /tmp/packages.out; then
        fail "apr packages should not report the older version as current"
      else
        pass "apr packages does not report the older version as current"
      fi
      $APR --json packages --registry test-reg > /tmp/packages.json 2>&1 || {
        cat /tmp/packages.json
        fail "apr --json packages lists published packages"
      }
      ${pkgs.jq}/bin/jq -e \
        'length == 1 and .[0].name == "testpkg" and .[0].version == "2.0.0"' \
        /tmp/packages.json >/dev/null || {
        cat /tmp/packages.json
        fail "apr --json packages reports latest published version"
      }
      pass "apr --json packages reports latest published version"

      $APR packages --registry test-reg --outdated \
        > /tmp/packages-outdated.out 2>&1 || {
        cat /tmp/packages-outdated.out
        fail "apr packages --outdated lists multi-version packages"
      }
      assert_file_contains /tmp/packages-outdated.out "testpkg 2.0.0" \
        "apr packages --outdated reports the latest available version"

      $APR show testpkg --registry test-reg --version 1.0.0 \
        > /tmp/show-v1.out 2>&1 || {
        cat /tmp/show-v1.out
        fail "apr show --version selects existing version"
      }
      assert_file_contains /tmp/show-v1.out "Version: 1.0.0" \
        "apr show --version prints selected v1"
      if grep -q "Version: 2.0.0" /tmp/show-v1.out; then
        cat /tmp/show-v1.out
        fail "apr show --version should not print v2"
      else
        pass "apr show --version hides non-selected versions"
      fi
      $APR --json show testpkg --registry test-reg --version 1.0.0 \
        > /tmp/show-v1.json 2>&1 || {
        cat /tmp/show-v1.json
        fail "apr --json show --version selects existing version"
      }
      ${pkgs.jq}/bin/jq -e --arg store "${aosPkg}" \
        '.package.name == "testpkg"
          and (.versions | length) == 1
          and .versions[0].version == "1.0.0"
          and .versions[0].platforms."x86_64-linux".store_path == $store' \
        /tmp/show-v1.json >/dev/null || {
        cat /tmp/show-v1.json
        fail "apr --json show --version reports only selected v1"
      }
      pass "apr --json show --version reports only selected v1"

      $APR show testpkg --registry test-reg --version 1.0.0 --raw \
        > /tmp/show-v1-raw.out 2>&1 || {
        cat /tmp/show-v1-raw.out
        fail "apr show --version --raw selects existing version"
      }
      assert_file_contains /tmp/show-v1-raw.out "version = \"1.0.0\"" \
        "apr show --version --raw prints selected v1"
      if grep -q "version = \"2.0.0\"" /tmp/show-v1-raw.out; then
        cat /tmp/show-v1-raw.out
        fail "apr show --version --raw should not print v2"
      else
        pass "apr show --version --raw hides non-selected versions"
      fi

      if $APR show testpkg --registry test-reg --version 9.9.9 \
        > /tmp/show-missing-version.out 2>&1; then
        cat /tmp/show-missing-version.out
        fail "apr show should reject missing versions"
      else
        assert_file_contains /tmp/show-missing-version.out \
          "does not contain version '9.9.9'" \
          "apr show reports missing requested version"
      fi

      check_fail
    '';
  };

  # -------------------------------------------------------------------------
  # registry-publish-alt-nix-state — Publish against re-rooted Nix state
  # -------------------------------------------------------------------------
  registry-publish-alt-nix-state = testing.mkVMTest {
    name = "apm-registry-publish-alt-nix-state";
    rootfsDeps = publishDeps;
    memory = 1024;
    testScript = ''
      ${fixtures.setupPreamble}
      ${setupAltNixPublishEnv}

      echo "==> Test: apr publish honors alternate Nix state DB"

      $APR create alt-state-reg
      REG_DIR="$REG_STORAGE/alt-state-reg"
      echo "local maintainer note" > "$REG_DIR/maintainer-notes.txt"

      $APR publish ${aosPkg} \
        --name alt-state-pkg \
        --version 1.0.0 \
        --description "Published from alternate Nix state" \
        --license MIT \
        --maintainer alt-state@example.invalid \
        --registry alt-state-reg > /tmp/alt-state-publish.out 2>&1 || {
        cat /tmp/alt-state-publish.out
        fail "apr publish succeeds using AOS_NIX_STATE_DIR"
      }
      cat /tmp/alt-state-publish.out

      assert_file_exists "$REG_DIR/packages/a/alt-state-pkg.toml" \
        "alternate-state publish writes package metadata"
      assert_file_contains "$REG_DIR/packages/a/alt-state-pkg.toml" \
        "store_path = \"${aosPkg}\"" \
        "alternate-state publish records the requested store path"
      assert_file_contains "$REG_DIR/packages/a/alt-state-pkg.toml" \
        "nar_hash" "alternate-state publish records NAR hash"

      STORE_HASH=$(basename ${aosPkg} | cut -d- -f1)
      assert_file_exists "$REG_DIR/store/$(printf %.2s "$STORE_HASH")/$STORE_HASH" \
        "alternate-state publish writes store realisation record"
      assert_file_contains "$REG_DIR/store/$(printf %.2s "$STORE_HASH")/$STORE_HASH" "nar:sha256:" \
        "alternate-state store record carries a realisation header"
      if git -C "$REG_DIR" ls-tree -r --name-only HEAD | grep -q "maintainer-notes.txt"; then
        fail "apr publish should not commit unrelated maintainer scratch files"
      else
        pass "apr publish leaves unrelated maintainer scratch files out of HEAD"
      fi
      git -C "$REG_DIR" status --short --untracked-files=all \
        > /tmp/alt-state-publish-status.out
      assert_file_contains /tmp/alt-state-publish-status.out \
        "maintainer-notes.txt" \
        "apr publish leaves unrelated maintainer scratch file untracked"
      rm -f "$REG_DIR/maintainer-notes.txt"

      $APR verify --registry alt-state-reg > /tmp/alt-state-verify.out 2>&1 || {
        cat /tmp/alt-state-verify.out
        fail "apr verify accepts alternate-state published registry"
      }
      assert_file_contains /tmp/alt-state-verify.out "no errors" \
        "apr verify validates alternate-state published registry"

      check_fail
    '';
  };

  # -------------------------------------------------------------------------
  # registry-publish-sysroot — Publish a sysroot package with images
  # -------------------------------------------------------------------------
  registry-publish-sysroot = testing.mkVMTest {
    name = "apm-registry-publish-sysroot";
    rootfsDeps =
      publishDeps
      ++ [
        publishSysrootImage
        publishSysrootDisk
        publishSysrootInfo
        publishSysrootUki
      ];
    memory = 512;
    testScript = ''
      ${fixtures.setupPreamble}
      ${setupNixPublishEnv}

      echo "==> Test: publish sysroot package with images"

      # Create registry
      $APR create test-reg
      REG_DIR="$REG_STORAGE/test-reg"

      $APR publish ${aosPkg} \
        --name server \
        --version 2026.03 \
        --description "Published sysroot by the APR VM workflow" \
        --license MIT \
        --maintainer test \
        --sysroot \
        --image-payload ${publishSysrootImage} \
        --image-disk ${publishSysrootDisk} \
        --image-info ${publishSysrootInfo} \
        --image-format raw \
        --image-uki ${publishSysrootUki}/systemd-bootx64.efi \
        --registry test-reg

      # Verify sysroot flag
      assert_file_contains "$REG_DIR/packages/s/server.toml" \
        "sysroot = true" "TOML has sysroot = true"

      # Verify images block
      assert_file_contains "$REG_DIR/packages/s/server.toml" \
        "format = \"raw\"" "TOML has image format"
      assert_file_contains "$REG_DIR/packages/s/server.toml" \
        "images" "TOML has images section"

      check_fail
    '';
  };
}
