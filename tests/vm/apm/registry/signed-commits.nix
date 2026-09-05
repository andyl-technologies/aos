# Registry VM checks for signed commits workflows.
{
  testing,
  pkgs,
  fixtures,
  maintainerWorkflowDeps,
  setupNixPublishEnv,
  signedLeafToolV1,
  signedToolV1,
  signedLeafToolV2,
  signedToolV2,
  signedLeafToolV3,
  signedToolV3,
  signedLeafToolV4,
  signedToolV4,
  signedLeafToolV5,
  signedToolV5,
}: {
  # -------------------------------------------------------------------------
  # registry-signed-commit-trust — Trusted commit signatures for git sync
  # -------------------------------------------------------------------------
  registry-signed-commit-trust = testing.mkVMTest {
    name = "apm-registry-signed-commit-trust";
    rootfsDeps =
      maintainerWorkflowDeps
      ++ [
        signedLeafToolV1
        signedToolV1
        signedLeafToolV2
        signedToolV2
        signedLeafToolV3
        signedToolV3
        signedLeafToolV4
        signedToolV4
        signedLeafToolV5
        signedToolV5
      ];
    memory = 2048;
    testScript = ''
      ${fixtures.setupPreamble}
      ${setupNixPublishEnv}

      echo "==> Test: trusted signed commits for registry sync"

      export GIT_CONFIG_NOSYSTEM=1
      export GIT_CONFIG_GLOBAL=/tmp/empty-gitconfig
      : > "$GIT_CONFIG_GLOBAL"

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
        if nix-store --check-validity "$path" > "/tmp/signed-valid-$label.out" 2>&1; then
          pass "$label valid in store"
        else
          cat "/tmp/signed-valid-$label.out"
          fail "$label should be valid in store"
        fi
      }

      assert_store_missing() {
        path="$1"
        label="$2"
        if nix-store --check-validity "$path" > "/tmp/signed-missing-$label.out" 2>&1; then
          cat "/tmp/signed-missing-$label.out"
          fail "$label should be missing from store"
        else
          pass "$label missing from store"
        fi
      }

      delete_store_path() {
        path="$1"
        label="$2"
        if nix-store --delete --ignore-liveness "$path" > "/tmp/signed-delete-$label.out" 2>&1; then
          pass "$label deleted before apm download"
        else
          cat "/tmp/signed-delete-$label.out"
          fail "$label should be deletable before apm download"
          return 1
        fi
        assert_store_missing "$path" "$label"
      }

      wait_for_cache_server() {
        for _i in 1 2 3 4 5 6 7 8 9 10; do
          if curl -sf http://127.0.0.1:18106/nix-cache-info >/dev/null; then
            return 0
          fi
          sleep 1
        done
        return 1
      }

      # `apr release` is the only producer command that seals TUF metadata
      # (root/targets/snapshot/timestamp) into a signed commit: it publishes the
      # store path, generates + uploads the static cache, signs the commit, and
      # creates the signed release tag. Consumers reject any synced commit whose
      # TUF metadata is missing or stale, so the legacy `apr publish --no-commit`
      # + hand `git commit -S` flow no longer authorizes a sync.
      release_signed_tool() {
        version="$1"
        store="$2"
        key="$3"
        label="$4"
        shift 4
        $APR release "$version" \
          --registry signed-reg \
          --store-path "$store" \
          --name signed-tool \
          --description "Signed commit trust workflow tool" \
          --license MIT \
          --maintainer signed-commit@example.invalid \
          --key "$key" \
          --cache-key /tmp/signed-cache.sec \
          --cache-url http://127.0.0.1:18106 \
          --cache-priority 52 \
          --upload-url file:///tmp/signed-cache \
          "$@" > "/tmp/signed-release-$label.out" 2>&1 || {
          cat "/tmp/signed-release-$label.out"
          fail "apr release signed-tool $version ($label) succeeds"
          return 1
        }
        cat "/tmp/signed-release-$label.out"
      }

      # A metadata-only release re-seals TUF without publishing a package. It is
      # used to re-seal the root after a roster change (rotation/retirement),
      # because `apr keys add`/`apr keys retire` commit the roster but do not
      # re-seal the TUF root themselves.
      reseal_release() {
        version="$1"
        key="$2"
        label="$3"
        shift 3
        $APR release "$version" \
          --registry signed-reg \
          --key "$key" \
          --cache-key /tmp/signed-cache.sec \
          --cache-url http://127.0.0.1:18106 \
          --cache-priority 52 \
          --upload-url file:///tmp/signed-cache \
          "$@" > "/tmp/signed-reseal-$label.out" 2>&1 || {
          cat "/tmp/signed-reseal-$label.out"
          fail "apr reseal release $version ($label) succeeds"
          return 1
        }
        cat "/tmp/signed-reseal-$label.out"
      }

      # Re-sign only the HEAD commit with a different key, leaving the sealed TUF
      # tree untouched. Used to forge a commit whose TUF metadata is valid (good
      # key) but whose commit signature is from an untrusted/retired key, so the
      # consumer's rejection is specifically a commit-signature failure.
      amend_commit() {
        key="$1"
        label="$2"
        git -C "$REG_DIR" \
          -c gpg.format=ssh \
          -c "user.signingkey=$key" \
          commit --amend --no-edit -S > "/tmp/signed-amend-$label.out" 2>&1 || {
          cat "/tmp/signed-amend-$label.out"
          fail "re-sign commit $label succeeds"
          return 1
        }
        git -C "$REG_DIR" cat-file -p HEAD > "/tmp/signed-amend-$label.object"
        assert_file_contains "/tmp/signed-amend-$label.object" \
          "BEGIN SSH SIGNATURE" "re-signed commit $label carries SSH signature"
      }

      push_branch() {
        git -C "$REG_DIR" push origin "$DEFAULT_BRANCH" \
          > /tmp/signed-push.out 2>&1 || {
          cat /tmp/signed-push.out
          fail "git push signed-reg branch"
          return 1
        }
      }

      GOOD_KEY=/tmp/signed-commit-good
      BAD_KEY=/tmp/signed-commit-bad
      NEXT_KEY=/tmp/signed-commit-next
      ssh-keygen -q -t ed25519 -N "" -f "$GOOD_KEY"
      ssh-keygen -q -t ed25519 -N "" -f "$BAD_KEY"
      ssh-keygen -q -t ed25519 -N "" -f "$NEXT_KEY"
      GOOD_PUBLIC=$(cut -d ' ' -f2 < "$GOOD_KEY.pub")
      NEXT_PUBLIC=$(cut -d ' ' -f2 < "$NEXT_KEY.pub")
      TRUST_KEY="signed-reg:Ed25519:$GOOD_PUBLIC"
      NEXT_TRUST_KEY="signed-reg:Ed25519:$NEXT_PUBLIC"

      TOOL_V1_STORE="${signedToolV1}"
      TOOL_V1_DEP_STORE="${signedLeafToolV1}"
      TOOL_V2_STORE="${signedToolV2}"
      TOOL_V2_DEP_STORE="${signedLeafToolV2}"
      TOOL_V3_STORE="${signedToolV3}"
      TOOL_V3_DEP_STORE="${signedLeafToolV3}"
      TOOL_V4_STORE="${signedToolV4}"
      TOOL_V4_DEP_STORE="${signedLeafToolV4}"
      TOOL_V5_STORE="${signedToolV5}"
      TOOL_V5_DEP_STORE="${signedLeafToolV5}"
      TOOL_V1_HASH=$(basename "$TOOL_V1_STORE" | cut -d- -f1)
      TOOL_V1_DEP_HASH=$(basename "$TOOL_V1_DEP_STORE" | cut -d- -f1)
      TOOL_V2_HASH=$(basename "$TOOL_V2_STORE" | cut -d- -f1)
      TOOL_V2_DEP_HASH=$(basename "$TOOL_V2_DEP_STORE" | cut -d- -f1)
      TOOL_V3_HASH=$(basename "$TOOL_V3_STORE" | cut -d- -f1)
      TOOL_V3_DEP_HASH=$(basename "$TOOL_V3_DEP_STORE" | cut -d- -f1)
      TOOL_V4_HASH=$(basename "$TOOL_V4_STORE" | cut -d- -f1)
      TOOL_V4_DEP_HASH=$(basename "$TOOL_V4_DEP_STORE" | cut -d- -f1)
      TOOL_V5_HASH=$(basename "$TOOL_V5_STORE" | cut -d- -f1)
      TOOL_V5_DEP_HASH=$(basename "$TOOL_V5_DEP_STORE" | cut -d- -f1)

      mount -o remount,rw / || true
      nix-store -q --references "$TOOL_V1_STORE" > /tmp/signed-v1-refs.out
      assert_file_contains /tmp/signed-v1-refs.out "$TOOL_V1_DEP_STORE" \
        "signed-tool v1 root has a real dependency closure"
      nix-store -q --references "$TOOL_V2_STORE" > /tmp/signed-v2-refs.out
      assert_file_contains /tmp/signed-v2-refs.out "$TOOL_V2_DEP_STORE" \
        "signed-tool v2 root has a real dependency closure"
      nix-store -q --references "$TOOL_V3_STORE" > /tmp/signed-v3-refs.out
      assert_file_contains /tmp/signed-v3-refs.out "$TOOL_V3_DEP_STORE" \
        "signed-tool v3 root has a real dependency closure"
      nix-store -q --references "$TOOL_V4_STORE" > /tmp/signed-v4-refs.out
      assert_file_contains /tmp/signed-v4-refs.out "$TOOL_V4_DEP_STORE" \
        "signed-tool v4 root has a real dependency closure"
      nix-store -q --references "$TOOL_V5_STORE" > /tmp/signed-v5-refs.out
      assert_file_contains /tmp/signed-v5-refs.out "$TOOL_V5_DEP_STORE" \
        "signed-tool v5 root has a real dependency closure"
      assert_store_valid "$TOOL_V1_STORE" "signed-tool-v1"
      assert_store_valid "$TOOL_V1_DEP_STORE" "signed-leaf-v1"
      assert_store_valid "$TOOL_V2_STORE" "signed-tool-v2"
      assert_store_valid "$TOOL_V2_DEP_STORE" "signed-leaf-v2"
      assert_store_valid "$TOOL_V3_STORE" "signed-tool-v3"
      assert_store_valid "$TOOL_V3_DEP_STORE" "signed-leaf-v3"
      assert_store_valid "$TOOL_V4_STORE" "signed-tool-v4"
      assert_store_valid "$TOOL_V4_DEP_STORE" "signed-leaf-v4"
      assert_store_valid "$TOOL_V5_STORE" "signed-tool-v5"
      assert_store_valid "$TOOL_V5_DEP_STORE" "signed-leaf-v5"

      echo "==> Maintainer: release signed-tool 1.0.0 with trusted commit key"
      $APR create signed-reg --trust-key "$TRUST_KEY" --trust-key-id initial \
        --key "$GOOD_KEY"
      REG_DIR="$REG_STORAGE/signed-reg"
      DEFAULT_BRANCH=$(git -C "$REG_DIR" symbolic-ref --short HEAD)
      assert_file_contains "$REG_DIR/keys.toml" 'id = "initial"' \
        "registry records initial commit signing key id"
      assert_file_contains "$REG_DIR/keys.toml" "$TRUST_KEY" \
        "registry records initial commit signing key value"

      git init --bare --object-format=sha256 /tmp/signed-origin.git
      git -C /tmp/signed-origin.git symbolic-ref HEAD "refs/heads/$DEFAULT_BRANCH"
      git -C "$REG_DIR" remote add origin /tmp/signed-origin.git

      ${pkgs.iproute2}/sbin/ip link set lo up || true
      ${pkgs.iproute2}/sbin/ip addr add 127.0.0.1/8 dev lo 2>/dev/null || true

      nix --extra-experimental-features nix-command key generate-secret \
        --key-name signed-cache > /tmp/signed-cache.sec

      release_signed_tool 1.0.0 "$TOOL_V1_STORE" "$GOOD_KEY" v1
      assert_file_exists "/tmp/signed-cache/$TOOL_V1_HASH.narinfo" \
        "static cache has signed-tool v1 narinfo"
      assert_file_exists "/tmp/signed-cache/$TOOL_V1_DEP_HASH.narinfo" \
        "static cache has signed-tool v1 dependency narinfo"
      assert_file_contains "$REG_DIR/registry.toml" \
        "http://127.0.0.1:18106" "registry records signed cache URL"
      assert_file_exists "$REG_DIR/tuf/root.json" \
        "release seals TUF root metadata into the registry tree"
      git -C "$REG_DIR" cat-file -p HEAD > /tmp/signed-head-v1.object
      assert_file_contains /tmp/signed-head-v1.object \
        "BEGIN SSH SIGNATURE" "release commit v1 carries SSH signature"
      push_branch

      PYTHONUNBUFFERED=1 python3 -m http.server 18106 --bind 127.0.0.1 \
        --directory /tmp/signed-cache > /tmp/signed-cache-http.log 2>&1 &
      CACHE_PID=$!
      if wait_for_cache_server; then
        pass "signed static cache HTTP server started"
      else
        cat /tmp/signed-cache-http.log || true
        fail "signed static cache HTTP server started"
      fi

      echo "==> Consumer: add trusted signed registry and install v1"
      export HOME=/tmp/signed-consumer
      export USER=signeduser
      APM_CONFIG="$HOME/.config/apm"
      mkdir -p "$HOME"

      $APM registry add file:///tmp/signed-origin.git \
        --name signed-reg \
        --branch "$DEFAULT_BRANCH" \
        --trust-key "$TRUST_KEY" > /tmp/signed-add.out 2>&1 || {
        cat /tmp/signed-add.out
        fail "apm registry add syncs trusted signed registry"
      }
      cat /tmp/signed-add.out
      assert_file_contains /tmp/signed-add.out "Signing.*trusted key.*pinned" \
        "registry add reports pinned signing key"
      CONFIG_FILE="$APM_CONFIG/registries.d/signed-reg.toml"
      assert_file_contains "$CONFIG_FILE" "required = true" \
        "consumer config requires signed commits"
      assert_file_contains "$CONFIG_FILE" "$TRUST_KEY" \
        "consumer config stores trusted signing key"
      assert_file_contains "$HOME/.local/share/apm/registries/signed-reg/registry.toml" \
        "http://127.0.0.1:18106" "signed registry sync materializes cache endpoint"
      assert_file_contains "$HOME/.local/share/apm/registries/signed-reg/keys.toml" \
        'id = "initial"' "signed registry sync materializes initial trust roster"
      assert_file_contains "$HOME/.local/share/apm/registries/signed-reg/keys.toml" \
        "$TRUST_KEY" "signed registry sync materializes initial trust key"

      $APM search signed-tool --registry signed-reg > /tmp/signed-search-v1.out 2>&1 || {
        cat /tmp/signed-search-v1.out
        fail "apm search sees trusted signed v1"
      }
      assert_file_contains /tmp/signed-search-v1.out "1.0.0" \
        "trusted signed registry exposes v1"

      delete_store_path "$TOOL_V1_STORE" "signed-tool-v1"
      delete_store_path "$TOOL_V1_DEP_STORE" "signed-leaf-v1"
      rm -rf "$HOME/.cache/apm"
      mkdir -p "$HOME/.cache/apm"
      $APM install signed-tool --registry signed-reg --yes \
        > /tmp/signed-install-v1.out 2>&1 || {
        cat /tmp/signed-install-v1.out
        fail "apm install downloads trusted signed v1"
      }
      cat /tmp/signed-install-v1.out
      assert_file_contains /tmp/signed-install-v1.out "Downloading 2 NAR" \
        "apm install downloads signed v1 closure"
      assert_store_valid "$TOOL_V1_STORE" "signed-tool-v1"
      assert_store_valid "$TOOL_V1_DEP_STORE" "signed-leaf-v1"
      PROFILE_TOOL="/var/lib/profiles/per-user/$USER/current/bin/signed-tool"
      "$PROFILE_TOOL" > /tmp/signed-run-v1.out
      assert_file_contains /tmp/signed-run-v1.out \
        "^signed-tool 1.0.0 via signed-leaf 1.0.0$" \
        "trusted signed v1 executable runs through dependency"

      echo "==> Maintainer: release v2 sealed by the trusted key, commit re-signed wrong"
      export HOME=/tmp
      export USER=root
      APM_CONFIG="$HOME/.config/apm"
      # Seal v2's TUF with the trusted key, then re-sign only the commit with an
      # untrusted key: the tree (and TUF metadata) stay valid, isolating the
      # rejection to the commit signature.
      release_signed_tool 2.0.0 "$TOOL_V2_STORE" "$GOOD_KEY" v2-bad --previous 1.0.0
      assert_file_exists "/tmp/signed-cache/$TOOL_V2_HASH.narinfo" \
        "static cache has signed-tool v2 narinfo"
      assert_file_exists "/tmp/signed-cache/$TOOL_V2_DEP_HASH.narinfo" \
        "static cache has signed-tool v2 dependency narinfo"
      amend_commit "$BAD_KEY" v2-bad
      push_branch

      echo "==> Consumer: reject wrong-key registry update"
      export HOME=/tmp/signed-consumer
      export USER=signeduser
      APM_CONFIG="$HOME/.config/apm"
      if $APM update --registry signed-reg > /tmp/signed-update-bad.out 2>&1; then
        cat /tmp/signed-update-bad.out
        fail "apm update should reject commit signed by wrong key"
      else
        cat /tmp/signed-update-bad.out
        pass "apm update rejects commit signed by wrong key"
      fi
      assert_file_contains /tmp/signed-update-bad.out \
        "commit signature verification failed" \
        "wrong-key update reports signature verification failure"
      $APM search signed-tool --registry signed-reg > /tmp/signed-search-after-bad.out 2>&1 || {
        cat /tmp/signed-search-after-bad.out
        fail "apm search still works after rejected signed update"
      }
      assert_file_contains /tmp/signed-search-after-bad.out "1.0.0" \
        "rejected signed update leaves v1 metadata active"
      assert_file_not_contains /tmp/signed-search-after-bad.out "2.0.0" \
        "rejected signed update does not expose wrong-key v2"
      "$PROFILE_TOOL" > /tmp/signed-run-after-bad.out
      assert_file_contains /tmp/signed-run-after-bad.out \
        "^signed-tool 1.0.0 via signed-leaf 1.0.0$" \
        "wrong-key update leaves installed v1 active"

      echo "==> Maintainer: release v3 sealed and signed by the trusted key"
      export HOME=/tmp
      export USER=root
      APM_CONFIG="$HOME/.config/apm"
      release_signed_tool 3.0.0 "$TOOL_V3_STORE" "$GOOD_KEY" v3-good --previous 2.0.0
      assert_file_exists "/tmp/signed-cache/$TOOL_V3_HASH.narinfo" \
        "static cache has signed-tool v3 narinfo"
      assert_file_exists "/tmp/signed-cache/$TOOL_V3_DEP_HASH.narinfo" \
        "static cache has signed-tool v3 dependency narinfo"
      push_branch

      echo "==> Consumer: recover on trusted signed update and upgrade"
      export HOME=/tmp/signed-consumer
      export USER=signeduser
      APM_CONFIG="$HOME/.config/apm"
      delete_store_path "$TOOL_V3_STORE" "signed-tool-v3"
      delete_store_path "$TOOL_V3_DEP_STORE" "signed-leaf-v3"
      rm -rf "$HOME/.cache/apm"
      mkdir -p "$HOME/.cache/apm"
      $APM update --registry signed-reg > /tmp/signed-update-good.out 2>&1 || {
        cat /tmp/signed-update-good.out
        fail "apm update accepts trusted signed v3"
      }
      cat /tmp/signed-update-good.out
      $APM list --upgradable > /tmp/signed-upgradable-v3.out 2>&1 || {
        cat /tmp/signed-upgradable-v3.out
        fail "apm list --upgradable sees trusted v3"
      }
      assert_file_contains /tmp/signed-upgradable-v3.out "signed-tool" \
        "trusted signed v3 update names package"
      assert_file_contains /tmp/signed-upgradable-v3.out "3.0.0" \
        "trusted signed v3 update reports candidate"

      $APM upgrade signed-tool --yes > /tmp/signed-upgrade-v3.out 2>&1 || {
        cat /tmp/signed-upgrade-v3.out
        fail "apm upgrade downloads trusted signed v3"
      }
      cat /tmp/signed-upgrade-v3.out
      assert_file_contains /tmp/signed-upgrade-v3.out "Downloading 2 NAR" \
        "apm upgrade downloads signed v3 closure"
      assert_store_valid "$TOOL_V3_STORE" "signed-tool-v3"
      assert_store_valid "$TOOL_V3_DEP_STORE" "signed-leaf-v3"
      "$PROFILE_TOOL" > /tmp/signed-run-v3.out
      assert_file_contains /tmp/signed-run-v3.out \
        "^signed-tool 3.0.0 via signed-leaf 3.0.0$" \
        "trusted signed v3 executable runs through dependency"

      echo "==> Maintainer: rotate trust roster to add a new signing key, release v4"
      export HOME=/tmp
      export USER=root
      APM_CONFIG="$HOME/.config/apm"
      # Add the next key to the roster in a commit signed by the still-trusted
      # initial key, then re-seal + publish v4 on top. The consumer accepts the
      # rotation because it is delivered by a currently-trusted key.
      $APR keys add next "$NEXT_TRUST_KEY" --registry signed-reg \
        --key "$GOOD_KEY" > /tmp/signed-keys-add-next.out 2>&1 || {
        cat /tmp/signed-keys-add-next.out
        fail "apr keys add next succeeds"
      }
      cat /tmp/signed-keys-add-next.out
      assert_file_contains "$REG_DIR/keys.toml" 'id = "next"' \
        "registry records next commit signing key id"
      assert_file_contains "$REG_DIR/keys.toml" "$NEXT_TRUST_KEY" \
        "registry records next commit signing key value"
      release_signed_tool 4.0.0 "$TOOL_V4_STORE" "$GOOD_KEY" v4 --previous 3.0.0
      assert_file_exists "/tmp/signed-cache/$TOOL_V4_HASH.narinfo" \
        "static cache has signed-tool v4 narinfo"
      push_branch

      echo "==> Consumer: accept roster rotation and upgrade to v4"
      export HOME=/tmp/signed-consumer
      export USER=signeduser
      APM_CONFIG="$HOME/.config/apm"
      delete_store_path "$TOOL_V4_STORE" "signed-tool-v4"
      delete_store_path "$TOOL_V4_DEP_STORE" "signed-leaf-v4"
      rm -rf "$HOME/.cache/apm"
      mkdir -p "$HOME/.cache/apm"
      $APM update --registry signed-reg > /tmp/signed-update-rotate.out 2>&1 || {
        cat /tmp/signed-update-rotate.out
        fail "apm update accepts roster rotation signed by existing key"
      }
      cat /tmp/signed-update-rotate.out
      assert_file_contains "$HOME/.local/share/apm/registries/signed-reg/keys.toml" \
        'id = "next"' "consumer materializes rotated trust key id"
      assert_file_contains "$HOME/.local/share/apm/registries/signed-reg/keys.toml" \
        "$NEXT_TRUST_KEY" "consumer materializes rotated trust key value"
      $APM upgrade signed-tool --yes > /tmp/signed-upgrade-v4.out 2>&1 || {
        cat /tmp/signed-upgrade-v4.out
        fail "apm upgrade downloads signed v4"
      }
      cat /tmp/signed-upgrade-v4.out
      assert_file_contains /tmp/signed-upgrade-v4.out "Downloading 2 NAR" \
        "apm upgrade downloads signed v4 closure"
      assert_store_valid "$TOOL_V4_STORE" "signed-tool-v4"
      assert_store_valid "$TOOL_V4_DEP_STORE" "signed-leaf-v4"
      "$PROFILE_TOOL" > /tmp/signed-run-v4.out
      assert_file_contains /tmp/signed-run-v4.out \
        "^signed-tool 4.0.0 via signed-leaf 4.0.0$" \
        "rotated-roster v4 executable runs through dependency"

      echo "==> Maintainer: release v5 with a commit signed by the rotated key"
      export HOME=/tmp
      export USER=root
      APM_CONFIG="$HOME/.config/apm"
      # Seal v5 with the trusted initial key, then re-sign the commit with the
      # rotated next key (now an active roster member): the consumer accepts it.
      release_signed_tool 5.0.0 "$TOOL_V5_STORE" "$GOOD_KEY" v5 --previous 4.0.0
      assert_file_exists "/tmp/signed-cache/$TOOL_V5_HASH.narinfo" \
        "static cache has signed-tool v5 narinfo"
      amend_commit "$NEXT_KEY" v5
      push_branch

      echo "==> Consumer: accept update signed by rotated key and upgrade to v5"
      export HOME=/tmp/signed-consumer
      export USER=signeduser
      APM_CONFIG="$HOME/.config/apm"
      delete_store_path "$TOOL_V5_STORE" "signed-tool-v5"
      delete_store_path "$TOOL_V5_DEP_STORE" "signed-leaf-v5"
      rm -rf "$HOME/.cache/apm"
      mkdir -p "$HOME/.cache/apm"
      $APM update --registry signed-reg > /tmp/signed-update-v5.out 2>&1 || {
        cat /tmp/signed-update-v5.out
        fail "apm update accepts commit signed by rotated key"
      }
      cat /tmp/signed-update-v5.out
      $APM upgrade signed-tool --yes > /tmp/signed-upgrade-v5.out 2>&1 || {
        cat /tmp/signed-upgrade-v5.out
        fail "apm upgrade downloads rotated-key signed v5"
      }
      cat /tmp/signed-upgrade-v5.out
      assert_file_contains /tmp/signed-upgrade-v5.out "Downloading 2 NAR" \
        "apm upgrade downloads signed v5 closure"
      assert_store_valid "$TOOL_V5_STORE" "signed-tool-v5"
      assert_store_valid "$TOOL_V5_DEP_STORE" "signed-leaf-v5"
      "$PROFILE_TOOL" > /tmp/signed-run-v5.out
      assert_file_contains /tmp/signed-run-v5.out \
        "^signed-tool 5.0.0 via signed-leaf 5.0.0$" \
        "rotated-key signed v5 executable runs through dependency"

      echo "==> Maintainer: retire the original signing key and rotate the TUF root"
      export HOME=/tmp
      export USER=root
      APM_CONFIG="$HOME/.config/apm"
      $APR keys retire initial --vouched-by next --reason "rotation complete" \
        --key "$NEXT_KEY" \
        --registry signed-reg > /tmp/signed-keys-retire-initial.out 2>&1 || {
        cat /tmp/signed-keys-retire-initial.out
        fail "apr keys retire initial succeeds"
      }
      cat /tmp/signed-keys-retire-initial.out
      assert_file_contains "$REG_DIR/keys.toml" 'revoked' \
        "registry records retired signing key section"
      assert_file_contains "$REG_DIR/keys.toml" 'id = "initial"' \
        "registry records retired initial signing key id"
      # Retiring a key revokes it in the roster and re-signs tags but does not
      # re-seal the TUF root, which still lists the retired key. Rotate the root
      # off the retired key with a metadata-only release co-signed by the
      # retiring key (--rotate-from) so consumers can authorize the transition.
      reseal_release 5.1.0 "$NEXT_KEY" retire-reseal --previous 5.0.0 \
        --rotate-from "$GOOD_KEY"
      assert_file_not_contains "$REG_DIR/tuf/root.json" "$GOOD_PUBLIC" \
        "rotated TUF root drops the retired key material"
      push_branch

      echo "==> Consumer: accept retirement signed by rotated key"
      export HOME=/tmp/signed-consumer
      export USER=signeduser
      APM_CONFIG="$HOME/.config/apm"
      $APM update --registry signed-reg > /tmp/signed-update-retire.out 2>&1 || {
        cat /tmp/signed-update-retire.out
        fail "apm update accepts original key retirement"
      }
      cat /tmp/signed-update-retire.out
      assert_file_contains "$HOME/.local/share/apm/registries/signed-reg/keys.toml" \
        'revoked' "consumer materializes retired signing key section"
      assert_file_contains "$HOME/.local/share/apm/registries/signed-reg/keys.toml" \
        'id = "initial"' "consumer materializes retired initial signing key id"

      echo "==> Maintainer: forge a commit signed by the retired original key"
      export HOME=/tmp
      export USER=root
      APM_CONFIG="$HOME/.config/apm"
      # Seal the metadata with the active next key, then re-sign the commit with
      # the retired initial key: the consumer must reject the retired signature.
      reseal_release 5.2.0 "$NEXT_KEY" retired-forge --previous 5.1.0
      amend_commit "$GOOD_KEY" retired-forge
      push_branch

      echo "==> Consumer: reject update signed by retired original key"
      export HOME=/tmp/signed-consumer
      export USER=signeduser
      APM_CONFIG="$HOME/.config/apm"
      if $APM update --registry signed-reg > /tmp/signed-update-retired.out 2>&1; then
        cat /tmp/signed-update-retired.out
        fail "apm update should reject commit signed by retired key"
      else
        cat /tmp/signed-update-retired.out
        pass "apm update rejects retired-key signed commit"
      fi
      assert_file_contains /tmp/signed-update-retired.out \
        "commit signature verification failed" \
        "retired-key update reports signature verification failure"
      $APM search signed-tool --registry signed-reg > /tmp/signed-search-after-retired.out 2>&1 || {
        cat /tmp/signed-search-after-retired.out
        fail "apm search still works after rejected retired-key update"
      }
      assert_file_contains /tmp/signed-search-after-retired.out "5.0.0" \
        "rejected retired-key update leaves v5 metadata active"
      "$PROFILE_TOOL" > /tmp/signed-run-after-retired.out
      assert_file_contains /tmp/signed-run-after-retired.out \
        "^signed-tool 5.0.0 via signed-leaf 5.0.0$" \
        "retired-key update leaves installed v5 active"

      if kill "$CACHE_PID" 2>/dev/null; then
        pass "signed static cache HTTP server stopped"
      fi
      wait "$CACHE_PID" 2>/dev/null || true

      check_fail
    '';
  };
}
