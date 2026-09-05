# Registry VM checks for channels workflows.
{
  testing,
  pkgs,
  fixtures,
  maintainerWorkflowDeps,
  setupNixPublishEnv,
  closureLeafTool,
  closureRootTool,
  closureLeafToolV2,
  closureRootToolV2,
  closureLeafToolV3,
  closureRootToolV3,
}: {
  # -------------------------------------------------------------------------
  # registry-channel-workflow — Signed channel rollout and consumer upgrade
  # -------------------------------------------------------------------------
  registry-channel-workflow = testing.mkVMTest {
    name = "apm-registry-channel-workflow";
    rootfsDeps =
      maintainerWorkflowDeps
      ++ [
        pkgs.jq
        closureLeafTool
        closureRootTool
        closureLeafToolV2
        closureRootToolV2
        closureLeafToolV3
        closureRootToolV3
      ];
    memory = 2048;
    testScript = ''
      ${fixtures.setupPreamble}
      ${setupNixPublishEnv}

      echo "==> Test: signed channel rollout, sync, install, and upgrade"

      TOOL_V1_STORE="${closureRootTool}"
      TOOL_V1_DEP_STORE="${closureLeafTool}"
      TOOL_V2_STORE="${closureRootToolV2}"
      TOOL_V2_DEP_STORE="${closureLeafToolV2}"
      TOOL_V3_STORE="${closureRootToolV3}"
      TOOL_V3_DEP_STORE="${closureLeafToolV3}"
      TOOL_V1_HASH=$(basename "$TOOL_V1_STORE" | cut -d- -f1)
      TOOL_V1_DEP_HASH=$(basename "$TOOL_V1_DEP_STORE" | cut -d- -f1)
      TOOL_V2_HASH=$(basename "$TOOL_V2_STORE" | cut -d- -f1)
      TOOL_V2_DEP_HASH=$(basename "$TOOL_V2_DEP_STORE" | cut -d- -f1)
      TOOL_V3_HASH=$(basename "$TOOL_V3_STORE" | cut -d- -f1)
      TOOL_V3_DEP_HASH=$(basename "$TOOL_V3_DEP_STORE" | cut -d- -f1)
      nix-store -q --references "$TOOL_V1_STORE" > /tmp/channel-v1-refs.out
      assert_file_contains /tmp/channel-v1-refs.out "$TOOL_V1_DEP_STORE" \
        "channel v1 root has a real dependency closure"
      nix-store -q --references "$TOOL_V2_STORE" > /tmp/channel-v2-refs.out
      assert_file_contains /tmp/channel-v2-refs.out "$TOOL_V2_DEP_STORE" \
        "channel v2 root has a real dependency closure"
      nix-store -q --references "$TOOL_V3_STORE" > /tmp/channel-v3-refs.out
      assert_file_contains /tmp/channel-v3-refs.out "$TOOL_V3_DEP_STORE" \
        "channel v3 root has a real dependency closure"

      ssh-keygen -q -t ed25519 -N "" -f /tmp/channel-release-key
      CHANNEL_PUBLIC=$(cut -d ' ' -f2 < /tmp/channel-release-key.pub)
      CHANNEL_TRUST_KEY="chan-reg:Ed25519:$CHANNEL_PUBLIC"

      $APR create chan-reg --trust-key "$CHANNEL_TRUST_KEY" \
        --key /tmp/channel-release-key
      REG_DIR="$REG_STORAGE/chan-reg"
      assert_file_contains "$REG_DIR/keys.toml" "chan-reg:Ed25519" \
        "registry records initial channel trust key"
      {
        printf '[registry]\n'
        printf 'name = "chan-reg"\n'
        printf 'url = "file://%s"\n\n' "$REG_DIR"
        printf '[registry.signing_keys]\n'
        printf 'initial = "/tmp/channel-release-key"\n'
      } > "$APM_CONFIG/registries.d/chan-reg.toml"

      echo "local maintainer note" > "$REG_DIR/maintainer-notes.txt"
      if $APR release 1.0.0 \
        --registry chan-reg \
        --store-path "$TOOL_V1_STORE" \
        --name channel-tool \
        --description "Channel workflow tool" \
        --license MIT \
        --maintainer channel@example.invalid \
        --key /tmp/channel-release-key \
        --cache-url http://127.0.0.1:18091 \
        --upload-url file:///tmp/channel-cache \
        --channel stable \
        --init-channel \
        > /tmp/channel-release-dirty.out 2>&1; then
        cat /tmp/channel-release-dirty.out
        fail "apr release --store-path should refuse a dirty registry before publishing"
      else
        cat /tmp/channel-release-dirty.out
        assert_file_contains /tmp/channel-release-dirty.out \
          "uncommitted changes" \
          "apr release --store-path reports dirty registry preflight"
      fi
      assert_file_not_exists "$REG_DIR/packages/c/channel-tool.toml" \
        "dirty release does not write package metadata"
      if git -C "$REG_DIR" rev-parse "1.0.0^{tag}" >/tmp/channel-release-dirty-tag.out 2>&1; then
        cat /tmp/channel-release-dirty-tag.out
        fail "dirty release should not create a release tag"
      else
        pass "dirty release does not create a release tag"
      fi
      if git -C "$REG_DIR" ls-tree -r --name-only HEAD | grep -q "maintainer-notes.txt"; then
        fail "dirty release should not commit unrelated maintainer scratch files"
      else
        pass "dirty release leaves unrelated maintainer scratch files out of HEAD"
      fi
      rm -f "$REG_DIR/maintainer-notes.txt"

      $APR release 1.0.0 \
        --registry chan-reg \
        --store-path "$TOOL_V1_STORE" \
        --name channel-tool \
        --description "Channel workflow tool" \
        --license MIT \
        --maintainer channel@example.invalid \
        --key /tmp/channel-release-key \
        --cache-url http://127.0.0.1:18091 \
        --upload-url file:///tmp/channel-cache \
        --channel stable \
        --init-channel \
        > /tmp/channel-release-v1.out 2>&1 || {
        cat /tmp/channel-release-v1.out
        fail "apr release initializes signed channel"
      }
      cat /tmp/channel-release-v1.out
      assert_file_contains /tmp/channel-release-v1.out \
        "Initialized channel 'stable' with 256/256 partitions on 1.0.0" \
        "apr release initializes every channel partition"
      assert_file_exists "$REG_DIR/.git/channels/stable/00" \
        "channel partition object is written to static origin"
      assert_file_contains "$REG_DIR/.git/channels/stable/00" \
        "BEGIN SSH SIGNATURE" "channel partition object is signed"

      assert_file_exists "/tmp/channel-cache/$TOOL_V1_HASH.narinfo" \
        "static cache has channel-tool v1 narinfo"
      assert_file_exists "/tmp/channel-cache/$TOOL_V1_DEP_HASH.narinfo" \
        "static cache has channel-tool v1 dependency narinfo"

      $APR channel init canary 1.0.0 \
        --registry chan-reg \
        --key-id initial \
        > /tmp/channel-init-canary.out 2>&1 || {
        cat /tmp/channel-init-canary.out
        fail "apr channel init initializes canary channel with key id"
      }
      cat /tmp/channel-init-canary.out
      assert_file_contains /tmp/channel-init-canary.out \
        "Initialized channel 'canary' with 256/256 partitions on 1.0.0" \
        "apr channel init reports direct channel initialization"
      assert_file_exists "$REG_DIR/.git/channels/canary/00" \
        "direct channel init writes static partition object"
      assert_file_contains "$REG_DIR/.git/channels/canary/00" \
        "BEGIN SSH SIGNATURE" "direct channel init signs partition object"
      $APR channel status canary --registry chan-reg > /tmp/channel-status-canary.out 2>&1
      assert_file_contains /tmp/channel-status-canary.out "1.0.0" \
        "direct channel init status reports release frontier"
      assert_file_contains /tmp/channel-status-canary.out "256/256" \
        "direct channel init status reports full partition set"

      ${pkgs.iproute2}/sbin/ip link set lo up || true
      ${pkgs.iproute2}/sbin/ip addr add 127.0.0.1/8 dev lo 2>/dev/null || true

      PYTHONUNBUFFERED=1 python3 -m http.server 18090 --bind 127.0.0.1 \
        --directory "$REG_DIR/.git" > /tmp/channel-origin-http.log 2>&1 &
      ORIGIN_PID=$!
      PYTHONUNBUFFERED=1 python3 -m http.server 18091 --bind 127.0.0.1 \
        --directory /tmp/channel-cache > /tmp/channel-cache-http.log 2>&1 &
      CACHE_PID=$!
      for _i in 1 2 3 4 5 6 7 8 9 10; do
        if curl -sf http://127.0.0.1:18090/info/refs >/dev/null \
          && curl -sf http://127.0.0.1:18091/nix-cache-info >/dev/null; then
          break
        fi
        sleep 1
      done
      if curl -sf http://127.0.0.1:18090/channels/stable/00 >/tmp/channel-00.tag \
        && curl -sf http://127.0.0.1:18091/nix-cache-info >/dev/null; then
        pass "static origin and cache HTTP servers started"
      else
        cat /tmp/channel-origin-http.log || true
        cat /tmp/channel-cache-http.log || true
        fail "static origin and cache HTTP servers started"
      fi
      curl -sf http://127.0.0.1:18090/channels/canary/00 \
        >/tmp/channel-canary-00.tag || {
        cat /tmp/channel-origin-http.log || true
        fail "direct channel init is served by static origin"
      }
      assert_file_contains /tmp/channel-canary-00.tag \
        "BEGIN SSH SIGNATURE" "static origin serves direct channel partition"

      export HOME=/tmp/channel-consumer
      export USER=channeluser
      mkdir -p "$HOME"

      $APM registry add http://127.0.0.1:18090 \
        --name chan-reg \
        --channel stable \
        --trust-key "$CHANNEL_TRUST_KEY" \
        > /tmp/channel-add.out 2>&1 || {
        cat /tmp/channel-add.out
        fail "apm registry add syncs signed channel"
      }
      cat /tmp/channel-add.out
      CONSUMER_CONFIG="$HOME/.config/apm/registries.d/chan-reg.toml"
      assert_file_contains "$CONSUMER_CONFIG" 'channel = "stable"' \
        "consumer config records channel tracking"
      assert_file_contains "$CONSUMER_CONFIG" 'public_key = "chan-reg:Ed25519:' \
        "consumer config records trusted signing key"
      assert_file_contains "$CONSUMER_CONFIG" 'floor = "1.0.0"' \
        "initial channel sync records semver floor"
      assert_file_contains "$CONSUMER_CONFIG" "bucket = " \
        "initial channel sync records rollout bucket"
      BUCKET=$(grep '^bucket = ' "$CONSUMER_CONFIG" | cut -d= -f2 | tr -d ' ')
      if [ -n "$BUCKET" ]; then
        pass "consumer rollout bucket is readable"
      else
        fail "consumer rollout bucket is readable"
      fi

      $APM search channel-tool --registry chan-reg > /tmp/channel-search-v1.out 2>&1
      assert_file_contains /tmp/channel-search-v1.out "1.0.0" \
        "consumer sees channel v1 package"
      assert_file_contains "$HOME/.local/share/apm/registries/chan-reg/registry.toml" \
        "http://127.0.0.1:18091" "consumer syncs channel cache endpoint"

      mount -o remount,rw / || true
      nix-store --delete --ignore-liveness "$TOOL_V1_STORE" \
        > /tmp/channel-delete-v1.out 2>&1 || {
        cat /tmp/channel-delete-v1.out
        fail "deleted v1 store path before channel install"
      }
      nix-store --delete --ignore-liveness "$TOOL_V1_DEP_STORE" \
        > /tmp/channel-delete-v1-dep.out 2>&1 || {
        cat /tmp/channel-delete-v1-dep.out
        fail "deleted v1 dependency store path before channel install"
      }

      $APM install channel-tool --registry chan-reg --yes \
        > /tmp/channel-install-v1.out 2>&1 || {
        cat /tmp/channel-install-v1.out
        fail "apm install downloads channel v1"
      }
      cat /tmp/channel-install-v1.out
      assert_file_contains /tmp/channel-install-v1.out "Downloading 2 NAR" \
        "apm install downloads v1 root and dependency NARs"
      PROFILE_TOOL="/var/lib/profiles/per-user/$USER/current/bin/closure-root"
      "$PROFILE_TOOL" > /tmp/channel-tool-v1.out
      assert_file_contains /tmp/channel-tool-v1.out \
        "^closure-root 1.0.0 via closure-leaf 1.0.0$" \
        "installed v1 channel closure executes with its dependency"

      export HOME=/tmp
      export USER=root
      $APR release 2.0.0 \
        --registry chan-reg \
        --store-path "$TOOL_V2_STORE" \
        --name channel-tool \
        --description "Channel workflow tool" \
        --license MIT \
        --maintainer channel@example.invalid \
        --previous 1.0.0 \
        --key /tmp/channel-release-key \
        --cache-url http://127.0.0.1:18091 \
        --upload-url file:///tmp/channel-cache \
        --channel stable \
        --partitions "$BUCKET" \
        > /tmp/channel-release-v2.out 2>&1 || {
        cat /tmp/channel-release-v2.out
        fail "apr release advances consumer channel partition"
      }
      cat /tmp/channel-release-v2.out
      assert_file_contains /tmp/channel-release-v2.out \
        "Advanced channel 'stable' 1 partition(s) to 2.0.0" \
        "apr release advances selected channel partition"
      assert_file_exists "/tmp/channel-cache/$TOOL_V2_HASH.narinfo" \
        "static cache has channel-tool v2 narinfo"
      assert_file_exists "/tmp/channel-cache/$TOOL_V2_DEP_HASH.narinfo" \
        "static cache has channel-tool v2 dependency narinfo"
      $APR channel status stable --registry chan-reg > /tmp/channel-status-v2.out 2>&1
      assert_file_contains /tmp/channel-status-v2.out "2.0.0" \
        "channel status reports v2 frontier"
      assert_file_contains /tmp/channel-status-v2.out "1/256" \
        "channel status reports one v2 partition"
      $APR --json channel status stable --registry chan-reg \
        > /tmp/channel-status-v2.json 2>&1 || {
        cat /tmp/channel-status-v2.json
        fail "apr --json channel status reports advanced channel"
      }
      ${pkgs.jq}/bin/jq -e \
        '.channel == "stable"
          and .frontier == "2.0.0"
          and .missing_partitions == 0
          and (.versions | any(.version == "2.0.0" and .partitions == 1))
          and (.versions | any(.version == "1.0.0" and .partitions == 255))' \
        /tmp/channel-status-v2.json >/dev/null || {
        cat /tmp/channel-status-v2.json
        fail "apr --json channel status reports advanced partition counts"
      }
      pass "apr --json channel status reports advanced partition counts"

      export HOME=/tmp/channel-consumer
      export USER=channeluser
      nix-store --delete --ignore-liveness "$TOOL_V2_STORE" \
        > /tmp/channel-delete-v2.out 2>&1 || {
        cat /tmp/channel-delete-v2.out
        fail "deleted v2 store path before channel upgrade"
      }
      nix-store --delete --ignore-liveness "$TOOL_V2_DEP_STORE" \
        > /tmp/channel-delete-v2-dep.out 2>&1 || {
        cat /tmp/channel-delete-v2-dep.out
        fail "deleted v2 dependency store path before channel upgrade"
      }
      rm -rf "$HOME/.cache/apm"
      mkdir -p "$HOME/.cache/apm"

      $APM update --registry chan-reg > /tmp/channel-update-v2.out 2>&1 || {
        cat /tmp/channel-update-v2.out
        fail "apm update follows advanced channel partition"
      }
      cat /tmp/channel-update-v2.out
      assert_file_contains "$CONSUMER_CONFIG" 'floor = "2.0.0"' \
        "channel update raises consumer semver floor"
      $APM list --upgradable > /tmp/channel-upgradable.out 2>&1 || {
        cat /tmp/channel-upgradable.out
        fail "apm list --upgradable sees channel upgrade"
      }
      assert_file_contains /tmp/channel-upgradable.out "channel-tool" \
        "channel upgrade candidate names package"
      assert_file_contains /tmp/channel-upgradable.out "2.0.0" \
        "channel upgrade candidate shows v2"

      $APM upgrade channel-tool --yes > /tmp/channel-upgrade.out 2>&1 || {
        cat /tmp/channel-upgrade.out
        fail "apm upgrade downloads and activates channel v2"
      }
      cat /tmp/channel-upgrade.out
      assert_file_contains /tmp/channel-upgrade.out "Downloading 2 NAR" \
        "apm upgrade downloads v2 root and dependency NARs"
      assert_file_contains /tmp/channel-upgrade.out "Upgraded 1 package" \
        "apm upgrade activates channel v2"
      "$PROFILE_TOOL" > /tmp/channel-tool-v2.out
      assert_file_contains /tmp/channel-tool-v2.out \
        "^closure-root 2.0.0 via closure-leaf 2.0.0$" \
        "upgraded v2 channel closure executes with its dependency"

      export HOME=/tmp
      export USER=root
      $APR release 3.0.0 \
        --registry chan-reg \
        --store-path "$TOOL_V3_STORE" \
        --name channel-tool \
        --description "Channel workflow tool" \
        --license MIT \
        --maintainer channel@example.invalid \
        --previous 2.0.0 \
        --key /tmp/channel-release-key \
        --cache-url http://127.0.0.1:18091 \
        --upload-url file:///tmp/channel-cache \
        > /tmp/channel-release-v3.out 2>&1 || {
        cat /tmp/channel-release-v3.out
        fail "apr release creates v3 before direct channel advance"
      }
      cat /tmp/channel-release-v3.out
      assert_file_contains /tmp/channel-release-v3.out \
        "Created signed tag '3.0.0'" \
        "apr release creates signed v3 tag"
      assert_file_exists "/tmp/channel-cache/$TOOL_V3_HASH.narinfo" \
        "static cache has channel-tool v3 narinfo"
      assert_file_exists "/tmp/channel-cache/$TOOL_V3_DEP_HASH.narinfo" \
        "static cache has channel-tool v3 dependency narinfo"

      if $APR channel advance stable 3.0.0 \
        --registry chan-reg \
        --key /tmp/channel-release-key \
        --count 1 \
        --partitions "$BUCKET" \
        > /tmp/channel-advance-conflict.out 2>&1; then
        cat /tmp/channel-advance-conflict.out
        fail "apr channel advance should reject conflicting partition selectors"
      else
        cat /tmp/channel-advance-conflict.out
        pass "apr channel advance rejects conflicting partition selectors"
      fi
      assert_file_contains /tmp/channel-advance-conflict.out \
        "use only one of --count or --partitions" \
        "apr channel advance explains selector conflict"

      $APR channel advance stable 3.0.0 \
        --registry chan-reg \
        --key /tmp/channel-release-key \
        --partitions "$BUCKET" \
        > /tmp/channel-advance-v3.out 2>&1 || {
        cat /tmp/channel-advance-v3.out
        fail "apr channel advance moves selected consumer partition"
      }
      cat /tmp/channel-advance-v3.out
      assert_file_contains /tmp/channel-advance-v3.out \
        "Advanced channel 'stable' 1 partition(s) to 3.0.0" \
        "apr channel advance reports direct partition rollout"
      $APR channel status stable --registry chan-reg > /tmp/channel-status-v3.out 2>&1
      assert_file_contains /tmp/channel-status-v3.out "3.0.0" \
        "channel status reports v3 frontier after direct advance"
      assert_file_contains /tmp/channel-status-v3.out "1/256" \
        "channel status keeps one v3 partition after direct advance"

      export HOME=/tmp/channel-consumer
      export USER=channeluser
      nix-store --delete --ignore-liveness "$TOOL_V3_STORE" \
        > /tmp/channel-delete-v3.out 2>&1 || {
        cat /tmp/channel-delete-v3.out
        fail "deleted v3 store path before direct channel upgrade"
      }
      nix-store --delete --ignore-liveness "$TOOL_V3_DEP_STORE" \
        > /tmp/channel-delete-v3-dep.out 2>&1 || {
        cat /tmp/channel-delete-v3-dep.out
        fail "deleted v3 dependency store path before direct channel upgrade"
      }
      rm -rf "$HOME/.cache/apm"
      mkdir -p "$HOME/.cache/apm"

      $APM update --registry chan-reg > /tmp/channel-update-v3.out 2>&1 || {
        cat /tmp/channel-update-v3.out
        fail "apm update follows direct channel advance"
      }
      cat /tmp/channel-update-v3.out
      assert_file_contains "$CONSUMER_CONFIG" 'floor = "3.0.0"' \
        "direct channel advance raises consumer semver floor"
      $APM list --upgradable > /tmp/channel-upgradable-v3.out 2>&1 || {
        cat /tmp/channel-upgradable-v3.out
        fail "apm list --upgradable sees direct channel advance"
      }
      assert_file_contains /tmp/channel-upgradable-v3.out "channel-tool" \
        "direct channel upgrade candidate names package"
      assert_file_contains /tmp/channel-upgradable-v3.out "3.0.0" \
        "direct channel upgrade candidate shows v3"

      $APM upgrade channel-tool --yes > /tmp/channel-upgrade-v3.out 2>&1 || {
        cat /tmp/channel-upgrade-v3.out
        fail "apm upgrade downloads and activates directly advanced v3"
      }
      cat /tmp/channel-upgrade-v3.out
      assert_file_contains /tmp/channel-upgrade-v3.out "Downloading 2 NAR" \
        "apm upgrade downloads directly advanced v3 root and dependency NARs"
      assert_file_contains /tmp/channel-upgrade-v3.out "Upgraded 1 package" \
        "apm upgrade activates directly advanced v3"
      "$PROFILE_TOOL" > /tmp/channel-tool-v3.out
      assert_file_contains /tmp/channel-tool-v3.out \
        "^closure-root 3.0.0 via closure-leaf 3.0.0$" \
        "upgraded v3 channel closure executes with its dependency"

      kill "$ORIGIN_PID" "$CACHE_PID" 2>/dev/null || true
      wait "$ORIGIN_PID" "$CACHE_PID" 2>/dev/null || true
      check_fail
    '';
  };
}
