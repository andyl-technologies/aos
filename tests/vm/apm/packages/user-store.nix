# Personal packages use signed imports through the shared, root-owned Nix store.
{
  testing,
  pkgs,
  fixtures,
  installBasicTool,
  installDepTool,
  installWithDepsTool,
  realInstallDeps,
  setupNixEnv,
}: {
  user-store-trust = testing.mkVMTest {
    name = "apm-user-store-trust";
    memory = 1536;
    rootfsDeps = realInstallDeps ++ [pkgs.util-linux pkgs.diffutils pkgs.sed];

    testScript = ''
      set -euo pipefail
      ${fixtures.setupPreamble}
      ${setupNixEnv}

      BASIC_STORE="${installBasicTool}"
      DEP_STORE="${installDepTool}"
      WRAPPER_STORE="${installWithDepsTool}"
      BASIC_HASH=$(basename "$BASIC_STORE" | cut -d- -f1)
      DEP_HASH=$(basename "$DEP_STORE" | cut -d- -f1)
      WRAPPER_HASH=$(basename "$WRAPPER_STORE" | cut -d- -f1)
      CACHE=/tmp/user-store-cache
      FIRST_PROFILE=/var/lib/profiles/per-user/client
      SECOND_PROFILE=/var/lib/profiles/per-user/second-client

      mount -o remount,rw / || true
      nix-store --generate-binary-cache-key user-store-1 /tmp/user-store.key /tmp/user-store.pub
      nix-store --generate-binary-cache-key unapproved-1 /tmp/unapproved.key /tmp/unapproved.pub
      create_publish_registry user-store-reg
      REG_DIR="$REG_STORAGE/user-store-reg"
      REGISTRY_KEY=/tmp/vm-publish-keys/user-store-reg
      REGISTRY_PUBLIC_KEY=$(cut -d ' ' -f2 "$REGISTRY_KEY.pub")
      DEFAULT_BRANCH=$(git -C "$REG_DIR" symbolic-ref --short HEAD)

      for package in "$BASIC_STORE" "$DEP_STORE" "$WRAPPER_STORE"; do
        package_name=$(basename "$package" | cut -d- -f2- | sed 's/-[0-9].*$//')
        package_version=$(basename "$package" | sed 's/^.*-\([0-9][^-]*\)$/\1/')
        publish_vm_package "$package" --registry user-store-reg \
          --name "$package_name" --version "$package_version" \
          --description "Shared-store user install fixture" \
          --license MIT --maintainer fixture@example.invalid --no-commit
      done
      $APR cache generate --registry user-store-reg --output "$CACHE" \
        --key /tmp/user-store.key --cache-url http://127.0.0.1:18096 --no-commit
      $APR cache generate --registry user-store-reg --output /tmp/unapproved-cache \
        --key /tmp/unapproved.key --cache-url http://127.0.0.1:18096 --no-commit
      grep -q '^Sig: user-store-1:' "$CACHE/$BASIC_HASH.narinfo"
      grep -q '^Sig: unapproved-1:' "/tmp/unapproved-cache/$BASIC_HASH.narinfo"
      cp "$CACHE/$BASIC_HASH.narinfo" /tmp/basic-signed.narinfo

      git init --bare --object-format=sha256 /tmp/user-store-origin.git
      git -C /tmp/user-store-origin.git symbolic-ref HEAD "refs/heads/$DEFAULT_BRANCH"
      git -C "$REG_DIR" remote add origin /tmp/user-store-origin.git

      git -C "$REG_DIR" add -A
      git -C "$REG_DIR" -c gpg.format=ssh -c user.signingkey="$REGISTRY_KEY" \
        commit -S -m "Publish signed user package fixture"

      # Release seals TUF catalog metadata as well as the signed registry commit.
      release_vm_package 1.0.0 --registry user-store-reg \
        --cache-key /tmp/user-store.key --cache-url http://127.0.0.1:18096 \
        --upload-url "file://$CACHE"
      test -f "$REG_DIR/tuf/root.json"
      git -C "$REG_DIR" push origin "$DEFAULT_BRANCH"

      # Accounts own their profiles and caches; neither can write the shared store.
      cat > /etc/passwd <<'PASSWD'
      root:x:0:0:root:/root:${pkgs.bash}/bin/bash
      client:x:1000:100:client:/tmp/client:${pkgs.bash}/bin/bash
      second-client:x:1001:100:second client:/tmp/second-client:${pkgs.bash}/bin/bash
      PASSWD
      cat > /etc/group <<'GROUP'
      root:x:0:root
      users:x:100:client,second-client
      GROUP
      mkdir -p /tmp/client /tmp/second-client "$FIRST_PROFILE" "$SECOND_PROFILE"
      chown 1000:100 /tmp/client "$FIRST_PROFILE"
      chown 1001:100 /tmp/second-client "$SECOND_PROFILE"
      chmod 0700 /tmp/client /tmp/second-client "$FIRST_PROFILE" "$SECOND_PROFILE"
      chmod 0755 /var/lib/profiles /var/lib/profiles/per-user /nix/store

      # The daemon owns signer policy. A personal registry cannot enlarge it.
      mkdir -p /tmp/user-daemon-config /nix/var/nix/daemon-socket
      {
        printf 'experimental-features = nix-command\n'
        printf 'allowed-users = *\ntrusted-users = root\nrequire-sigs = true\n'
        printf 'build-users-group =\nsubstituters =\nsandbox = false\n'
        printf 'trusted-public-keys = %s\n' "$(cat /tmp/user-store.pub)"
      } > /tmp/user-daemon-config/nix.conf
      export NIX_CONF_DIR=/tmp/user-daemon-config
      export NIX_REMOTE=local
      for package in "$WRAPPER_STORE" "$DEP_STORE" "$BASIC_STORE"; do
        nix-store --delete --ignore-liveness "$package"
        if nix-store --check-validity "$package"; then
          echo "Fixture package must be absent before import" >&2
          exit 1
        fi
      done
      nix-daemon --daemon > /tmp/user-store-daemon.log 2>&1 &
      DAEMON_PID=$!
      trap 'kill "$DAEMON_PID" "''${CACHE_PID:-}" 2>/dev/null || true' EXIT

      run_user() {
        uid=$1
        account=$2
        shift 2
        ${pkgs.util-linux}/bin/setpriv --reuid="$uid" --regid=100 --clear-groups \
          ${pkgs.coreutils}/bin/env HOME="/tmp/$account" USER="$account" \
          NIX_CONF_DIR=/tmp/user-daemon-config NIX_REMOTE=daemon "$@"
      }
      for attempt in {1..100}; do
        if test -S /nix/var/nix/daemon-socket/socket && \
           run_user 1000 client nix-store --query --hash ${pkgs.bash} >/dev/null 2>&1; then
          break
        fi
        sleep 0.1
      done
      run_user 1000 client ${pkgs.coreutils}/bin/id -u > /tmp/first-uid
      run_user 1001 second-client ${pkgs.coreutils}/bin/id -u > /tmp/second-uid
      test "$(cat /tmp/first-uid)" = 1000
      test "$(cat /tmp/second-uid)" = 1001
      if run_user 1000 client test -w /nix/store; then
        echo "Ordinary user must not have direct shared-store write permission" >&2
        exit 1
      fi

      ${pkgs.iproute2}/sbin/ip link set lo up || true
      ${pkgs.iproute2}/sbin/ip addr add 127.0.0.1/8 dev lo 2>/dev/null || true
      python3 -m http.server 18096 --bind 127.0.0.1 --directory "$CACHE" \
        > /tmp/user-store-http.log 2>&1 &
      CACHE_PID=$!
      for attempt in {1..100}; do
        if curl -sf http://127.0.0.1:18096/nix-cache-info >/dev/null; then
          break
        fi
        sleep 0.1
      done
      for account in client second-client; do
        case "$account" in client) uid=1000 ;; second-client) uid=1001 ;; esac
        # The read-only fixture origin is root-owned, unlike a normal remote server.
        run_user "$uid" "$account" git config --global --add safe.directory /tmp/user-store-origin.git
        run_user "$uid" "$account" git ls-remote file:///tmp/user-store-origin.git \
          "refs/heads/$DEFAULT_BRANCH" > "/tmp/$account-origin-ref"
        test -s "/tmp/$account-origin-ref"
        run_user "$uid" "$account" "$APM" registry add file:///tmp/user-store-origin.git \
          --name user-store-reg --branch "$DEFAULT_BRANCH" \
          --trust-key "user-store-reg:Ed25519:$REGISTRY_PUBLIC_KEY"
        run_user "$uid" "$account" "$APM" update --registry user-store-reg
      done

      run_user 1000 client "$APM" install install-with-deps --registry user-store-reg --yes
      run_user 1000 client "$FIRST_PROFILE/current/bin/install-with-deps" > /tmp/first-run
      grep -qx 'install-libfoo 1.0.0' /tmp/first-run
      nix-store --check-validity "$WRAPPER_STORE" "$DEP_STORE"
      STORE_IDENTITY=$(stat -c '%d:%i' "$WRAPPER_STORE")
      run_user 1001 second-client "$APM" install install-with-deps --registry user-store-reg --yes
      test "$(stat -c '%d:%i' "$WRAPPER_STORE")" = "$STORE_IDENTITY"
      test "$(readlink "$FIRST_PROFILE/current")" = gen-1
      test "$(readlink "$SECOND_PROFILE/current")" = gen-1
      test "$(stat -c %u "$FIRST_PROFILE/gen-1")" = 1000
      test "$(stat -c %u "$SECOND_PROFILE/gen-1")" = 1001
      grep -q '"explicit": true' "$FIRST_PROFILE/meta/$WRAPPER_HASH.json"
      grep -q '"explicit": false' "$FIRST_PROFILE/meta/$DEP_HASH.json"
      cp -a "$FIRST_PROFILE" /tmp/profile-before-rejections

      reject_basic_install() {
        label=$1
        expected=$2
        rm -rf /tmp/client/.cache/apm
        if run_user 1000 client "$APM" install install-basic-tool \
          --registry user-store-reg --yes > "/tmp/$label.out" 2>&1; then
          cat "/tmp/$label.out" >&2
          echo "Expected $label import rejection" >&2
          exit 1
        fi
        grep -Eiq "$expected" "/tmp/$label.out"
        diff --no-dereference -qr "$FIRST_PROFILE" /tmp/profile-before-rejections
        if nix-store --check-validity "$BASIC_STORE" >/dev/null 2>&1 || test -e "$BASIC_STORE"; then
          echo "Rejected package must not be registered or materialized" >&2
          exit 1
        fi
        test "$(stat -c '%d:%i' "$WRAPPER_STORE")" = "$STORE_IDENTITY"
      }

      sed '/^Sig:/d' /tmp/basic-signed.narinfo > "$CACHE/$BASIC_HASH.narinfo"
      reject_basic_install unsigned-cache 'signature|trusted key'
      cp "/tmp/unapproved-cache/$BASIC_HASH.narinfo" "$CACHE/$BASIC_HASH.narinfo"
      reject_basic_install unapproved-cache 'signature|trusted key'

      # Client-side trust is independent of the root daemon's approved signer list.
      mkdir -p /tmp/client/.config/nix
      printf 'trusted-public-keys = %s\n' "$(cat /tmp/unapproved.pub)" \
        > /tmp/client/.config/nix/nix.conf
      chown -R 1000:100 /tmp/client/.config/nix
      reject_basic_install personal-extra-key 'signature|trusted key'
      cp /tmp/basic-signed.narinfo "$CACHE/$BASIC_HASH.narinfo"
      BASIC_NAR=$(sed -n 's/^URL: //p' /tmp/basic-signed.narinfo)
      cp "$CACHE/$BASIC_NAR" /tmp/basic-good.nar.zst
      printf 'tampered' >> "$CACHE/$BASIC_NAR"
      reject_basic_install modified-nar 'hash|size|corrupt'
      cp /tmp/basic-good.nar.zst "$CACHE/$BASIC_NAR"

      run_user 1000 client "$APM" install install-basic-tool --registry user-store-reg --yes
      test "$(readlink "$FIRST_PROFILE/current")" = gen-2
      test "$(readlink "$SECOND_PROFILE/current")" = gen-1
      run_user 1000 client "$FIRST_PROFILE/current/bin/install-basic-tool" > /tmp/basic-run
      grep -qx 'install-basic-tool 1.0.0' /tmp/basic-run
      check_fail
      echo "Signed personal packages share the daemon store without sharing profile ownership"
    '';
  };
}
