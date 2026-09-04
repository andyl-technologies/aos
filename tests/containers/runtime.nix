##! tests/containers/runtime.nix -- focused Phase-2 container runtime checks.
##!
##! Exercises the production init transaction against an isolated rooted local
##! store and validates the build-time golden-package facade without requiring
##! chroot, mounts, a container daemon, or host tools.
{
  pkgs,
  lib,
  containerImage,
  aosSystem,
  systemIdentity,
  goldenRoots,
  forbiddenRuntimeRoots,
}: let
  oci = import ../../lib/build/oci {
    inherit lib;
    inherit (pkgs) mkDerivation coreutils findutils gzip jq tar;
  };
  firstPackage = pkgs.runCommand "container-runtime-first-package" {} ''
    mkdir -p "$out/bin" "$out/sbin"
    printf '#!${pkgs.bash}/bin/bash\nprintf first-only\\n\n' > "$out/bin/first-only"
    printf '#!${pkgs.bash}/bin/bash\nprintf first-wins\\n\n' > "$out/bin/shared"
    printf '#!${pkgs.bash}/bin/bash\nprintf hidden\\n\n' > "$out/bin/.hidden-internal"
    printf '#!${pkgs.bash}/bin/bash\nprintf first-sbin\\n\n' > "$out/sbin/first-sbin"
    chmod 0555 "$out/bin/first-only" "$out/bin/shared" \
      "$out/bin/.hidden-internal" "$out/sbin/first-sbin"
  '';
  secondPackage = pkgs.runCommand "container-runtime-second-package" {} ''
    mkdir -p "$out/bin" "$out/sbin"
    printf '#!${pkgs.bash}/bin/bash\nprintf shadowed\\n\n' > "$out/bin/shared"
    printf '#!${pkgs.bash}/bin/bash\nprintf second-only\\n\n' > "$out/sbin/second-only"
    chmod 0555 "$out/bin/shared" "$out/sbin/second-only"
    # Make the first fixture a real runtime reference, so registration covers
    # both a root and a referenced path rather than two unrelated leaves.
    printf '%s\n' ${lib.escapeShellArg (builtins.toString firstPackage)} > "$out/first-reference"
  '';
  roots = [firstPackage secondPackage];
  referenceGraph = oci.mkReferenceGraph {
    pname = "aos-container-runtime-test-reference-graph";
    rootPaths = roots;
  };
  bakedRootInventory = pkgs.writeTextFile {
    name = "aos-container-runtime-test-baked-roots";
    text = builtins.concatStringsSep "\n" (map builtins.toString roots) + "\n";
    destination = "/baked-roots";
  };
  facadeLayer = import ../../lib/containers/facade-layer.nix {
    inherit lib pkgs oci referenceGraph;
    packageRoots = roots;
    expectedCollisions = ["shared"];
    pname = "aos-container-runtime-test-facade";
  };
  recorder = pkgs.writeShellScriptBin "aos-container-runtime-recorder" ''
    : "''${AOS_CONTAINER_TEST_RECORD:?}"
    : > "$AOS_CONTAINER_TEST_RECORD"
    printf 'path=%s\n' "$PATH" >> "$AOS_CONTAINER_TEST_RECORD"
    printf 'nix-remote=%s\n' "''${NIX_REMOTE-unset}" >> "$AOS_CONTAINER_TEST_RECORD"
    printf 'read-only=%s\n' "''${AOS_CONTAINER_READ_ONLY-unset}" >> "$AOS_CONTAINER_TEST_RECORD"
    if [ -n "''${AOS_CONTAINER_TEST_LOCK-}" ]; then
      exec 8> "$AOS_CONTAINER_TEST_LOCK"
      if ${pkgs.util-linux}/bin/flock -n 8; then
        printf 'init-lock=released\n' >> "$AOS_CONTAINER_TEST_RECORD"
      else
        printf 'init-lock=held\n' >> "$AOS_CONTAINER_TEST_RECORD"
      fi
      exec 8>&-
    fi
    for argument in "$@"; do
      printf 'arg=%s\n' "$argument" >> "$AOS_CONTAINER_TEST_RECORD"
    done
  '';
  testRoot = "/build/aos-container-runtime-root";
  initText = import ../../lib/containers/init-script.nix {
    inherit lib pkgs;
    rootPrefix = testRoot;
    registrationPath = "${referenceGraph}/registration";
    storePathsPath = "${referenceGraph}/store-paths";
    bakedRootsPath = "${bakedRootInventory}/baked-roots";
    defaultCommand = ["${recorder}/bin/aos-container-runtime-recorder" "default argument"];
  };
  initProgram = pkgs.writeTextFile {
    name = "aos-container-runtime-test-init";
    text = initText;
    destination = "/init";
    executable = true;
  };
  productionMetadata = containerImage.checks.metadataLayer;
  productionFacade = containerImage.checks.facadeLayer;
  productionReferenceGraph = containerImage.checks.referenceGraph;
  productionImage = containerImage.platforms.${aosSystem}.image;
  productionDockerArchive = containerImage.platforms.${aosSystem}.dockerArchive;
  productionIndex = containerImage.ociIndex;
  forbiddenRuntimePathStrings =
    map
    (value: builtins.unsafeDiscardStringContext (builtins.toString value))
    forbiddenRuntimeRoots;
in
  pkgs.mkDerivation {
    pname = "aos-container-runtime-check";
    version = "1";
    src = null;
    buildDeps =
      [
        pkgs.bash
        pkgs.coreutils
        pkgs.findutils
        pkgs.grep
        pkgs.gzip
        pkgs.jq
        pkgs.nix
        pkgs.tar
        pkgs.util-linux
        bakedRootInventory
        facadeLayer
        initProgram
        productionFacade
        productionDockerArchive
        productionImage
        productionIndex
        productionMetadata
        productionReferenceGraph
        recorder
        referenceGraph
      ]
      ++ roots;
    dontStrip = true;
    dontNukeRefs = true;

    phases = [
      {
        name = "check";
        script = ''
          set -eu

          fail() {
            echo "FAIL: $1" >&2
            exit 1
          }

          test_root=${lib.escapeShellArg testRoot}
          state_dir="$test_root/nix/var/nix"
          store_dir="$test_root/nix/store"
          gcroots="$state_dir/gcroots"
          store_uri="local?root=$test_root"
          runtime_path='profile-bin:profile-sbin:/usr/bin:/usr/sbin:/bin'

          mkdir -p "$store_dir" "$state_dir"
          while IFS= read -r store_path; do
            cp -a --no-preserve=ownership "$store_path" "$store_dir/"
          done < ${referenceGraph}/store-paths

          record="$TMPDIR/record"
          literal='literal; touch /build/aos-container-runtime-shell-reparse'
          PATH="$runtime_path" \
            AOS_CONTAINER_TEST_RECORD="$record" \
            AOS_CONTAINER_TEST_LOCK="$state_dir/.aos-container-init.lock" \
            ${initProgram}/init \
              ${recorder}/bin/aos-container-runtime-recorder \
              'first argument' "$literal"

          grep -Fx "path=$runtime_path" "$record" >/dev/null \
            || fail "init did not restore the exact OCI PATH before exec"
          grep -Fx "nix-remote=$store_uri" "$record" >/dev/null \
            || fail "init did not select the rooted local store"
          grep -Fx 'read-only=unset' "$record" >/dev/null \
            || fail "writable initialization exported the read-only marker"
          grep -Fx 'init-lock=released' "$record" >/dev/null \
            || fail "init lock leaked across workload exec"
          test "$(stat -c %a "$state_dir/.aos-container-init.lock")" = 600 \
            || fail "init lock mode is not private"
          grep -Fx 'schema=aos.container.ready/v1' \
            "$state_dir/.aos-container-ready" >/dev/null \
            || fail "init did not publish the readiness schema"
          pid1_stat=$(< /proc/1/stat)
          pid1_fields_text="''${pid1_stat##*) }"
          read -r -a pid1_fields <<< "$pid1_fields_text"
          grep -Fx "pid1_start_time=''${pid1_fields[19]}" \
            "$state_dir/.aos-container-ready" >/dev/null \
            || fail "readiness marker is not bound to the current PID 1"
          grep -Fx 'arg=first argument' "$record" >/dev/null
          grep -Fx "arg=$literal" "$record" >/dev/null \
            || fail "init reparsed an argv element"
          test ! -e /build/aos-container-runtime-shell-reparse \
            || fail "init executed shell syntax from argv"

          test -d "$gcroots/aos-container-baked" \
            || fail "baked GC-root set is not a real directory"
          test ! -L "$gcroots/aos-container-baked" \
            || fail "baked GC-root set must not be an indirection symlink"
          test -d "$gcroots/aos-profiles/per-user/root" \
            || fail "APM profile root is not inside Nix-scanned gcroots"
          for baked_root in ${lib.concatMapStringsSep " " lib.escapeShellArg (map builtins.toString roots)}; do
            root_name=''${baked_root##*/}
            test "$(readlink "$gcroots/aos-container-baked/$root_name")" = "$baked_root" \
              || fail "baked GC root has the wrong target: $root_name"
            nix-store --store "$store_uri" --check-validity "$baked_root" \
              || fail "baked root is not valid after initialization: $baked_root"
          done

          # Simulate an interrupted initializer and a corrupted live root set.
          stale="$gcroots/.aos-container-baked.fresh.interrupted"
          mkdir "$stale"
          ln -s ${firstPackage} "$stale/leaked-root"
          first_name=${builtins.baseNameOf (builtins.toString firstPackage)}
          rm "$gcroots/aos-container-baked/$first_name"
          ln -s ${secondPackage} "$gcroots/aos-container-baked/tampered"

          PATH="$runtime_path" AOS_CONTAINER_TEST_RECORD="$record" \
            ${initProgram}/init ${recorder}/bin/aos-container-runtime-recorder repaired
          test ! -e "$stale" \
            || fail "init did not clean an interrupted temporary GC-root set"
          test ! -e "$gcroots/aos-container-baked/tampered" \
            || fail "init did not replace a corrupted baked GC-root set"
          test "$(find "$gcroots/aos-container-baked" -mindepth 1 -maxdepth 1 | wc -l)" \
            -eq ${toString (builtins.length roots)} \
            || fail "reconciled baked GC-root set has unexpected entries"

          nix-store --store "$store_uri" --gc
          while IFS= read -r baked_root; do
            nix-store --store "$store_uri" --check-validity "$baked_root" \
              || fail "baked root was collected after reconciliation: $baked_root"
            test -e "$test_root$baked_root" \
              || fail "baked root bytes were collected: $baked_root"
          done < ${bakedRootInventory}/baked-roots

          # A writable state mount must reconstruct its DB even when the store
          # itself is read-only, while marking package mutation unsupported.
          rm -rf "$state_dir/db" "$state_dir/gcroots"
          mkdir -p "$state_dir"
          chmod 0555 "$store_dir"
          PATH="$runtime_path" AOS_CONTAINER_TEST_RECORD="$record" \
            ${initProgram}/init ${recorder}/bin/aos-container-runtime-recorder store-read-only
          grep -Fx 'read-only=1' "$record" >/dev/null \
            || fail "read-only store did not export the runtime marker"
          cmp "$state_dir/.aos-container-read-only" - <<'EOF' \
            || fail "read-only store did not persist the runtime marker"
          schema=aos.container.read-only/v1
          EOF
          test -d "$state_dir/db" \
            || fail "writable Nix state was not rebuilt for a read-only store"
          test -d "$state_dir/gcroots/aos-container-baked" \
            || fail "baked roots were not rebuilt with writable state"

          # With state itself read-only, init must perform no DB/root mutation
          # and still exec an immutable baked command with the stable marker.
          state_before=$(find "$state_dir" -printf '%P:%y:%l\n' | sort | sha256sum)
          chmod 0555 "$state_dir"
          PATH="$runtime_path" AOS_CONTAINER_TEST_RECORD="$record" \
            ${initProgram}/init ${recorder}/bin/aos-container-runtime-recorder state-read-only
          state_after=$(find "$state_dir" -printf '%P:%y:%l\n' | sort | sha256sum)
          test "$state_before" = "$state_after" \
            || fail "read-only state path was mutated"
          grep -Fx 'read-only=1' "$record" >/dev/null \
            || fail "read-only state did not export the runtime marker"
          grep -Fx 'arg=state-read-only' "$record" >/dev/null \
            || fail "read-only startup did not exec the baked command"

          mkdir facade-root
          gzip -dc ${facadeLayer}/blob \
            | tar --same-permissions --no-same-owner -xf - -C facade-root
          test "$(readlink facade-root/usr/bin/shared)" = ${lib.escapeShellArg "${firstPackage}/bin/shared"} \
            || fail "golden facade did not preserve first-wins package order"
          test "$(readlink facade-root/usr/bin/second-only)" = ${lib.escapeShellArg "${secondPackage}/sbin/second-only"} \
            || fail "golden facade omitted an sbin executable"
          test ! -e facade-root/usr/bin/.hidden-internal \
            || fail "golden facade exposed a hidden wrapper implementation"
          jq -e '
            .schema == "aos.container.facade-policy/v1"
            and .directoryOrder == ["bin", "sbin"]
            and .expectedCollisions == ["shared"]
          ' ${facadeLayer}/facade.json >/dev/null
          jq -e \
            --arg winner ${lib.escapeShellArg "${firstPackage}/bin/shared"} \
            --arg shadowed ${lib.escapeShellArg "${secondPackage}/bin/shared"} '
              .collisions == [{
                name: "shared",
                winner: $winner,
                shadowed: $shadowed,
                shadowedSource: $shadowed
              }]
            ' ${facadeLayer}/facade.json >/dev/null \
            || fail "golden facade collision manifest is incorrect"

          mkdir production-metadata production-facade
          gzip -dc ${productionMetadata}/blob \
            | tar --same-permissions --no-same-owner -xf - -C production-metadata
          gzip -dc ${productionFacade}/blob \
            | tar --same-permissions --no-same-owner -xf - -C production-facade

          test "$(stat -c %a production-metadata/root)" = 700 \
            || fail "production HOME is not private"
          test "$(stat -c %a production-metadata/tmp)" = 1777 \
            || fail "production /tmp mode is incorrect"
          test "$(stat -c %a production-metadata/etc/shadow)" = 600 \
            || fail "production shadow mode is incorrect"
          test "$(stat -c %a production-metadata/etc/passwd)" = 644
          test "$(stat -c %a production-metadata/etc/group)" = 644
          test "$(stat -c %a production-metadata/usr/bin/aos-container-init)" = 555 \
            || fail "production init is not executable"
          test "$(stat -c %a production-metadata/nix/var/nix/.aos-container-init.lock)" = 600 \
            || fail "production init lock mode is not private"
          test ! -s production-metadata/nix/var/nix/.aos-container-init.lock \
            || fail "production init lock is not empty"
          grep -Fx 'root:x:0:0:root:/root:/usr/bin/sh' production-metadata/etc/passwd >/dev/null
          grep -Fx 'root:x:0:' production-metadata/etc/group >/dev/null
          grep -Fx 'root:!:1::::::' production-metadata/etc/shadow >/dev/null
          grep -Fx 'sandbox = false' production-metadata/etc/nix/nix.conf >/dev/null
          grep -Fx 'substituters =' production-metadata/etc/nix/nix.conf >/dev/null
          test -s production-metadata/aos-registration
          cmp production-metadata/aos-registration ${productionReferenceGraph}/registration \
            || fail "embedded production registration differs from the authoritative graph"
          cmp production-metadata/usr/lib/aos-container/store-paths \
            ${productionReferenceGraph}/store-paths \
            || fail "embedded production store inventory differs from the authoritative graph"
          printf '%s\n' ${lib.concatMapStringsSep " " lib.escapeShellArg (map builtins.toString (lib.unique (goldenRoots ++ [pkgs.aos pkgs.aos.apm pkgs.aos.apr])))} \
            > expected-production-baked-roots
          cmp expected-production-baked-roots \
            production-metadata/usr/lib/aos-container/baked-roots \
            || fail "embedded baked roots differ from the production golden package list"
          test "$(readlink production-metadata/var/lib/profiles)" \
            = /nix/var/nix/gcroots/aos-profiles \
            || fail "APM profiles are not rooted inside Nix gcroots"
          for ca_alias in \
            etc/ssl/certs/ca-certificates.crt \
            etc/ssl/certs/ca-bundle.crt \
            etc/pki/tls/certs/ca-bundle.crt; do
            test -L "production-metadata/$ca_alias" \
              || fail "missing production CA alias: $ca_alias"
          done
          test ! -e production-metadata/etc/hosts
          test ! -e production-metadata/etc/hostname
          test ! -e production-metadata/etc/resolv.conf
          grep -Fx ${lib.escapeShellArg "AOS_STATE_VERSION=${systemIdentity.stateVersion}"} \
            production-metadata/etc/os-release >/dev/null
          grep -Fx ${lib.escapeShellArg "AOS_MODULE_ABI=${toString systemIdentity.moduleAbi}"} \
            production-metadata/etc/os-release >/dev/null

          for command in aos apm apr; do
            test -L "production-facade/usr/bin/$command" \
              || fail "production facade omits $command"
          done
          test ! -e production-facade/usr/bin/.aos-unwrapped
          test ! -e production-facade/usr/bin/.apm-unwrapped
          test ! -e production-facade/usr/bin/.apr-unwrapped
          test "$(readlink production-facade/usr/bin/kill)" = ${pkgs.coreutils}/bin/coreutils \
            || fail "production facade changed the reviewed kill winner"
          jq -e \
            --arg winner ${lib.escapeShellArg "${pkgs.coreutils}/bin/coreutils"} \
            --arg shadowed ${lib.escapeShellArg "${pkgs.util-linux}/bin/kill"} '
              .expectedCollisions == ["kill"]
              and .collisions == [{
                name: "kill",
                winner: $winner,
                shadowed: $shadowed,
                shadowedSource: $shadowed
              }]
            ' ${productionFacade}/facade.json >/dev/null \
            || fail "production facade collisions differ from reviewed policy"

          jq -e \
            --arg version ${lib.escapeShellArg systemIdentity.version} \
            --arg stateVersion ${lib.escapeShellArg systemIdentity.stateVersion} \
            --arg moduleAbi ${lib.escapeShellArg (toString systemIdentity.moduleAbi)} '
              .config.Labels["org.opencontainers.image.version"] == $version
              and .config.Labels["dev.andyl.aos.state-version"] == $stateVersion
              and .config.Labels["dev.andyl.aos.module-abi"] == $moduleAbi
              and (.config.Env | index("NIX_REMOTE=local") != null)
              and (.config.Env | index("PATH=/var/lib/profiles/per-user/root/current/bin:/var/lib/profiles/per-user/root/current/sbin:/usr/bin:/usr/sbin:/bin") != null)
              and (.config | has("Volumes") | not)
              and .config.Volumes == null
            ' ${productionImage}/config.json >/dev/null \
            || fail "production OCI config omits release/runtime metadata"

          for forbidden_root in ${lib.concatMapStringsSep " " lib.escapeShellArg forbiddenRuntimePathStrings}; do
            if grep -Fx "$forbidden_root" ${productionReferenceGraph}/store-paths >/dev/null; then
              fail "bootable-system artifact entered the container closure: $forbidden_root"
            fi
          done

          for self_contained in \
            ${productionMetadata} \
            ${productionFacade} \
            ${productionImage} \
            ${productionDockerArchive} \
            ${productionIndex}; do
            test -z "$(nix-store -q --references "$self_contained")" \
              || fail "published container output retains a Nix reference: $self_contained"
          done

          mkdir -p "$out"
          printf '%s\n' PASS > "$out/result"
          cp ${facadeLayer}/facade.json "$out/facade.json"
        '';
      }
    ];

    meta.description = "Focused daemonless AOS container runtime and facade checks";
  }
