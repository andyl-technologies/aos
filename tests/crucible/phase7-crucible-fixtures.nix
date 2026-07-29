{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase7.crucibleFixtures",
  taskIds ? ["T-PKG-13"],
  crucibleFixtures ? pkgs.crucible-fixtures,
  anyGuestGate ? throw "crucible phase7 crucible-fixtures check requires checks.crucible.phase2.gates.anyGuest",
}: let
  packagingDoc = builtins.readFile ../../docs/rfcs/0010-crucible/26-packaging-aos-integration.md;
  fixturesNix = builtins.readFile ../../pkgs/tools/crucible-fixtures.nix;
  defaultChecks = builtins.readFile ./default.nix;
  deterministicLaunch = builtins.readFile ../../crates/crucible-qemu/src/launch.rs;
  entropyLaunch = builtins.readFile ../../crates/crucible-qemu/src/launch/entropy.rs;
  anyGuestGateSource = builtins.readFile ./phase2-any-guest.nix;

  fixtureName = "aos-minimal";
  taskList = builtins.concatStringsSep "," taskIds;
  fixturesProbe = import ../../pkgs/tools/crucible-fixtures.nix {
    inherit lib;
    mkDerivation = args: args // {type = "derivation-probe";};
    bash = "/stub/aos-bash";
    coreutils = "/stub/aos-coreutils";
    e2fsprogs = "/stub/aos-e2fsprogs";
    fakeroot = "/stub/aos-fakeroot";
    util-linux = "/stub/aos-util-linux";
    crucible-guest = "/stub/crucible-guest";
  };

  fixtureNodes =
    if fixturesProbe ? passthru && fixturesProbe.passthru ? crucibleFixtureNodes
    then fixturesProbe.passthru.crucibleFixtureNodes
    else throw "crucible phase7 crucible-fixtures check requires passthru.crucibleFixtureNodes";
  fixtureExt4Features =
    if fixturesProbe ? passthru && fixturesProbe.passthru ? crucibleFixtureExt4Features
    then fixturesProbe.passthru.crucibleFixtureExt4Features
    else "";
  fixtureEntropyMechanism =
    if fixturesProbe ? passthru && fixturesProbe.passthru ? crucibleFixtureEntropySeedMechanism
    then fixturesProbe.passthru.crucibleFixtureEntropySeedMechanism
    else "";
  fixtureThirdPartyPath =
    if fixturesProbe ? passthru && fixturesProbe.passthru ? crucibleFixtureThirdPartyGuestPath
    then fixturesProbe.passthru.crucibleFixtureThirdPartyGuestPath
    else "";

  inherit (import ./_lib.nix {inherit lib;}) hasInfix failuresFor forbiddenFor;



  hasLocalMac = node:
    node ? macAddress
    && node.macAddress == "build-output-derived";
  hasNodeIdentityMac = node:
    node ? contentAddressedNodeId
    && node ? macDerivation
    && node.contentAddressedNodeId == "build-output-root-image-sha256"
    && node.macDerivation == "sha256(root-image-sha256)";
  nodeFailures =
    lib.concatMap (
      node:
        lib.optionals (!(hasLocalMac node)) [
          "pkgs.crucible-fixtures.passthru.crucibleFixtureNodes: node ${node.name or "(unnamed)"} must document build-output-derived MAC material"
        ]
        ++ lib.optionals (!(hasNodeIdentityMac node)) [
          "pkgs.crucible-fixtures.passthru.crucibleFixtureNodes: node ${node.name or "(unnamed)"} must derive MAC from the root-image content hash"
        ]
    )
    fixtureNodes;

  failures =
    lib.optionals (fixturesProbe.pname or "" != "crucible-fixtures") [
      "pkgs.crucible-fixtures: expected pname crucible-fixtures, got ${fixturesProbe.pname or "(missing)"}"
    ]
    ++ lib.optionals (fixtureExt4Features != "^has_journal,^metadata_csum,^64bit") [
      "pkgs.crucible-fixtures: ext4 feature passthru must be ^has_journal,^metadata_csum,^64bit"
    ]
    ++ lib.optionals (fixtureEntropyMechanism != "scenario-seed-fw_cfg-plus-seeded-qemu-rng") [
      "pkgs.crucible-fixtures: entropy mechanism must name the deterministic fw_cfg/QEMU seed path"
    ]
    ++ lib.optionals (!(hasInfix "third-party-guests/generic-aos-linux-unmodified/manifest.toml" fixtureThirdPartyPath)) [
      "pkgs.crucible-fixtures: third-party guest path must point at the packaged generic unmodified guest manifest"
    ]
    ++ nodeFailures
    ++ failuresFor "docs/rfcs/0010-crucible/26-packaging-aos-integration.md" packagingDoc [
      {
        label = "T-PKG-13 checklist complete";
        needle = "- [x] **T-PKG-13**";
      }
      {
        label = "T-PKG-13 completion note";
        needle = "Completed by `checks.crucible.phase7.crucibleFixtures`";
      }
      {
        label = "crucible-fixtures package reference";
        needle = "`pkgs.crucible-fixtures`";
      }
    ]
    ++ failuresFor "pkgs/tools/crucible-fixtures.nix" fixturesNix [
      {
        label = "package derivation";
        needle = "pname = \"crucible-fixtures\";";
      }
      {
        label = "closure graph for boot shell/tools";
        needle = "exportReferencesGraph = graphPairs;";
      }
      {
        label = "filesystem image reference-scrub opt-out";
        needle = "dontNukeRefs = true;";
      }
      {
        label = "sandbox-compatible ext4 population";
        needle = "fakeroot -- mkfs.ext4 -d \"$source_dir\"";
      }
      {
        label = "required ext4 feature flags";
        needle = "ext4FeatureFlags = \"^has_journal,^metadata_csum,^64bit\";";
      }
      {
        label = "read-only fixture image";
        needle = "chmod 0444 \"$image\"";
      }
      {
        label = "content-addressed fixture image sidecar";
        needle = "image_sha256()";
      }
      {
        label = "rootfs init shebang exception";
        needle = "#!/bin/sh";
      }
      {
        label = "AOS bash shell target";
        needle = "rootfs/bin/sh";
      }
      {
        label = "virtio-9p readonly store mount";
        needle = "mount -t 9p -o trans=virtio,version=9p2000.L,cache=none,ro";
      }
      {
        label = "QEMU readonly 9p fsdev";
        needle = "readonly=on";
      }
      {
        label = "CoW overlay launch model";
        needle = "format=qcow2";
      }
      {
        label = "CoW overlay preparation artifact";
        needle = "prepare-cow-overlay";
      }
      {
        label = "CoW backing file relation";
        needle = "create -f qcow2 -F raw -b";
      }
      {
        label = "rootfs init kernel argument";
        needle = "init=/init";
      }
      {
        label = "deterministic entropy seed artifact";
        needle = "crucible-guest-entropy-seed.bin";
      }
      {
        label = "node-id MAC hash derivation";
        needle = "mac_from_hash()";
      }
      {
        label = "content-addressed node identity";
        needle = "root_node_id=\"sha256:$root_hash\"";
      }
      {
        label = "third-party unmodified guest package path";
        needle = "thirdPartyGuestName = \"generic-aos-linux-unmodified\";";
      }
      {
        label = "third-party guest has no Crucible payload";
        needle = "in_guest_crucible_content_required = false";
      }
    ]
    ++ forbiddenFor "pkgs/tools/crucible-fixtures.nix" fixturesNix [
      {
        label = "loop device image construction";
        needle = "losetup";
      }
      {
        label = "non-hermetic bash shebang";
        needle = "#!/bin/bash";
      }
      {
        label = "env shebang";
        needle = "#!/usr/bin/env";
      }
      {
        label = "nixpkgs import";
        needle = "<nixpkgs>";
      }
      {
        label = "host tools pattern";
        needle = "hostTools";
      }
      {
        label = "spawn-order MAC derivation";
        needle = "spawn order";
      }
      {
        label = "spawn-index MAC derivation";
        needle = "spawn_index";
      }
    ]
    ++ failuresFor "crates/crucible-qemu/src/launch.rs" deterministicLaunch [
      {
        label = "deterministic fw_cfg entropy argument";
        needle = "name={GUEST_ENTROPY_FW_CFG_NAME},file={}";
      }
      {
        label = "scenario seed source";
        needle = "\"guest_entropy_seed_source=scenario-seed\".to_owned(),";
      }
      {
        label = "QEMU rng-builtin seed scope";
        needle = "qemu_run_seed_controls=guest-random,glib-global-prng,rng-builtin";
      }
    ]
    ++ failuresFor "crates/crucible-qemu/src/launch/entropy.rs" entropyLaunch [
      {
        label = "fixture seed filename alignment";
        needle = "crucible-guest-entropy-seed.bin";
      }
      {
        label = "32-byte guest entropy seed";
        needle = "const GUEST_ENTROPY_SEED_BYTES: usize = 32;";
      }
      {
        label = "scenario seed derivation";
        needle = "from_scenario_seed";
      }
    ]
    ++ failuresFor "tests/crucible/phase2-any-guest.nix" anyGuestGateSource [
      {
        label = "unmodified generic guest fixture";
        needle = "guest_fixture=aos-linux-generated-initramfs";
      }
      {
        label = "any guest requires no Crucible content";
        needle = "in_guest_crucible_content_required=false";
      }
      {
        label = "any guest CoW non-mutation";
        needle = "base_image_mutation=false";
      }
    ]
    ++ failuresFor "tests/crucible/default.nix" defaultChecks [
      {
        label = "phase7 crucible-fixtures check imported";
        needle = "crucibleFixtures = import ./phase7-crucible-fixtures.nix";
      }
      {
        label = "phase7 crucible-fixtures check uses package";
        needle = "crucibleFixtures = pkgs.crucible-fixtures;";
      }
      {
        label = "phase7 crucible-fixtures check depends on any-guest proof";
        needle = "anyGuestGate = phase2.gates.anyGuest.rawGate;";
      }
      {
        label = "phase7 e2e determinism consumes fixture proof";
        needle = "dependencies = [perfBench.rawGate phase7.crucibleLinuxKernel phase7.crucibleFixtures phase7.crucibleGateCiWiring phase7.crucibleReleaseManifest phase7.reproductionProvenanceTriple];";
      }
    ];
in
  if failures != []
  then throw "crucible phase7 crucible-fixtures check failed:\n${builtins.concatStringsSep "\n" failures}"
  else
    pkgs.mkDerivation {
      pname = "crucible-phase7-crucible-fixtures";
      version = "0";
      src = null;

      buildDeps = [
        pkgs.coreutils
        pkgs.grep
      ];

      passthru.crucibleFixtures = crucibleFixtures;

      phases = [
        {
          name = "write-result";
          script = ''
            set -eu

            : "${crucibleFixtures}"
            : "${anyGuestGate}"

            fixtures_root="${crucibleFixtures}/share/crucible/fixtures"
            image="$fixtures_root/root/${fixtureName}-root.ext4"
            image_hash="$fixtures_root/root/${fixtureName}-root.ext4.sha256"
            manifest="$fixtures_root/manifest.toml"
            seed="$fixtures_root/entropy/crucible-guest-entropy-seed.bin"
            third_party_dir="$fixtures_root/third-party-guests/generic-aos-linux-unmodified"
            third_party="$third_party_dir/manifest.toml"
            third_party_image="$third_party_dir/root.ext4"
            third_party_hash="$third_party_dir/root.ext4.sha256"
            qemu_fragment="$fixtures_root/qemu/launch-fragment.txt"
            prepare_cow="$fixtures_root/qemu/prepare-cow-overlay"

            test -f "$image"
            test -f "$image_hash"
            test -f "$manifest"
            test -f "$seed"
            test -f "$third_party"
            test -f "$third_party_image"
            test -f "$third_party_hash"
            test -f "$qemu_fragment"
            test -x "$prepare_cow"

            seed_size=$(wc -c < "$seed" | tr -d ' ')
            if [ "$seed_size" != 32 ]; then
              echo "crucible-fixtures: entropy seed artifact must be 32 bytes, got $seed_size" >&2
              exit 1
            fi
            if [ -w "$image" ]; then
              echo "crucible-fixtures: root image must be read-only" >&2
              exit 1
            fi
            if [ -w "$third_party_image" ]; then
              echo "crucible-fixtures: third-party root image must be read-only" >&2
              exit 1
            fi

            grep -q '^read_only_base = true$' "$manifest"
            grep -q '^copy_on_write_boot = true$' "$manifest"
            grep -q '^virtio_9p_store_share = true$' "$manifest"
            grep -q '^ext4_feature_flags = "-O \^has_journal,\^metadata_csum,\^64bit"$' "$manifest"
            grep -q '^init_kernel_arg = "init=/init"$' "$manifest"
            grep -q '^root_image_sha256 = "[0-9a-f][0-9a-f]' "$manifest"
            grep -q '^mechanism = "scenario-seed-fw_cfg-plus-seeded-qemu-rng"$' "$manifest"
            grep -Eq '^mac_address = "02:([0-9a-f]{2}:){4}[0-9a-f]{2}"$' "$manifest"
            grep -q '^mac_derivation = "sha256(root-image-sha256)"$' "$manifest"
            grep -q '^unmodified_third_party_guest_path = "share/crucible/fixtures/third-party-guests/generic-aos-linux-unmodified/manifest.toml"$' "$manifest"
            grep -q '^exercised_by_gate = "checks.crucible.phase2.gates.anyGuest"$' "$third_party"
            grep -q '^in_guest_crucible_content_required = false$' "$third_party"
            grep -q '^root_image_sha256 = "[0-9a-f][0-9a-f]' "$third_party"
            if grep -q 'crucible-guest' "$third_party"; then
              echo "crucible-fixtures: third-party guest manifest must not require Crucible guest content" >&2
              exit 1
            fi
            grep -q 'readonly=on' "$qemu_fragment"
            grep -q 'format=qcow2' "$qemu_fragment"
            grep -q 'init=/init' "$qemu_fragment"
            grep -q 'create -f qcow2 -F raw -b' "$prepare_cow"
            grep -q 'BASE_IMAGE must be read-only' "$prepare_cow"
            grep -q '^gate=gate:any-guest$' "${anyGuestGate}/result"
            grep -q '^in_guest_crucible_content_required=false$' "${anyGuestGate}/result"
            grep -q '^base_image_mutation=false$' "${anyGuestGate}/result"

            mkdir -p "$out"
            cat > "$out/result" <<RESULT
            PASS
            check=${attrPath}
            tasks=${taskList}
            package=crucible-fixtures
            package_passthru=pkgs.crucible-fixtures
            root_image=$image
            root_image_sha256=$(cat "$image_hash")
            third_party_root_image=$third_party_image
            third_party_root_image_sha256=$(cat "$third_party_hash")
            manifest=$manifest
            read_only_base=true
            copy_on_write_boot=true
            virtio_9p_store_share=true
            ext4_features=-O ${fixtureExt4Features}
            entropy_seed_mechanism=${fixtureEntropyMechanism}
            entropy_seed_artifact=$seed
            entropy_seed_size_bytes=$seed_size
            node_mac_derivation=sha256-root-image-sha256
            third_party_guest_path=${fixtureThirdPartyPath}
            any_guest_gate=${anyGuestGate}
            e2e_gate_dependency=true
            RESULT
          '';
        }
      ];
    }
