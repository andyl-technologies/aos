{
  pkgs,
  lib,
}: let
  requiredAttrs = [
    "crucible"
    "crucible-qemu-plugin"
    "qemu-crucible"
  ];

  attrFailures =
    lib.concatMap (
      attr:
        lib.optionals (!(builtins.hasAttr attr pkgs)) [
          "pkgs.${attr} is not exposed by the AOS package set"
        ]
    )
    requiredAttrs;

  packages =
    if attrFailures == []
    then {
      inherit (pkgs) crucible crucible-qemu-plugin qemu-crucible;
    }
    else {};
in
  if attrFailures != []
  then throw "crucible phase1 AOS workspace build lint failed:\n${builtins.concatStringsSep "\n" attrFailures}"
  else
    pkgs.mkDerivation {
      pname = "crucible-phase1-aos-workspace-build";
      version = "0";
      src = null;

      buildDeps = [
        pkgs.coreutils
        pkgs.grep
        packages.crucible
        packages.crucible-qemu-plugin
        packages.qemu-crucible
      ];

      phases = [
        {
          name = "check";
          script = ''
            set -eu

            test -x ${packages.crucible}/bin/crucible
            test -f ${packages.crucible-controller}/nix-support/crucible-build-info
            grep -q '^build_system=mkCargoPackage$' \
              ${packages.crucible-controller}/nix-support/crucible-build-info
            grep -q '^cargo_deps=fetchCargoDeps$' \
              ${packages.crucible-controller}/nix-support/crucible-build-info
            grep -q '^cargo_workspace_flags=--workspace' \
              ${packages.crucible-controller}/nix-support/crucible-build-info
            grep -q -- '--exclude aos' \
              ${packages.crucible-controller}/nix-support/crucible-build-info
            grep -q -- 'cargo_workspace_flags=.*--exclude crucible-qemu-plugin' \
              ${packages.crucible-controller}/nix-support/crucible-build-info
            grep -q '^qemu_package=qemu-crucible$' \
              ${packages.crucible}/nix-support/crucible-build-info
            grep -q '^qemu_path=${packages.qemu-crucible}/bin/qemu-system-x86_64$' \
              ${packages.crucible}/nix-support/crucible-build-info
            grep -q '^plugin_package=crucible-qemu-plugin$' \
              ${packages.crucible}/nix-support/crucible-build-info
            grep -q '^plugin_path=${packages.crucible-qemu-plugin}/lib/libcrucible_qemu_plugin.so$' \
              ${packages.crucible}/nix-support/crucible-build-info
            grep -q '^discovery_hint=runtime-environment-wrapper$' \
              ${packages.crucible}/nix-support/crucible-build-info
            grep -q '^shmem_abi_version=5$' \
              ${packages.crucible}/nix-support/crucible-build-info
            grep -q '^shmem_abi=crucible-shmem-abi-v5$' \
              ${packages.crucible}/nix-support/crucible-build-info
            grep -q '^guest_host_protocol_version=1$' \
              ${packages.crucible}/nix-support/crucible-build-info
            grep -q '^guest_host_protocol_abi=crucible-guest-host-channel-v1$' \
              ${packages.crucible}/nix-support/crucible-build-info
            grep -q '^rpc_abi_version=4.0.0$' \
              ${packages.crucible}/nix-support/crucible-build-info
            grep -q '^rpc_abi_build=crucible-rpc-abi-v4$' \
              ${packages.crucible}/nix-support/crucible-build-info

            test -f ${packages.crucible-qemu-plugin}/lib/libcrucible_qemu_plugin.so
            test -e ${packages.crucible-qemu-plugin}/lib/qemu/plugins/crucible-qemu-plugin.so
            test -f ${packages.crucible-qemu-plugin}/nix-support/crucible-qemu-plugin-build-info
            grep -q '^build_system=mkCargoPackage$' \
              ${packages.crucible-qemu-plugin}/nix-support/crucible-qemu-plugin-build-info
            grep -q '^cargo_deps=fetchCargoDeps$' \
              ${packages.crucible-qemu-plugin}/nix-support/crucible-qemu-plugin-build-info
            grep -q '^qemu_package=qemu-crucible$' \
              ${packages.crucible-qemu-plugin}/nix-support/crucible-qemu-plugin-build-info
            grep -q '^qemu_sim_capability_marker=${packages.qemu-crucible}/share/aos/crucible/qemu-build-identity.env$' \
              ${packages.crucible-qemu-plugin}/nix-support/crucible-qemu-plugin-build-info
            grep -q '^qemu_plugin_header=${packages.qemu-crucible}/include/qemu/qemu-plugin.h$' \
              ${packages.crucible-qemu-plugin}/nix-support/crucible-qemu-plugin-build-info
            grep -q '^qemu_plugin_api_version=4$' \
              ${packages.crucible-qemu-plugin}/nix-support/crucible-qemu-plugin-build-info
            grep -q '^qemu_plugin_abi=qemu-plugin-api-v4$' \
              ${packages.crucible-qemu-plugin}/nix-support/crucible-qemu-plugin-build-info
            grep -q '^shmem_abi_version=5$' \
              ${packages.crucible-qemu-plugin}/nix-support/crucible-qemu-plugin-build-info
            grep -q '^shmem_abi=crucible-shmem-abi-v5$' \
              ${packages.crucible-qemu-plugin}/nix-support/crucible-qemu-plugin-build-info
            grep -q '^qemu_shmem_abi=crucible-shmem-abi-v5$' \
              ${packages.crucible-qemu-plugin}/nix-support/crucible-qemu-plugin-build-info
            grep -q '^shmem_generated_header=${packages.qemu-crucible}/include/aos/crucible/crucible_shmem_abi.h$' \
              ${packages.crucible-qemu-plugin}/nix-support/crucible-qemu-plugin-build-info
            grep -q '^shmem_generated_header_hash=${packages.qemu-crucible.passthru.shmemHeaderHash}$' \
              ${packages.crucible-qemu-plugin}/nix-support/crucible-qemu-plugin-build-info
            grep -q '^plugin_abi=crucible-shmem-abi-v5$' \
              ${packages.crucible-qemu-plugin}/nix-support/crucible-qemu-plugin-build-info

            test -f ${packages.qemu-crucible}/include/qemu/qemu-plugin.h
            grep -q 'qemu_plugin_crucible_rr_switch_quantum' \
              ${packages.qemu-crucible}/include/qemu/qemu-plugin.h
            test -f ${packages.qemu-crucible}/include/aos/crucible/crucible_shmem_abi.h
            grep -q '#define CRUCIBLE_SHMEM_ABI_VERSION 5u' \
              ${packages.qemu-crucible}/include/aos/crucible/crucible_shmem_abi.h
            test -f ${packages.qemu-crucible}/share/aos/crucible/qemu-build-identity.env
            grep -q '^qemu_sim_capability=qemu-crucible$' \
              ${packages.qemu-crucible}/share/aos/crucible/qemu-build-identity.env
            grep -q '^qemu_shmem_abi_version=5$' \
              ${packages.qemu-crucible}/share/aos/crucible/qemu-build-identity.env
            grep -q '^qemu_shmem_abi=crucible-shmem-abi-v5$' \
              ${packages.qemu-crucible}/share/aos/crucible/qemu-build-identity.env
            grep -q '^qemu_shmem_header=include/aos/crucible/crucible_shmem_abi.h$' \
              ${packages.qemu-crucible}/share/aos/crucible/qemu-build-identity.env
            grep -q '^qemu_shmem_header_hash=${packages.qemu-crucible.passthru.shmemHeaderHash}$' \
              ${packages.qemu-crucible}/share/aos/crucible/qemu-build-identity.env

            mkdir -p "$out"
            cat > "$out/result" <<'RESULT'
            PASS
            check=checks.crucible.phase1.aosWorkspaceBuild
            tasks=T-CRATE-14
            packages=crucible-controller,crucible,crucible-qemu-plugin,qemu-crucible
            cargo_deps=fetchCargoDeps
            plugin_headers=qemu-crucible
            plugin_library=lib/libcrucible_qemu_plugin.so
            plugin_search_path=lib/qemu/plugins/crucible-qemu-plugin.so
            qemu_discovery_hint=runtime-environment-wrapper
            qemu_plugin_abi=qemu-plugin-api-v4
            shmem_abi=crucible-shmem-abi-v5
            guest_host_protocol_abi=crucible-guest-host-channel-v1
            rpc_abi=4.0.0+crucible-rpc-abi-v4
            qemu_sim_capability=qemu-crucible
            generated_shmem_header=include/aos/crucible/crucible_shmem_abi.h
            RESULT
          '';
        }
      ];
    }
