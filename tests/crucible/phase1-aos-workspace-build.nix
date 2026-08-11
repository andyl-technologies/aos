{
  pkgs,
  lib,
}: let
  requiredAttrs = [
    "crucible"
    "crucible-controller"
    "crucible-qemu-plugin"
    "qemu-crucible"
    "qemu-crucible-source"
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
      inherit (pkgs) crucible crucible-controller crucible-qemu-plugin qemu-crucible qemu-crucible-source;
    }
    else {};
  nativeQemuSystemBinary =
    {
      "x86_64-linux" = "qemu-system-x86_64";
      "aarch64-linux" = "qemu-system-aarch64";
    }.${
      pkgs.stdenv.hostPlatform.system
    }
    or (throw "crucible phase1 AOS workspace build does not support ${pkgs.stdenv.hostPlatform.system}");
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

            stale_shmem_label="crucible-shmem-abi-v$((6 - 1))"
            if grep -R "$stale_shmem_label" crates pkgs tests docs; then
              echo "stale shared-memory ABI identity: $stale_shmem_label" >&2
              exit 1
            fi

            test -x ${packages.crucible}/bin/crucible
            test -x ${packages.crucible}/bin/gdb
            test -x ${packages.crucible}/bin/ssh
            test -x ${packages.crucible}/bin/crucible-debugger-live-fixture
            test -x ${packages.crucible}/bin/crucible-debugger-live-matrix
            test -x ${packages.crucible}/bin/gdbserver
            test -f ${packages.crucible}/share/licenses/crucible/Apache-2.0.txt
            test -f ${packages.crucible}/share/licenses/crucible/MIT.txt
            test -f ${packages.crucible}/share/licenses/crucible/GPL-2.0-only.txt
            test -f ${packages.crucible}/share/licenses/crucible/GPL-2.0-or-later.txt
            test -f ${packages.crucible}/share/licenses/crucible/GPL-3.0.txt
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
            grep -q '^qemu_path=${packages.qemu-crucible}/bin/${nativeQemuSystemBinary}$' \
              ${packages.crucible}/nix-support/crucible-build-info
            grep -q '^plugin_package=crucible-qemu-plugin$' \
              ${packages.crucible}/nix-support/crucible-build-info
            grep -q '^plugin_path=${packages.crucible-qemu-plugin}/lib/libcrucible_qemu_plugin.so$' \
              ${packages.crucible}/nix-support/crucible-build-info
            grep -q '^component_licenses=Apache-2.0,MIT,GPL-2.0-only,GPL-2.0-or-later,GPL-3.0-or-later,BSD-2-Clause$' \
              ${packages.crucible}/nix-support/crucible-build-info
            grep -q '^gdb_package=gdb$' \
              ${packages.crucible}/nix-support/crucible-build-info
            grep -q '^gdb_path=${packages.gdb}/bin/gdb$' \
              ${packages.crucible}/nix-support/crucible-build-info
            grep -q '^gdb_license=GPL-3.0-or-later$' \
              ${packages.crucible}/nix-support/crucible-build-info
            grep -q '^ssh_package=openssh$' \
              ${packages.crucible}/nix-support/crucible-build-info
            grep -q '^ssh_path=${pkgs.openssh}/bin/ssh$' \
              ${packages.crucible}/nix-support/crucible-build-info
            grep -q '^ssh_license=BSD-2-Clause$' \
              ${packages.crucible}/nix-support/crucible-build-info
            grep -q '^boundary_crates=crucible-protocol,crucible-shmem$' \
              ${packages.crucible}/nix-support/crucible-build-info
            grep -q '^boundary_crates_license=MIT$' \
              ${packages.crucible}/nix-support/crucible-build-info
            grep -q '^qemu_component_licenses=GPL-2.0-only,GPL-2.0-or-later,MIT$' \
              ${packages.crucible}/nix-support/crucible-build-info
            grep -q '^qemu_generated_boundary_header_license_option=MIT$' \
              ${packages.crucible}/nix-support/crucible-build-info
            grep -q '^qemu_corresponding_source_path=${packages.qemu-crucible-source}$' \
              ${packages.crucible}/nix-support/crucible-build-info
            grep -q '^artifact_role=aggregate-release-root$' \
              ${packages.crucible}/nix-support/aos-release-policy
            grep -q '^pair_count=1$' ${packages.crucible}/nix-support/aos-release-policy
            grep -q '^pair_1_component_path=${packages.qemu-crucible}$' \
              ${packages.crucible}/nix-support/aos-release-policy
            grep -q '^pair_1_corresponding_source_path=${packages.qemu-crucible-source}$' \
              ${packages.crucible}/nix-support/aos-release-policy
            grep -q '^pair_1_identity=${packages.qemu-crucible.passthru.qemuBuildIdentity}$' \
              ${packages.crucible}/nix-support/aos-release-policy
            grep -q '^discovery_hint=runtime-environment-wrapper$' \
              ${packages.crucible}/nix-support/crucible-build-info
            grep -q '^shmem_abi_version=6$' \
              ${packages.crucible}/nix-support/crucible-build-info
            grep -q '^shmem_abi=crucible-shmem-abi-v6$' \
              ${packages.crucible}/nix-support/crucible-build-info
            grep -q '^guest_host_protocol_version=1$' \
              ${packages.crucible}/nix-support/crucible-build-info
            grep -q '^guest_host_protocol_abi=crucible-guest-host-channel-v1$' \
              ${packages.crucible}/nix-support/crucible-build-info
            grep -q '^doorbell_instruction_abi_version=4$' \
              ${packages.crucible}/nix-support/crucible-build-info
            grep -q '^rpc_abi_version=5.0.0$' \
              ${packages.crucible}/nix-support/crucible-build-info
            grep -q '^rpc_abi_build=crucible-rpc-abi-v5$' \
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
            grep -q '^shmem_abi_version=6$' \
              ${packages.crucible-qemu-plugin}/nix-support/crucible-qemu-plugin-build-info
            grep -q '^shmem_abi=crucible-shmem-abi-v6$' \
              ${packages.crucible-qemu-plugin}/nix-support/crucible-qemu-plugin-build-info
            grep -q '^qemu_shmem_abi=crucible-shmem-abi-v6$' \
              ${packages.crucible-qemu-plugin}/nix-support/crucible-qemu-plugin-build-info
            grep -q '^shmem_generated_header=${packages.qemu-crucible}/include/aos/crucible/crucible_shmem_abi.h$' \
              ${packages.crucible-qemu-plugin}/nix-support/crucible-qemu-plugin-build-info
            grep -q '^shmem_generated_header_hash=${packages.qemu-crucible.passthru.shmemHeaderHash}$' \
              ${packages.crucible-qemu-plugin}/nix-support/crucible-qemu-plugin-build-info
            grep -q '^plugin_abi=crucible-shmem-abi-v6$' \
              ${packages.crucible-qemu-plugin}/nix-support/crucible-qemu-plugin-build-info

            test -f ${packages.qemu-crucible}/include/qemu/qemu-plugin.h
            grep -q '^standalone_release=false$' \
              ${packages.qemu-crucible}/nix-support/aos-release-policy
            grep -q '^corresponding_source_identity=${packages.qemu-crucible.passthru.qemuBuildIdentity}$' \
              ${packages.qemu-crucible}/nix-support/aos-release-policy
            test -f ${packages.qemu-crucible}/share/licenses/qemu-crucible/MIT.txt
            test -f ${packages.qemu-crucible}/share/licenses/qemu-crucible/GPL-2.0-or-later.txt
            test -f ${packages.qemu-crucible}/share/licenses/qemu-crucible/AOS-PATCH-LICENSES.md
            grep -q '^qemu_combined_work_license=GPL-2.0-only$' \
              ${packages.qemu-crucible}/share/aos/crucible/qemu-build-identity.env
            grep -q '^qemu_unmarked_source_default_license=GPL-2.0-or-later$' \
              ${packages.qemu-crucible}/share/aos/crucible/qemu-build-identity.env
            grep -q '^qemu_plugin_header_license=GPL-2.0-or-later$' \
              ${packages.qemu-crucible}/share/aos/crucible/qemu-build-identity.env
            grep -q '^qemu_shmem_header_license_option=MIT$' \
              ${packages.qemu-crucible}/share/aos/crucible/qemu-build-identity.env
            grep -q 'qemu_plugin_crucible_rr_switch_quantum' \
              ${packages.qemu-crucible}/include/qemu/qemu-plugin.h
            test -f ${packages.qemu-crucible}/include/aos/crucible/crucible_shmem_abi.h
            grep -q '#define CRUCIBLE_SHMEM_ABI_VERSION 6u' \
              ${packages.qemu-crucible}/include/aos/crucible/crucible_shmem_abi.h
            test -f ${packages.qemu-crucible}/share/aos/crucible/qemu-build-identity.env
            grep -q '^qemu_sim_capability=qemu-crucible$' \
              ${packages.qemu-crucible}/share/aos/crucible/qemu-build-identity.env
            grep -q '^qemu_shmem_abi_version=6$' \
              ${packages.qemu-crucible}/share/aos/crucible/qemu-build-identity.env
            grep -q '^qemu_shmem_abi=crucible-shmem-abi-v6$' \
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
            shmem_abi=crucible-shmem-abi-v6
            guest_host_protocol_abi=crucible-guest-host-channel-v1
            rpc_abi=5.0.0+crucible-rpc-abi-v5
            qemu_sim_capability=qemu-crucible
            generated_shmem_header=include/aos/crucible/crucible_shmem_abi.h
            RESULT
          '';
        }
      ];
    }
