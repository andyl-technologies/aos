{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase1.qemuDoorbellNoPatch",
  taskIds ? ["T-PATCH-15"],
  qemuPackage ? pkgs.qemu-crucible,
}: let
  patchDir = ../../pkgs/emulation/qemu-patches;
  qemuNix = builtins.readFile ../../pkgs/emulation/qemu.nix;
  qemuPatchSpec = builtins.readFile ../../docs/rfcs/0010-crucible/11-qemu-patches.md;
  riskSpec = builtins.readFile ../../docs/rfcs/0010-crucible/30-risks-spikes.md;
  decisionRegister = builtins.readFile ../../docs/rfcs/0010-crucible/31-decision-register.md;
  phase0S2Plugin = builtins.readFile ./phase0-s2-io-idle-plugin.c;
  phase0S5Plugin = builtins.readFile ./phase0-s5-virtual-memory-plugin.c;
  phase0S5Check = builtins.readFile ./phase0-s5.nix;
  pluginLib = builtins.readFile ../../crates/crucible-qemu-plugin/src/lib.rs;
  pluginWhiteboxDoorbell = builtins.readFile ../../crates/crucible-qemu-plugin/src/whitebox_doorbell.rs;
  defaultChecks = builtins.readFile ./default.nix;
  patchSeriesCheck = builtins.readFile ./phase2-qemu-patch-series.nix;
  phase0S2 = import ./phase0-s2.nix {inherit pkgs lib;};
  phase0S5 = import ./phase0-s5.nix {inherit pkgs lib;};
  qemuPluginWhiteboxDoorbell = import ./phase2-plugin-whitebox-doorbell.nix {inherit pkgs lib;};

  patchFiles =
    builtins.sort builtins.lessThan
    (builtins.filter
      (name: lib.hasSuffix ".patch" name)
      (builtins.attrNames (builtins.readDir patchDir)));
  patchSources =
    map (name: {
      inherit name;
      source = builtins.readFile (patchDir + "/${name}");
    })
    patchFiles;

  inherit (import ./_lib.nix {inherit lib;}) hasInfix failuresFor;

  forbiddenDoorbellPatchNeedles = [
    "qemu_plugin_register_doorbell_trap"
    "qemu_plugin_guest_memory_read"
    "crucible-doorbell"
    "crucible_doorbell"
  ];

  forbiddenPatchHits =
    lib.concatMap (
      patch:
        lib.concatMap (
          needle:
            lib.optionals (hasInfix needle patch.source) [
              "pkgs/emulation/qemu-patches/${patch.name}: T-PATCH-15 must not carry bespoke doorbell patch symbol `${needle}`"
            ]
        )
        forbiddenDoorbellPatchNeedles
    )
    patchSources;

  doorbellPatchNames =
    builtins.filter (name: hasInfix "doorbell" name) patchFiles;

  failures =
    lib.optionals (doorbellPatchNames != []) [
      "pkgs/emulation/qemu-patches: T-PATCH-15 no-patch decision found doorbell patch files: ${builtins.concatStringsSep "," doorbellPatchNames}"
    ]
    ++ forbiddenPatchHits
    ++ lib.concatMap (
      needle:
        lib.optionals (hasInfix needle qemuNix) [
          "pkgs/emulation/qemu.nix: T-PATCH-15 must not wire bespoke doorbell patch symbol `${needle}`"
        ]
    )
    forbiddenDoorbellPatchNeedles
    ++ failuresFor "docs/rfcs/0010-crucible/11-qemu-patches.md" qemuPatchSpec [
      {
        label = "no new QEMU patch decision";
        needle = "no QEMU patch was added";
      }
      {
        label = "PATCH-33 cross reference";
        needle = "PATCH-33";
      }
      {
        label = "upstream read-memory evidence";
        needle = "qemu_plugin_read_memory_vaddr";
      }
    ]
    ++ failuresFor "docs/rfcs/0010-crucible/30-risks-spikes.md" riskSpec [
      {
        label = "retired RISK-12 upstream read-memory evidence";
        needle = "qemu_plugin_read_memory_vaddr_available=true";
      }
      {
        label = "production white-box channel remains later";
        needle = "production_whitebox_channel_implemented=false";
      }
    ]
    ++ failuresFor "docs/rfcs/0010-crucible/31-decision-register.md" decisionRegister [
      {
        label = "RISK-12 decision evidence";
        needle = "qemu_plugin_read_memory_vaddr_available=true";
      }
    ]
    ++ failuresFor "tests/crucible/phase0-s2-io-idle-plugin.c" phase0S2Plugin [
      {
        label = "plugin memory callback surface";
        needle = "qemu_plugin_register_vcpu_mem_cb";
      }
      {
        label = "I/O-address query surface";
        needle = "qemu_plugin_hwaddr_is_io";
      }
      {
        label = "hardware-address resolution";
        needle = "qemu_plugin_get_hwaddr";
      }
    ]
    ++ failuresFor "tests/crucible/phase0-s5-virtual-memory-plugin.c" phase0S5Plugin [
      {
        label = "upstream virtual memory read";
        needle = "qemu_plugin_read_memory_vaddr";
      }
      {
        label = "translation callback surface";
        needle = "qemu_plugin_register_vcpu_tb_trans_cb";
      }
      {
        label = "register read surface";
        needle = "qemu_plugin_read_register";
      }
    ]
    ++ failuresFor "tests/crucible/phase0-s5.nix" phase0S5Check [
      {
        label = "read-memory capability evidence";
        needle = "qemu_plugin_read_memory_vaddr_available=true";
      }
      {
        label = "instruction-marker doorbell evidence";
        needle = "doorbell_surface=phase0_instruction_marker_double";
      }
      {
        label = "byte-match evidence";
        needle = "read_bytes_match_expected=true";
      }
      {
        label = "side-effect-free evidence";
        needle = "side_effect_free_fingerprint_match=true";
      }
    ]
    ++ failuresFor "crates/crucible-qemu-plugin/src/lib.rs" pluginLib [
      {
        label = "doorbell execution callback symbol exported";
        needle = "QEMU_PLUGIN_DOORBELL_EXEC_CB_SYMBOL";
      }
      {
        label = "guest-memory read symbol exported";
        needle = "QEMU_PLUGIN_GUEST_MEMORY_READ_SYMBOL";
      }
    ]
    ++ failuresFor "crates/crucible-qemu-plugin/src/whitebox_doorbell.rs" pluginWhiteboxDoorbell [
      {
        label = "translated-instruction callback symbol";
        needle = "qemu_plugin_register_vcpu_insn_exec_cb";
      }
      {
        label = "upstream read-memory symbol";
        needle = "qemu_plugin_read_memory_vaddr";
      }
      {
        label = "trap alias does not require bespoke QEMU symbol";
        needle = "QEMU_PLUGIN_REGISTER_DOORBELL_TRAP_SYMBOL: &str =";
      }
      {
        label = "trap alias points at upstream execution callback";
        needle = "QEMU_PLUGIN_DOORBELL_EXEC_CB_SYMBOL";
      }
      {
        label = "off-mode inert plan";
        needle = "WhiteboxDoorbellRegistrationPlan::Disabled";
      }
      {
        label = "trap reads guest memory through adapter";
        needle = "GuestMemoryReader";
      }
      {
        label = "trap icount stamp";
        needle = "event.current_icount()";
      }
    ]
    ++ failuresFor "tests/crucible/default.nix" defaultChecks [
      {
        label = "phase1 exposes QEMU doorbell no-patch check";
        needle = "qemuDoorbellNoPatch = import ./phase1-qemu-doorbell-no-patch.nix";
      }
    ]
    ++ failuresFor "tests/crucible/phase2-qemu-patch-series.nix" patchSeriesCheck [
      {
        label = "T-PATCH-15 no-patch decision recorded";
        needle = "noPatchDecisions";
      }
      {
        label = "doorbell no-patch evidence check";
        needle = "checks.crucible.phase1.qemuDoorbellNoPatch";
      }
    ];
in
  if failures != []
  then throw "crucible phase1 QEMU doorbell no-patch check failed:\n${builtins.concatStringsSep "\n" failures}"
  else
    pkgs.mkDerivation {
      pname = "crucible-phase1-qemu-doorbell-no-patch";
      version = "0";
      src = null;

      buildDeps = [
        pkgs.coreutils
        pkgs.grep
        pkgs.tar
        pkgs.xz
      ];

      phases = [
        {
          name = "check-qemu-doorbell-no-patch";
          script = ''
            set -eu

            fail() {
              echo "FAIL: $*" >&2
              exit 1
            }

            mkdir -p "$out"

            source_dir="$TMPDIR/qemu-source"
            mkdir -p "$source_dir"
            tar -xf ${qemuPackage.src} -C "$source_dir"
            header="$source_dir/qemu-${qemuPackage.version}/include/qemu/qemu-plugin.h"
            [ -f "$header" ] || fail "missing QEMU plugin header: $header"

            for declaration in \
              'qemu_plugin_register_vcpu_tb_trans_cb(' \
              'qemu_plugin_register_vcpu_insn_exec_cb(' \
              'qemu_plugin_read_memory_vaddr(' \
              'qemu_plugin_read_register('
            do
              grep -q "$declaration" "$header" || fail "QEMU plugin header missing upstream doorbell surface: $declaration"
            done

            cp "${phase0S2}/result" "$out/phase0-s2.result"
            cp "${phase0S5}/result" "$out/phase0-s5.result"
            cp "${qemuPluginWhiteboxDoorbell}/result" "$out/plugin-whitebox-doorbell.result"

            grep -q '^PASS$' "$out/phase0-s2.result"
            grep -q '^s2_complete=true$' "$out/phase0-s2.result"
            grep -q '^block_io_events_observed_per_operation=true$' "$out/phase0-s2.result"
            grep -q '^ninep_io_events_observed_per_operation=true$' "$out/phase0-s2.result"
            grep -q '^PASS$' "$out/phase0-s5.result"
            grep -q '^qemu_plugin_read_memory_vaddr_available=true$' "$out/phase0-s5.result"
            grep -q '^doorbell_surface=phase0_instruction_marker_double$' "$out/phase0-s5.result"
            grep -q '^read_bytes_match_expected=true$' "$out/phase0-s5.result"
            grep -q '^side_effect_free_fingerprint_match=true$' "$out/phase0-s5.result"
            grep -q '^s5_complete=true$' "$out/phase0-s5.result"
            grep -q '^PASS$' "$out/plugin-whitebox-doorbell.result"
            grep -q '^off_mode=disabled-plan-installs-no-trap$' "$out/plugin-whitebox-doorbell.result"
            grep -q '^guest_memory=read-through-qemu-plugin-api-trait$' "$out/plugin-whitebox-doorbell.result"
            grep -q '^marker_stamp=exact-current-icount$' "$out/plugin-whitebox-doorbell.result"

            cat > "$out/result" <<'RESULT'
            PASS
            check=${attrPath}
            tasks=${builtins.concatStringsSep "," taskIds}
            gate=gate:patch-microtests
            qemu_package=${qemuPackage}
            qemu_package_version=${qemuPackage.version}
            qemu_doorbell_patch_required=false
            bespoke_qemu_doorbell_patch_present=false
            qemu_upstream_tb_trans_cb_available=true
            qemu_upstream_mem_cb_available=true
            qemu_upstream_io_query_available=true
            qemu_upstream_read_memory_vaddr_available=true
            qemu_upstream_read_register_available=true
            phase0_s5_virtual_read_validated=true
            phase0_s2_io_trap_surface_validated=true
            whitebox_mode_off_installs_no_trap_validated=true
            carried_patch_count=${toString (builtins.length patchFiles)}
            RESULT
          '';
        }
      ];
    }
