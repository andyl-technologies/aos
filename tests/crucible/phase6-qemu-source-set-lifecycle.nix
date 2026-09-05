# Exercises the real coordinator's native VMState freeze/abort/resumed-save path.
# This is a prerequisite flight, not whole-world fork acceptance.
{
  pkgs,
  lib,
  qemuPackage ? pkgs.qemu-crucible,
  pluginPackage ?
    import ../../pkgs/emulation/crucible-qemu-plugin.nix {
      inherit lib;
      inherit (pkgs) mkCargoPackage mkCargoArtifacts mkCargoDummySource fetchCargoVendor glib pkg-config;
      qemu-crucible = qemuPackage;
    },
  attrPath ? "checks.crucible.phase6.qemuSourceSetLifecycle",
  taskIds ? [],
}: let
  crucibleSrc = import ../../pkgs/tools/crucible/_source.nix {inherit lib;};
  cargoDeps = import ./_cargo-deps.nix {inherit pkgs lib;};
in
  pkgs.mkDerivation {
    pname = "crucible-phase6-qemu-source-set-lifecycle";
    version = "0";
    src = crucibleSrc;
    buildDeps = [pkgs.coreutils pkgs.grep pkgs.rust pkgs.sed qemuPackage pluginPackage];

    phases = [
      {
        name = "unpack";
        script = ''
          cp -R "$src" source
          chmod -R u+w source
          cd source
        '';
      }
      {
        name = "configure";
        script = ''
          export CARGO_HOME="$TMPDIR/cargo"
          mkdir -p "$CARGO_HOME" .cargo
          sed "s|@vendor@|${cargoDeps}|g" "${cargoDeps}/.cargo/config.toml" \
            > .cargo/config.toml
        '';
      }
      {
        name = "exercise-source-set-lifecycle";
        script = ''
          set -eu
          cargo build --frozen --offline \
            --target-dir "$TMPDIR/source-set-target" \
            --manifest-path crates/Cargo.toml \
            -p crucible-qemu --example crucible-qemu-live-source-set
          mkdir -p "$out"
          for kernel in ${pkgs.linux}/boot/vmlinuz-*; do
            test -f "$kernel"
            break
          done
          "$TMPDIR/source-set-target/debug/examples/crucible-qemu-live-source-set" \
            ${qemuPackage}/bin/qemu-system-x86_64 \
            ${pluginPackage}/lib/libcrucible_qemu_plugin.so \
            "$kernel" ${qemuPackage}/share/qemu/bios-256k.bin \
            "$TMPDIR/live-source-set" > "$out/result" 2> "$out/flight.stderr"
          grep -Fxq PASS "$out/result"
          grep -Fxq 'retained_transactions=2' "$out/result"
          grep -Fxq 'restored_vmstate_saves=2' "$out/result"
          grep -Fxq 'suffix_icount=9000001' "$out/result"
          grep -Fxq 'whole_world_child_handoff=false' "$out/result"
          printf '%s\n' 'check=${attrPath}' \
            'tasks=${builtins.concatStringsSep "," taskIds}' >> "$out/result"
          cp ${qemuPackage}/share/aos/crucible/qemu-build-identity.env "$out/"
          cp ${qemuPackage}/share/aos/crucible/block-backend-tests.tap "$out/"
        '';
      }
    ];
  }
