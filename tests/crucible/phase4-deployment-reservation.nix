# Exercises the real L2 reservation in dedicated, unprivileged Linux processes.
{
  pkgs,
  lib,
}: let
  source = import ../../pkgs/tools/crucible/_source.nix {inherit lib;};
  cargoDeps = import ./_cargo-deps.nix {inherit pkgs lib;};
in
  pkgs.mkDerivation {
    pname = "crucible-deployment-reservation-check";
    version = "0";
    src = source;
    buildDeps = [pkgs.coreutils pkgs.grep pkgs.rust pkgs.sed];
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
        name = "build";
        script = ''
          set -eu
          export CARGO_HOME="$TMPDIR/cargo"
          mkdir -p "$CARGO_HOME" .cargo
          sed "s|@vendor@|${cargoDeps}|g" \
            "${cargoDeps}/.cargo/config.toml" > .cargo/config.toml
          cargo build --frozen --offline --release -j"$NIX_BUILD_CORES" \
            --manifest-path crates/Cargo.toml --target-dir "$TMPDIR/target" \
            -p crucible-host-resources --example crucible-deployment-reservation-controls
        '';
      }
      {
        name = "run-dedicated-process-controls";
        script = ''
          set -eu
          binary="$TMPDIR/target/release/examples/crucible-deployment-reservation-controls"
          test -x "$binary"
          mkdir -p "$out/evidence"
          sha256sum "$binary" > "$out/evidence/example-elf.sha256"
          sha256sum \
            crates/Cargo.lock \
            crates/crucible/crucible-host-resources/Cargo.toml \
            crates/crucible/crucible-host-resources/src/lib.rs \
            crates/crucible/crucible-host-resources/src/linux_process_supervisor.rs \
            crates/crucible/crucible-host-resources/src/linux_process_supervisor/bootstrap.rs \
            crates/crucible/crucible-host-resources/src/linux_process_supervisor/current.rs \
            crates/crucible/crucible-host-resources/src/linux_process_supervisor/reservation.rs \
            crates/crucible/crucible-host-resources/examples/crucible-deployment-reservation-controls.rs \
            > "$out/evidence/source-inputs.sha256"

          # This independent hard wall bounds the launcher and its process group;
          # only the example's dedicated children install resource ceilings.
          if timeout --signal=KILL 30s "$binary" all \
            > "$out/evidence/controls.log" 2>&1; then
            cat "$out/evidence/controls.log"
          else
            status=$?
            cat "$out/evidence/controls.log"
            exit "$status"
          fi

          test "$(grep -Fxc 'handoff: owner_dropped=true leases_revoked=true process_once=true' "$out/evidence/controls.log")" -eq 1
          test "$(grep -Ec '^birth-refusal: pid=[0-9]+ failure=ForeignAuthority output_retained=true actor_joined=true process_once=true unchanged=' "$out/evidence/controls.log")" -eq 1
          test "$(grep -Ec '^inherited-child: pid=[0-9]+ inherited_preserved=true accepted_strictly_larger=true$' "$out/evidence/controls.log")" -eq 1
          test "$(grep -Ec '^sticky-revocation: pid=[0-9]+ observed=.* restored=.* first=Err\(ForeignAuthority\) still_revoked=true$' "$out/evidence/controls.log")" -eq 1
          test "$(grep -Ec '^all: launcher_pid=[0-9]+ unchanged=' "$out/evidence/controls.log")" -eq 1
          {
            echo PASS
            echo check=checks.crucible.phase4.deploymentReservation
            echo modes=4
            echo scope=dedicated-process-L2-reservation-controls
            echo source_semantic_credit=unqualified
            echo ready=unqualified
            echo production_cli=unqualified
          } > "$out/result"
        '';
      }
    ];
  }
