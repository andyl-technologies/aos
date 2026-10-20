# Compares the production presence helper with the retained visitor bodies.
# Vector mutations use bounded providers; native guest qualification is separate.
{pkgs}: let
  patchDir = ../../pkgs/emulation/qemu-patches;
  atomicPatch = import (patchDir + "/_atomic-patch.nix");
  abiHeader = ../../crates/crucible/protocol/crucible-qemu-shmem/include/crucible_shmem_abi.h;
in
  pkgs.mkDerivation {
    pname = "crucible-phase1-qemu-fault-rule-presence";
    version = "0";
    src = pkgs.qemu-crucible.src;

    buildDeps = [
      pkgs.coreutils
      pkgs.glib
      pkgs.glib.dev
      pkgs.grep
      pkgs.patch
      pkgs.python3
      pkgs.tar
      pkgs.xz
    ];

    phases = [
      {
        name = "unpack-and-apply-atomic-patch";
        script = ''
          set -eu
          tar -xf "$src"
          cd qemu-${atomicPatch.qemuVersion}
          patch --batch --forward --fuzz=0 -p1 -i "${patchDir}/${atomicPatch.file}"
        '';
      }
      {
        name = "run-production-rule-presence";
        script = ''
          set -eu
          export CC=cc
          export CFLAGS="-std=gnu11 -O2 -Wall -Wextra -Werror -Wmissing-prototypes -Wstrict-prototypes -Wredundant-decls -I$PWD -I$PWD/include -I${pkgs.glib.dev}/include/glib-2.0 -I${pkgs.glib.dev}/lib/glib-2.0/include"
          export LDFLAGS="-L${pkgs.glib.dev}/lib -Wl,-rpath,${pkgs.glib}/lib -lglib-2.0"

          mkdir -p "$out"
          ${pkgs.python3}/bin/python3 tests/unit/test-crucible-fault-rule-presence.py \
            --abi-header "${abiHeader}" --output-dir "$out/proof" > "$out/production-proof.result"
          cat "$out/production-proof.result"
          grep -q '^PASS production-body differential rule-presence fixture' "$out/production-proof.result"

          # Require a compiled assertion failure for each mutation so parser or
          # provider failures cannot substitute for a causal regression proof.
          for negative in initializer early-return skipped-comparison wrong-kind \
            stale-vector boundary-conditions; do
            if ${pkgs.python3}/bin/python3 tests/unit/test-crucible-fault-rule-presence.py \
              --abi-header "${abiHeader}" --output-dir "$out/negative-$negative" \
              --negative-control "$negative" > "$out/negative-$negative.log" 2>&1; then
              echo "negative rule-presence control $negative unexpectedly passed" >&2
              exit 1
            fi
            grep -q '^Compiled production-body differential rule-presence fixture' "$out/negative-$negative.log"
            if test "$negative" = initializer; then
              grep -Eq "^ERROR:.*:check_initializer: 'crucible_node_rules' should not be NULL" "$out/negative-$negative.log"
            else
              grep -q '^ERROR:.*: assertion failed' "$out/negative-$negative.log"
            fi
          done

          cat > "$out/result" <<'RESULT'
          PASS
          check=checks.crucible.phase1.qemuFaultRulePresence
          original_initializer_and_complete_ordered_scan_preserved=true
          all_uint16_kinds_and_full_comparison_reads_equivalent=true
          instruction_context_and_phase_deadline_order_preserved=true
          modeled_vector_mutations_and_native_fixture_fork_preserved=true
          six_compiled_causal_negative_controls_rejected=true
          bounded_provider_fixture_without_guest_execution=true
          RESULT
        '';
      }
    ];
  }
