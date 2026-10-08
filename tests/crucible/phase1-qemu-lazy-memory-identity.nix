# Exercises the production memory transaction guard and instruction identity
# helpers. The package repeats the proof with its configured compiler.
{pkgs}: let
  patchDir = ../../pkgs/emulation/qemu-patches;
  atomicPatch = import (patchDir + "/_atomic-patch.nix");
in
  pkgs.mkDerivation {
    pname = "crucible-phase1-qemu-lazy-memory-identity";
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
        name = "run-production-lazy-memory-identity";
        script = ''
          set -eu
          export CC=cc
          export CFLAGS="-std=gnu11 -O2 -Wall -Wextra -Werror -Wmissing-prototypes -I$PWD -I$PWD/include -I${pkgs.glib.dev}/include/glib-2.0 -I${pkgs.glib.dev}/lib/glib-2.0/include"
          export LDFLAGS="-L${pkgs.glib.dev}/lib -Wl,-rpath,${pkgs.glib}/lib -lglib-2.0"

          mkdir -p "$out"
          ${pkgs.python3}/bin/python3 tests/unit/test-crucible-lazy-memory-identity.py \
            --output-dir "$out/proof" > "$out/production-proof.result"
          cat "$out/production-proof.result"
          grep -q '^PASS production lazy memory identity:' "$out/production-proof.result"

          # Restoring eager identity lookup must compile and then expose a
          # lookup while the production memory transaction guard is inactive.
          if ${pkgs.python3}/bin/python3 tests/unit/test-crucible-lazy-memory-identity.py \
            --output-dir "$out/negative-eager-identity" \
            --negative-control eager-identity > "$out/negative-eager-identity.log" 2>&1; then
            echo "negative eager identity control unexpectedly passed" >&2
            exit 1
          fi
          grep -q '^Compiled production lazy memory identity fixture' "$out/negative-eager-identity.log"
          grep -q 'assertion failed.*identities' "$out/negative-eager-identity.log"

          cat > "$out/result" <<'RESULT'
          PASS
          check=checks.crucible.phase1.qemuLazyMemoryIdentity
          inactive_memory_transactions_skip_instruction_identity_lookup=true
          active_and_invalid_identity_callback_arguments_and_icount_preserved=true
          production_guard_cleanup_remains_exactly_once=true
          unrelated_register_and_instruction_rules_preserved=true
          causal_eager_identity_negative_rejected=true
          bounded_provider_fixture_without_guest_execution=true
          RESULT
        '';
      }
    ];
  }
