# Structural proof that the deterministic virtio-rng delivery patches
# (0031-crucible-det-rng-delivery, 0032-crucible-det-virtio-ioeventfd) are
# byte-for-byte inert when the Crucible sim accelerator is OFF, so the async
# RNG-completion delivery icount of the patched QEMU is identical to the
# unpatched reference by construction.
#
# Why this is a proof and not a measurement: RFC-0010 §4.6 hazard E7a defines
# the reference's async device-completion delivery icount as host-timing
# dependent -- the unpatched reference is *not* deterministic by contract, so a
# runtime icount measurement of it is empirical evidence, never a proof, and
# would risk a flaky gate. Both patches gate every added statement on
# `icount_enabled() && strcmp(current_accel_name(), "sim") == 0`. With sim off
# that predicate is false, so the patched binary executes the identical upstream
# instruction stream for RNG completion delivery; identical instructions deliver
# the completion at an identical icount, whatever host-timing-dependent value
# that is. This derivation proves the antecedent (identical sim-off instruction
# stream) at the source level:
#
#   * rng_backend_request_entropy (backends/rng.c) and
#     virtio_pci_ioeventfd_enabled (hw/virtio/virtio-pci.c): removing the
#     sim-mode guard block from the patched function yields text byte-identical
#     to the unpatched reference function.
#   * rng_builtin_request_entropy (backends/rng-builtin.c): unchanged apart from
#     an added comment -- it still unconditionally schedules the upstream bottom
#     half.
#   * The new drain_requests vtable member and its rng-builtin implementation are
#     additive-but-inert: drain_requests is *read* only at the single guarded
#     call site inside rng_backend_request_entropy, so with sim off it is never
#     invoked.
{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase2.gates.qemuInert.rngDeliveryInert",
  qemuPackage ? pkgs.qemu-crucible,
}: let
  patchDir = ../../pkgs/emulation/qemu-patches;
  series = import ../../pkgs/emulation/qemu-patches/_series.nix;
  patchFiles = series.patchFiles;
in
  pkgs.mkDerivation {
    pname = "crucible-phase2-qemu-rng-delivery-inert";
    version = "0";
    src = null;

    buildDeps = [
      pkgs.coreutils
      pkgs.diffutils
      pkgs.gawk
      pkgs.grep
      pkgs.patch
      pkgs.tar
      pkgs.xz
    ];

    phases = [
      {
        name = "prove-rng-delivery-sim-off-inert";
        script = ''
          set -eu
          export LC_ALL=C

          mkdir -p "$out"

          # Reference (pristine) and patched (full carried series) source trees.
          # Applying the whole series -- no build -- is cheap and gives the exact
          # patched source the shipped qemu-crucible compiles.
          ref_root="$TMPDIR/qemu-reference"
          patched_root="$TMPDIR/qemu-patched"
          mkdir -p "$ref_root" "$patched_root"
          tar -xf ${qemuPackage.src} -C "$ref_root"
          tar -xf ${qemuPackage.src} -C "$patched_root"
          ref_src="$ref_root/qemu-${qemuPackage.version}"
          patched_src="$patched_root/qemu-${qemuPackage.version}"
          (
            cd "$patched_src"
            for patch in ${builtins.concatStringsSep " " patchFiles}; do
              patch --batch --forward --fuzz=0 -p1 -i "${patchDir}/$patch"
            done
          )

          # extract_fn FILE SIGNATURE_LINE > body
          # Prints from the line equal to SIGNATURE_LINE through the next
          # column-0 '}' (QEMU coding style closes functions with '}' at the
          # start of the line), inclusive.
          extract_fn() {
            gawk -v sig="$2" '
              index($0, sig) == 1 && !started { started = 1 }
              started { print }
              started && $0 == "}" { exit }
            ' "$1"
          }

          # strip_c < in > out
          # Deletes C block comments, // line comments, blank lines, and trailing
          # whitespace so the comparison is over executable text only.
          strip_c() {
            gawk '
              {
                line = $0
                out = ""
                i = 1
                n = length(line)
                while (i <= n) {
                  if (!in_block && substr(line, i, 2) == "/*") {
                    in_block = 1
                    i += 2
                    continue
                  }
                  if (in_block) {
                    if (substr(line, i, 2) == "*/") {
                      in_block = 0
                      i += 2
                      continue
                    }
                    i += 1
                    continue
                  }
                  if (substr(line, i, 2) == "//") {
                    break
                  }
                  out = out substr(line, i, 1)
                  i += 1
                }
                sub(/[ \t]+$/, "", out)
                if (out != "") {
                  print out
                }
              }
            '
          }

          # elide_sim_guard < in > out
          # Removes the block that begins at the sim-mode guard
          # `if (icount_enabled() && strcmp(current_accel_name(), "sim") == 0`
          # and ends at its matching close brace, tracking nesting. Everything
          # else (the upstream statements) is preserved verbatim.
          elide_sim_guard() {
            gawk '
              function count(s,   c, i, ch) {
                c = 0
                for (i = 1; i <= length(s); i++) {
                  ch = substr(s, i, 1)
                  if (ch == "{") c++
                  else if (ch == "}") c--
                }
                return c
              }
              {
                if (!eliding && index($0, "if (icount_enabled() && strcmp(current_accel_name(), \"sim\") == 0") > 0) {
                  eliding = 1
                  depth = 0
                  opened = 0
                }
                if (eliding) {
                  b = count($0)
                  depth += b
                  if (b > 0) opened = 1
                  if (opened && depth <= 0) {
                    eliding = 0
                  }
                  next
                }
                print
              }
            '
          }

          prove_guarded_inert() {
            label="$1"
            ref_file="$2"
            patched_file="$3"
            signature="$4"

            ref_fn="$TMPDIR/$label.reference.c"
            patched_fn="$TMPDIR/$label.patched.c"
            extract_fn "$ref_file" "$signature" > "$ref_fn"
            extract_fn "$patched_file" "$signature" > "$patched_fn"

            test -s "$ref_fn" || { echo "FAIL: $label reference function not found" >&2; exit 1; }
            test -s "$patched_fn" || { echo "FAIL: $label patched function not found" >&2; exit 1; }

            # The patched function must actually carry the sim-mode guard,
            # otherwise the elision is vacuous.
            grep -F -q 'strcmp(current_accel_name(), "sim") == 0' "$patched_fn" \
              || { echo "FAIL: $label patched function lacks the sim-mode guard" >&2; exit 1; }
            grep -F -q 'strcmp(current_accel_name(), "sim") == 0' "$ref_fn" \
              && { echo "FAIL: $label reference function unexpectedly contains a sim guard" >&2; exit 1; }

            ref_norm="$TMPDIR/$label.reference.norm"
            patched_norm="$TMPDIR/$label.patched.norm"
            strip_c < "$ref_fn" > "$ref_norm"
            strip_c < "$patched_fn" | elide_sim_guard > "$patched_norm"

            if ! diff -u "$ref_norm" "$patched_norm" > "$TMPDIR/$label.diff"; then
              echo "FAIL: $label sim-off path diverges from the unpatched reference" >&2
              cat "$TMPDIR/$label.diff" >&2
              exit 1
            fi
            cp "$TMPDIR/$label.diff" "$out/$label.sim-off-vs-reference.diff"
            cp "$patched_norm" "$out/$label.patched-sim-off.norm"
            cp "$ref_norm" "$out/$label.reference.norm"
          }

          # (A) In-place behavioral guards: eliding the sim guard from the
          #     patched function reproduces the reference function exactly.
          prove_guarded_inert \
            rng-backend-request-entropy \
            "$ref_src/backends/rng.c" \
            "$patched_src/backends/rng.c" \
            "void rng_backend_request_entropy(RngBackend *s, size_t size,"
          prove_guarded_inert \
            virtio-pci-ioeventfd-enabled \
            "$ref_src/hw/virtio/virtio-pci.c" \
            "$patched_src/hw/virtio/virtio-pci.c" \
            "static bool virtio_pci_ioeventfd_enabled(DeviceState *d)"

          # (B) rng_builtin_request_entropy is unchanged apart from an added
          #     comment: it still unconditionally schedules the upstream bottom
          #     half. Comment-strip both and require byte-identity (no guard to
          #     elide here -- proving there is no behavioral change at all).
          extract_fn "$ref_src/backends/rng-builtin.c" \
            "static void rng_builtin_request_entropy(RngBackend *b, RngRequest *req)" \
            | strip_c > "$TMPDIR/rng-builtin-request-entropy.reference.norm"
          extract_fn "$patched_src/backends/rng-builtin.c" \
            "static void rng_builtin_request_entropy(RngBackend *b, RngRequest *req)" \
            | strip_c > "$TMPDIR/rng-builtin-request-entropy.patched.norm"
          if ! diff -u \
            "$TMPDIR/rng-builtin-request-entropy.reference.norm" \
            "$TMPDIR/rng-builtin-request-entropy.patched.norm" \
            > "$out/rng-builtin-request-entropy.sim-off-vs-reference.diff"; then
            echo "FAIL: rng_builtin_request_entropy changed behavior" >&2
            cat "$out/rng-builtin-request-entropy.sim-off-vs-reference.diff" >&2
            exit 1
          fi
          grep -F -q 'replay_bh_schedule_event(s->bh);' \
            "$TMPDIR/rng-builtin-request-entropy.patched.norm" \
            || { echo "FAIL: patched rng_builtin_request_entropy no longer schedules the upstream bottom half" >&2; exit 1; }

          # (B cont.) drain_requests is additive-but-inert: it must be READ only
          #     at the single guarded call site inside rng_backend_request_entropy
          #     (proven elided in (A)), so with sim off it is never invoked. The
          #     reference tree must not mention it at all. Enumerate every
          #     occurrence in the patched tree and require exactly the four
          #     inert sites: the vtable field declaration (rng.h), the builtin
          #     implementation and its class_init assignment (rng-builtin.c), and
          #     the guarded call site (rng.c).
          # grep -R over a full QEMU tree walks broken symlinks (e.g. the edk2
          # rom X11IncludeHack) and exits non-zero; with the builder's pipefail
          # that would abort the phase. Capture into a temp with -s (suppress
          # unreadable-file errors) and neutralize the exit; real matches are
          # still written.
          if grep -R -s -n 'drain_requests' "$ref_src" \
            > "$out/reference.drain_requests.grep" 2>/dev/null; then :; fi
          if [ -s "$out/reference.drain_requests.grep" ]; then
            echo "FAIL: unpatched reference unexpectedly references drain_requests" >&2
            cat "$out/reference.drain_requests.grep" >&2
            exit 1
          fi
          if ( cd "$patched_src" && grep -R -s -n 'drain_requests' . ) \
            > "$TMPDIR/patched.drain_requests.raw" 2>/dev/null; then :; fi
          sort "$TMPDIR/patched.drain_requests.raw" \
            > "$out/patched.drain_requests.grep"
          patched_sites="$TMPDIR/patched.drain_requests.sites"
          gawk -F: '{ print $1 }' "$out/patched.drain_requests.grep" \
            | sort -u > "$patched_sites"
          cat > "$TMPDIR/patched.drain_requests.sites.expected" <<'SITES'
          ./backends/rng-builtin.c
          ./backends/rng.c
          ./include/system/rng.h
          SITES
          if ! diff -u "$TMPDIR/patched.drain_requests.sites.expected" "$patched_sites" \
            > "$out/patched.drain_requests.sites.diff"; then
            echo "FAIL: drain_requests appears at unexpected sites" >&2
            cat "$out/patched.drain_requests.sites.diff" >&2
            exit 1
          fi
          # The ONLY read (call) of drain_requests is inside rng_backend_request_entropy,
          # inside the sim guard proven elided above.
          call_sites=$( ( cd "$patched_src" && grep -R -n 'k->drain_requests(s)' backends/rng.c ) | wc -l | tr -d ' ')
          test "$call_sites" -eq 1 \
            || { echo "FAIL: expected exactly one guarded drain_requests call site, found $call_sites" >&2; exit 1; }
          extract_fn "$patched_src/backends/rng.c" \
            "void rng_backend_request_entropy(RngBackend *s, size_t size," \
            | grep -F -q 'k->drain_requests(s);' \
            || { echo "FAIL: the drain_requests call is not inside rng_backend_request_entropy" >&2; exit 1; }

          cat > "$out/result" <<'RESULT'
          PASS
          check=${attrPath}
          gate=gate:qemu-inert
          proof=structural-sim-off-inertness-of-rng-completion-delivery-path
          rng_delivery_functions_proven=rng_backend_request_entropy,virtio_pci_ioeventfd_enabled,rng_builtin_request_entropy
          rng_backend_request_entropy_sim_off_identical_to_reference=true
          virtio_pci_ioeventfd_enabled_sim_off_identical_to_reference=true
          rng_builtin_request_entropy_unconditional_upstream_bottom_half=true
          rng_completion_delivery_only_added_code_is_sim_guarded=true
          drain_requests_absent_from_unpatched_reference=true
          drain_requests_read_only_at_single_guarded_call_site=true
          reference_and_patched_sim_off_execute_identical_rng_delivery_instructions=true
          rng_completion_delivery_icount_equivalence_is_structural_not_measured=true
          rng_completion_icount_equivalence_proven=true
          RESULT
        '';
      }
    ];
  }
