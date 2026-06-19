{pkgs}: let
  generatorSource = builtins.readFile ./phase0-abi-drift-generator.rs;
in
  pkgs.mkDerivation {
    pname = "crucible-phase0-abi-drift";
    version = "0";
    src = null;

    generator = generatorSource;
    passAsFile = ["generator"];

    buildDeps = [
      pkgs.coreutils
      pkgs.diffutils
      pkgs.grep
      pkgs.rust
    ];

    phases = [
      {
        name = "run-abi-drift";
        script = ''
          set -eu

          cp "$generatorPath" phase0-abi-drift-generator.rs
          rustc --edition=2021 -O phase0-abi-drift-generator.rs -o phase0-abi-drift-generator

          work="$TMPDIR/abi-drift"
          ./phase0-abi-drift-generator "$work"

          cc -std=c11 -Wall -Wextra -Werror -I"$work" "$work/c-good.c" -o "$TMPDIR/c-good"
          rustc --edition=2021 "$work/rust-good.rs" -o "$TMPDIR/rust-good"
          cc -std=c11 -Wall -Wextra -Werror -I"$work" "$work/c-encode-good.c" -o "$TMPDIR/c-encode-good"
          cc -std=c11 -Wall -Wextra -Werror -I"$work" "$work/c-roundtrip-good.c" -o "$TMPDIR/c-roundtrip-good"
          rustc --edition=2021 "$work/rust-roundtrip-good.rs" -o "$TMPDIR/rust-roundtrip-good"

          "$TMPDIR/c-encode-good" "$TMPDIR/golden-good-c.bin"
          cmp -s "$work/golden-good.bin" "$TMPDIR/golden-good-c.bin"
          "$TMPDIR/c-roundtrip-good" "$work/golden-good.bin" "$TMPDIR/golden-good-c-roundtrip.bin"
          cmp -s "$work/golden-good.bin" "$TMPDIR/golden-good-c-roundtrip.bin"
          "$TMPDIR/rust-roundtrip-good" "$TMPDIR/golden-good-c.bin" "$TMPDIR/golden-good-rust-roundtrip.bin"
          cmp -s "$work/golden-good.bin" "$TMPDIR/golden-good-rust-roundtrip.bin"
          [ "$(wc -c < "$work/golden-good.bin")" -eq 256 ]
          [ "$(wc -c < "$TMPDIR/golden-good-c.bin")" -eq 256 ]

          mkdir -p "$out"

          if diff -u "$work/crucible_shmem_abi.h" "$work/crucible_shmem_abi_drifted.h" > "$out/header.diff"; then
            echo "ABI drift header diff unexpectedly passed" >&2
            exit 1
          fi

          if cc -std=c11 -Wall -Wextra -Werror -I"$work" "$work/c-drift.c" -o "$TMPDIR/c-drift" > "$out/c-drift.log" 2>&1; then
            echo "C drift static assertions unexpectedly compiled" >&2
            exit 1
          fi
          grep -q "RegionHeader.node_count offset" "$out/c-drift.log"
          grep -q "RegionHeader.queue_capacity offset" "$out/c-drift.log"
          if grep -q "RegionHeader size" "$out/c-drift.log"; then
            echo "C drift failed size assertion; expected size-preserving offset drift" >&2
            exit 1
          fi

          if rustc --edition=2021 "$work/rust-drift.rs" -o "$TMPDIR/rust-drift" > "$out/rust-drift.log" 2>&1; then
            echo "Rust drift static assertions unexpectedly compiled" >&2
            exit 1
          fi
          grep -q "offset_of!(RegionHeader, node_count) == 12" "$out/rust-drift.log"
          grep -q "offset_of!(RegionHeader, queue_capacity) == 16" "$out/rust-drift.log"
          if grep -q "size_of::<RegionHeader>() == 256" "$out/rust-drift.log"; then
            echo "Rust drift failed size assertion; expected size-preserving offset drift" >&2
            exit 1
          fi

          if cmp -s "$work/golden-good.bin" "$work/golden-drift.bin"; then
            echo "ABI golden-vector drift unexpectedly matched" >&2
            exit 1
          fi
          cc -std=c11 -Wall -Wextra -Werror -I"$work" "$work/c-encode-drift.c" -o "$TMPDIR/c-encode-drift"
          "$TMPDIR/c-encode-drift" "$TMPDIR/golden-drift-c.bin"
          [ "$(wc -c < "$work/golden-drift.bin")" -eq 256 ]
          [ "$(wc -c < "$TMPDIR/golden-drift-c.bin")" -eq 256 ]
          cmp -s "$work/golden-drift.bin" "$TMPDIR/golden-drift-c.bin"
          if cmp -s "$work/golden-good.bin" "$TMPDIR/golden-drift-c.bin"; then
            echo "C ABI golden-vector drift unexpectedly matched" >&2
            exit 1
          fi

          cp "$work/crucible_shmem_abi.h" "$out/crucible_shmem_abi.h"
          cp "$work/crucible_shmem_abi_drifted.h" "$out/crucible_shmem_abi_drifted.h"
          cp "$work/golden-good.bin" "$out/golden-good.bin"
          cp "$work/golden-drift.bin" "$out/golden-drift.bin"
          cp "$TMPDIR/golden-good-c.bin" "$out/golden-good-c.bin"
          cp "$TMPDIR/golden-drift-c.bin" "$out/golden-drift-c.bin"
          cp "$TMPDIR/golden-good-c-roundtrip.bin" "$out/golden-good-c-roundtrip.bin"
          cp "$TMPDIR/golden-good-rust-roundtrip.bin" "$out/golden-good-rust-roundtrip.bin"

          {
            echo "PASS"
            echo "spike=shmem-abi-drift"
            echo "generated_header_diff_detected=1"
            echo "c_static_assert_drift_failed=1"
            echo "c_static_assert_specific_offset_failed=1"
            echo "rust_static_assert_drift_failed=1"
            echo "rust_static_assert_specific_offset_failed=1"
            echo "golden_vector_drift_mismatch=1"
            echo "golden_vector_good_c_matches_rust=1"
            echo "golden_vector_good_c_roundtrip=1"
            echo "golden_vector_good_rust_roundtrip=1"
            echo "golden_vector_drifted_c_matches_generated=1"
            echo "golden_vector_drifted_c_mismatch=1"
            echo "good_c_header_compiles=1"
            echo "good_rust_layout_compiles=1"
            echo "drifted_field=node_count"
            echo "expected_node_count_offset=12"
            echo "drifted_node_count_offset=16"
            echo "drifted_header_size=256"
          } > "$out/result"
        '';
      }
    ];

    meta = {
      description = "Crucible Phase 0 shmem ABI drift spike";
    };
  }
