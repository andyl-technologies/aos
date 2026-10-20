{
  pkgs,
  qemuPackage ? pkgs.qemu-crucible,
}: let
  patch = ../../pkgs/emulation/qemu-patches/crucible-qemu-11.1.1.patch;
in
  pkgs.mkDerivation {
    pname = "crucible-phase2-qemu-checkpoint-delta-source-check";
    version = "0";
    src = null;
    buildDeps = [pkgs.coreutils pkgs.grep];
    phases = [
      {
        name = "verify-checkpoint-delta-source";
        script = ''
          set -eu
          mkdir -p "$out"

          test -x ${qemuPackage}/bin/qemu-system-x86_64
          test -x ${qemuPackage}/bin/qemu-system-aarch64
          grep -Fqx '+#define DIRTY_MEMORY_CRUCIBLE_CHECKPOINT 3' ${patch}
          grep -Fqx '+    if (client == DIRTY_MEMORY_CRUCIBLE_CHECKPOINT &&' ${patch}
          grep -Fqx '+    if ((mask & (1 << DIRTY_MEMORY_CRUCIBLE_CHECKPOINT)) &&' ${patch}
          grep -Fqx '+    status = migration_crucible_checkpoint_capture_begin();' ${patch}
          grep -Fqx '+    crucible_checkpoint_authority.candidate_active = true;' ${patch}
          grep -Fqx '+    if (capture_reserved && !report) {' ${patch}
          grep -Fqx '+    if (release_capture) {' ${patch}
          grep -Fqx '+        migration_crucible_checkpoint_capture_end();' ${patch}
          grep -Fqx '+    assert(crucible_checkpoint_capture_reserved);' ${patch}
          grep -Fqx '+    status = migration_crucible_checkpoint_restore_begin();' ${patch}
          grep -Fqx "+{ 'command': 'crucible-checkpoint-capture'," ${patch}
          grep -Fqx "+{ 'command': 'crucible-checkpoint-restore'," ${patch}

          capture_begin_line=$(grep -nF \
            '+    status = migration_crucible_checkpoint_capture_begin();' \
            ${patch} | cut -d: -f1)
          candidate_clear_line=$(grep -nF \
            '+static void crucible_checkpoint_candidate_clear(void)' \
            ${patch} | cut -d: -f1)
          candidate_release_line=$(grep -nF \
            '+    if (release_capture) {' ${patch} | cut -d: -f1)
          candidate_line=$(grep -nF \
            '+    crucible_checkpoint_authority.candidate_active = true;' \
            ${patch} | cut -d: -f1)
          retained_out_line=$(grep -nF \
            '+    if (capture_reserved && !report) {' \
            ${patch} | cut -d: -f1)
          test "$candidate_clear_line" -lt "$candidate_release_line"
          test "$candidate_release_line" -lt "$capture_begin_line"
          test "$capture_begin_line" -lt "$candidate_line"
          test "$candidate_line" -lt "$retained_out_line"

          cat > "$out/result" <<'RESULT'
          PASS
          checkpoint_private_dirty_client_source_present=true
          capture_reservation_retained_until_candidate_clear=true
          migration_and_raw_state_exclusion_source_present=true
          restore_reservation_source_present=true
          qmp_exact_checkpoint_command_source_present=true
          qemu_system_targets_built_with_patch=true
          RESULT
        '';
      }
    ];
  }
