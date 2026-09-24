{
  pkgs,
  attrPath ? "checks.crucible.phase7.gates.hotForkIsolation.rawGate",
  taskIds ? [],
  nativeIsolation,
  dependencies ? [],
}: let
  taskList = builtins.concatStringsSep "," taskIds;
in
  pkgs.mkDerivation {
    pname = "crucible-phase7-hot-fork-isolation";
    version = "0";
    src = null;

    buildDeps =
      [
        pkgs.coreutils
        pkgs.grep
        nativeIsolation
      ]
      ++ dependencies;

    phases = [
      {
        name = "certify-native-hot-fork-isolation";
        script = ''
          set -eu
          grep -Fxq PASS ${nativeIsolation}/result
          tr -d '\r' < ${nativeIsolation}/serial.log > "$TMPDIR/native-atomic-world.evidence"
          grep -Fxq 'gate=gate:world-fork-atomicity' "$TMPDIR/native-atomic-world.evidence"
          grep -Fxq 'io=block,ninep' "$TMPDIR/native-atomic-world.evidence"
          grep -Fxq \
            'native_resource_isolation=memfd,eventfd,writable-qcow2-root,serial' \
            "$TMPDIR/native-atomic-world.evidence"
          grep -Fxq \
            'native_temp_files_isolated=true' \
            "$TMPDIR/native-atomic-world.evidence"
          grep -Fxq \
            'ambient_outputs_rejected=pidfile,export-socket' \
            "$TMPDIR/native-atomic-world.evidence"
          grep -Fxq \
            'native_running_sibling_mutation_isolated=true' \
            "$TMPDIR/native-atomic-world.evidence"
          grep -Fxq \
            'native_isolation_scopes=network-device,native-9p-device,writable-qcow2-root,serial,pidfile,export-socket,temp-files,native-running-sibling-mutation' \
            "$TMPDIR/native-atomic-world.evidence"
          grep -Fxq \
            'native_negative_isolation_matrix=private-ring-omitted,qmp-control-aliased,console-diagnostics-aliased,writable-disk-backing-aliased,network-omitted,ninep-aliased,host-continuation-identity-aliased' \
            "$TMPDIR/native-atomic-world.evidence"
          grep -Fxq \
            'native_negative_isolation_rejected_before=child-readiness,resume,world-publication' \
            "$TMPDIR/native-atomic-world.evidence"
          grep -Fxq \
            'native_negative_isolation_source_unchanged=true' \
            "$TMPDIR/native-atomic-world.evidence"
          grep -Fxq \
            'native_real_resource_omission=child-vmstate-destination' \
            "$TMPDIR/native-atomic-world.evidence"
          grep -Fxq \
            'native_real_resource_omission_nodes=2' \
            "$TMPDIR/native-atomic-world.evidence"
          grep -Fxq \
            'native_real_resource_omission_rejected_before=child-readiness,world-publication' \
            "$TMPDIR/native-atomic-world.evidence"
          grep -Fxq \
            'native_real_resource_omission_source_unchanged=true' \
            "$TMPDIR/native-atomic-world.evidence"
          grep -Fxq \
            'native_real_resource_alias=child-vmstate-destination' \
            "$TMPDIR/native-atomic-world.evidence"
          grep -Fxq \
            'native_real_resource_alias_nodes=2' \
            "$TMPDIR/native-atomic-world.evidence"
          grep -Fxq \
            'native_real_resource_alias_rejected_before=child-readiness,world-publication' \
            "$TMPDIR/native-atomic-world.evidence"
          grep -Fxq \
            'native_real_resource_alias_source_unchanged=true' \
            "$TMPDIR/native-atomic-world.evidence"

          mkdir -p "$out/evidence"
          cp ${nativeIsolation}/result "$out/evidence/native-atomic-world.result"
          cp "$TMPDIR/native-atomic-world.evidence" "$out/evidence/native-atomic-world.serial.log"
          cat > "$out/result" <<RESULT
          PASS
          check=${attrPath}
          gate=gate:hot-fork-isolation
          tasks=${taskList}
          scope=native-production
          private_devices=network,9p
          private_descriptors=memfd,eventfd
          private_files=writable-qcow2-root,temp-files
          private_sockets=serial
          ambient_outputs_rejected=pidfile,export-socket
          running_sibling_mutation_isolated=true
          native_isolation_scopes=network-device,native-9p-device,writable-qcow2-root,serial,pidfile,export-socket,temp-files,native-running-sibling-mutation
          native_negative_isolation_matrix=private-ring-omitted,qmp-control-aliased,console-diagnostics-aliased,writable-disk-backing-aliased,network-omitted,ninep-aliased,host-continuation-identity-aliased
          native_negative_isolation_rejected_before=child-readiness,resume,world-publication
          native_negative_isolation_source_unchanged=true
          native_real_resource_omission=child-vmstate-destination
          native_real_resource_omission_nodes=2
          native_real_resource_omission_rejected_before=child-readiness,world-publication
          native_real_resource_omission_source_unchanged=true
          native_real_resource_alias=child-vmstate-destination
          native_real_resource_alias_nodes=2
          native_real_resource_alias_rejected_before=child-readiness,world-publication
          native_real_resource_alias_source_unchanged=true
          RESULT
        '';
      }
    ];
  }
