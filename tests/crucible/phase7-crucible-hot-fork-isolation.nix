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
          grep -Fxq 'gate=gate:world-fork-atomicity' ${nativeIsolation}/result
          grep -Fxq 'io=block,ninep' ${nativeIsolation}/result
          grep -Fxq \
            'native_resource_isolation=memfd,eventfd,writable-qcow2-root,serial' \
            ${nativeIsolation}/result
          grep -Fxq \
            'native_temp_files_isolated=true' \
            ${nativeIsolation}/result
          grep -Fxq \
            'ambient_outputs_rejected=pidfile,export-socket' \
            ${nativeIsolation}/result
          grep -Fxq \
            'native_running_sibling_mutation_isolated=true' \
            ${nativeIsolation}/result
          grep -Fxq \
            'native_isolation_scopes=network-device,native-9p-device,writable-qcow2-root,serial,pidfile,export-socket,temp-files,native-running-sibling-mutation' \
            ${nativeIsolation}/result
          grep -Fxq \
            'native_negative_isolation_matrix=private-ring-omitted,qmp-control-aliased,console-diagnostics-aliased,writable-disk-backing-aliased,network-omitted,ninep-aliased,host-continuation-identity-aliased' \
            ${nativeIsolation}/result
          grep -Fxq \
            'native_negative_isolation_rejected_before=child-readiness,resume,world-publication' \
            ${nativeIsolation}/result
          grep -Fxq \
            'native_negative_isolation_source_unchanged=true' \
            ${nativeIsolation}/result
          grep -Fxq \
            'native_real_resource_omission=child-vmstate-destination' \
            ${nativeIsolation}/result
          grep -Fxq \
            'native_real_resource_omission_nodes=2' \
            ${nativeIsolation}/result
          grep -Fxq \
            'native_real_resource_omission_rejected_before=child-readiness,world-publication' \
            ${nativeIsolation}/result
          grep -Fxq \
            'native_real_resource_omission_source_unchanged=true' \
            ${nativeIsolation}/result
          grep -Fxq \
            'native_real_resource_alias=child-vmstate-destination' \
            ${nativeIsolation}/result
          grep -Fxq \
            'native_real_resource_alias_nodes=2' \
            ${nativeIsolation}/result
          grep -Fxq \
            'native_real_resource_alias_rejected_before=child-readiness,world-publication' \
            ${nativeIsolation}/result
          grep -Fxq \
            'native_real_resource_alias_source_unchanged=true' \
            ${nativeIsolation}/result

          mkdir -p "$out/evidence"
          cp ${nativeIsolation}/result "$out/evidence/native-atomic-world.result"
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
