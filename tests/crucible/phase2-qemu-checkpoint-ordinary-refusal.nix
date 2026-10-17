# Ordinary QMP cannot commit a simulator checkpoint or observe a SIM CPU.
{
  pkgs,
  qemuPackage ? pkgs.qemu-crucible,
}: let
  identity = builtins.concatStringsSep "" (builtins.genList (_: "0") 64);
  command = {
    execute = "crucible-checkpoint-commit";
    arguments = {
      checkpoint-sha256 = identity;
      target-sha256 = identity;
      frontier-sha256 = identity;
      capture-generation = 1;
    };
    id = "commit";
  };
  phases = [
    {
      name = "check-ordinary-qmp-refusal";
      script = ''
        set -eu
        mkdir -p "$out"
        cat > "$TMPDIR/commands" <<'COMMANDS'
        {"execute":"qmp_capabilities","id":"capabilities"}
        {"execute":"query-crucible-checkpoint-epoch","id":"before"}
        ${builtins.toJSON command}
        {"execute":"query-crucible-paused-cpu","arguments":{"vcpu-index":0},"id":"paused-cpu"}
        {"execute":"query-crucible-checkpoint-epoch","id":"after"}
        {"execute":"quit","id":"quit"}
        COMMANDS

        # No simulator accelerator or plugin is present. The empty stopped
        # machine isolates QMP admission from guest execution and paging.
        ${pkgs.coreutils}/bin/timeout -k 5 60 \
          ${qemuPackage}/bin/qemu-system-x86_64 \
          -machine none -accel tcg -S -nodefaults -display none \
          -monitor none -serial none -qmp stdio \
          < "$TMPDIR/commands" > "$out/qmp.jsonl"

        ${pkgs.jq}/bin/jq -es '
          def response($id):
            [.[] | select(.id == $id)] |
            if length == 1 then .[0] else error("ambiguous response") end;
          (response("capabilities") | .return == {}) and
          (response("commit") | .error.class == "GenericError" and
            .error.desc == "Crucible checkpoint commit requires the exact paused deterministic simulator boundary") and
          (response("paused-cpu") | .error.class == "GenericError" and
            .error.desc == "Paused CPU observation requires an admitted paused SIM boundary") and
          ((response("before") | .return) == (response("after") | .return)) and
          (response("before") | .return["schema-version"] == 3 and
            .return["candidate-active"] == false and .return["epoch-active"] == false) and
          (response("quit") | .return == {})
        ' "$out/qmp.jsonl" > /dev/null

        cat > "$out/result" <<'RESULT'
        PASS
        scope=ordinary-qmp-component
        qemu_package=${qemuPackage}
        ordinary_mode_checkpoint_commit_rejected=true
        ordinary_mode_checkpoint_epoch_unchanged=true
        ordinary_mode_paused_cpu_observation_rejected=true
        RESULT
      '';
    }
  ];
in
  pkgs.mkDerivation {
    pname = "crucible-qemu-checkpoint-ordinary-refusal";
    version = "0";
    src = null;
    buildDeps = [qemuPackage pkgs.coreutils pkgs.jq];
    inherit phases;
    passthru.runtimeScript = (builtins.head phases).script;
  }
