{
  pkgs,
  attrPath,
  taskIds,
  component,
  evidence,
  dependencies ? [],
}:
pkgs.mkDerivation {
  pname = "crucible-retained-task-evidence";
  version = "0";
  src = null;

  buildDeps = [pkgs.coreutils] ++ dependencies;

  phases = [
    {
      name = "write-result";
      script = ''
        set -eu
        : "$DEPENDENCY_PATHS"
        mkdir -p "$out"
        cat > "$out/result" <<RESULT
        PASS
        check=$ATTR_PATH
        tasks=$TASK_IDS
        component=$COMPONENT
        evidence=$EVIDENCE
        dependency_count=$DEPENDENCY_COUNT
        RESULT
      '';
    }
  ];

  ATTR_PATH = attrPath;
  TASK_IDS = builtins.concatStringsSep "," taskIds;
  COMPONENT = component;
  EVIDENCE = evidence;
  DEPENDENCY_COUNT = toString (builtins.length dependencies);
  DEPENDENCY_PATHS = builtins.concatStringsSep ":" dependencies;
}
