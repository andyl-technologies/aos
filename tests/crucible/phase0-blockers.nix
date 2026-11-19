{
  pkgs,
  blockers,
  attrPath ? "checks.crucible.phase0.gates.blockers",
}:
pkgs.mkDerivation {
  pname = "crucible-phase0-blockers";
  version = "0";
  src = null;

  buildDeps = [pkgs.coreutils] ++ blockers;

  phases = [
    {
      name = "write-result";
      script = ''
        set -eu
        mkdir -p "$out"
        cat > "$out/result" <<'RESULT'
        PASS
        check=${attrPath}
        gate=phase0:blockers
        blockers=checks.crucible.phase0.s2HltBusyPoll,checks.crucible.phase0.s4ShmemVisibility,checks.crucible.phase0.s11MultiVcpuFingerprint
        RESULT
      '';
    }
  ];
}
