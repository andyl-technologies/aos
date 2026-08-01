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
        tasks=T-RISK-1,T-RISK-2,T-RISK-3,T-RISK-4,T-RISK-17
        blockers=checks.crucible.phase0.s1Fingerprint,checks.crucible.phase0.s2HltBusyPoll,checks.crucible.phase0.s4ShmemVisibility,checks.crucible.phase0.s3SavevmLoadvm,checks.crucible.phase0.s11MultiVcpuFingerprint
        RESULT
      '';
    }
  ];
}
