{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase4.guestHostEmitterAbsence",
  taskIds ? ["T-GHC-11"],
  dependencies ? [],
}:
import ./_retained-task-evidence.nix {
  inherit pkgs attrPath taskIds dependencies;
  # The channel wiring gate reads this pointer to ensure there is one owner.
  # canonical_gate_wiring=checks.crucible.phase4.guestHostChannelGateWiring
  component = "crucible-guest-host-emitter-absence";
  evidence = "preserved=determinism,signal-faults,coverage,observable-io,backend-fingerprint";
}
