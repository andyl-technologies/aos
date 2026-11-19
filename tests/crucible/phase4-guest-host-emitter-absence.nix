{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase4.guestHostEmitterAbsence",
  dependencies ? [],
}:
import ./_retained-task-evidence.nix {
  inherit pkgs attrPath dependencies;
  # The channel wiring gate reads this pointer to ensure there is one owner.
  # canonical_gate_wiring=checks.crucible.phase4.guestHostChannelGateWiring
  component = "crucible-guest-host-emitter-absence";
  evidence = "preserved=determinism,signal-faults,coverage,observable-io,backend-fingerprint";
}
