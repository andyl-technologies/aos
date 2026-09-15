##! lib/abilities/diagnostic.nix - Stable authoring rejection diagnostics.
##!
##! Nix exceptions remain human-readable, but the restricted evaluator also
##! needs a machine-readable condition that does not depend on that prose. The
##! marker is deliberately simple ASCII so stock Nix preserves it verbatim in
##! stderr and native adapters can extract the enclosed versioned code.
let
  marker = "AOS_ABILITY_DIAGNOSTIC_V1";
in {
  inherit marker;

  throw = code: message:
    builtins.throw "${marker}[${code}]: ${message}";
}
