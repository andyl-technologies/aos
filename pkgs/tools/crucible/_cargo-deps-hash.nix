# The shared vendor retains its verified archive beneath the local seed patch.
{cargoDeps}: let
  unpatchedVendor = cargoDeps.passthru.unpatchedVendor;
in
  unpatchedVendor.passthru.aos.fixedOutput.hash
