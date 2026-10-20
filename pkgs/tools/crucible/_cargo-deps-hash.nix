# Resolve provenance from the shared monorepo vendor rather than another pin.
{cargoDeps}: cargoDeps.passthru.aos.fixedOutput.hash
