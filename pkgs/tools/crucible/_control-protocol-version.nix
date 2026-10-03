# Reads the numeric authority included by the Rust control protocol. Release
# metadata must retain the value, never the Rust include expression itself.
{versionFile ? ../../../crates/crucible-protocol/src/control_protocol_version.in}: let
  matched = builtins.match "([1-9][0-9]*)\n?" (builtins.readFile versionFile);
  version =
    if matched == null
    then throw "Crucible control protocol version must be one canonical positive decimal u32"
    else builtins.head matched;
in
  if builtins.stringLength version > 10 || builtins.fromJSON version > 4294967295
  then throw "Crucible control protocol version exceeds u32"
  else version
