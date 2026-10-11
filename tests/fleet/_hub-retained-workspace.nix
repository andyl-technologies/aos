##! Selects the Cargo workspace members present in a retained source bundle.
source:
builtins.filter
(member: builtins.pathExists (source + "/crates/${member}/Cargo.toml"))
(builtins.fromTOML (builtins.readFile (source + "/crates/Cargo.toml"))).workspace.members
