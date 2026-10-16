##! Distinguishes Cargo output directories from Rust source modules.
##!
##! A source module may be named `target`; an outer Cargo output directory is
##! pruned before any nested `src` tree can be visited by the source filter.
root: path: let
  pathString = toString path;
  relative =
    builtins.substring
    (builtins.stringLength (toString root) + 1)
    (builtins.stringLength pathString)
    pathString;
  base = builtins.baseNameOf path;
  targetName = base == "target" || builtins.match "target-.*" base != null;
  rustSource = builtins.match "(.*/)?src/.*" relative != null;
in
  targetName && !rustSource
