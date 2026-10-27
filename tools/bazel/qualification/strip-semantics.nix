##! Checks native stripping defaults and removal of linked C debug information.
{pkgs}:
pkgs.runCommand "aos-bazel-strip-semantics" {
  buildDeps = [pkgs.python3 pkgs.rust pkgs.cc pkgs.binutils];
} ''
  mkdir -p "$out"
  PYTHONDONTWRITEBYTECODE=1 ${pkgs.python3}/bin/python3 ${./strip_semantics.py} \
    --rustc ${pkgs.rust}/bin/rustc --cc ${pkgs.cc}/bin/cc \
    --readelf ${pkgs.binutils}/bin/readelf --output "$out/evidence.json"
''
