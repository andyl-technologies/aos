##! Executes native Rust profile defaults instead of assuming omitted settings.
{pkgs}:
pkgs.runCommand "aos-bazel-rust-profile-semantics" {
  buildDeps = [pkgs.python3 pkgs.rust pkgs.cc pkgs.binutils];
} ''
  mkdir -p "$out"
  PYTHONDONTWRITEBYTECODE=1 ${pkgs.python3}/bin/python3 ${./profile_semantics.py} \
    --rustc ${pkgs.rust}/bin/rustc --rustc-unwrapped ${pkgs.rust}/bin/rustc.unwrapped \
    --cc ${pkgs.cc}/bin/cc \
    --readelf ${pkgs.binutils}/bin/readelf --output "$out/evidence.json"
''
