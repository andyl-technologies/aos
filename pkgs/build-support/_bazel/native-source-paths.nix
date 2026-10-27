##! Opt-in compiler adapter for stable native source locations across sandboxes.
{pkgs}:
pkgs.runCommand "aos-bazel-native-source-paths" {
  sharedBuildCache = false;
} ''
  mkdir -p "$out/bin"
  cat > "$out/bin/cc" <<'WRAPPER'
  #!${pkgs.bash}/bin/bash
  exec ${pkgs.python3}/bin/python3 ${../../../tools/bazel/toolchains/native_cc.py} \
    --compiler ${pkgs.cc}/bin/cc -- "$@"
  WRAPPER
  chmod +x "$out/bin/cc"
''
