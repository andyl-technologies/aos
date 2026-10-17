##! Actual guest ARM PMULL and PMULL2 polynomial multiply regression
{
  mkDerivation,
  gem5,
  llvm-gem5,
  coreutils,
  grep,
}:
mkDerivation {
  pname = "gem5-aarch64-pmull-check";
  version = "1";
  platformSupport = {
    build = [
      {
        abi = ["gnu"];
        cpu = ["x86_64"];
        os = ["linux"];
      }
    ];
    host = [
      {
        abi = ["gnu"];
        cpu = ["x86_64"];
        os = ["linux"];
      }
    ];
    target = [];
    role = "public-package";
  };
  buildDeps = [gem5 llvm-gem5 coreutils grep];
  phases = [
    {
      name = "build";
      script = ''
        ${llvm-gem5}/bin/clang --target=aarch64-linux-gnu -nostdlib -static \
          -fuse-ld=lld -Wl,--build-id=none ${./_gem5/aarch64-pmull-workload.S} -o guest
      '';
    }
    {
      name = "check";
      script = ''
        ulimit -c 0
        timeout 120 ${gem5}/bin/gem5 --listener-mode=off --outdir=native-output \
          ${./_gem5/aarch64-pmull-check.py} "$PWD/guest" "$PWD/inputs" "$PWD/outputs" \
          > native-check.log 2>&1
        grep -q '"lowerUpper64BitVerified":true' native-check.log
      '';
    }
    {
      name = "install";
      script = ''
        mkdir -p "$out"
        grep '"schema":"crucible.gem5.aarch64-pmull-mechanism.v1"' \
          native-check.log > "$out/result.json"
      '';
    }
  ];
  meta.description = "Executes ARM polynomial multiply instructions against independent GF(2) coefficient vectors";
}
