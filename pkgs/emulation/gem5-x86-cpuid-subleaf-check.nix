##! Native x86 CPUID configured-row and unsupported-subleaf bounds witness
{
  mkDerivation,
  gem5,
  coreutils,
}:
mkDerivation {
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
  pname = "gem5-x86-cpuid-subleaf-check";
  version = "0";
  dontUnpack = true;
  buildDeps = [gem5 coreutils];
  phases = [
    {
      name = "build";
      script = ''
        cc -nostdlib -static -no-pie -Wl,--build-id=none \
          ${./_gem5/x86-cpuid-subleaf-workload.S} -o cpuid-workload
      '';
    }
    {
      name = "check";
      script = ''
        ulimit -c 0
        ${gem5}/bin/gem5 --listener-mode=off --outdir=native-output \
          ${./_gem5/x86-cpuid-subleaf-check.py} \
          "$PWD/cpuid-workload" "$PWD/guest-registers" > native-check.log 2>&1
      '';
    }
    {
      name = "install";
      script = ''
        mkdir -p "$out"
        cp native-check.log guest-registers "$out/"
        printf '%s\n' 'Native CPUID configured tuples and unsupported subleaf bounds verified.' > "$out/result"
      '';
    }
  ];
  meta.description = "Executes actual guest CPUID instructions to verify configured rows and unsupported subleaf bounds";
}
