##! Native held-Terminal-FIFO source-exit continuation mechanism
{
  mkDerivation,
  gem5-full-system-foundation,
  dmtcp,
  gem5-process-custody,
  python3,
  coreutils,
  abseil-cpp,
}:
mkDerivation {
  pname = "gem5-terminal-continuation-check";
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
  buildDeps = [python3 coreutils];
  runtimeDeps = [gem5-full-system-foundation dmtcp gem5-process-custody];
  phases = [
    {
      name = "check";
      script = ''
        export PYTHONDONTWRITEBYTECODE=1
        ${python3}/bin/python3 -B ${./_gem5/terminal-custody-check.py} \
          ${./_gem5/terminal-continuation-check.py}
        export LD_LIBRARY_PATH="${abseil-cpp}/lib''${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
        witness_root="$(mktemp -d /tmp/gem5-terminal-continuation.XXXXXXXX)"
        ${coreutils}/bin/timeout 300 ${python3}/bin/python3 -B \
          ${./_gem5/terminal-continuation-check.py} \
          ${gem5-full-system-foundation}/bin/gem5 ${dmtcp} \
          ${gem5-process-custody}/lib/libcrucible-resource-custody.so \
          ${./_gem5/terminal-continuation-owner.py} "$witness_root/native"
        mkdir -p "$out/share/checks" "$out/share/licenses/gem5-terminal-continuation-check"
        cp "$witness_root/native/result.json" "$out/share/checks/terminal-continuation.json"
        cp ${../../LICENSES/MIT.txt} "$out/share/licenses/gem5-terminal-continuation-check/LICENSE"
        rm -rf "$witness_root"
      '';
    }
  ];
  meta = {
    description = "Checks genuine process-image preservation of held serial bytes and a future native callback after original namespace deletion; full-system admission remains refused";
    license = "MIT";
  };
}
