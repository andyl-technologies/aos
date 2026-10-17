##! Native retained VirtIO network I/O and exclusive-boundary witnesses
{
  mkDerivation,
  gem5,
  coreutils,
  grep,
}: let
  witness = ./_gem5/virtio-network-check.py;
in
  mkDerivation {
    pname = "gem5-virtio-network-check";
    version = "0";
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
    buildDeps = [coreutils grep];
    runtimeDeps = [gem5];

    phases = [
      {
        name = "check";
        script = ''
          ulimit -c 0
          ${gem5}/bin/gem5 --outdir=native-output ${witness} > native.log 2>&1
          grep -q '"deviceParityQualified":false' native.log
          grep -q '"actualRxBytes":14' native.log
          grep -q '"actualTxBytes":14' native.log
        '';
      }
      {
        name = "install";
        script = ''
          mkdir -p "$out"
          # Retain the compact native observation, rather than compiler logs.
          grep '^{' native.log > "$out/result.json"
        '';
      }
    ];

    meta.description = "Checks native retained VirtIO network custody without advertising full-system device parity";
  }
