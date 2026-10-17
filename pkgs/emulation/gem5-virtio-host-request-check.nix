##! Native bounded asynchronous block/9p requests and sealed completion witnesses
{
  mkDerivation,
  gem5,
  coreutils,
  grep,
}: let
  witness = ./_gem5/virtio-host-request-check.py;
in
  mkDerivation {
    pname = "gem5-virtio-host-request-check";
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
          for kind in block 9p; do
            ${gem5}/bin/gem5 --outdir="$kind-output" ${witness} \
              "$kind" > "$kind.log" 2>&1
            grep -q '"frozenGuestSpansVerified":true' "$kind.log"
            grep -q '"deviceParityQualified":false' "$kind.log"

            if ${gem5}/bin/gem5 --outdir="$kind-reset-output" ${witness} \
              "$kind" reprogram > "$kind-reset.log" 2>&1; then
              echo "native reply crossed queue reconfiguration: $kind" >&2
              exit 1
            fi
            grep -Fq 'Sealed reply belongs to a different native queue incarnation' \
              "$kind-reset.log"
          done
        '';
      }
      {
        name = "install";
        script = ''
          mkdir -p "$out"
          grep '^{' block.log > "$out/block.json"
          grep '^{' 9p.log > "$out/9p.json"
        '';
      }
    ];

    meta.description = "Checks bounded native asynchronous disk/filesystem request custody without advertising guest device parity";
  }
