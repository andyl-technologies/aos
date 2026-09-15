##! Longhorn Engine — Block device data plane
{
  lib,
  mkDerivation,
  fetchurl,
  buildPackages,
  zlib,
  libqcow,
}: let
  version = "1.8.1";
in
  mkDerivation {
    pname = "longhorn-engine";
    qualification.packageProbe = lib.qualification.commandProbe {
      "primary" = {
        "artifacts" = [];
        "expected" = "The command describes its supported invocation contract.";
        "files" = {};
        "input" = "The packaged longhorn-engine command-line interface.";
        "operation" = "Request its offline command inventory.";
        "steps" = [
          {
            "argv" = [
              "@python@"
              "-c"
              "import subprocess\nresult = subprocess.run([\"@out@/bin/longhorn-engine\"] + [\"--help\"], capture_output=True, text=True)\nassert result.returncode == 0 and \"controller\" in (result.stdout + result.stderr).lower(), (result.returncode, result.stdout, result.stderr)\nprint(\"longhorn-engine primary passed\")\n"
            ];
            "exit_code" = 0;
            "stderr" = {
              "exact" = "";
            };
            "stdout" = {
              "exact" = "longhorn-engine primary passed\n";
            };
          }
        ];
      };
      "badInput" = {
        "artifacts" = [];
        "expected" = "The command rejects the unsupported operation.";
        "files" = {};
        "input" = "A longhorn-engine invocation naming an unsupported command.";
        "operation" = "Parse the unknown command without starting a service.";
        "steps" = [
          {
            "argv" = [
              "@python@"
              "-c"
              "import subprocess, sys\nresult = subprocess.run([\"@out@/bin/longhorn-engine\"] + [\"aos-invalid-command\"], capture_output=True, text=True)\nassert result.returncode != 0 and \"unrecognized command\" in (result.stdout + result.stderr).lower(), (result.returncode, result.stdout, result.stderr)\nsys.stderr.write(\"longhorn-engine rejected invalid input\\n\")\nraise SystemExit(7)\n"
            ];
            "exit_code" = 7;
            "observes_rejection" = true;
            "stderr" = {
              "exact" = "longhorn-engine rejected invalid input\n";
            };
            "stdout" = {
              "exact" = "";
            };
          }
        ];
      };
    };

    inherit version;

    src = fetchurl {
      urls = [
        "https://github.com/longhorn/longhorn-engine/archive/v${version}/longhorn-engine-${version}.tar.gz"
      ];
      hash = "sha256-y5xSKdDfVtoZncdjadhxSpokmakfJ8H2VHbT1dhz2hI=";
    };

    buildDeps = [buildPackages.go];
    runtimeDeps = [zlib libqcow];

    phases = [
      {
        name = "unpack";
        script = ''
          tar xf $src
          cd longhorn-engine-${version}
        '';
      }
      {
        name = "build";
        script = ''
          export GOPATH=$TMPDIR/go
          export GOCACHE=$TMPDIR/go-cache
          export CGO_ENABLED=1
          export GOPROXY=off
          if [ -n "''${AOS_CROSS_COMPILING:-}" ]; then
            export GOOS="$AOS_GOOS"
            export GOARCH="$AOS_GOARCH"
          fi
          export GOFLAGS="-trimpath -mod=vendor"
          mkdir -p "$GOPATH" "$GOCACHE"

          go build -ldflags "-s -w -X main.Version=${version}" \
            -o longhorn-engine .
        '';
      }
      {
        name = "install";
        script = ''
          mkdir -p $out/bin
          install -m 755 longhorn-engine $out/bin/
        '';
      }
    ];

    checks = {
      testing,
      self,
      pkgs,
    }: {
      version = testing.mkToolCheck {
        pname = "tool-longhorn-engine";
        tool = self;
        command = "longhorn-engine version";
      };
    };

    meta = {
      description = "Longhorn Engine — block device data plane";
      homepage = "https://longhorn.io";
      license = "Apache-2.0";
    };
  }
