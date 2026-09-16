##! Longhorn Instance Manager — Engine and replica process manager
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
    platformSupport = {
      build = [{abi = ["gnu"]; os = ["linux"];}];
      host = [{abi = ["gnu"]; cpu = ["x86_64" "aarch64"]; os = ["linux"];}];
      target = [];
      role = "public-package";
    };
    pname = "longhorn-instance-manager";
    qualification.packageProbe = lib.qualification.commandProbe {
      "primary" = {
        "artifacts" = [];
        "expected" = "The command describes its supported invocation contract.";
        "files" = {};
        "input" = "The packaged longhorn-instance-manager command-line interface.";
        "operation" = "Request its offline command inventory.";
        "steps" = [
          {
            "argv" = [
              "@python@"
              "-c"
              "import subprocess\nresult = subprocess.run([\"@out@/bin/longhorn-instance-manager\"] + [\"--help\"], capture_output=True, text=True)\nassert result.returncode == 0 and \"instance-manager\" in (result.stdout + result.stderr).lower(), (result.returncode, result.stdout, result.stderr)\nprint(\"longhorn-instance-manager primary passed\")\n"
            ];
            "exit_code" = 0;
            "stderr" = {
              "exact" = "";
            };
            "stdout" = {
              "exact" = "longhorn-instance-manager primary passed\n";
            };
          }
        ];
      };
      "badInput" = {
        "artifacts" = [];
        "expected" = "The command rejects the unsupported operation.";
        "files" = {};
        "input" = "A longhorn-instance-manager invocation naming an unsupported command.";
        "operation" = "Parse the unknown command without starting a service.";
        "steps" = [
          {
            "argv" = [
              "@python@"
              "-c"
              "import subprocess, sys\nresult = subprocess.run([\"@out@/bin/longhorn-instance-manager\"] + [\"aos-invalid-command\"], capture_output=True, text=True)\nassert result.returncode != 0 and \"no help topic\" in (result.stdout + result.stderr).lower(), (result.returncode, result.stdout, result.stderr)\nsys.stderr.write(\"longhorn-instance-manager rejected invalid input\\n\")\nraise SystemExit(7)\n"
            ];
            "exit_code" = 7;
            "observes_rejection" = true;
            "stderr" = {
              "exact" = "longhorn-instance-manager rejected invalid input\n";
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
        "https://github.com/longhorn/longhorn-instance-manager/archive/v${version}/longhorn-instance-manager-${version}.tar.gz"
      ];
      hash = "sha256-DA/MwHcPNtWrySn2ZaWbWmKc/MspHsZxrAAuUPqmYpA=";
    };

    buildDeps = [buildPackages.go];
    runtimeDeps = [zlib libqcow];

    phases = [
      {
        name = "unpack";
        script = ''
          tar xf $src
          cd longhorn-instance-manager-${version}
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
            -o longhorn-instance-manager .
        '';
      }
      {
        name = "install";
        script = ''
          mkdir -p $out/bin
          install -m 755 longhorn-instance-manager $out/bin/
        '';
      }
    ];

    checks = {
      testing,
      self,
      pkgs,
    }: {
      version = testing.mkToolCheck {
        pname = "tool-longhorn-instance-manager";
        tool = self;
        command = "longhorn-instance-manager version";
      };
    };

    meta = {
      description = "Longhorn Instance Manager — engine and replica process manager";
      homepage = "https://longhorn.io";
      license = "Apache-2.0";
    };
  }
