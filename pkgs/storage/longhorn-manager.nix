##! Longhorn Manager — Longhorn orchestration controller
{
  lib,
  mkDerivation,
  fetchurl,
  buildPackages,
  longhorn-engine,
  longhorn-instance-manager,
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
    pname = "longhorn-manager";
    qualification.packageProbe = lib.qualification.commandProbe {
      "primary" = {
        "artifacts" = [];
        "expected" = "The command describes its supported invocation contract.";
        "files" = {};
        "input" = "The packaged longhorn-manager command-line interface.";
        "operation" = "Request its offline command inventory.";
        "steps" = [
          {
            "argv" = [
              "@python@"
              "-c"
              "import subprocess\nresult = subprocess.run([\"@out@/bin/longhorn-manager\"] + [\"--help\"], capture_output=True, text=True)\nassert result.returncode == 0 and \"longhorn manager\" in (result.stdout + result.stderr).lower(), (result.returncode, result.stdout, result.stderr)\nprint(\"longhorn-manager primary passed\")\n"
            ];
            "exit_code" = 0;
            "stderr" = {
              "exact" = "";
            };
            "stdout" = {
              "exact" = "longhorn-manager primary passed\n";
            };
          }
        ];
      };
      "badInput" = {
        "artifacts" = [];
        "expected" = "The command rejects the unsupported operation.";
        "files" = {};
        "input" = "A longhorn-manager invocation naming an unsupported command.";
        "operation" = "Parse the unknown command without starting a service.";
        "steps" = [
          {
            "argv" = [
              "@python@"
              "-c"
              "import subprocess, sys\nresult = subprocess.run([\"@out@/bin/longhorn-manager\"] + [\"aos-invalid-command\"], capture_output=True, text=True)\nassert result.returncode != 0 and \"unrecognized command\" in (result.stdout + result.stderr).lower(), (result.returncode, result.stdout, result.stderr)\nsys.stderr.write(\"longhorn-manager rejected invalid input\\n\")\nraise SystemExit(7)\n"
            ];
            "exit_code" = 7;
            "observes_rejection" = true;
            "stderr" = {
              "exact" = "longhorn-manager rejected invalid input\n";
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
        "https://github.com/longhorn/longhorn-manager/archive/v${version}/longhorn-manager-${version}.tar.gz"
      ];
      hash = "sha256-dZLMYwijkUDyxKh8wVoHIrCvVkuzHnOYgakF012u3Tc=";
    };

    buildDeps = [buildPackages.go];
    # The signed add-on resource bundle refers to these payloads as its
    # authenticated runtime companions. Keep them in the package closure so
    # publication, installation, rollback, and GC retain one complete add-on.
    runtimeDeps = [longhorn-engine longhorn-instance-manager];
    abilities = ./_longhorn-config/module.nix;

    phases = [
      {
        name = "unpack";
        script = ''
          tar xf $src
          cd longhorn-manager-${version}
        '';
      }
      {
        name = "build";
        script = ''
          export GOPATH=$TMPDIR/go
          export GOCACHE=$TMPDIR/go-cache
          export CGO_ENABLED=0
          export GOPROXY=off
          if [ -n "''${AOS_CROSS_COMPILING:-}" ]; then
            export GOOS="$AOS_GOOS"
            export GOARCH="$AOS_GOARCH"
          fi
          export GOFLAGS="-trimpath -mod=vendor"
          mkdir -p "$GOPATH" "$GOCACHE"

          go build -ldflags "-s -w -X main.Version=${version}" \
            -o longhorn-manager .
        '';
      }
      {
        name = "install";
        script = ''
          mkdir -p $out/bin
          install -m 755 longhorn-manager $out/bin/
        '';
      }
    ];

    checks = {
      testing,
      self,
      pkgs,
    }: {
      version = testing.mkToolCheck {
        pname = "tool-longhorn-manager";
        tool = self;
        command = "longhorn-manager --help";
      };
    };

    meta = {
      description = "Longhorn Manager — distributed block storage orchestrator";
      homepage = "https://longhorn.io";
      license = "Apache-2.0";
    };
  }
