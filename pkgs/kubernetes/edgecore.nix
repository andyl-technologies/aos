##! EdgeCore — KubeEdge edge-side agent
{
  lib,
  mkDerivation,
  fetchurl,
  buildPackages,
  kubeedgeSource,
}:
let
  inherit (kubeedgeSource) version src;
in
mkDerivation {
  pname = "edgecore";
  qualification.packageProbe = lib.qualification.commandProbe {
    "primary" = {
      "artifacts" = [];
      "expected" = "The command returns success and documents its invocation contract.";
      "files" = {};
      "input" = "The packaged edgecore command-line interface.";
      "operation" = "Request its offline help text.";
      "steps" = [
        {
          "argv" = [
            "@python@"
            "-c"
            "import subprocess\nresult = subprocess.run([\"@out@/bin/edgecore\", \"--help\"], capture_output=True, text=True)\nassert result.returncode == 0 and \"usage\" in (result.stdout + result.stderr).lower(), (result.returncode, result.stdout, result.stderr)\nprint(\"edgecore operation passed\")\n"
          ];
          "exit_code" = 0;
          "stderr" = {
            "exact" = "";
          };
          "stdout" = {
            "exact" = "edgecore operation passed\n";
          };
        }
      ];
    };
    "badInput" = {
      "artifacts" = [];
      "expected" = "The command rejects the unsupported option before runtime initialization.";
      "files" = {};
      "input" = "A edgecore invocation containing an unsupported option.";
      "operation" = "Parse the invalid option without starting the service.";
      "steps" = [
        {
          "argv" = [
            "@python@"
            "-c"
            "import subprocess, sys\nresult = subprocess.run([\"@out@/bin/edgecore\", \"--aos-invalid-option\"], capture_output=True, text=True)\nassert result.returncode != 0, (result.returncode, result.stdout, result.stderr)\nsys.stderr.write(\"edgecore rejected invalid input\\n\")\nraise SystemExit(7)\n"
          ];
          "exit_code" = 7;
          "observes_rejection" = true;
          "stderr" = {
            "exact" = "edgecore rejected invalid input\n";
          };
          "stdout" = {
            "exact" = "";
          };
        }
      ];
    };
  };

  inherit version;
  inherit src;

  buildDeps = [ buildPackages.go ];
  runtimeDeps = [ ];

  abilities = ./_edgecore-config/module.nix;

  phases = [
    {
      name = "unpack";
      script = ''
        tar xf $src
        cd kubeedge-${version}
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
        # KubeEdge uses a Go workspace (go.work) but the vendor dir was
        # created from go.mod replace directives. Disable workspace mode
        # so -mod=vendor uses go.mod consistently with vendor/modules.txt.
        export GOWORK=off
        export GOFLAGS="-trimpath -mod=vendor"
        mkdir -p "$GOPATH" "$GOCACHE"

        go build -ldflags "-s -w \
          -X github.com/kubeedge/kubeedge/pkg/version.Version=v${version}" \
          -o edgecore ./edge/cmd/edgecore
      '';
    }
    {
      name = "install";
      script = ''
        mkdir -p $out/bin
        install -m 755 edgecore $out/bin/
      '';
    }
  ];

  checks = {
    testing,
    self,
    ...
  }: {
    version = testing.mkToolCheck {
      pname = "tool-edgecore";
      tool = self;
      command = "edgecore --help";
    };
  };

  meta = {
    description = "EdgeCore — KubeEdge edge-side agent";
    homepage = "https://kubeedge.io";
    license = "Apache-2.0";
  };
}
