##! CloudCore — KubeEdge cloud-side component
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
  pname = "cloudcore";
  qualification.packageProbe = lib.qualification.commandProbe {
    "primary" = {
      "artifacts" = [];
      "expected" = "The command returns success and documents its invocation contract.";
      "files" = {};
      "input" = "The packaged cloudcore command-line interface.";
      "operation" = "Request its offline help text.";
      "steps" = [
        {
          "argv" = [
            "@python@"
            "-c"
            "import subprocess\nresult = subprocess.run([\"@out@/bin/cloudcore\", \"--help\"], capture_output=True, text=True)\nassert result.returncode == 0 and \"usage\" in (result.stdout + result.stderr).lower(), (result.returncode, result.stdout, result.stderr)\nprint(\"cloudcore operation passed\")\n"
          ];
          "exit_code" = 0;
          "stderr" = {
            "exact" = "";
          };
          "stdout" = {
            "exact" = "cloudcore operation passed\n";
          };
        }
      ];
    };
    "badInput" = {
      "artifacts" = [];
      "expected" = "The command rejects the unsupported option before runtime initialization.";
      "files" = {};
      "input" = "A cloudcore invocation containing an unsupported option.";
      "operation" = "Parse the invalid option without starting the service.";
      "steps" = [
        {
          "argv" = [
            "@python@"
            "-c"
            "import subprocess, sys\nresult = subprocess.run([\"@out@/bin/cloudcore\", \"--aos-invalid-option\"], capture_output=True, text=True)\nassert result.returncode != 0, (result.returncode, result.stdout, result.stderr)\nsys.stderr.write(\"cloudcore rejected invalid input\\n\")\nraise SystemExit(7)\n"
          ];
          "exit_code" = 7;
          "observes_rejection" = true;
          "stderr" = {
            "exact" = "cloudcore rejected invalid input\n";
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

  abilities = ./_cloudcore-config/module.nix;

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
          -o cloudcore ./cloud/cmd/cloudcore
      '';
    }
    {
      name = "install";
      script = ''
        mkdir -p $out/bin
        install -m 755 cloudcore $out/bin/
      '';
    }
  ];

  checks = {
    testing,
    self,
    ...
  }: {
    version = testing.mkToolCheck {
      pname = "tool-cloudcore";
      tool = self;
      command = "cloudcore --help";
    };
  };

  meta = {
    description = "CloudCore — KubeEdge cloud-side component";
    homepage = "https://kubeedge.io";
    license = "Apache-2.0";
  };
}
