##! containerd — Container runtime
{
  mkDerivation,
  fetchurl,
  buildPackages,
  gnumake,
  runc,
  lib,
}: let
  version = "2.3.5";
  payload = mkDerivation {
    pname = "containerd-payload";
    inherit version;
    src = fetchurl {
      urls = [
        "https://github.com/containerd/containerd/archive/v${version}/containerd-${version}.tar.gz"
      ];
      hash = "sha256-qZpNypgGEGT/TLNdJ9HsI0VxfpEIyCIyn87JHccr/5Y=";
    };
    buildDeps = [gnumake buildPackages.go];
    runtimeDeps = [runc];
    disallowedReferences = [buildPackages.go];
    phases = [
      {
        name = "unpack";
        script = ''
          tar xf $src
          cd containerd-${version}
        '';
      }
      {
        name = "setup-gopath";
        script = ''
          export GOPATH=$TMPDIR/go
          mkdir -p $GOPATH/src/github.com/containerd
          ln -sf $PWD $GOPATH/src/github.com/containerd/containerd
        '';
      }
      {
        name = "build";
        script = ''
          export GOPATH=$TMPDIR/go
          export GOCACHE=$TMPDIR/go-cache
          export CGO_ENABLED=0
          export GOPROXY=off
          export GOFLAGS="-trimpath"
          if [ -n "''${AOS_CROSS_COMPILING:-}" ]; then
            export GOOS="$AOS_GOOS"
            export GOARCH="$AOS_GOARCH"
          fi
          mkdir -p "$GOCACHE"
          make SHELL="$CONFIG_SHELL" VERSION=v${version} \
            REVISION=v${version} \
            STATIC=1 \
            GO_BUILD_FLAGS="-trimpath" \
            binaries
        '';
      }
      {
        name = "install";
        script = ''
          mkdir -p $out/bin
          install -m 755 bin/* $out/bin/
        '';
      }
    ];
  };
in
  mkDerivation {
    pname = "containerd";
    qualification.packageProbe = lib.qualification.commandProbe {
      "primary" = {
        "artifacts" = [];
        "expected" = "Containerd returns success and reports its packaged version.";
        "files" = {};
        "input" = "The packaged containerd daemon's release identity.";
        "operation" = "Request its version without starting the daemon.";
        "steps" = [
          {
            "argv" = [
              "@python@"
              "-c"
              "import subprocess\nresult = subprocess.run([\"@out@/bin/containerd\", \"--version\"], capture_output=True, text=True)\nassert result.returncode == 0 and \"containerd\" in (result.stdout + result.stderr).lower(), (result.returncode, result.stdout, result.stderr)\nprint(\"containerd operation passed\")\n"
            ];
            "exit_code" = 0;
            "stderr" = {
              "exact" = "";
            };
            "stdout" = {
              "exact" = "containerd operation passed\n";
            };
          }
        ];
      };
      "badInput" = {
        "artifacts" = [];
        "expected" = "Containerd rejects the unsupported option.";
        "files" = {};
        "input" = "A containerd invocation containing an unknown global option.";
        "operation" = "Parse the invalid option before daemon initialization.";
        "steps" = [
          {
            "argv" = [
              "@python@"
              "-c"
              "import subprocess, sys\nresult = subprocess.run([\"@out@/bin/containerd\", \"--aos-invalid-option\"], capture_output=True, text=True)\nassert result.returncode != 0, (result.returncode, result.stdout, result.stderr)\nsys.stderr.write(\"containerd rejected invalid input\\n\")\nraise SystemExit(7)\n"
            ];
            "exit_code" = 7;
            "observes_rejection" = true;
            "stderr" = {
              "exact" = "containerd rejected invalid input\n";
            };
            "stdout" = {
              "exact" = "";
            };
          }
        ];
      };
    };

    inherit version;

    src = null;
    runtimeDeps = [payload runc];
    propagatedDeps = [];

    abilities = ./_containerd-config/module.nix;

    passthru.evidenceSources = [
      ./containerd.nix
      payload.src
    ];

    phases = [
      {
        name = "install";
        script = ''
          mkdir -p $out/bin
          for program in ${payload}/bin/*; do
            ln -s "$program" "$out/bin/$(basename "$program")"
          done
          # containerd resolves its default OCI runtime by executable name.
          # Retain that declared runtime inside the standalone package closure.
          ln -s ${runc}/sbin/runc $out/bin/runc
        '';
      }
    ];

    checks = {
      testing,
      self,
      pkgs,
    }: {
      version = testing.mkToolCheck {
        pname = "tool-containerd";
        tool = self;
        command = "containerd --version";
      };
      config-module-contract = import ./_containerd-tests/contract.nix {
        inherit pkgs lib self;
      };
      runtime-contract = import ./_containerd-tests/lifecycle.nix {
        inherit testing self;
        inherit (pkgs) coreutils grep iproute2;
      };
    };

    meta = {
      description = "containerd — industry-standard container runtime";
      homepage = "https://containerd.io";
      license = "Apache-2.0";
    };
  }
