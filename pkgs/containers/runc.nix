##! runc — OCI container runtime
{
  lib,
  mkDerivation,
  fetchurl,
  buildPackages,
  gnumake,
  pkg-config,
  libseccomp,
  libselinux,
}: let
  version = "1.5.1";
in
  mkDerivation {
    platformSupport = {
      build = [{abi = ["gnu"]; os = ["linux"];}];
      host = [{abi = ["gnu"]; cpu = ["x86_64" "aarch64"]; os = ["linux"];}];
      target = [];
      role = "public-package";
    };
    pname = "runc";
    qualification.packageProbe = lib.qualification.commandProbe {
      "primary" = {
        "artifacts" = [];
        "expected" = "Runc emits a rootless process configuration using rootfs as the root path.";
        "files" = {
          "verify.py" = "import json\n\nconfig = json.load(open(\"config.json\", encoding=\"utf-8\"))\nassert config[\"ociVersion\"].startswith(\"1.\")\nassert config[\"root\"][\"path\"] == \"rootfs\"\nassert config[\"process\"][\"args\"]\nprint(\"runc specification passed\")\n";
        };
        "input" = "An empty bundle directory requesting runc's rootless OCI template.";
        "operation" = "Generate config.json and validate its core OCI fields independently.";
        "steps" = [
          {
            "argv" = [
              "@out@/bin/runc"
              "--root"
              "@work@/primary/state"
              "spec"
              "--rootless"
            ];
            "exit_code" = 0;
            "stderr" = {
              "exact" = "";
            };
            "stdout" = {
              "exact" = "";
            };
          }
          {
            "argv" = [
              "@python@"
              "verify.py"
            ];
            "exit_code" = 0;
            "stderr" = {
              "exact" = "";
            };
            "stdout" = {
              "exact" = "runc specification passed\n";
            };
          }
        ];
      };
      "badInput" = {
        "artifacts" = [
          {
            "path" = "config.json";
            "text" = "{}\n";
          }
        ];
        "expected" = "Runc refuses to overwrite the existing bundle configuration.";
        "files" = {
          "config.json" = "{}\n";
        };
        "input" = "A bundle directory in which config.json already exists.";
        "operation" = "Attempt to generate a second OCI configuration over the existing file.";
        "steps" = [
          {
            "argv" = [
              "@out@/bin/runc"
              "--root"
              "@work@/bad-input/state"
              "spec"
              "--rootless"
            ];
            "exit_code" = 1;
            "observes_rejection" = true;
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
        "https://github.com/opencontainers/runc/archive/v${version}/runc-${version}.tar.gz"
      ];
      hash = "sha256-MihvGImaZE7HwViWiKlgC6VMxlJk8j8fWHe6IUynbnU=";
    };

    buildDeps = [
      gnumake
      buildPackages.go
      pkg-config
    ];
    runtimeDeps = [
      libseccomp
      libselinux
    ];
    propagatedDeps = [];

    phases = [
      {
        name = "unpack";
        script = ''
          tar xf $src
          cd runc-${version}
        '';
      }
      {
        name = "setup-gopath";
        script = ''
          export GOPATH=$TMPDIR/go
          mkdir -p $GOPATH/src/github.com/opencontainers
          ln -sf $PWD $GOPATH/src/github.com/opencontainers/runc
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
          export BUILDTAGS="seccomp selinux"
          export CGO_CFLAGS="-I${libseccomp}/include -I${libselinux}/include"
          export CGO_LDFLAGS="-L${libseccomp}/lib -L${libselinux}/lib"
          mkdir -p "$GOCACHE"
          make SHELL="$CONFIG_SHELL" BUILDTAGS="$BUILDTAGS" \
            COMMIT=v${version} \
            runc
        '';
      }
      {
        name = "install";
        script = ''
          mkdir -p $out/sbin
          install -m 755 runc $out/sbin/runc
        '';
      }
    ];

    checks = {
      testing,
      self,
      pkgs,
    }: {
      version = testing.mkToolCheck {
        pname = "tool-runc";
        tool = self;
        command = "runc --version";
      };
    };

    meta = {
      description = "runc — CLI tool for spawning and running OCI containers";
      homepage = "https://github.com/opencontainers/runc";
      license = "Apache-2.0";
    };
  }
