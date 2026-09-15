##! containerd — Container runtime
{
  mkDerivation,
  fetchurl,
  buildPackages,
  gnumake,
  runc,
  kmod,
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
          mkdir -p $out/bin $out/lib/systemd/system
          install -m 755 bin/* $out/bin/
          sed \
            -e 's|/usr/local/bin/containerd|'"$out/bin/containerd"'|g' \
            -e 's|/sbin/modprobe|${kmod}/sbin/modprobe|g' \
            containerd.service > $out/lib/systemd/system/containerd.service
        '';
      }
    ];
  };
in
  mkDerivation {
    pname = "containerd";
    inherit version;

    src = null;
    runtimeDeps = [payload runc kmod];
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
