##! containerd — Container runtime
{
  mkDerivation,
  fetchurl,
  gnumake,
  go,
  runc,
  kmod,
}: let
  version = "2.2.1";
in
  mkDerivation {
    pname = "containerd";
    inherit version;

    src = fetchurl {
      urls = [
        "https://github.com/containerd/containerd/archive/v${version}/containerd-${version}.tar.gz"
      ];
      hash = "sha256-r1cHomiRSGMyFCzAreTwxUP3B9OVSDj1zs7nO4M8+bQ=";
    };

    buildDeps = [
      gnumake
      go
    ];
    runtimeDeps = [runc];
    propagatedDeps = [];

    # Pure stage-2 inventory: generateUnits can reproduce the historical
    # systemd.packages symlink farm without inspecting this output at eval
    # time (and therefore without import-from-derivation).
    passthru.systemdUnitInventory.system = [
      "lib/systemd/system/containerd.service"
    ];

    # Guard: containerd's shim used to bake the go-1.26.0 store path into
    # its DWARF + runtime.GOROOT(). The -trimpath flags below strip that;
    # disallowedReferences catches any future regression at build time.
    # Mirrors mkGoPackage's default.
    disallowedReferences = [go];

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
          # -trimpath strips the build-dir + go-1.26.0 store path out of
          # the binary's DWARF and runtime.GOROOT(); without it the shim
          # pins go (212 MiB) into the runtime closure. GOFLAGS reaches
          # the shim's `go build` invocation; GO_BUILD_FLAGS reaches the
          # main containerd / ctr invocations (Makefile naming).
          export GOFLAGS="-trimpath"
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

          # Install the upstream `containerd.service` file so that AOS
          # modules can consume it via `systemd.packages = [ pkgs.containerd ]`
          # instead of re-declaring the unit inline. Two path-fixups are
          # applied to make the upstream file work in a hermetic
          # no-FHS environment:
          #
          #   /usr/local/bin/containerd -> $out/bin/containerd
          #   /sbin/modprobe            -> ${kmod}/sbin/modprobe
          #
          # Everything else (Delegate, KillMode, OOMScoreAdjust, the
          # standard Limit* values, Description, After, Documentation,
          # the [Install] stanza) stays byte-identical with upstream,
          # so any AOS-specific tweaks belong in a drop-in layered by
          # the consuming module.
          sed \
            -e 's|/usr/local/bin/containerd|'"$out/bin/containerd"'|g' \
            -e 's|/sbin/modprobe|${kmod}/sbin/modprobe|g' \
            containerd.service > $out/lib/systemd/system/containerd.service
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
    };

    meta = {
      description = "containerd — industry-standard container runtime";
      homepage = "https://containerd.io";
      license = "Apache-2.0";
    };
  }
