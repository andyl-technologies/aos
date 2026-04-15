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
          mkdir -p "$GOCACHE"
          make SHELL="$CONFIG_SHELL" VERSION=v${version} \
            REVISION=v${version} \
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
