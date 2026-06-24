##! Ignition — first-boot machine provisioning utility
{
  mkDerivation,
  fetchurl,
  go,
  util-linux,
}: let
  version = "2.25.1";
  modPath = "github.com/coreos/ignition/v2";
in
  mkDerivation {
    pname = "ignition";
    inherit version;

    src = fetchurl {
      urls = [
        "https://github.com/coreos/ignition/archive/v${version}/ignition-${version}.tar.gz"
      ];
      hash = "sha256-dPvBvkFjXrf6QTGn1WzUowPvZxcSphujUc2MCWHoAYE=";
    };

    # Patches applied after unpack:
    #   0001 — Add `file://` URL scheme support so ignition can fetch
    #          configs and resources from the initrd's local filesystem.
    #          Used by AOS to merge local first-boot configs via
    #          `ignition.config.merge`.
    patches = [
      ./ignition-patches/0001-add-file-url-scheme-support.patch
    ];

    buildDeps = [go];
    runtimeDeps = [util-linux];
    propagatedDeps = [];

    phases = [
      {
        name = "unpack";
        script = ''
          tar xf $src
          cd ignition-${version}
        '';
      }
      {
        name = "configure";
        script = ''
          export HOME=$TMPDIR
          export GOPATH=$TMPDIR/go
          export GOCACHE=$TMPDIR/go-cache
          export GOFLAGS="-mod=vendor"
          export GOPROXY=off
          export CGO_ENABLED=1
          export CGO_CFLAGS="-I${util-linux}/include"
          export CGO_LDFLAGS="-L${util-linux}/lib"
          mkdir -p "$GOPATH" "$GOCACHE"
        '';
      }
      {
        name = "build";
        script = ''
          # Override the compiled-in "has ignition run" stamp path so it
          # lives under /var/etc (ext4 root, persistent) instead of
          # /etc (which is the immutable overlay lower layer in AOS, so
          # the stamp would be invisible on subsequent boots and
          # ignition-files' "previous report" detection would never see
          # it). `resultFilePath` is declared `var` in internal/distro
          # — see the comment at distro.go:22 — so `-X` sets it.
          ldflags="-s -w"
          ldflags="$ldflags -X ${modPath}/internal/version.Raw=v${version}"
          ldflags="$ldflags -X ${modPath}/internal/distro.resultFilePath=/var/etc/.ignition-result.json"
          # Disable SELinux file relabeling at every stage. Ignition's
          # default (distro.go:74 `selinuxRelabel = "true"`) calls
          # `setfiles -r /sysroot /etc/selinux/config …`, which crashes
          # the `files` stage here because the initrd ships no
          # /etc/selinux/config. AOS handles relabeling itself via the
          # security/selinux.nix unit in stage 2, so skipping it inside
          # ignition is correct.
          ldflags="$ldflags -X ${modPath}/internal/distro.selinuxRelabel=false"

          # -trimpath: strip all filesystem paths from the resulting binary.
          # Without it Go embeds absolute paths into the runtime's PC→line
          # tables for panic/stack traces — including /nix/store/.../go-*/src/
          # for every stdlib file used. That drags the full Go toolchain
          # (~231 MB) into ignition's runtime closure and therefore the
          # initrd. -trimpath replaces those with relative module paths, so
          # stack traces still show readable locations but the binary no
          # longer references ${go}. Matches nixpkgs' go.buildGoModule.
          echo "==> Building ignition"
          go build -trimpath -buildmode=pie -ldflags "$ldflags" \
            -o ignition ./internal

          echo "==> Building ignition-validate"
          go build -trimpath -ldflags "$ldflags" \
            -o ignition-validate ./validate
        '';
      }
      {
        name = "install";
        script = ''
          mkdir -p $out/bin
          install -m 0755 ignition $out/bin/ignition
          install -m 0755 ignition-validate $out/bin/ignition-validate
        '';
      }
    ];

    meta = {
      description = "Ignition — machine provisioning utility";
      homepage = "https://github.com/coreos/ignition";
      license = "Apache-2.0";
    };
  }
