##! zfstools — Scheduled ZFS snapshot management utilities
{
  mkDerivation,
  fetchurl,
  ruby,
  zfs,
  coreutils,
  grep,
  mariadb,
  postgresql,
}: let
  version = "0.3.6";
  runtimePath = "${zfs}/bin:${zfs}/sbin:${coreutils}/bin:${mariadb}/bin:${postgresql}/bin";
in
  mkDerivation {
    pname = "zfstools";
    inherit version;

    src = fetchurl {
      urls = ["https://github.com/bdrewery/zfstools/archive/refs/tags/v${version}.tar.gz"];
      hash = "sha256-BgES2J8R6VQV8HzbwF/vKaahvFBGBGxW038WsSMvss8=";
    };

    buildDeps = [];
    runtimeDeps = [ruby zfs coreutils mariadb postgresql];
    propagatedDeps = [];

    phases = [
      {
        name = "unpack";
        script = ''
          tar xf "$src"
          cd zfstools-${version}
        '';
      }
      {
        name = "install";
        script = ''
          mkdir -p "$out/bin" "$out/lib"
          cp -R bin/. "$out/bin/"
          cp -R lib/. "$out/lib/"

          for script in "$out"/bin/*; do
            sed -i '1c #!${ruby}/bin/ruby' "$script"
            chmod 0755 "$script"
          done

          # The upstream library intentionally invokes the ZFS and optional
          # database clients by name.  Give those subprocesses an exact,
          # source-built runtime path without relying on a global environment.
          sed -i "2iENV['PATH'] = '${runtimePath}:' + ENV.fetch('PATH', String.new)" \
            "$out/lib/zfstools.rb"

          "$out/bin/zfs-auto-snapshot" > usage.txt
          grep -q '^Usage:' usage.txt
        '';
      }
    ];

    checks = {
      testing,
      self,
      ...
    }: {
      tool = testing.mkToolCheck {
        pname = "tool-zfstools";
        tool = self;
        extraDeps = [grep];
        command = "zfs-auto-snapshot > /tmp/zfstools-usage && grep -q '^Usage:' /tmp/zfstools-usage";
      };
    };

    meta = {
      description = "OpenSolaris-compatible automatic snapshot tools for ZFS";
      homepage = "https://github.com/bdrewery/zfstools";
      license = "BSD-2-Clause";
      mainProgram = "zfs-auto-snapshot";
    };
  }
