##! Immutable A-only root, explicitly not the production guest root template.
{
  mkDerivation,
  coreutils,
  buildPackages,
}: let
  # This is the existing offline DATA measurer, not a guest/agent launch.
  rootMeasurer = buildPackages.aos-sandbox-agent;
in mkDerivation {
  pname = "aos-sandbox-deployment-specimen-root";
  version = "0.1.0";
  src = ../security/aos-installed-filter-collector;
  dontStrip = true;

  buildDeps = [coreutils rootMeasurer];
  runtimeDeps = [];
  propagatedDeps = [];

  phases = [
    {
      name = "unpack";
      script = ''
        cp -R $src source
        chmod -R u+w source
        cd source
      '';
    }
    {
      name = "build";
      script = ''
        $CC -std=c17 -O2 -Wall -Wextra -Werror -static \
          specimen.c -o aos-deployment-specimen-init
        $STRIP -s aos-deployment-specimen-init
      '';
    }
    {
      name = "install";
      script = ''
        mkdir -p $out/root/usr/lib/systemd $out/root/sbin $out/root/etc \
          $out/root/proc $out/root/sys $out/root/dev $out/root/run $out/root/var
        cp aos-deployment-specimen-init $out/root/usr/lib/systemd/systemd
        chmod 0555 $out/root/usr/lib/systemd/systemd
        ln -s ../usr/lib/systemd/systemd $out/root/sbin/init
        printf '%s\n' 'ID=aos-deployment-specimen' > $out/root/etc/os-release
        printf '%s\n' '55555555555555555555555555555555' > $out/root/etc/machine-id
        chmod 0444 $out/root/etc/os-release $out/root/etc/machine-id

        # The complete tree digest includes entry modes. Normalize the fixed
        # directories to their immutable installed modes before measuring.
        chmod 0555 $out/root $out/root/usr $out/root/usr/lib \
          $out/root/usr/lib/systemd $out/root/sbin $out/root/etc \
          $out/root/proc $out/root/sys $out/root/dev $out/root/run $out/root/var

        # The executable is statically linked from the AOS toolchain; there is
        # no host/interpreter/library closure to substitute or copy at runtime.
        sha256sum $out/root/usr/lib/systemd/systemd | cut -d ' ' -f 1 \
          > $out/specimen-init.sha256
        # Measure every actual template entry with the runtime tree algorithm,
        # including directory modes, file bytes and symlink targets. A partial
        # list of selected metadata is not a physical root commitment.
        ${rootMeasurer}/bin/aos-sandbox-guest-root-tree-digest \
          "$out/root" > "$out/specimen-root.sha256"
        chmod 0444 $out/specimen-init.sha256 $out/specimen-root.sha256
      '';
    }
  ];

  passthru.evidenceSources = [
    ./aos-sandbox-deployment-specimen-root.nix
    ../security/aos-installed-filter-collector/specimen.c
    ../../crates/aos-sandbox-agent/src/guest_root_tree.rs
    ../../crates/aos-sandbox-agent/src/bin/aos-sandbox-guest-root-tree-digest.rs
  ];

  meta = {
    description = "Fixed A-only deployment specimen root, without guest or runtime initialization";
    license = "Apache-2.0";
    platforms = ["x86_64-linux"];
  };
}
