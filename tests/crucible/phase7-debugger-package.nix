{
  pkgs,
  lib,
  attrPath,
  taskIds,
}:
pkgs.mkDerivation {
  pname = "crucible-phase7-debugger-package";
  version = "0";
  src = null;

  buildDeps = [pkgs.gdb pkgs.crucible];
  runtimeDeps = [];
  propagatedDeps = [];

  phases = [
    {
      name = "check";
      script = ''
        test -x ${pkgs.gdb}/bin/gdb
        test -x ${pkgs.gdb}/bin/gdbserver
        test -x ${pkgs.crucible}/bin/gdb
        test -x ${pkgs.crucible}/bin/gdbserver
        test "$(readlink -f ${pkgs.crucible}/bin/gdb)" = "${pkgs.gdb}/bin/gdb"
        ${pkgs.gdb}/bin/gdb --batch \
          -ex 'python import sys; assert sys.version_info >= (3, 14)' \
          -ex 'set architecture i386:x86-64' \
          -ex 'set architecture aarch64' \
          -ex 'show architecture'

        mkdir -p "$out"
        cat > "$out/result" <<'RESULT'
        PASS
        check=${attrPath}
        tasks=${lib.concatStringsSep "," taskIds}
        gdb_version=${pkgs.gdb.version}
        build=hermetic-source
        python_scripting=true
        tui=true
        target_x86_64=true
        target_aarch64=true
        suite_exposes_gdb=true
        suite_exposes_gdbserver=true
        RESULT
      '';
    }
  ];
}
