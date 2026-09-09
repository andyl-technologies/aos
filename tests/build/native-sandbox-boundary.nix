##! Detects ambient host tools in the ordinary native package sandbox.
{pkgs}:
pkgs.mkDerivation {
  pname = "aos-native-sandbox-boundary";
  version = "1";
  src = null;
  dontStrip = true;
  dontNukeRefs = true;
  phases = [
    {
      name = "check";
      script = ''
        mkdir -p "$out"
        failed=0
        for candidate in /usr/bin/cc /usr/bin/gcc /usr/include/stdio.h /usr/bin/env /bin/bash; do
          if [ -e "$candidate" ]; then
            echo "unexpected ambient host path: $candidate" >&2
            failed=1
          fi
        done

        # Nix may inject a shell even when the host root is hidden. A foreign
        # BusyBox is an undeclared executable dependency, not a sandbox escape.
        if [ -e /bin/sh ] && ! cmp -s /bin/sh ${pkgs.bash}/bin/bash; then
          echo "sandbox injects a shell other than the declared AOS bash" >&2
          failed=1
        fi

        cat > probe.c <<'C'
        #include <stdio.h>

        int main(void) {
            return puts("native compilation passed") < 0;
        }
        C
        "$CC" -### probe.c -o probe > "$out/driver.stdout" 2> "$out/driver.stderr"
        "$CC" probe.c -o probe
        ./probe > "$out/runtime.txt"
        test "$failed" -eq 0
      '';
    }
  ];
}
