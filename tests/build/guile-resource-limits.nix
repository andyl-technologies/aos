##! Runs Guile's resource-limit and POSIX regressions under an AArch64 kernel.
{
  pkgs,
  guile,
}: let
  native = pkgs.buildPackages or pkgs;
  guestPackages = [guile pkgs.bash pkgs.coreutils pkgs.util-linux];
  guestPath = builtins.concatStringsSep ":" (map (package: "${package}/bin") guestPackages);
  init = native.writeTextFile {
    name = "guile-resource-limits-init";
    destination = "/init";
    text = ''
      #!${pkgs.bash}/bin/bash
      export PATH=${guestPath}:/bin
      mount -t devtmpfs devtmpfs /dev
      exec </dev/console >/dev/console 2>&1
      set -eu
      mount -t proc proc /proc
      mount -t sysfs sysfs /sys
      export HOME=/root TMPDIR=/tmp LC_ALL=C
      test "$(uname -m)" = aarch64
      guile -c '(exit (if (defined? (quote setrlimit)) 0 1))'

      for test in test-out-of-memory test-stack-overflow; do
        if ! timeout --signal=KILL 300 bash "/tests/$test"; then
          echo "AOS_GUILE_RESOURCE_LIMIT_FAIL:$test"
          exec sleep infinity
        fi
        echo "AOS_GUILE_RESOURCE_LIMIT_PASS:$test"
      done

      cd /tmp
      export TEST_SUITE_DIR=/source/test-suite
      export GUILE_LOAD_PATH=/source/test-suite
      if ! timeout --signal=KILL 300 guile --debug --no-auto-compile -L /source/test-suite \
        -e main -s /source/test-suite/guile-test \
        --test-suite /source/test-suite/tests --log-file /tmp/guile-posix.log posix.test; then
        cat /tmp/guile-posix.log
        echo AOS_GUILE_RESOURCE_LIMIT_FAIL:posix.test
        exec sleep infinity
      fi
      cat /tmp/guile-posix.log
      echo AOS_GUILE_RESOURCE_LIMIT_PASS:posix.test
      echo AOS_GUILE_RESOURCE_LIMITS_COMPLETE
      exec sleep infinity
    '';
  };
in
  assert pkgs.stdenv.hostPlatform.system == "aarch64-linux";
    native.mkDerivation {
      pname = "aos-guile-aarch64-resource-limits";
      version = "1";
      src = null;
      buildDeps = [native.cpio native.gzip native.python3 native.qemu];
      exportReferencesGraph.runtime = guestPackages;
      outputChecks.out = {};
      dontNukeRefs = true;

      phases = [
        {
          name = "prepare";
          script = ''
            mkdir -p root/dev root/proc root/sys root/tmp root/root root/tests root/bin root/source
            ${native.python3}/bin/python3 - <<'PY'
            import json
            import os
            import pathlib
            import shutil

            attributes = json.loads(pathlib.Path(os.environ['NIX_ATTRS_JSON_FILE']).read_text())
            for entry in attributes['runtime']:
                source = pathlib.Path(entry['path'])
                destination = pathlib.Path('root') / source.relative_to('/')
                destination.parent.mkdir(parents=True, exist_ok=True)
                if source.is_dir():
                    shutil.copytree(source, destination, symlinks=True)
                else:
                    shutil.copy2(source, destination, follow_symlinks=False)
            PY

            # Preserve the two scripts exactly as shipped in the pinned source.
            tar xf ${guile.src}
            cp guile-${guile.version}/test-suite/standalone/test-out-of-memory root/tests/
            cp guile-${guile.version}/test-suite/standalone/test-stack-overflow root/tests/
            cp -R guile-${guile.version}/test-suite root/source/
            ln -s ${pkgs.bash}/bin/bash root/bin/sh
            cp ${init}/init root/init
            chmod +x root/init
            (cd root && find . -print0 | cpio --null -o --format=newc) \
              | gzip -1 > initrd.gz
          '';
        }
        {
          name = "check";
          script = ''
            mkdir -p "$out"
            ${native.python3}/bin/python3 ${./guile-resource-limits.py} \
              ${native.qemu}/bin/qemu-system-aarch64 \
              ${pkgs.linux}/boot/vmlinuz-${pkgs.linux.version} \
              "$PWD/initrd.gz" "$out/serial.log"
            echo PASS > "$out/result"
          '';
        }
      ];
    }
