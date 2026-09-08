##! libcap-ng — POSIX capability manipulation library
{
  mkDerivation,
  fetchurl,
  lib,
  stdenv,
  buildPackages,
  targetPackages,
  autoconf,
  automake,
  libtool,
  gnumake,
  pkg-config,
  swig,
  python3,
  linux-headers,
}: let
  version = "0.9.5";
  src = fetchurl {
    urls = ["https://github.com/stevegrubb/libcap-ng/archive/refs/tags/v${version}.tar.gz"];
    hash = "sha256-orQhH1myMdYHxh6ioT6eyzj0Rv52m0ThLak51a9tl4o=";
  };

  isAarch64Cross =
    stdenv.isCross
    && stdenv.buildPlatform.isLinux
    && stdenv.hostPlatform.system == "aarch64-linux";
  targetLinuxHeaders =
    if stdenv.isCross
    then targetPackages.linux-headers
    else linux-headers;
  buildPython =
    if stdenv.isCross
    then buildPackages.python3
    else python3;
  pythonVersionsMatch = buildPython.version == python3.version;

  mkLibcapNg = {
    collectGuestTests ? false,
    guestQualification ? null,
  }:
    mkDerivation {
      pname = "libcap-ng";
      inherit version src;
      buildDeps =
        [autoconf automake libtool gnumake pkg-config swig buildPython]
        ++ lib.optional (!stdenv.isCross) linux-headers
        ++ lib.optional stdenv.isCross buildPackages.bash;
      runtimeDeps = [python3];
      propagatedDeps = [];
      phases = [
        {
          name = "unpack";
          script = ''
            tar xf "$src"
            cd libcap-ng-${version}
          '';
        }
        {
          name = "patch";
          script = ''
            touch NEWS
            sed -i 's|/usr/bin/captest|captest|g' utils/captest.c
            sed -i \
              's|/usr/include/linux/capability.h|${targetLinuxHeaders}/include/linux/capability.h|g' \
              bindings/python3/Makefile.am
          '';
        }
        {
          name = "configure";
          script = ''
            # Python switches to hash-based pyc invalidation when this is set,
            # keeping independent payload and public installs byte-identical.
            export SOURCE_DATE_EPOCH=1
            export C_INCLUDE_PATH="${targetLinuxHeaders}/include''${C_INCLUDE_PATH:+:$C_INCLUDE_PATH}"
            ${lib.optionalString stdenv.isCross ''
              # AOS binutils defaults to real archive timestamps. Both tools
              # need deterministic mode because ranlib otherwise rewrites the
              # zero symbol-table timestamp emitted by ar.
              export ARFLAGS=crD
              export RANLIB="$RANLIB -D"
            ''}
            ${lib.optionalString isAarch64Cross ''
              target_gettid=$(printf '%s\n' '#include <sys/syscall.h>' '__NR_gettid' \
                | "$CC" -E -P -x c -)
              test "$target_gettid" = 178 || {
                echo "libcap-ng selected non-AArch64 syscall headers: __NR_gettid=$target_gettid" >&2
                exit 1
              }
            ''}
            export ACLOCAL_PATH="${libtool}/share/aclocal:${pkg-config}/share/aclocal"
            autoreconf -fiv
            ${lib.optionalString stdenv.isCross ''
              mkdir -p .aos-native-tools
              cat > .aos-native-tools/python3-config <<'PYTHON_CONFIG'
              #!${buildPackages.bash}/bin/bash
              exec ${buildPackages.bash}/bin/bash ${python3}/bin/python3-config "$@"
              PYTHON_CONFIG
              chmod 0755 .aos-native-tools/python3-config
            ''}
            python_config_arg=${lib.optionalString stdenv.isCross "PYTHON3_CONFIG=$PWD/.aos-native-tools/python3-config"}
            ./configure $configureFlags \
              --prefix="$out" \
              --with-python3 \
              $python_config_arg \
              PYTHON=${buildPython}/bin/python3
            sed -i \
              's|/usr/include/linux/capability.h|${targetLinuxHeaders}/include/linux/capability.h|g' \
              bindings/python3/Makefile
          '';
        }
        {
          name = "build";
          script = ''
            make -j"$NIX_BUILD_CORES"
            ${lib.optionalString collectGuestTests ''
              # Build every configured test without executing target code on
              # the build kernel. The guest qualification consumes these exact
              # binaries from the installed payload.
              make -C src check TESTS=
              make -C utils check TESTS=
            ''}
          '';
        }
        {
          name = "check";
          script =
            if collectGuestTests
            then "true"
            else if guestQualification != null
            then ''
              test "$(head -n 1 ${guestQualification}/result)" = PASS
            ''
            else ''
              make -C src check
              make -C utils check
              (
                cd bindings/python3/test
                PYTHONPATH=..:../.libs \
                  LD_LIBRARY_PATH="$PWD/../../../src/.libs" \
                  ${python3}/bin/python3 capng-test.py
              )
            '';
        }
        {
          name = "install";
          script = ''
            make install
            ${
              if collectGuestTests
              then ''
                test_root="$out/libexec/libcap-ng-tests"
                mkdir -p "$test_root"
                : > "$test_root/manifest"

                collect_tests() {
                  test_directory=$1
                  destination=$2
                  configured_tests=$(make -s -C "$test_directory" \
                    --eval='aos-print-tests: ; @printf "%s\n" "$(TESTS)"' \
                    aos-print-tests)

                  mkdir -p "$test_root/$destination"
                  for test_name in $configured_tests; do
                    executable="$test_directory/$test_name"
                    if [ -x "$test_directory/.libs/$test_name" ]; then
                      executable="$test_directory/.libs/$test_name"
                    fi
                    test -x "$executable"
                    cp "$executable" "$test_root/$destination/$test_name"
                    printf '%s/%s\n' "$destination" "$test_name" \
                      >> "$test_root/manifest"
                  done
                }

                collect_tests src/test src
                collect_tests utils/test utils
                collect_tests utils/cap-audit/test cap-audit
                mkdir -p "$test_root/python"
                cp bindings/python3/test/capng-test.py "$test_root/python/"
                test -s "$test_root/manifest"
              ''
              else if guestQualification != null
              then ''
                # Target execution is covered by the full-system guest check.
                :
              ''
              else ''
                python_path=$(find "$out/lib" -type d -name site-packages -print -quit)
                test -n "$python_path"
                PYTHONPATH="$python_path" ${python3}/bin/python3 -c 'import capng'
              ''
            }
          '';
        }
      ];
      postFinalize =
        ''
          # The generic fixup strips archive members after ar and ranlib have
          # produced deterministic archives. Put their headers back into GNU
          # deterministic mode so independently built installs stay identical.
          for archive in lib/libcap-ng.a lib/libdrop_ambient.a; do
            test -f "$out/$archive"
            strip -D -S "$out/$archive"
          done
        ''
        + lib.optionalString (guestQualification != null) ''
          # Both builds use the same pname so their store paths have the same
          # length. Normalize only that expected prefix difference, remove the
          # payload's private test tree, and compare every public artifact after
          # the standard fixup, reference scrub, and platform metadata phases.
          comparison="$TMPDIR/tested-install"
          mkdir -p "$comparison"
          cp -a ${guestTestPayload}/. "$comparison/"
          chmod -R u+w "$comparison"
          rm -rf "$comparison/libexec/libcap-ng-tests"
          rmdir "$comparison/libexec" 2>/dev/null || true

          find "$comparison" -type f -exec \
            sed -i 's|${guestTestPayload}|'$out'|g' {} +
          find "$comparison" -type l -print | while IFS= read -r link; do
            target=$(readlink "$link")
            normalized=$(printf '%s\n' "$target" \
              | sed 's|${guestTestPayload}|'$out'|g')
            if [ "$target" != "$normalized" ]; then
              ln -sfn "$normalized" "$link"
            fi
          done
          diff -r --no-dereference "$comparison" "$out"
        '';
      checks =
        if collectGuestTests
        then {}
        else
          {
            testing,
            self,
            ...
          }: {
            link = testing.mkLinkCheck {
              pname = "link-libcap-ng";
              library = self;
              libs = ["-lcap-ng"];
              testSource = ''
                #include <cap-ng.h>
                int main(void) {
                  capng_clear(CAPNG_SELECT_BOTH);
                  return capng_have_capabilities(CAPNG_SELECT_BOTH) < 0;
                }
              '';
            };
          };
      meta = {
        description = "Library and utilities for working with POSIX capabilities";
        homepage = "https://github.com/stevegrubb/libcap-ng";
        license = "LGPL-2.1-only";
      };
    };

  guestTestPayload = mkLibcapNg {collectGuestTests = true;};
  guestQualification =
    if isAarch64Cross
    then
      import ../../tests/build/libcap-ng-aarch64-guest.nix {
        inherit lib buildPackages targetPackages version;
        payload = guestTestPayload;
      }
    else null;
in
  assert pythonVersionsMatch;
    mkLibcapNg {inherit guestQualification;}
