##! cmocka — Unit testing library for C
{
  mkDerivation,
  fetchurl,
  cmake,
  ninja,
}: let
  version = "2.0.1";
in
  mkDerivation {
    pname = "cmocka";
    inherit version;

    src = fetchurl {
      urls = ["https://cmocka.org/files/2.0/cmocka-${version}.tar.xz"];
      hash = "sha256-PzUzOCuimrOr9cT0snt50WXw31HqWH3nSbEbaLQBkYA=";
    };

    buildDeps = [cmake ninja];
    runtimeDeps = [];
    propagatedDeps = [];

    phases = [
      {
        name = "unpack";
        script = ''
          tar xf "$src"
          cd cmocka-${version}

          # The installed header uses uintptr_t independently of CMake's
          # private configuration header, so make the public contract explicit.
          sed -i '/#define CMOCKA_H_/a #include <stdint.h>\n#define HAVE_UINTPTR_T 1' include/cmocka.h
        '';
      }
      {
        name = "configure";
        script = ''
          cmake -S . -B build -G Ninja \
            $cmakeFlags \
            -DCMAKE_BUILD_TYPE=Release \
            -DCMAKE_INSTALL_PREFIX="$out" \
            -DCMAKE_INSTALL_LIBDIR=lib \
            -DBUILD_SHARED_LIBS=ON \
            -DUNIT_TESTING=ON
        '';
      }
      {
        name = "build";
        script = ''ninja -C build -j"$NIX_BUILD_CORES"'';
      }
      {
        name = "check";
        script = ''ctest --test-dir build --output-on-failure -j"$NIX_BUILD_CORES"'';
      }
      {
        name = "install";
        script = ''ninja -C build install'';
      }
    ];

    checks = {
      testing,
      self,
      ...
    }: {
      link = testing.mkLinkCheck {
        pname = "lib-cmocka";
        library = self;
        libs = ["-lcmocka"];
        testSource = ''
          #include <stddef.h>
          #include <setjmp.h>
          #include <stdarg.h>
          #include <cmocka.h>

          static void succeeds(void **state) {
              (void)state;
              assert_true(1);
          }

          int main(void) {
              const struct CMUnitTest tests[] = { cmocka_unit_test(succeeds) };
              return cmocka_run_group_tests(tests, NULL, NULL);
          }
        '';
      };
    };

    meta = {
      description = "Lightweight unit testing library for C";
      homepage = "https://cmocka.org/";
      license = "Apache-2.0";
    };
  }
