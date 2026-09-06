##! duktape — Embeddable JavaScript engine
{
  mkDerivation,
  fetchurl,
  gnumake,
}: let
  version = "2.7.0";
in
  mkDerivation {
    pname = "duktape";
    inherit version;

    src = fetchurl {
      urls = ["https://duktape.org/duktape-${version}.tar.xz"];
      hash = "sha256-kPjS+otVZ8aJmDDd7ywD88J5YLEayiIvoXqnrGE8KJA=";
    };

    buildDeps = [gnumake];
    runtimeDeps = [];
    propagatedDeps = [];

    phases = [
      {
        name = "unpack";
        script = ''
          tar xf "$src"
          cd duktape-${version}
        '';
      }
      {
        name = "build";
        script = ''
          make -j"$NIX_BUILD_CORES" -f Makefile.cmdline
          make -j"$NIX_BUILD_CORES" -f Makefile.sharedlibrary
        '';
      }
      {
        name = "install";
        script = ''
          install -Dm755 duk "$out/bin/duk"
          make -f Makefile.sharedlibrary INSTALL_PREFIX="$out" install
          sed -i "s|^prefix=/usr/local$|prefix=$out|" \
            "$out/lib/pkgconfig/duktape.pc"
        '';
      }
    ];

    checks = {
      testing,
      self,
      ...
    }: {
      link = testing.mkLinkCheck {
        pname = "lib-duktape";
        library = self;
        libs = ["-lduktape"];
        testSource = ''
          #include <duktape.h>

          int main(void) {
              duk_context *context = duk_create_heap_default();
              if (context == NULL) {
                  return 1;
              }
              duk_destroy_heap(context);
              return 0;
          }
        '';
      };
      tool = testing.mkToolCheck {
        pname = "tool-duktape";
        tool = self;
        command = "printf 'print(6 * 7);' | duk | grep -qx 42";
      };
    };

    meta = {
      description = "Embeddable JavaScript engine focused on portability";
      homepage = "https://duktape.org/";
      license = "MIT";
      mainProgram = "duk";
    };
  }
