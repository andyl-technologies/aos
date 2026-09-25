##! duktape — Embeddable JavaScript engine
{
  mkDerivation,
  fetchurl,
  gnumake,
  stdenv,
}: let
  version = "2.7.0";
  sharedLibraryPlatform =
    if stdenv.hostPlatform.isDarwin
    then "DETECTED_OS=Darwin"
    else "";
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
          # Upstream detects the build host with uname, which is Linux here.
          ${
            if stdenv.hostPlatform.isDarwin
            then ''
              sed -i \
                -e 's|-Wl,$(LD_SONAME_ARG),libduktape\.|-Wl,$(LD_SONAME_ARG),$(INSTALL_PREFIX)$(LIBDIR)/libduktape.|g' \
                -e 's|-Wl,$(LD_SONAME_ARG),libduktaped\.|-Wl,$(LD_SONAME_ARG),$(INSTALL_PREFIX)$(LIBDIR)/libduktaped.|g' \
                Makefile.sharedlibrary
              make -j"$NIX_BUILD_CORES" -f Makefile.sharedlibrary ${sharedLibraryPlatform} INSTALL_PREFIX="$out"
            ''
            else ''make -j"$NIX_BUILD_CORES" -f Makefile.sharedlibrary''
          }
        '';
      }
      {
        name = "install";
        script = ''
          install -Dm755 duk "$out/bin/duk"
          make -f Makefile.sharedlibrary ${sharedLibraryPlatform} INSTALL_PREFIX="$out" install
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
