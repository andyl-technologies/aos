##! lua — Embeddable scripting language
{
  mkDerivation,
  fetchurl,
  gnumake,
  readline,
  ncurses,
  stdenv,
}: let
  version = "5.5.1";
  abiVersion = "5.5";
in
  mkDerivation {
    pname = "lua";
    inherit version;

    src = fetchurl {
      urls = ["https://www.lua.org/ftp/lua-${version}.tar.gz"];
      hash = "sha256-HEtAaNZwYfKiIxrStUIud6zqFIfqmJD2Mgr2FPQ3Pc4=";
    };

    buildDeps = [gnumake];
    runtimeDeps = [readline ncurses];
    propagatedDeps = [];

    phases = [
      {
        name = "unpack";
        script = ''
          tar xf "$src"
          cd lua-${version}
        '';
      }
      {
        name = "patch";
        script = ''
          sed -i "s@#define LUA_ROOT.*@#define LUA_ROOT \"$out/\"@" src/luaconf.h
        '';
      }
      {
        name = "build";
        script = ''
          ${
            if stdenv.hostPlatform.isDarwin
            then ''
              make -j"$NIX_BUILD_CORES" macosx \
                MYCFLAGS="-fPIC" \
                MYLIBS="-lm -lreadline -lncurses"

              objects=$(ar t src/liblua.a)
              object_paths=""
              for object in $objects; do
                object_paths="$object_paths src/$object"
              done
              cc -dynamiclib \
                -Wl,-install_name,$out/lib/liblua.${abiVersion}.dylib \
                -o src/liblua.${version}.dylib \
                $object_paths \
                -lm -lreadline -lncurses
            ''
            else ''
              make -j"$NIX_BUILD_CORES" linux \
                MYCFLAGS="-fPIC" \
                MYLIBS="-ldl -lm -lreadline -lncurses"

              objects=$(ar t src/liblua.a)
              object_paths=""
              for object in $objects; do
                object_paths="$object_paths src/$object"
              done
              cc -shared \
                -Wl,-soname,liblua.so.${abiVersion} \
                -o src/liblua.so.${version} \
                $object_paths \
                -ldl -lm -lreadline -lncurses
            ''
          }
        '';
      }
      {
        name = "install";
        script = ''
          make install INSTALL_TOP="$out"
          ${
            if stdenv.hostPlatform.isDarwin
            then ''
              install -m 755 src/liblua.${version}.dylib "$out/lib/"
              ln -s liblua.${version}.dylib "$out/lib/liblua.${abiVersion}.dylib"
              ln -s liblua.${abiVersion}.dylib "$out/lib/liblua.dylib"
            ''
            else ''
              install -m 755 src/liblua.so.${version} "$out/lib/"
              ln -s liblua.so.${version} "$out/lib/liblua.so.${abiVersion}"
              ln -s liblua.so.${abiVersion} "$out/lib/liblua.so"
            ''
          }

          mkdir -p "$out/lib/pkgconfig"
          cat > "$out/lib/pkgconfig/lua.pc" << EOF
          prefix=$out
          libdir=$out/lib
          includedir=$out/include

          Name: Lua
          Description: Embeddable scripting language
          Version: ${version}
          Libs: -L$out/lib -llua -lm${
            if stdenv.hostPlatform.isDarwin
            then ""
            else " -ldl"
          }
          Cflags: -I$out/include
          EOF
        '';
      }
    ];

    checks = {
      testing,
      self,
      ...
    }: {
      link = testing.mkLinkCheck {
        pname = "lib-lua";
        library = self;
        libs =
          ["-llua" "-lm"]
          ++ (
            if stdenv.hostPlatform.isDarwin
            then []
            else ["-ldl"]
          );
        testSource = ''
          #include <lua.h>
          #include <lauxlib.h>

          int main(void) {
              lua_State *state = luaL_newstate();
              if (state == NULL) return 1;
              lua_close(state);
              return 0;
          }
        '';
      };
      tool = testing.mkToolCheck {
        pname = "tool-lua";
        tool = self;
        command = "lua -e 'print(_VERSION)'";
        expectedOutput = "Lua ${abiVersion}";
      };
    };

    meta = {
      description = "Embeddable scripting language";
      homepage = "https://www.lua.org/";
      license = "MIT";
      mainProgram = "lua";
    };
  }
