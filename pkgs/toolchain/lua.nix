##! lua — Embeddable scripting language
{
  mkDerivation,
  fetchurl,
  gnumake,
  readline,
  ncurses,
}: let
  version = "5.4.7";
in
  mkDerivation {
    pname = "lua";
    inherit version;

    src = fetchurl {
      urls = ["https://www.lua.org/ftp/lua-${version}.tar.gz"];
      hash = "sha256-n79eKO+GxphY9tPTTszDLpEcGii0Eg/z6EqqcM+/HjA=";
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
          make -j"$NIX_BUILD_CORES" linux \
            MYCFLAGS="-fPIC" \
            MYLIBS="-ldl -lm -lreadline -lncurses"

          objects=$(ar t src/liblua.a)
          object_paths=""
          for object in $objects; do
            object_paths="$object_paths src/$object"
          done
          cc -shared \
            -Wl,-soname,liblua.so.5.4 \
            -o src/liblua.so.${version} \
            $object_paths \
            -ldl -lm -lreadline -lncurses
        '';
      }
      {
        name = "install";
        script = ''
          make install INSTALL_TOP="$out"
          install -m 755 src/liblua.so.${version} "$out/lib/"
          ln -s liblua.so.${version} "$out/lib/liblua.so.5.4"
          ln -s liblua.so.5.4 "$out/lib/liblua.so"

          mkdir -p "$out/lib/pkgconfig"
          cat > "$out/lib/pkgconfig/lua.pc" << EOF
          prefix=$out
          libdir=$out/lib
          includedir=$out/include

          Name: Lua
          Description: Embeddable scripting language
          Version: ${version}
          Libs: -L$out/lib -llua -lm -ldl
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
        libs = ["-llua" "-lm" "-ldl"];
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
        expectedOutput = "Lua 5.4";
      };
    };

    meta = {
      description = "Embeddable scripting language";
      homepage = "https://www.lua.org/";
      license = "MIT";
      mainProgram = "lua";
    };
  }
