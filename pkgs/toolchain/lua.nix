##! lua — Embeddable scripting language
{
  lib,
  mkDerivation,
  fetchurl,
  gnumake,
  readline,
  ncurses,
}: let
  version = "5.5.1";
  abiVersion = "5.5";
in
  mkDerivation {
    platformSupport = {
      build = [{abi = ["gnu"]; os = ["linux"];}];
      host = [{abi = ["gnu"]; cpu = ["x86_64" "aarch64"]; os = ["linux"];} {abi = ["darwin"]; cpu = ["x86_64" "aarch64"]; os = ["darwin"];}];
      target = [];
      role = "public-package";
    };
    pname = "lua";
    qualification.packageProbe = lib.qualification.commandProbe {
      "primary" = {
        "artifacts" = [];
        "expected" = "Lua prints the exact integer result 42.";
        "files" = {};
        "input" = "A Lua expression that adds 19 and 23.";
        "operation" = "Evaluate the expression with the packaged Lua interpreter.";
        "steps" = [
          {
            "argv" = [
              "@out@/bin/lua"
              "-e"
              "print(19 + 23)"
            ];
            "exit_code" = 0;
            "stderr" = {
              "exact" = "";
            };
            "stdout" = {
              "exact" = "42\n";
            };
          }
        ];
      };
      "badInput" = {
        "artifacts" = [];
        "expected" = "Lua exits with its syntax-error status.";
        "files" = {};
        "input" = "A Lua function declaration with an unclosed parameter list.";
        "operation" = "Parse the malformed expression with the packaged interpreter.";
        "steps" = [
          {
            "argv" = [
              "@out@/bin/lua"
              "-e"
              "function broken("
            ];
            "exit_code" = 1;
            "observes_rejection" = true;
          }
        ];
      };
    };

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
        '';
      }
      {
        name = "install";
        script = ''
          make install INSTALL_TOP="$out"
          install -m 755 src/liblua.so.${version} "$out/lib/"
          ln -s liblua.so.${version} "$out/lib/liblua.so.${abiVersion}"
          ln -s liblua.so.${abiVersion} "$out/lib/liblua.so"

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
