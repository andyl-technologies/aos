##! dtc — Device Tree Compiler and flattened device tree library
{
  lib,
  mkDerivation,
  fetchurl,
  gnumake,
  pkg-config,
  flex,
  bison,
  libyaml,
  bash,
  stdenv,
}: let
  version = "1.8.1";
in
  mkDerivation {
    platformSupport = {
      build = [{abi = ["gnu"]; os = ["linux"];}];
      host = [{abi = ["gnu"]; cpu = ["x86_64" "aarch64"]; os = ["linux"];} {abi = ["darwin"]; cpu = ["x86_64" "aarch64"]; os = ["darwin"];}];
      target = [];
      role = "public-package";
    };
    pname = "dtc";
    qualification.packageProbe = lib.qualification.commandProbe {
      "primary" = {
        "artifacts" = [];
        "expected" = "The compiled blob reports the exact decimal property value.";
        "files" = {
          "tree.dts" = "/dts-v1/;\n/ {\n  compatible = \"aos,qualification\";\n  probe {\n    answer = <42>;\n  };\n};\n";
        };
        "input" = "A device tree containing a 32-bit answer property.";
        "operation" = "Compile the source tree to a blob, then read the property with fdtget.";
        "steps" = [
          {
            "argv" = [
              "@out@/bin/dtc"
              "-I"
              "dts"
              "-O"
              "dtb"
              "-o"
              "tree.dtb"
              "tree.dts"
            ];
            "exit_code" = 0;
            "stderr" = {
              "exact" = "";
            };
            "stdout" = {
              "exact" = "";
            };
          }
          {
            "argv" = [
              "@out@/bin/fdtget"
              "-t"
              "u"
              "tree.dtb"
              "/probe"
              "answer"
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
        "expected" = "Dtc rejects the syntax error with status 1.";
        "files" = {
          "invalid.dts" = "/dts-v1/;\n/ { node { value = <1>; };\n";
        };
        "input" = "A device tree source with an unterminated node.";
        "operation" = "Compile the malformed device tree source.";
        "steps" = [
          {
            "argv" = [
              "@out@/bin/dtc"
              "-I"
              "dts"
              "-O"
              "dtb"
              "-o"
              "invalid.dtb"
              "invalid.dts"
            ];
            "exit_code" = 1;
            "observes_rejection" = true;
            "stdout" = {
              "exact" = "";
            };
          }
        ];
      };
    };

    inherit version;

    src = fetchurl {
      urls = [
        "https://mirrors.edge.kernel.org/pub/software/utils/dtc/dtc-${version}.tar.xz"
      ];
      hash = "sha256-I1JgFabxVQ4FQaU/56zqG1oR42l83zo73AdqvDj2BF0=";
    };

    buildDeps = [
      gnumake
      pkg-config
      flex
      bison
    ];
    runtimeDeps =
      [libyaml]
      ++ (
        if stdenv.hostPlatform.isDarwin
        then [bash]
        else []
      );
    propagatedDeps = [];

    phases = [
      {
        name = "unpack";
        script = ''
          tar xf $src
          cd dtc-${version}
        '';
      }
      {
        name = "build";
        script =
          if stdenv.hostPlatform.isDarwin
          then ''
            # The release makefile does not declare util.o's dependency on
            # this generated header, which races under a parallel build.
            make HOSTOS=darwin NO_PYTHON=1 version_gen.h
            make -j$NIX_BUILD_CORES \
              HOSTOS=darwin \
              SHAREDLIB_LDFLAGS="-fPIC -dynamiclib -Wl,-install_name,$out/lib/" \
              EXTRA_CFLAGS="-Wno-error=unknown-warning-option -Wno-error=unused-command-line-argument -ffile-prefix-map=$PWD=. -fdebug-prefix-map=$PWD=. -fdebug-compilation-dir=." \
              NO_PYTHON=1
          ''
          else ''
            make -j$NIX_BUILD_CORES \
              ${
              if stdenv.hostPlatform.isDarwin
              then "HOSTOS=darwin"
              else ""
            } \
              NO_PYTHON=1
          '';
      }
      {
        name = "install";
        script =
          if stdenv.hostPlatform.isDarwin
          then ''
            make \
              HOSTOS=darwin \
              SHAREDLIB_LDFLAGS="-fPIC -dynamiclib -Wl,-install_name,$out/lib/" \
              EXTRA_CFLAGS="-Wno-error=unknown-warning-option -Wno-error=unused-command-line-argument -ffile-prefix-map=$PWD=. -fdebug-prefix-map=$PWD=. -fdebug-compilation-dir=." \
              NO_PYTHON=1 \
              PREFIX=$out \
              install
            sed -i "1s|^#!.*|#!${bash}/bin/bash|" "$out/bin/dtdiff"
          ''
          else ''
            make \
              NO_PYTHON=1 \
              PREFIX=$out \
              install
          '';
      }
    ];

    meta = {
      description = "Device Tree Compiler and flattened device tree library";
      homepage = "https://git.kernel.org/pub/scm/utils/dtc/dtc.git";
      license = "GPL-2.0-or-later";
    };
  }
