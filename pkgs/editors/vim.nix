##! vim — Vi-compatible text editor
{
  lib,
  mkDerivation,
  fetchurl,
  stdenv,
  buildPackages,
  gnumake,
  gettext,
  pkg-config,
  ncurses,
  bash,
  gawk,
  perl,
  python3,
}: let
  version = "9.2.1036";
  nativeTools =
    if stdenv.isCross
    then buildPackages
    else {inherit gnumake gettext pkg-config;};
in
  mkDerivation {
    platformSupport = {
      build = [{abi = ["gnu"]; os = ["linux"];}];
      host = [{abi = ["gnu"]; cpu = ["x86_64" "aarch64"]; os = ["linux"];} {abi = ["darwin"]; cpu = ["x86_64" "aarch64"]; os = ["darwin"];}];
      target = [];
      role = "public-package";
    };
    pname = "vim";
    qualification.packageProbe = lib.qualification.commandProbe {
      "primary" = {
        "artifacts" = [
          {
            "path" = "answer.txt";
            "text" = "answer=42\n";
          }
        ];
        "expected" = "Vim writes the transformed value 42 to the file.";
        "files" = {
          "answer.txt" = "answer=41\n";
        };
        "input" = "A text file containing the decimal value 41.";
        "operation" = "Run a noninteractive Vim substitution and save the buffer.";
        "steps" = [
          {
            "argv" = [
              "@out@/bin/vim"
              "-Nu"
              "NONE"
              "-n"
              "-es"
              "-c"
              "%s/41/42/"
              "-c"
              "wq"
              "answer.txt"
            ];
            "exit_code" = 0;
            "stderr" = {
              "exact" = "";
            };
            "stdout" = {
              "exact" = "";
            };
          }
        ];
      };
      "badInput" = {
        "artifacts" = [];
        "expected" = "Vim rejects the command with a failure status.";
        "files" = {};
        "input" = "An Ex command name that Vim does not define.";
        "operation" = "Execute the unknown command in noninteractive mode.";
        "steps" = [
          {
            "argv" = [
              "@out@/bin/vim"
              "-Nu"
              "NONE"
              "-n"
              "-es"
              "-c"
              "QualificationUnknownCommand"
              "-c"
              "quit"
            ];
            "exit_code" = 1;
            "observes_rejection" = true;
            "stderr" = {
              "exact" = "";
            };
            "stdout" = {
              "exact" = "";
            };
          }
        ];
      };
    };

    # Keep module compatibility at this release until a broader policy is reviewed.
    version = "=${version}";

    src = fetchurl {
      urls = ["https://github.com/vim/vim/archive/refs/tags/v${version}.tar.gz"];
      hash = "sha256-m9IiOjBWZ9GxniHTcEMsiqIlCpLmrxT+kxPsyYU1PQQ=";
    };

    buildDeps = [nativeTools.gnumake nativeTools.gettext nativeTools.pkg-config];
    runtimeDeps = [ncurses bash gawk perl python3];
    propagatedDeps = [];
    # Vim's one-byte flexible-array declarations are not compatible with
    # glibc's fortified string builtins and otherwise abort at runtime.
    hardeningDisable = ["fortify"];
    configureFlags = builtins.concatStringsSep " " [
      "--enable-multibyte"
      "--enable-nls"
      "--with-tlib=ncursesw"
    ];

    # Vim uses a cached uname result to select Darwin APIs even when Autoconf
    # knows the host triple. Keep those answers tied to the target platform.
    preConfigure = lib.optionalString stdenv.hostPlatform.isDarwin ''
      export CPPFLAGS="$CPPFLAGS -I${ncurses}/include -I${ncurses}/include/ncursesw"
      # Link metadata binds NSSound to the native AppKit implementation.
      export LIBS="''${LIBS-} -L$PWD/src -laos-vim-appkit -laos-vim-coreservices"
      export vim_cv_uname_output=Darwin
      export vim_cv_uname_m_output=${
        if stdenv.hostPlatform.isAarch64
        then "arm64"
        else "x86_64"
      }
    '';

    postPatch = ''
      sed -i 's|/usr/bin/man |man |' runtime/ftplugin/man.vim
      sed -i "s|^#!/bin/sh|#!$CONFIG_SHELL|" src/which.sh
      ${lib.optionalString stdenv.hostPlatform.isDarwin ''
        # Keep the sound and clipboard declarations local to Vim's API surface.
        cp ${./_vim-darwin/api.h} src/aos-darwin-api.h
        cp ${./_vim-darwin/appkit.tbd} src/libaos-vim-appkit.tbd
        cp ${./_vim-darwin/text.h} src/aos-darwin-text.h
        cp ${./_vim-darwin/coreservices.tbd} src/libaos-vim-coreservices.tbd
        sed -i '/^#include <CoreServices\/CoreServices.h>$/a #include "aos-darwin-text.h"' src/os_mac_conv.c
        sed -i '/^#import <AppKit\/AppKit.h>$/a #include "aos-darwin-api.h"' src/os_macosx.m
      ''}
    '';

    postInstall = ''
      ln -s vim "$out/bin/vi"

      for tool in ex xxd vi view vimdiff; do
        test -e "$out/bin/$tool"
      done

      grep -rlZ -e '^#! */bin/sh' -e '^#! */usr/bin/env perl' "$out" \
        | while IFS= read -r -d "" file; do
          case "$file" in
            *.pl) sed -i "1s|^#!.*|#!${perl}/bin/perl|" "$file" ;;
            *) sed -i "1s|^#!.*|#!${bash}/bin/bash|" "$file" ;;
          esac
        done
      sed -i "1s|^#!.*|#!${python3}/bin/python3|" \
        "$out/share/vim/vim92/tools/demoserver.py"
      # This non-executable helper escapes the generic shebang pass. It must
      # name the target interpreter even when configure found a native awk.
      sed -i "1s|^#!.*|#!${gawk}/bin/gawk -f|" \
        "$out/share/vim/vim92/tools/mve.awk"

      cat > "$out/share/vim/vim92/tools/vim132" <<'EOF'
      #!${bash}/bin/bash
      oldterm=''${TERM-}
      printf '\033[?3h\n'
      export TERM=vt100-w
      vim "$@"
      export TERM="$oldterm"
      printf '\033[?3l\n'
      EOF
      chmod 755 "$out/share/vim/vim92/tools/vim132"
    '';

    checks = {
      testing,
      self,
      ...
    }: {
      tool = testing.mkToolCheck {
        pname = "tool-vim";
        tool = self;
        command = "vim --clean --not-a-term -es +'call assert_equal(4, 2 + 2)' +qall";
      };
    };

    meta = {
      description = "Highly configurable Vi-compatible text editor";
      homepage = "https://www.vim.org/";
      license = "Vim";
      mainProgram = "vim";
    };
  }
