##! vim — Vi-compatible text editor
{
  mkDerivation,
  fetchurl,
  gnumake,
  gettext,
  pkg-config,
  ncurses,
  bash,
  gawk,
  perl,
  python3,
}: let
  version = "9.2.0541";
in
  mkDerivation {
    pname = "vim";
    inherit version;

    src = fetchurl {
      urls = ["https://github.com/vim/vim/archive/refs/tags/v${version}.tar.gz"];
      hash = "sha256-CWO/QmhmfmT98VCQhxJMr0vR/j5cZvTiPpUrVx5dbQo=";
    };

    buildDeps = [gnumake gettext pkg-config];
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

    postPatch = ''
      sed -i 's|/usr/bin/man |man |' runtime/ftplugin/man.vim
      sed -i "s|^#!/bin/sh|#!$CONFIG_SHELL|" src/which.sh
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
