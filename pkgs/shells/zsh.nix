##! zsh — Interactive shell with programmable completion
{
  mkDerivation,
  fetchurl,
  gnumake,
  perl,
  texinfo,
  pkg-config,
  ncurses,
  pcre2,
  util-linux,
}: let
  version = "5.9.2";
in
  mkDerivation {
    pname = "zsh";
    inherit version;

    src = fetchurl {
      urls = [
        "https://downloads.sourceforge.net/project/zsh/zsh/${version}/zsh-${version}.tar.xz"
      ];
      hash = "sha256-NvpzQ3S0R4NYLOwJvNZ4IuL5ksd57BYkq1WW3weNL4E=";
    };

    buildDeps = [gnumake perl texinfo pkg-config];
    runtimeDeps = [ncurses pcre2 util-linux];
    propagatedDeps = [];
    configureFlags = builtins.concatStringsSep " " [
      "--enable-maildir-support"
      "--enable-multibyte"
      "--with-tcsetpgrp"
      "--enable-pcre"
      "--enable-zshenv=${builtins.placeholder "out"}/etc/zshenv"
      "--disable-site-fndir"
    ];

    postPatch = ''
      # gawk 5.4 can misclassify this @...$@ recipe as an Autoconf file
      # substitution and omit it from the generated Makefile.
      recipe='@$(MAKE) -f Makemod $(MAKEDEFS) $@'
      test "$(grep -Fc "$recipe" Src/Makefile.in)" -eq 2
      sed -i 's/^\([[:space:]]*\)@$(MAKE) -f Makemod $(MAKEDEFS) $@$/\1$(MAKE) -f Makemod $(MAKEDEFS) $@/' Src/Makefile.in
      test "$(grep -Fc "$recipe" Src/Makefile.in)" -eq 0
      test "$(grep -Fc '$(MAKE) -f Makemod $(MAKEDEFS) $@' Src/Makefile.in)" -eq 2
    '';

    checkPhase = ''
      # Pseudo-terminal tests require a controlling terminal unavailable inside
      # the build sandbox; retain the complete non-PTY correctness suite.
      make TESTNUM=ABCDEVW test
    '';

    postInstall = ''
      mkdir -p "$out/etc"
      : > "$out/etc/zshenv"
      rm -f "$out/bin/zsh-${version}"
    '';

    checks = {
      testing,
      self,
      ...
    }: {
      tool = testing.mkToolCheck {
        pname = "tool-zsh";
        tool = self;
        command = "zsh --version && zsh -fc 'autoload -Uz compinit; compinit -d /tmp/zcompdump'";
      };
    };

    meta = {
      description = "Powerful interactive shell with programmable completion";
      homepage = "https://www.zsh.org/";
      license = "MIT";
      mainProgram = "zsh";
    };
  }
