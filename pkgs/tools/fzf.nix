##! fzf — Interactive fuzzy finder with upstream shell integration.
{
  lib,
  mkGoPackage,
  fetchurl,
  fetchGoModules,
  bash,
  coreutils,
  gawk,
}: let
  version = "0.74.4";
  src = fetchurl {
    name = "fzf-${version}.tar.gz";
    urls = ["https://codeload.github.com/junegunn/fzf/tar.gz/refs/tags/v${version}"];
    hash = "sha256-EEaFfDN/W9Bfb6SCRGtaQqARYVEFdD775O/uCXCyS7c=";
  };
  runtimeTools = [bash coreutils gawk];
in
  mkGoPackage {
    platformSupport = {
      build = [
        {
          abi = ["gnu"];
          os = ["linux"];
        }
      ];
      host = [
        {
          abi = ["gnu"];
          cpu = ["x86_64" "aarch64"];
          os = ["linux"];
        }
        {
          abi = ["darwin"];
          cpu = ["x86_64" "aarch64"];
          os = ["darwin"];
        }
      ];
      target = [
        {
          abi = ["gnu"];
          cpu = ["x86_64" "aarch64"];
          os = ["linux"];
        }
        {
          abi = ["darwin"];
          cpu = ["x86_64" "aarch64"];
          os = ["darwin"];
        }
      ];
      role = "public-package";
    };
    pname = "fzf";
    inherit version src;
    goModules = fetchGoModules {
      inherit src;
      hash = "sha256-T9BoEk/+4b/SCjV9heRyKaCxIoGMhfoDkixn6quilSA=";
    };
    goOutput = "fzf";
    ldflags = "-s -w -X main.version=${version} -X main.revision=tarball";
    runtimeDeps = runtimeTools;

    postPatch = ''
      # Preview/reload commands need a source-built shell even without SHELL.
      sed -i 's|shell = "sh"|shell = "${bash}/bin/bash"|' src/util/util_unix.go
    '';

    postInstall = ''
      mkdir -p "$out/libexec" "$out/share/fzf" "$out/share/man/man1" \
        "$out/share/vim/vimfiles/plugin"
      mv "$out/bin/fzf" "$out/libexec/fzf"
      cat > "$out/bin/fzf" <<EOF_WRAPPER
      #!${bash}/bin/bash
      export PATH="${lib.makeBinPath runtimeTools}:\$PATH"
      exec "$out/libexec/fzf" "\$@"
      EOF_WRAPPER
      chmod +x "$out/bin/fzf"

      cp shell/completion.* shell/key-bindings.* "$out/share/fzf/"
      cp man/man1/*.1 "$out/share/man/man1/"
      cp plugin/fzf.vim "$out/share/vim/vimfiles/plugin/"
      for helper in fzf-tmux fzf-preview.sh; do
        sed '1c\#!${bash}/bin/bash' "bin/$helper" > "$out/bin/$helper"
        chmod +x "$out/bin/$helper"
      done
    '';

    qualification.packageProbe = lib.qualification.commandProbe {
      primary = {
        input = "Three history-like commands including a fuzzy match.";
        operation = "Filter commands using fzf's matcher without opening a terminal.";
        expected = "The unique matching command is returned unchanged.";
        files = {};
        steps = [
          {
            argv = ["@out@/bin/fzf" "--filter=gs" "--no-sort"];
            stdin = "git status\nnix build\ngit log\n";
            exit_code = 0;
            stdout.exact = "git status\n";
            stderr.exact = "";
          }
        ];
        artifacts = [];
      };
      badInput = {
        input = "An unsupported command-line option.";
        operation = "Ask fzf to parse an invalid option.";
        expected = "The option is rejected before any terminal is opened.";
        files = {};
        steps = [
          {
            argv = ["@out@/bin/fzf" "--aos-invalid-option"];
            exit_code = 2;
            observes_rejection = true;
            stdout.exact = "";
            stderr.exact = "unknown option: --aos-invalid-option\n";
          }
        ];
        artifacts = [];
      };
    };

    checks = {
      testing,
      self,
      ...
    }: {
      tool = testing.mkToolCheck {
        pname = "tool-fzf";
        tool = self;
        command = "fzf --version";
      };
    };
    meta = {
      description = "Command-line fuzzy finder with shell history and completion integration";
      homepage = "https://junegunn.github.io/fzf/";
      license = "MIT";
      mainProgram = "fzf";
    };
  }
