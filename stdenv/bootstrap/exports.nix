##! Constructs public bootstrap tools after the GCC-built shell is available.
{
  tools,
  buildPlatform,
}: let
  withRuntimeShell = import ../toolchains/lib/with-runtime-shell.nix;
  buildInputs = tools // {inherit buildPlatform;};
  compilerForShell = import ./compiler.nix {
    inherit tools buildPlatform;
    inherit (tools) glibc bash;
  };
  compilerForLibc = import ./compiler.nix {
    inherit tools buildPlatform;
    inherit (tools) glibc;
    bash = exports.bash;
  };
  compilerForExports = import ./compiler.nix {
    inherit tools buildPlatform;
    inherit (exports) glibc bash;
  };
  publicTool = source: extra:
    withRuntimeShell {
      package = import source (buildInputs
        // {
          inherit (exports) gcc glibc bash binutils;
        }
        // extra);
      buildTools = tools;
      shell = "${exports.bash}/bin/bash";
    };

  exports = {
    # The shell cannot depend on the compiler wrapper that will invoke it.
    # Build it with the completed private stage-5 tools and use its own path
    # for auxiliary scripts such as bashbug.
    bash = withRuntimeShell {
      package = import ./stage5-bash.nix (buildInputs // {gcc = compilerForShell;});
      buildTools = tools;
      shell = "$out/bin/bash";
    };

    glibc = publicTool ./stage5-glibc.nix {
      gcc = compilerForLibc;
      binutils = tools.binutils;
    };
    binutils = publicTool ./stage5-binutils.nix {
      gcc = compilerForExports;
      binutils = tools.binutils;
    };
    gcc = publicTool ./stage5-gcc.nix {gcc = compilerForExports;};

    inherit (tools) linuxHeaders;

    coreutils = publicTool ./stage5-coreutils.nix {};
    gnumake = publicTool ./stage5-gnumake.nix {runtimeShell = "${exports.bash}/bin/bash";};
    sed = publicTool ./stage5-sed.nix {};
    grep = publicTool ./stage5-grep.nix {};
    patch = publicTool ./stage5-patch.nix {};
    gawk = publicTool ./stage5-gawk.nix {};
    findutils = publicTool ./stage5-findutils.nix {};
    diffutils = publicTool ./stage5-diffutils.nix {};
    tar = publicTool ./stage5-tar.nix {};
    gzip = publicTool ./stage5-gzip.nix {};
  };
in
  exports
