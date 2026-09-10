##! Adds an explicit runtime shell to an independently constructed tool output.
{
  package,
  buildTools,
  shell,
}: let
  attrs = package.drvAttrs;
  buildShell = "${buildTools.bash}/bin/bash";
  path = builtins.concatStringsSep ":" (map (tool: "${tool}/bin") [
    buildTools.coreutils
    buildTools.findutils
    buildTools.sed
    buildTools.grep
    buildTools.bash
  ]);
  patchScripts = ''
    export PATH="${path}"
    export AOS_RUNTIME_SHELL="${shell}"
    export AOS_BUILD_SHELL="${attrs.builder}"
    for runtime_output in ${builtins.concatStringsSep " " (package.outputs or ["out"])}; do
      ${buildShell} ${../../runtime-scripts.sh} "''${!runtime_output}"
    done
  '';
in
  assert attrs.args != [] && builtins.head attrs.args == "-c";
    builtins.derivation (attrs
      // {
        args = ["-c" (builtins.elemAt attrs.args 1 + "\n" + patchScripts)];
      })
    // {
      meta = package.meta or {};
      passthru = package.passthru or {};
    }
