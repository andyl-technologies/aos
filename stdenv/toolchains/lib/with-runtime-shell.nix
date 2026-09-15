##! Adds an explicit runtime shell to an independently constructed tool output.
{
  package,
  buildTools,
  shell,
  scriptFilterTool ? null,
}: let
  attrs = package.drvAttrs;
  buildShell = "${buildTools.bash}/bin/bash";
  scriptFilter = import ./source-script-filter.nix {
    filter = scriptFilterTool;
    sourceRoot = ''"''${!runtime_output}"'';
    # Build directories and store outputs can be separate mounts. Keep the
    # temporary hard links in the output filesystem and exclude them from scans.
    temporaryRoot = "\${!runtime_output}";
    temporaryName = ".aos-runtime-inputs";
    filterProgram = ../../filter-output-scripts.pl;
  };
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
      ${scriptFilter.setup}${buildShell} ${../../runtime-scripts.sh} ${scriptFilter.root}${scriptFilter.cleanup}
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
