##! Completes libc utilities after the public Perl can link against libc.
{
  package,
  buildTools,
  runtimePerl ? null,
  constructionPerl ? null,
  runtimeShell,
  constructionShell,
}: let
  attrs = package.drvAttrs;
  outputs = package.outputs or ["out"];
  split = builtins.elem "bin" outputs;
  rewritePerl =
    if runtimePerl != null && constructionPerl != null
    then ''
      sed 's|${constructionPerl}/bin/perl|${runtimePerl}/bin/perl|g' "$file" > rewritten
      cat rewritten > "$file"
    ''
    else "";

  # Keep interpreter-dependent programs out of the library output. Perl can
  # then consume the libraries without depending on its own utility export.
  libraries =
    if split
    then package
    else
      builtins.derivation (attrs
        // {
          outputs = outputs ++ ["bin"];
          args = [
            "-c"
            (builtins.elemAt attrs.args 1
              + ''
                mkdir -p "$bin"
                for directory in bin sbin; do
                  if [ -d "$out/$directory" ]; then
                    mv "$out/$directory" "$bin/$directory"
                  fi
                done
              '')
          ];
        });

  utilities = builtins.derivation {
    name = "${attrs.name}-utilities";
    system = attrs.system;
    builder = "${buildTools.bash}/bin/bash";
    args = [
      "-c"
      ''
        set -eu
        export PATH="${buildTools.coreutils}/bin:${buildTools.findutils}/bin:${buildTools.sed}/bin"
        mkdir -p "$out"
        cp -R ${libraries.bin}/. "$out/"
        chmod -R u+w "$out"
        find "$out" -type f -print0 > files
        while IFS= read -r -d "" file; do
          [ "$(head -c 2 "$file")" = '#!' ] || continue
          ${rewritePerl}sed -e 's|${constructionShell}|${runtimeShell}|g' \
            -e "s|${libraries}/bin/|$out/bin/|g" \
            -e "s|${libraries}/sbin/|$out/sbin/|g" "$file" > rewritten
          cat rewritten > "$file"
        done < files
      ''
    ];
  };
in
  libraries
  // {
    bin = utilities;
    meta = package.meta or {};
    passthru = package.passthru or {};
  }
