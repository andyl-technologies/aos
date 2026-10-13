##! Checks retained GSource geometry against the complete actual GLib library.
{
  mkDerivation,
  glib-crucible-owned-source,
}: let
  library = glib-crucible-owned-source;
  controls = ./tests/glib-crucible-owned-source.c;
in
  mkDerivation {
    pname = "glib-owned-source-check";
    version = "1";
    buildDeps = [library library.dev];
    runtimeDeps = [library];

    phases = [
      {
        name = "build";
        script = ''
          $CC -std=gnu11 -Wall -Wextra -Werror \
            -MMD -MF owned-source-controls.d ${controls} \
            -I${library.dev}/include/glib-2.0 \
            -I${library.dev}/lib/glib-2.0/include \
            -L${library}/lib -Wl,-rpath,${library}/lib \
            -lglib-2.0 -o owned-source-controls
          ./owned-source-controls > result.txt
        '';
      }
      {
        name = "install";
        script = ''
          mkdir -p "$out"
          cp owned-source-controls owned-source-controls.d result.txt "$out/"
          cp ${controls} "$out/controls.c"
          printf '%s\n' ${library} ${library.dev} ${library.source} \
            > "$out/actual-library-outputs"
        '';
      }
    ];
  }
