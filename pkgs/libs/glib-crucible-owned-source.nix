##! Builds the complete stable GLib library with retained native GSource backing.
##!
##! This primitive grants no native endpoint custody or dispatch permission.
{glib}: let
  recipe = ./glib-crucible-owned-source.nix;
  sourcePatch = ./glib-crucible-owned-source.patch;
  controls = ./tests/glib-crucible-owned-source.c;
in
  assert glib.version == "2.82.4";
    glib.overrideAttrs (original: {
      pname = "glib-crucible-owned-source";
      phases =
        builtins.map (
          phase:
            if phase.name == "unpack"
            then
              phase
              // {
                script =
                  phase.script
                  + ''
                    patch --batch -p1 < ${sourcePatch}
                  '';
              }
            else if phase.name == "install"
            then
              phase
              // {
                script =
                  phase.script
                  + ''
                    # Complete source carries the additive native primitive and the
                    # exact variant recipe alongside the original GLib sources.
                    cp ${sourcePatch} "$source/glib-crucible-owned-source.patch"
                    cp ${recipe} "$source/glib-crucible-owned-source.nix"
                    cp ${controls} "$source/tests/glib-crucible-owned-source.c"
                  '';
              }
            else phase
        )
        original.phases;
    })
