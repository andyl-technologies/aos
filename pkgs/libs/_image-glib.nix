##! GLib required by the image stack's Pango and librsvg versions.
{
  callPackage,
  mkDerivation,
  python3,
}:
callPackage ./glib.nix {
  version = "2.89.4";
  sourceHash = "0b2ax3iaa02yw1app5s4n6593ilrsmgpncxq2ipjx0sqyncvgnqw";
  enableIntrospection = true;
  mkDerivation = attributes:
    mkDerivation (attributes
      // {
        phases =
          attributes.phases
          ++ [
            {
              name = "installed-generators";
              script = ''
                # Newer GLib installs env-based Python entry points. Bind them
                # to the target interpreter retained by the tools output.
                for generator in "$tools/bin/"*; do
                  [ -f "$generator" ] || continue
                  if ! grep -q '^#!/usr/bin/env python3$' "$generator"; then
                    continue
                  fi
                  sed -i '1s|^#!/usr/bin/env python3$|#!${python3}/bin/python3|' "$generator"
                done
              '';
            }
          ];
      });
}
