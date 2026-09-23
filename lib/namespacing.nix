##! lib/namespacing.nix — module namespacing and extensible surface
##!
##! Helpers for the two-tier option namespace used by package configuration.
##! `module-system.md`:
##!
##!   - **Package declarations** — a package owns each option path for which it
##!     is the only authenticated declaring provenance.
##!   - **Shared / extension roots** — neutral roots (`firewall.*`, `nginx.*`)
##!     declared by one owner. The owner curates a *package extension
##!     surface* (F3-B) by setting `extensible = true` on the
##!     `mkOption` declarations non-owners may write into. [`optionSurface`]
##!     and [`extensibleSurface`] read that surface off an evaluated module
##!     set. The evaluator enforces that surface directly from provenance.
##!
##! Both functions are pure data over an already-evaluated module set. Neither
##! forces `config` or changes merge semantics. Publication also consumes the
##! surface as derived metadata.
_: rec {
  ## Extract the declared option surface from an `evalModules` result.
  ##
  ## Returns the list of `{ path, pathStr, extensible }` records the
  ## engine exposes as `result._optionDecls` — one per declared option path,
  ## derived purely from option *declarations* (it never forces any `config`
  ## value). This is the input to the publish-time options-only eval that
  ## builds the registry `option-path → package@version` inverted index.
  ##
  ## # Type
  ## `evaluatedModules -> [{ path = [string]; pathStr = string; extensible = bool; }]`
  optionSurface = evaluated: evaluated._optionDecls or [];

  ## The subset of [`optionSurface`] a non-owner package is allowed to write
  ## into (F3-B): the option paths whose owner declared `extensible =
  ## true`. The resolver authorizes a foreign write iff the def-path is at or
  ## below one of these paths (with `attrsOf` dynamic segments matching any
  ## one concrete attr name); a foreign write to any other path of a shared
  ## root — notably `enable` and owner-only globals — is rejected as
  ## conscription. `evalModules` enforces this from resolver-stamped package
  ## provenance; this helper exposes the same declaration-derived data.
  ##
  ## # Type
  ## `evaluatedModules -> [{ path = [string]; pathStr = string; extensible = bool; }]`
  extensibleSurface = evaluated:
    builtins.filter (d: d.extensible) (optionSurface evaluated);
}
