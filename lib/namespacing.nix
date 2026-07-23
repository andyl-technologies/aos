##! lib/namespacing.nix — module namespacing and contributable surface
##!
##! Helpers for the two-tier option namespace used by package configuration.
##! `module-system.md`:
##!
##!   - **Per-package roots `{pkg}.*`** — each package's `config` module is
##!     mounted as a submodule under its own name. Ownership is *structural*:
##!     the root segment IS the declaring package. [`mkPackageRoot`] /
##!     [`mountPackageModules`] build the mount used by the CS5 on-host
##!     `evalModules` assembly.
##!   - **Shared / extension roots** — neutral roots (`firewall.*`, `nginx.*`)
##!     declared by one owner. The owner curates a *capability-scoped
##!     contribution surface* (F3-B) by setting `contributable = true` on the
##!     `mkOption` declarations non-owners may write into. [`optionSurface`]
##!     and [`contributableSurface`] read that surface off an evaluated module
##!     set for the publish-time / resolve-time authorization check.
##!
##! All functions here are pure data over an already-evaluated module set or
##! over module values; none of them force `config`, and none change merge
##! semantics. They are additive scaffolding consumed by CS5 (resolver +
##! publish lint); this changeset only exposes the Nix-side constructs.
{
  types,
  mkOption,
}: rec {
  ## Extract the declared option surface from an `evalModules` result.
  ##
  ## Returns the list of `{ path, pathStr, contributable }` records the
  ## engine exposes as `result._optionDecls` — one per declared option path,
  ## derived purely from option *declarations* (it never forces any `config`
  ## value). This is the input to the publish-time options-only eval that
  ## builds the registry `option-path → package@version` inverted index.
  ##
  ## # Type
  ## `evaluatedModules -> [{ path = [string]; pathStr = string; contributable = bool; }]`
  optionSurface = evaluated: evaluated._optionDecls or [];

  ## The subset of [`optionSurface`] a non-owner package is allowed to write
  ## into (F3-B): the option paths whose owner declared `contributable =
  ## true`. The resolver authorizes a foreign write iff the def-path is at or
  ## below one of these paths (with `attrsOf` dynamic segments matching any
  ## one concrete attr name); a foreign write to any other path of a shared
  ## root — notably `enable` and owner-only globals — is rejected as
  ## conscription. Enforcement (provenance + reject) is resolver-side (CS5);
  ## this only surfaces the owner-declared data.
  ##
  ## # Type
  ## `evaluatedModules -> [{ path = [string]; pathStr = string; contributable = bool; }]`
  contributableSurface = evaluated:
    builtins.filter (d: d.contributable) (optionSurface evaluated);

  ## Mount one package's config module under its own root name (`{pkg}.*`).
  ##
  ## Produces an AOS module that declares `options.<name>` as a `submodule`
  ## carrying `pkgModule` (the package's private option surface, including its
  ## `<name>.enable`). The root segment IS the package name, so ownership is
  ## structural — no index is needed to answer "who declares `<name>.foo`".
  ## The module evaluator injects the root name as the submodule's `name`
  ## special-arg (the last `loc` segment is `<name>`), so package modules
  ## written `{ name, config, ... }: …` see their own root name.
  ##
  ## Intended for the CS5 on-host `evalModules` assembly, which mounts every
  ## resolved package this way. `default = {}` keeps an un-configured package
  ## root inert (its nested defaults fire lazily, nothing is forced).
  ##
  ## # Type
  ## `string -> (module | [module]) -> module`
  mkPackageRoot = name: pkgModule: {
    _file = "<aos package root: ${name}>";
    options.${name} = mkOption {
      type = types.submodule pkgModule;
      default = {};
      description = "Per-package configuration root for the `${name}` package ({pkg}.* namespace).";
    };
  };

  ## Mount many packages at once: `mkPackageRoot` lifted over a
  ## `name -> module` attrset, returning the list of per-package root modules
  ## ready to splice into an `evalModules` `modules` list. This is the shape
  ## CS5 hands the resolver-assembled working set.
  ##
  ## # Type
  ## `{ <name> = module | [module]; … } -> [module]`
  mountPackageModules = pkgModules:
    builtins.map (name: mkPackageRoot name pkgModules.${name}) (builtins.attrNames pkgModules);
}
