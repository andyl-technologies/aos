##! Validate declarative advisory identities without executing scanner code.
{lib}: let
  fields = label: required: optional: value:
    if !builtins.isAttrs value
    then throw "assessment: ${label} must be an attribute set"
    else let
      unknown = builtins.filter (name: !(builtins.elem name (required ++ optional))) (builtins.attrNames value);
      missing = builtins.filter (name: !(builtins.hasAttr name value)) required;
    in
      if unknown != [] || missing != []
      then throw "assessment: ${label} has unknown or missing fields"
      else value;

  text = label: maximum: value:
    if
      builtins.isString value
      && value != ""
      && builtins.stringLength value <= maximum
      && builtins.match ".*[[:cntrl:]].*" value == null
    then value
    else throw "assessment: ${label} requires bounded nonempty text without controls";

  enum = label: choices: value:
    if builtins.elem value choices
    then value
    else throw "assessment: unsupported ${label}";

  optionalText = value: name: maximum:
    lib.optionalAttrs (value ? ${name}) {
      ${name} = text name maximum value.${name};
    };

  cpeField = name: value: let
    checked = text "CPE ${name}" 256 value;
  in
    if checked == "-" || builtins.match ".*[*?:\\\\].*" checked != null
    then throw "assessment: CPE mappings require explicit product fields"
    else checked;

  normalizeIdentity = value: let
    kind = enum "security identity" ["cpe" "ecosystem" "git" "purl" "unmapped"] value.kind;
  in
    if kind == "ecosystem"
    then let
      checked = fields "ecosystem identity" ["kind" "ecosystem" "name"] [] value;
    in {
      inherit kind;
      ecosystem = text "advisory ecosystem" 128 checked.ecosystem;
      name = text "upstream package name" 1024 checked.name;
    }
    else if kind == "purl"
    then let
      checked = fields "Package URL identity" ["kind" "value"] [] value;
      purl = text "Package URL" 2048 checked.value;
    in
      if builtins.match "pkg:[a-z][a-z0-9.+-]*/.+" purl == null
      then throw "assessment: identity must contain a Package URL"
      else {
        inherit kind;
        value = purl;
      }
    else if kind == "git"
    then let
      checked = fields "Git identity" ["kind" "repository" "commit"] [] value;
      repository = text "upstream Git repository" 2048 checked.repository;
      commit = text "upstream Git commit" 64 checked.commit;
    in
      if
        builtins.match "https://[A-Za-z0-9.-]+(:[0-9]+)?/[^@?#[:cntrl:]]+" repository
        == null
        || !(builtins.elem (builtins.stringLength commit) [40 64])
        || builtins.match "[0-9a-f]+" commit == null
      then throw "assessment: Git identity requires credential-free HTTPS and a full immutable commit"
      else {inherit kind repository commit;}
    else if kind == "cpe"
    then let
      checked = fields "CPE identity" ["kind" "part" "vendor" "product"] ["edition" "targetSoftware" "targetHardware"] value;
    in
      {
        inherit kind;
        part = enum "CPE part" ["a" "o" "h"] checked.part;
        vendor = cpeField "vendor" checked.vendor;
        product = cpeField "product" checked.product;
      }
      // builtins.listToAttrs (builtins.map (name: {
        inherit name;
        value = cpeField name checked.${name};
      }) (builtins.filter (name: checked ? ${name}) ["edition" "targetSoftware" "targetHardware"]))
    else let
      checked = fields "unmapped identity" ["kind" "reason" "explanation"] [] value;
    in {
      inherit kind;
      reason = text "unmapped reason" 128 checked.reason;
      explanation = text "unmapped explanation" 4096 checked.explanation;
    };

  # This tuple order matches the shared Rust SecurityIdentity contract. JSON
  # object-key order must not become a second set-ordering algorithm.
  identityKey = identity:
    [identity.kind]
    ++ (
      if identity.kind == "cpe"
      then [identity.part identity.vendor identity.product (identity.edition or "") (identity.targetSoftware or "") (identity.targetHardware or "")]
      else if identity.kind == "ecosystem"
      then [identity.ecosystem identity.name]
      else if identity.kind == "git"
      then [identity.repository identity.commit]
      else if identity.kind == "purl"
      then [identity.value]
      else [identity.reason identity.explanation]
    );

  tupleLess = left: right:
    if left == []
    then right != []
    else if right == []
    then false
    else if builtins.head left == builtins.head right
    then tupleLess (builtins.tail left) (builtins.tail right)
    else builtins.head left < builtins.head right;

  ordered = label: maximum: key: values:
    if !builtins.isList values || builtins.length values > maximum
    then throw "assessment: ${label} exceeds bounded set scope"
    else if values != builtins.sort (left: right: tupleLess (key left) (key right)) (lib.unique values)
    then throw "assessment: ${label} must be sorted and unique"
    else values;

  normalizeSource = value: let
    checked = fields "advisory source" ["provider"] ["project"] value;
  in
    {
      provider = enum "advisory source profile" ["nvd" "osv"] checked.provider;
    }
    // optionalText checked "project" 1024;

  normalizeCoverage = value: let
    checked = fields "dependency coverage declaration" ["state" "basis"] [] value;
  in {
    state = enum "dependency coverage" ["complete" "partial" "unknown"] checked.state;
    basis = text "dependency coverage basis" 4096 checked.basis;
  };

  defaultDeclaration = {
    identities = [
      {
        kind = "unmapped";
        reason = "identity-unmapped";
        explanation = "No reviewed advisory identity is declared for this component.";
      }
    ];
    advisorySources = [];
    versionScheme = "unsupported";
    dependencyCoverage = {
      state = "unknown";
      basis = "Package source metadata does not establish built dependency inclusion.";
    };
  };
in {
  default = defaultDeclaration;

  normalize = value: let
    checked = fields "security declaration" ["identities" "advisorySources" "versionScheme" "dependencyCoverage"] ["dispositionRefs"] value;
    identities = ordered "security identities" 32 identityKey (builtins.map normalizeIdentity checked.identities);
    sources = ordered "advisory source mappings" 16 (source: [source.provider (source.project or "")]) (builtins.map normalizeSource checked.advisorySources);
    dispositionRefs = ordered "disposition references" 128 (value: [value]) (checked.dispositionRefs or []);
    normalized = {
      inherit identities;
      advisorySources = sources;
      versionScheme = enum "advisory comparator" ["semver" "dotted-numeric" "ecosystem" "git" "unsupported"] checked.versionScheme;
      dependencyCoverage = normalizeCoverage checked.dependencyCoverage;
    };
  in
    if identities == []
    then throw "assessment: an explicit identity or unmapped declaration is required"
    else if !builtins.all (digest: builtins.isString digest && builtins.match "sha256:[0-9a-f]{64}" digest != null) dispositionRefs
    then throw "assessment: disposition references require exact SHA-256 identities"
    else normalized // lib.optionalAttrs (dispositionRefs != []) {inherit dispositionRefs;};
}
