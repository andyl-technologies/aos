##! Typed explicit trust inputs for reopening an existing local repository.
{lib}: let
  types = lib.types;
  option = type: description: lib.mkOption {inherit type description;};
  nonempty = types.addCheck types.str (value: value != "");
  positive = types.addCheck types.int (value: value > 0);
  headReference = types.strMatching "refs/heads/.+";
  canonicalPath = path:
    builtins.match "/[A-Za-z0-9_./-]+" path
    != null
    && builtins.all (part: part != "" && part != "." && part != "..") (builtins.tail (lib.splitString "/" path));
  aclType = types.submodule {
    options = {
      principal = option nonempty "Explicit existing principal or group label.";
      verbs = option (types.listOf (types.enum ["read" "fork" "commit" "tag" "admin"])) "Explicit trusted verbs; an empty list grants nothing.";
    };
  };
  timingType = types.submodule {
    options = {
      maximumMs = option positive "Maximum publication duration in milliseconds.";
      graceMs = option positive "Collection grace window in milliseconds.";
      marginMs = option positive "Safety margin reserved within collection grace.";
    };
  };
in {
  type = types.submodule {
    options = {
      authorityDirectory = option (types.addCheck nonempty canonicalPath) "Existing protected absolute authority directory; never created by this module.";
      issuer = option nonempty "Explicit trusted issuer name.";
      keyId = option nonempty "Explicit trusted issuer rotation key identifier.";
      ownerUid = option (types.addCheck types.int (value: value >= 0 && value < 4294967295)) "Explicit expected authority and bucket owner UID.";
      storeName = option nonempty "Explicit authority store name for policy interpretation.";
      domain = option (types.strMatching "(public|tenant:.+|group:.+|private:.+)") "Canonical domain physically assigned to the bucket.";
      defaultPrivateDomain = option (types.strMatching "private:.+") "Explicit private default for original policy interpretation.";
      currentReference = option headReference "Existing canonical head authenticated during reopening; the runtime checks the complete reference grammar.";
      policyAuthority = lib.mkOption {
        type = types.nullOr headReference;
        default = null;
        description = "Optional separate trusted current policy head.";
      };
      acl = option (types.listOf aclType) "Required trusted ACL; an explicitly empty list denies access.";
      timing = option timingType "Required publication timing compatible with collection grace.";
    };
  };

  render = value:
    if value == null
    then null
    else {
      authority_directory = value.authorityDirectory;
      inherit (value) issuer domain;
      key_id = value.keyId;
      owner_uid = value.ownerUid;
      store_name = value.storeName;
      default_private_domain = value.defaultPrivateDomain;
      current_reference = value.currentReference;
      policy_authority = value.policyAuthority;
      acl = map (entry: {inherit (entry) principal verbs;}) value.acl;
      timing = {
        maximum_ms = value.timing.maximumMs;
        grace_ms = value.timing.graceMs;
        margin_ms = value.timing.marginMs;
      };
    };

  checks = {
    value,
    serveEnabled,
    serveUid,
  }:
    lib.optionals (value != null) [
      {
        assertion = !serveEnabled || value.ownerUid == serveUid;
        message = "Terrane local repository ownership must match the enabled serve identity.";
      }
      {
        assertion = value.timing.marginMs < value.timing.graceMs && value.timing.maximumMs < value.timing.graceMs - value.timing.marginMs;
        message = "Terrane publication maximum must fit strictly within collection grace after its safety margin.";
      }
    ];
}
