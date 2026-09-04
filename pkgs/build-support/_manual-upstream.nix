##! Closed metadata constructor for complex or human-led upstream units.
{platform}: {
  unitId,
  family,
  stream,
  owner,
  member ? family,
  version,
  upstreamId ? version,
  reason,
  riskFloor ? "high",
  repairScope ? [],
  lifecycle ? "supported",
  successorUnit ? null,
  reviewAfter ? null,
}: let
  requireString = label: value:
    if builtins.isString value && value != ""
    then value
    else throw "mkManualUpstream: ${label} must be a non-empty string";
  checkedUnit = requireString "unitId" unitId;
  checkedFamily = requireString "family" family;
  checkedStream = requireString "stream" stream;
  checkedOwner = requireString "owner" owner;
  checkedMember = requireString "member" member;
  checkedVersion = requireString "version" version;
  checkedUpstreamId = requireString "upstreamId" upstreamId;
  checkedReason = requireString "reason" reason;
  metadata =
    {
      schema = "aos.package-update/v1";
      unitId = checkedUnit;
      family = checkedFamily;
      stream = checkedStream;
      classification = "manual";
      package = {
        currentVersion = checkedVersion;
        versionProjection = {
          kind = "component-field";
          component = "main";
          field = "comparisonVersion";
        };
      };
      components.main = {
        current = {
          upstreamId = checkedUpstreamId;
          comparisonVersion = checkedVersion;
        };
        primary = null;
        advisors = [];
        releasePolicy = {
          strategy = "channel";
          versionScheme = "provider";
          seriesMajor = null;
          allowPrerelease = false;
          minimumAgeDays = 0;
        };
        sources = {};
      };
      owner = checkedOwner;
      members = [checkedMember];
      platforms = [platform];
      policy =
        {
          inherit lifecycle riskFloor repairScope;
        }
        // (
          if successorUnit == null
          then {}
          else {successorUnit = requireString "successorUnit" successorUnit;}
        );
      reason = checkedReason;
    }
    // (
      if reviewAfter == null
      then {}
      else {reviewAfter = requireString "reviewAfter" reviewAfter;}
    );
in {
  inherit version;
  update = metadata;
  updateFor = selectedMember:
    metadata
    // {
      members = [(requireString "member" selectedMember)];
    };
}
