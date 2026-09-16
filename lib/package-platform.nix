##! Package-owned build, host, and target constraint declarations.
##!
##! This module normalizes package facts only. Target selection and release
##! policy decide what those facts mean for a particular environment.
{
  lists,
  platform,
}: let
  constraintKeys = [
    "abi"
    "cpu"
    "features"
    "os"
  ];
  declarationKeys = [
    "build"
    "host"
    "requires"
    "roles"
    "stages"
    "target"
  ];

  invalid = context: message:
    throw "${context}: ${message}";
  normalizeStrings = context: values:
    if !builtins.isList values || !builtins.all builtins.isString values
    then invalid context "must be a list of strings"
    else if builtins.any (value: value == "") values
    then invalid context "must not contain empty strings"
    else if builtins.length (lists.unique values) != builtins.length values
    then invalid context "must not contain duplicates"
    else builtins.sort builtins.lessThan values;
  normalizeConstraintValue = context: value:
    normalizeStrings context (
      if builtins.isString value
      then [value]
      else value
    );
  normalizeConstraint = context: constraint: let
    keys =
      if builtins.isAttrs constraint
      then builtins.attrNames constraint
      else [];
    unknownKeys = builtins.filter (key: !(builtins.elem key constraintKeys)) keys;
  in
    if !builtins.isAttrs constraint
    then invalid context "must be an attribute set"
    else if unknownKeys != []
    then invalid context "has unknown fields ${builtins.toJSON unknownKeys}"
    else
      builtins.mapAttrs (
        key: value: normalizeConstraintValue "${context}.${key}" value
      )
      constraint;
  normalizeConstraints = context: constraints:
    if !builtins.isList constraints
    then invalid context "must be a list of constraint sets"
    else builtins.map (normalizeConstraint context) constraints;
in rec {
  schema = "aos.package-platform-support/v1";

  normalize = context: declaration: let
    keys =
      if builtins.isAttrs declaration
      then builtins.attrNames declaration
      else [];
    unknownKeys = builtins.filter (key: !(builtins.elem key declarationKeys)) keys;
    missingKeys = builtins.filter (key: !(builtins.hasAttr key declaration)) declarationKeys;
  in
    if !builtins.isAttrs declaration
    then invalid context "must be an attribute set"
    else if unknownKeys != []
    then invalid context "has unknown fields ${builtins.toJSON unknownKeys}"
    else if missingKeys != []
    then invalid context "is missing fields ${builtins.toJSON missingKeys}"
    else {
      build = normalizeConstraints "${context}.build" declaration.build;
      host = normalizeConstraints "${context}.host" declaration.host;
      target = normalizeConstraints "${context}.target" declaration.target;
      roles = normalizeStrings "${context}.roles" declaration.roles;
      stages = normalizeStrings "${context}.stages" declaration.stages;
      requires = normalizeStrings "${context}.requires" declaration.requires;
    };

  supports = platformIdentity: constraints: let
    normalized = normalizeConstraints "package platform constraints" constraints;
  in
    normalized
    == []
    || builtins.any (constraint: platform.satisfies platformIdentity constraint) normalized;
}
