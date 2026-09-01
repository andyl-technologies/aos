##! lib/hardening.nix — Compiler-hardening token vocabulary and set algebra
##!
##! Central definition of the hardening tokens the cc-wrapper understands, and
##! the pure logic that turns a (default, enable, disable) triple into the
##! effective token set exported to the builder as AOS_HARDENING_ENABLE.
##!
##! The token → compiler-flag mapping lives in stdenv/cc-wrapper.nix; this file
##! owns only the vocabulary, validation, implication rules, and platform
##! filtering so both sides agree on what each token means.
##!
##! Self-contained (no lib dependency) so it can be imported from both
##! lib/derivations.nix and the stdenv without fixpoint concerns.
let
  optional = cond: elem:
    if cond
    then [elem]
    else [];

  # Order-preserving dedup.
  unique = builtins.foldl' (acc: x:
    if builtins.elem x acc
    then acc
    else acc ++ [x]) [];

  # Every token the wrapper knows how to emit. Unknown tokens in
  # hardeningEnable / hardeningDisable are evaluation errors.
  knownTokens = [
    "stackprotector"
    "relro"
    "bindnow"
    "pie"
    "noexecstack"
    "fortify"
    "fortify3"
    "stackclashprotection"
    "format"
    "strictflexarrays1"
    "strictflexarrays3"
    "glibcxxassertions"
    "shadowstack"
    "pacret"
    "trivialautovarinit"
    "zerocallusedregs"
  ];

  # Tokens that only make sense on one architecture. They stay valid known
  # tokens everywhere, but are filtered out of the effective set on platforms
  # that cannot use them. The predicate receives an mkPlatform record.
  platformTokens = {
    # Clang accepts the option spelling for non-Linux targets but ignores it;
    # keeping it out of Darwin cross builds avoids turning that diagnostic
    # into a configure failure under packages that probe with -Werror.
    stackclashprotection = p: p.isLinux;
    shadowstack = p: p.isx86_64;
    pacret = p: p.isAarch64;
  };

  # "all" is accepted only in hardeningDisable; it clears the whole set.
  isKnown = tok: tok == "all" || builtins.elem tok knownTokens;

  validateTokens = name: attr: toks:
    builtins.map (
      tok:
        if isKnown tok
        then tok
        else throw "mkDerivation (${name}): unknown hardening token '${tok}' in ${attr} (known: ${builtins.concatStringsSep " " knownTokens})"
    )
    toks;

  # Compute the effective token list from a (default, enable, disable) triple.
  #
  #   (defaultFlags ++ hardeningEnable) - hardeningDisable
  #
  # with implication rules and platform filtering applied before returning:
  #   - fortify3 implies fortify;
  #   - disabling fortify also disables fortify3;
  #   - disabling fortify3 alone keeps fortify;
  #   - "all" in hardeningDisable clears every token;
  #   - architecture-specific tokens are dropped on platforms that can't use
  #     them.
  effectiveTokens = {
    name,
    platform,
    defaultFlags,
    hardeningEnable,
    hardeningDisable,
  }: let
    # Forcing the validated lists turns any unknown token into a throw.
    enable = validateTokens name "hardeningEnable" hardeningEnable;
    disable = validateTokens name "hardeningDisable" hardeningDisable;
    defaults = validateTokens name "defaultHardeningFlags" defaultFlags;

    disableAll = builtins.elem "all" disable;

    base = unique (defaults ++ enable);

    removeSet = disable ++ optional (builtins.elem "fortify" disable) "fortify3";

    afterDisable =
      if disableAll
      then []
      else builtins.filter (t: !(builtins.elem t removeSet)) base;

    withImplications =
      if builtins.elem "fortify3" afterDisable && !(builtins.elem "fortify" afterDisable)
      then afterDisable ++ ["fortify"]
      else afterDisable;

    platformFiltered =
      builtins.filter (
        t:
          if platformTokens ? ${t}
          then platformTokens.${t} platform
          else true
      )
      withImplications;
  in
    unique platformFiltered;

  effectiveString = args: builtins.concatStringsSep " " (effectiveTokens args);
in {
  inherit
    knownTokens
    platformTokens
    effectiveTokens
    effectiveString
    ;
}
