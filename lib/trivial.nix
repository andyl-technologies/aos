##! lib/trivial.nix — Basic utility functions
##!
##! Pure functions with no dependencies on other library modules.
{
  ## Identity function. Returns its argument unchanged.
  ## # Type
  ## `a -> a`
  id = x: x;

  ## Returns a function that always returns its first argument.
  ## # Type
  ## `a -> b -> a`
  const = x: _: x;

  ## Swap the order of arguments to a binary function.
  ## # Type
  ## `(a -> b -> c) -> b -> a -> c`
  flip = f: a: b:
    f b a;

  ## Compose a list of functions, applying left to right.
  ##
  ## `pipe [f g h] x == h (g (f x))`
  ## # Type
  ## `[a -> a] -> a -> a`
  pipe = fns: x: builtins.foldl' (acc: f: f acc) x fns;

  ## Function composition, right to left.
  ##
  ## `compose f g x == f (g x)`
  ## # Type
  ## `(b -> c) -> (a -> b) -> a -> c`
  compose = f: g: x:
    f (g x);

  ## Compute the fixed point of a function `f : self -> self`. `fix f`
  ## is `f (fix f)`. Used to build mutually-recursive data structures
  ## (e.g. the module system's config ← modules ← config cycle) where
  ## Nix's laziness provides the termination.
  ## # Type
  ## `(a -> a) -> a`
  fix = f: let x = f x; in x;

  ## Apply a function if the value is not null, otherwise return null.
  ## # Type
  ## `(a -> b) -> a | null -> b | null`
  mapNullable = f: v:
    if v == null
    then null
    else f v;

  ## Throw an error if condition is true, otherwise return the value.
  ## # Type
  ## `bool -> string -> a -> a`
  throwIf = cond: msg: val:
    if cond
    then throw msg
    else val;

  ## Throw an error if condition is false, otherwise return the value.
  ## # Type
  ## `bool -> string -> a -> a`
  throwIfNot = cond: msg: val:
    if cond
    then val
    else throw msg;

  ## Print a warning message to stderr and return the value.
  ## In Nix, builtins.trace writes to stderr during evaluation.
  ## # Type
  ## `string -> a -> a`
  warn = msg: builtins.trace "warning: ${msg}";

  ## Print an informational message to stderr and return the value.
  ## # Type
  ## `string -> a -> a`
  info = msg: builtins.trace "info: ${msg}";

  ## Trace the value and return it. Useful for debugging.
  ## # Type
  ## `a -> a`
  traceVal = v: builtins.trace v v;

  ## Trace the result of applying a function to the value, return the original.
  ## # Type
  ## `(a -> b) -> a -> a`
  traceValFn = f: v: builtins.trace (f v) v;

  ## # Type
  ## `int -> int -> int`
  min = a: b:
    if a < b
    then a
    else b;

  ## # Type
  ## `int -> int -> int`
  max = a: b:
    if a > b
    then a
    else b;

  ## Clamp a value between a lower and upper bound.
  ## # Type
  ## `int -> int -> int -> int`
  clamp = lower: upper: v:
    if v < lower
    then lower
    else if v > upper
    then upper
    else v;

  ## # Type
  ## `int -> int -> int`
  bitAnd = builtins.bitAnd;

  ## # Type
  ## `int -> int -> int`
  bitOr = builtins.bitOr;

  ## # Type
  ## `int -> int -> int`
  bitXor = builtins.bitXor;

  ## Convert a non-negative integer to a lowercase hex string.
  ## # Type
  ## `int -> string`
  toHexString = let
    hexDigit = d:
      if d < 10
      then builtins.toString d
      else builtins.elemAt ["a" "b" "c" "d" "e" "f"] (d - 10);
    go = n:
      if n < 16
      then hexDigit n
      else go (n / 16) + hexDigit (n - (n / 16) * 16);
  in
    n:
      if n == 0
      then "0"
      else go n;

  ## Read and parse a JSON file.
  ## # Type
  ## `path -> value`
  importJSON = path: builtins.fromJSON (builtins.readFile path);

  ## Read and parse a TOML file (requires Nix >= 2.15).
  ## # Type
  ## `path -> value`
  importTOML = path: builtins.fromTOML (builtins.readFile path);

  ## Get the expected argument attribute names of a function.
  ## # Type
  ## `(attrset -> a) -> attrset`
  functionArgs = builtins.functionArgs;

  ## # Type
  ## `a -> bool`
  isFunction = f: builtins.isFunction f || (builtins.isAttrs f && f ? __functor);

  ## Check whether a value is a Nix derivation. A derivation is an attrset
  ## whose `type` attribute is the string `"derivation"`.
  ## # Type
  ## `a -> bool`
  isDerivation = x: (x.type or null) == "derivation";

  ## Attach argument metadata to a function for introspection.
  ## # Type
  ## `(a -> b) -> attrset -> (a -> b)`
  setFunctionArgs = f: args: {
    __functor = self: f;
    __functionArgs = args;
  };

  ## AOS library version.
  ## # Type
  ## `string`
  version = "0.1.0";

  ## AOS release codename.
  ## # Type
  ## `string`
  release = "bootstrap";
}
