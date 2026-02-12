# lib/trivial.nix — Basic utility functions
#
# Pure functions with no dependencies on other library modules.
#

{
  # id :: a -> a
  # Identity function. Returns its argument unchanged.
  id = x: x;

  # const :: a -> b -> a
  # Returns a function that always returns its first argument.
  const = x: _: x;

  # flip :: (a -> b -> c) -> b -> a -> c
  # Swap the order of arguments to a binary function.
  flip =
    f: a: b:
    f b a;

  # pipe :: [a -> a] -> a -> a
  # Compose a list of functions, applying left to right.
  # pipe [f g h] x == h (g (f x))
  pipe = fns: x: builtins.foldl' (acc: f: f acc) x fns;

  # compose :: (b -> c) -> (a -> b) -> a -> c
  # Function composition, right to left.
  # compose f g x == f (g x)
  compose =
    f: g: x:
    f (g x);

  # mapNullable :: (a -> b) -> a | null -> b | null
  # Apply a function if the value is not null, otherwise return null.
  mapNullable = f: v: if v == null then null else f v;

  # throwIf :: bool -> string -> a -> a
  # Throw an error if condition is true, otherwise return the value.
  throwIf =
    cond: msg: val:
    if cond then throw msg else val;

  # throwIfNot :: bool -> string -> a -> a
  # Throw an error if condition is false, otherwise return the value.
  throwIfNot =
    cond: msg: val:
    if cond then val else throw msg;

  # warn :: string -> a -> a
  # Print a warning message to stderr and return the value.
  # In Nix, builtins.trace writes to stderr during evaluation.
  warn = msg: builtins.trace "warning: ${msg}";

  # info :: string -> a -> a
  # Print an informational message to stderr and return the value.
  info = msg: builtins.trace "info: ${msg}";

  # traceVal :: a -> a
  # Trace the value and return it. Useful for debugging.
  traceVal = v: builtins.trace v v;

  # traceValFn :: (a -> b) -> a -> a
  # Trace the result of applying a function to the value, return the original.
  traceValFn = f: v: builtins.trace (f v) v;

  # min :: int -> int -> int
  min = a: b: if a < b then a else b;

  # max :: int -> int -> int
  max = a: b: if a > b then a else b;

  # clamp :: int -> int -> int -> int
  # Clamp a value between a lower and upper bound.
  clamp =
    lower: upper: v:
    if v < lower then
      lower
    else if v > upper then
      upper
    else
      v;

  # bitAnd :: int -> int -> int
  bitAnd = builtins.bitAnd;

  # bitOr :: int -> int -> int
  bitOr = builtins.bitOr;

  # bitXor :: int -> int -> int
  bitXor = builtins.bitXor;

  # toHexString :: int -> string
  # Convert a non-negative integer to a lowercase hex string.
  toHexString =
    let
      hexDigit =
        d: if d < 10 then builtins.toString d else builtins.elemAt [ "a" "b" "c" "d" "e" "f" ] (d - 10);
      go = n: if n < 16 then hexDigit n else go (n / 16) + hexDigit (n - (n / 16) * 16);
    in
    n: if n == 0 then "0" else go n;

  # importJSON :: path -> value
  # Read and parse a JSON file.
  importJSON = path: builtins.fromJSON (builtins.readFile path);

  # importTOML :: path -> value
  # Read and parse a TOML file (requires Nix >= 2.15).
  importTOML = path: builtins.fromTOML (builtins.readFile path);

  # functionArgs :: (attrset -> a) -> attrset
  # Get the expected argument attribute names of a function.
  functionArgs = builtins.functionArgs;

  # isFunction :: a -> bool
  isFunction = f: builtins.isFunction f || (builtins.isAttrs f && f ? __functor);

  # setFunctionArgs :: (a -> b) -> attrset -> (a -> b)
  # Attach argument metadata to a function for introspection.
  setFunctionArgs = f: args: {
    __functor = self: f;
    __functionArgs = args;
  };

  # version :: string
  # AOS library version.
  version = "0.1.0";

  # release :: string
  # AOS release codename.
  release = "bootstrap";
}
