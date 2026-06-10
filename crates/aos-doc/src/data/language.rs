//! Nix language reference organized by chapter and topic.
//!
//! Each chapter groups related topics with substantive prose and code
//! examples, aimed at someone who knows programming but is learning Nix.
//! The content is compile-time constant: it backs the TUI's Language tab
//! directly and is merged into the doc index as
//! `language.<chapter>.<topic>` entries by [`crate::extract::build_index`].

/// A chapter of the language reference (e.g. "Values & Types").
pub struct LanguageChapter {
    /// Human-readable chapter title.
    pub name: &'static str,
    /// The chapter's topics, in reading order.
    pub topics: &'static [LanguageTopic],
}

/// A single topic within a chapter (e.g. "Strings").
pub struct LanguageTopic {
    /// Human-readable topic title.
    pub name: &'static str,
    /// One-sentence description shown in listings and search results.
    pub summary: &'static str,
    /// Full markdown body with prose and fenced `nix` code examples.
    pub body: &'static str,
}

/// Returns all language reference chapters, in reading order.
pub fn chapters() -> &'static [LanguageChapter] {
    &CHAPTERS
}

/// The language reference content, one entry per chapter.
static CHAPTERS: [LanguageChapter; 6] = [
    // ==================================================================
    // Chapter 1: Values & Types
    // ==================================================================
    LanguageChapter {
        name: "Values & Types",
        topics: &[
            LanguageTopic {
                name: "Strings",
                summary: "String literals, interpolation, and multi-line strings.",
                body: r#"Nix has two forms of string literals: double-quoted and multi-line (indented).

**Double-quoted strings** work like most languages:

```nix
"hello, world"
"path is ${toString x}/bin"
"escape a quote: \" and a dollar-brace: \${"
```

String interpolation uses `${ expr }` to embed any Nix expression.
The expression is converted to a string (via `toString`) and spliced in.

**Multi-line (indented) strings** use `'' ... ''`:

```nix
''
  line one
  line two
  interpolation: ${name}
''
```

Leading whitespace common to all lines is automatically stripped.
To include a literal `${`, write `''${`. To include `''` itself,
write `'''`.

Strings are the most common Nix type. They carry hidden "string context"
that tracks references to store paths, which Nix uses for dependency
tracking."#,
            },
            LanguageTopic {
                name: "Numbers",
                summary: "Integer and floating-point number literals.",
                body: r#"Nix supports two numeric types: **integers** (64-bit signed) and **floats**
(64-bit IEEE 754 double precision).

```nix
42        # integer
-7        # negative integer
3.14      # float
1.0e10    # float with exponent
```

Arithmetic operations on two integers produce an integer (with integer
division truncating towards zero). If either operand is a float, the
result is a float:

```nix
7 / 2       # => 3  (integer division)
7.0 / 2     # => 3.5
7 / 2.0     # => 3.5
```

There is no implicit conversion between integers and floats in
comparisons — `1 == 1.0` is `false`."#,
            },
            LanguageTopic {
                name: "Booleans",
                summary: "The true and false values.",
                body: r#"Nix has two boolean literals: `true` and `false`.

```nix
true
false
```

Boolean operations use `&&` (and), `||` (or), and `!` (not). Both
`&&` and `||` short-circuit: the right operand is only evaluated if
needed.

```nix
true && false     # => false
true || false     # => true
!true             # => false
```

Booleans are commonly used with `if-then-else` and `assert`."#,
            },
            LanguageTopic {
                name: "Paths",
                summary: "File path literals: relative, absolute, and angle-bracket.",
                body: r#"Nix has a dedicated **path** type, distinct from strings. Paths are
written without quotes and must contain at least one `/`:

```nix
./relative/path       # relative to the current file
/absolute/path        # absolute path
../parent/file.nix    # parent-relative path
```

When a path is used in a string context (e.g. interpolation or as a
derivation input), Nix copies the referenced file into the Nix store
and substitutes the store path. This is how Nix tracks source
dependencies.

**Angle-bracket paths** use the Nix search path (NIX_PATH):

```nix
<nixpkgs>             # looks up "nixpkgs" in NIX_PATH
<nixpkgs/lib>         # subdirectory within the found path
```

Angle-bracket paths are impure (they depend on environment) and are
discouraged in reproducible configurations. Flakes avoid them entirely."#,
            },
            LanguageTopic {
                name: "Null",
                summary: "The null value.",
                body: r#"Nix has a single null value, written as `null`:

```nix
null
```

`null` is its own type. It is commonly used as a default or sentinel
value in option declarations:

```nix
{ server = null; }  # "no server configured"
```

You can test for null with `== null` or `builtins.isNull`."#,
            },
            LanguageTopic {
                name: "Lists",
                summary: "Ordered collections of values.",
                body: r#"Lists are ordered, heterogeneous sequences enclosed in square brackets.
Elements are separated by whitespace (no commas):

```nix
[ 1 2 3 ]
[ "hello" 42 true ./path ]
[ [ 1 2 ] [ 3 4 ] ]            # nested lists
```

Lists are **immutable** — you create new lists rather than modifying
existing ones. Common list operations:

```nix
[ 1 2 ] ++ [ 3 4 ]             # => [ 1 2 3 4 ]  (concatenation)
builtins.head [ 1 2 3 ]        # => 1
builtins.tail [ 1 2 3 ]        # => [ 2 3 ]
builtins.length [ 1 2 3 ]      # => 3
builtins.elemAt [ 1 2 3 ] 1    # => 2
builtins.map (x: x * 2) [ 1 2 3 ]  # => [ 2 4 6 ]
```

Lists are evaluated lazily — elements are only computed when accessed."#,
            },
            LanguageTopic {
                name: "Attribute Sets",
                summary: "Key-value mappings: the central data structure in Nix.",
                body: r#"Attribute sets (attrsets) are unordered collections of name-value pairs,
enclosed in curly braces:

```nix
{ name = "hello"; version = "2.10"; }
```

Access attributes with dot notation:

```nix
let pkg = { name = "hello"; version = "2.10"; };
in pkg.name    # => "hello"
```

Nested access works naturally:

```nix
{ a.b.c = 1; }    # shorthand for { a = { b = { c = 1; }; }; }
```

**Recursive attrsets** (`rec { ... }`) allow attributes to reference
each other:

```nix
rec {
  x = 1;
  y = x + 1;    # => 2
}
```

The **merge operator** (`//`) combines two attrsets, with the right side
taking precedence:

```nix
{ a = 1; b = 2; } // { b = 3; c = 4; }
# => { a = 1; b = 3; c = 4; }
```

The `?` operator tests for attribute existence:

```nix
{ x = 1; } ? x    # => true
{ x = 1; } ? y    # => false
```"#,
            },
        ],
    },
    // ==================================================================
    // Chapter 2: Expressions
    // ==================================================================
    LanguageChapter {
        name: "Expressions",
        topics: &[
            LanguageTopic {
                name: "Let Bindings",
                summary: "Local variable definitions with let ... in.",
                body: r#"The `let ... in` expression introduces local bindings:

```nix
let
  x = 1;
  y = 2;
in
  x + y    # => 3
```

Bindings can reference each other (they are mutually recursive):

```nix
let
  a = b + 1;
  b = 1;
in
  a    # => 2
```

`let` bindings are lexically scoped — they shadow any outer bindings
of the same name within their body:

```nix
let x = 1; in
let x = 2; in
x    # => 2
```

Every `let` block requires an `in` clause that specifies the expression
to evaluate with those bindings in scope."#,
            },
            LanguageTopic {
                name: "If-Then-Else",
                summary: "Conditional expressions.",
                body: r#"Nix's conditional is an expression (it returns a value):

```nix
if x > 0 then "positive" else "non-positive"
```

Both branches are required — there is no `if` without `else`. The
condition must evaluate to a boolean.

Conditionals can be nested and used anywhere an expression is expected:

```nix
{
  greeting = if lang == "fr" then "bonjour"
             else if lang == "de" then "hallo"
             else "hello";
}
```

Because `if-then-else` is an expression, not a statement, it works
naturally in attribute sets, function arguments, and list elements."#,
            },
            LanguageTopic {
                name: "With",
                summary: "Bring attribute set members into scope.",
                body: r#"The `with` expression brings all attributes of a set into scope:

```nix
let attrs = { a = 1; b = 2; };
in with attrs; a + b    # => 3
```

This avoids having to write `attrs.a` and `attrs.b` repeatedly. A
common pattern is `with builtins;` to use builtins without the prefix.

**Important**: `with` does NOT shadow existing bindings. If a name is
already in scope, the existing binding wins:

```nix
let a = 10;
in with { a = 1; }; a    # => 10  (let binding wins)
```

Because of this, `with` can introduce subtle ambiguities. Prefer `let`
bindings or `inherit` when clarity matters."#,
            },
            LanguageTopic {
                name: "Assert",
                summary: "Assertions that guard evaluation.",
                body: r#"The `assert` expression checks a condition before proceeding:

```nix
assert x > 0; x * 2
```

If the condition is `false`, evaluation aborts with an assertion error.
If `true`, the expression after the semicolon is evaluated and returned.

Assertions are commonly used in function arguments:

```nix
{ port ? 80 }:
assert port > 0 && port < 65536;
{
  listenPort = port;
}
```

Unlike `throw`, assertion failures cannot be caught by `tryEval`."#,
            },
            LanguageTopic {
                name: "Inherit",
                summary: "Shorthand for bringing names into attribute sets or let bindings.",
                body: r#"The `inherit` keyword copies bindings by name, avoiding repetition.

**Inside attribute sets**, `inherit x;` is shorthand for `x = x;`:

```nix
let name = "hello"; version = "2.10";
in { inherit name version; }
# equivalent to: { name = name; version = version; }
```

**Inherit from another set** pulls attributes out of a specific attrset:

```nix
let src = { a = 1; b = 2; c = 3; };
in { inherit (src) a b; }
# => { a = 1; b = 2; }
```

`inherit` also works in `let` bindings:

```nix
let inherit (builtins) map filter;
in map (x: x + 1) (filter (x: x > 0) list)
```

This is purely syntactic sugar — it produces the same result as
explicit assignment."#,
            },
        ],
    },
    // ==================================================================
    // Chapter 3: Functions
    // ==================================================================
    LanguageChapter {
        name: "Functions",
        topics: &[
            LanguageTopic {
                name: "Lambda Syntax",
                summary: "Defining anonymous functions with x: body.",
                body: r#"Functions in Nix are anonymous lambdas written as `argument: body`:

```nix
x: x + 1
```

This defines a function that takes one argument `x` and returns `x + 1`.
To use it:

```nix
let inc = x: x + 1;
in inc 5    # => 6
```

Function application is by juxtaposition (no parentheses needed):

```nix
f x          # apply f to x
f x y        # apply f to x, then apply the result to y
```

Parentheses are used only for grouping:

```nix
f (x + 1)    # pass (x + 1) as a single argument to f
```"#,
            },
            LanguageTopic {
                name: "Currying",
                summary: "Multi-argument functions via nested lambdas.",
                body: r#"Nix functions take exactly one argument. Multi-argument functions are
expressed by returning another function (currying):

```nix
add = a: b: a + b;
```

This is syntactic sugar for:

```nix
add = a: (b: a + b);
```

Calling it with both arguments:

```nix
add 3 5    # => 8
```

Partial application is natural:

```nix
let add = a: b: a + b;
    add3 = add 3;      # a function that adds 3
in add3 5               # => 8
```

This pattern is idiomatic in Nix and very common in library functions."#,
            },
            LanguageTopic {
                name: "Pattern Arguments",
                summary: "Destructuring attribute set arguments with { a, b, ... }: body.",
                body: r#"Functions can destructure an attribute set argument:

```nix
{ name, version }: "${name}-${version}"
```

This function expects an attrset with exactly `name` and `version`. Extra
attributes cause an error unless you add `...`:

```nix
{ name, version, ... }: "${name}-${version}"
```

The `...` allows (and ignores) additional attributes. You can bind the
whole set with `@`:

```nix
args@{ name, version, ... }: "${name}-${version}-${toString args.rev}"
```

or equivalently:

```nix
{ name, version, ... }@args: "${name}-${version}"
```

Pattern arguments are the standard way to write "multi-argument"
functions in Nix, especially for package definitions and modules."#,
            },
            LanguageTopic {
                name: "Default Arguments",
                summary: "Optional function parameters with default values.",
                body: r#"Pattern arguments can have defaults using `?`:

```nix
{ name, version ? "0.0.0" }: "${name}-${version}"
```

If the caller omits `version`, it defaults to `"0.0.0"`:

```nix
f { name = "hello"; }                  # => "hello-0.0.0"
f { name = "hello"; version = "1.0"; } # => "hello-1.0"
```

Defaults can reference other arguments:

```nix
{ pname, version, name ? "${pname}-${version}" }: name
```

This is the predominant pattern in nixpkgs and NixOS modules, where
most options have sensible defaults."#,
            },
        ],
    },
    // ==================================================================
    // Chapter 4: Operators
    // ==================================================================
    LanguageChapter {
        name: "Operators",
        topics: &[
            LanguageTopic {
                name: "Attribute Set Merge (//)",
                summary: "Merge two attribute sets, right side wins on conflicts.",
                body: r#"The `//` operator merges two attribute sets:

```nix
{ a = 1; b = 2; } // { b = 3; c = 4; }
# => { a = 1; b = 3; c = 4; }
```

When both sides have the same key, the **right side wins**. The merge
is shallow — nested attrsets are replaced, not recursively merged:

```nix
{ x = { a = 1; b = 2; }; } // { x = { c = 3; }; }
# => { x = { c = 3; }; }   # x.a and x.b are lost!
```

For deep merging, use `lib.recursiveUpdate` or the module system.

Chaining is left-associative: `a // b // c` is `(a // b) // c`, so
the rightmost set has the highest priority."#,
            },
            LanguageTopic {
                name: "Has-Attribute (?)",
                summary: "Test whether an attrset contains a key.",
                body: r#"The `?` operator tests whether an attribute exists:

```nix
{ x = 1; } ? x    # => true
{ x = 1; } ? y    # => false
```

It works with nested paths too:

```nix
{ a.b.c = 1; } ? a.b.c    # => true
{ a.b.c = 1; } ? a.b.d    # => false
```

This is commonly used in conditional logic:

```nix
if attrs ? optionalField
then attrs.optionalField
else "default"
```

The operator does not evaluate the attribute's value, only checks its
existence."#,
            },
            LanguageTopic {
                name: "List Concatenation (++)",
                summary: "Concatenate two lists.",
                body: r#"The `++` operator concatenates two lists:

```nix
[ 1 2 ] ++ [ 3 4 ]    # => [ 1 2 3 4 ]
```

It creates a new list (lists are immutable). Commonly used to build up
dependency lists:

```nix
{
  buildDeps = [ make cmake ]
    ++ (if enableTests then [ check ] else []);
}
```

Like all operators, `++` is an expression and can be used anywhere."#,
            },
            LanguageTopic {
                name: "String Interpolation (${})",
                summary: "Embed expressions inside strings.",
                body: r#"The `${ expr }` syntax embeds any Nix expression inside a string:

```nix
let name = "world";
in "hello, ${name}"    # => "hello, world"
```

The expression is converted to a string via `toString`. This works
for integers, paths, derivations, and more:

```nix
"port ${toString 8080}"    # => "port 8080"
"src is ${./src}"          # => "src is /nix/store/...-src"
```

Interpolation works in both double-quoted and multi-line strings:

```nix
''
  export PATH=${pkg}/bin:$PATH
''
```

Note: `${ }` in multi-line strings is Nix interpolation. To produce
a literal `${` in the output, use `''${`."#,
            },
            LanguageTopic {
                name: "Comparison Operators",
                summary: "Equality and ordering: ==, !=, <, >, <=, >=.",
                body: r#"Nix provides the standard comparison operators:

```nix
1 == 1      # => true
1 != 2      # => true
1 < 2       # => true
2 > 1       # => true
1 <= 1      # => true
2 >= 3      # => false
```

**Equality** (`==`) performs deep structural comparison for attribute
sets and lists. Two values of different types are never equal:

```nix
1 == 1.0          # => false  (int vs float)
{ a = 1; } == { a = 1; }  # => true  (deep comparison)
```

**Ordering** (`<`, `>`, `<=`, `>=`) works on numbers and strings.
String comparison is lexicographic."#,
            },
            LanguageTopic {
                name: "Arithmetic Operators",
                summary: "Addition, subtraction, multiplication, and division.",
                body: r#"Nix supports the standard arithmetic operators:

```nix
1 + 2       # => 3   (addition)
5 - 3       # => 2   (subtraction)
3 * 4       # => 12  (multiplication)
7 / 2       # => 3   (integer division)
7.0 / 2     # => 3.5 (float division)
```

Integer division truncates towards zero. If either operand is a float,
the result is a float.

**Note**: The `+` operator is overloaded — it also concatenates strings
and, in some contexts, paths:

```nix
"hello" + " " + "world"  # => "hello world"
/tmp + "/file"            # => /tmp/file (path concatenation)
```

When concatenating a path with a string using `+`, the result is a path
if the left operand is a path. Use interpolation instead when you want
a string."#,
            },
            LanguageTopic {
                name: "Logical Operators",
                summary: "Boolean logic: &&, ||, !.",
                body: r#"Nix has three logical operators:

```nix
true && false    # => false  (logical AND)
true || false    # => true   (logical OR)
!true            # => false  (logical NOT)
```

Both `&&` and `||` **short-circuit**: the right operand is only evaluated
if the left operand does not determine the result. This is important
because Nix is lazy — short-circuiting prevents unnecessary evaluation:

```nix
false && (builtins.throw "never reached")  # => false
true || (builtins.throw "never reached")   # => true
```

Operator precedence (highest to lowest): `!`, `&&`, `||`. Use
parentheses for clarity in complex expressions.

The `->` (logical implication) operator is also available:

```nix
false -> anything    # => true  (false implies anything)
true -> false        # => false
true -> true         # => true
```"#,
            },
        ],
    },
    // ==================================================================
    // Chapter 5: Imports
    // ==================================================================
    LanguageChapter {
        name: "Imports",
        topics: &[
            LanguageTopic {
                name: "The import Keyword",
                summary: "Loading and evaluating external Nix files.",
                body: r#"The `import` expression reads a Nix file and evaluates its contents:

```nix
import ./lib.nix
```

If the imported file evaluates to a function, `import` returns that
function (it does NOT call it). You typically chain the call:

```nix
import ./package.nix { inherit pkgs; }
```

`import` can also load directories — if a directory is given, Nix looks
for `default.nix` inside it:

```nix
import ./some-directory    # loads ./some-directory/default.nix
```

Each unique path is only evaluated once per evaluation; subsequent
imports of the same path return a cached result."#,
            },
            LanguageTopic {
                name: "Relative and Absolute Paths",
                summary: "How path resolution works in imports.",
                body: r#"Paths in Nix are resolved relative to the **file containing the expression**,
not the working directory:

```nix
# In /project/modules/foo.nix:
import ../lib/utils.nix    # resolves to /project/lib/utils.nix
```

Absolute paths work as expected:

```nix
import /etc/nix/config.nix
```

When a path literal appears in Nix code, it is tracked as a dependency.
Nix copies the referenced file into the store, ensuring builds are
hermetic and reproducible.

Relative paths must start with `./` or `../` — a bare name like
`foo/bar` is interpreted as division (`foo` divided by `bar`), not a
path."#,
            },
            LanguageTopic {
                name: "Angle-Bracket Paths",
                summary: "Looking up paths via NIX_PATH with <...>.",
                body: r#"Angle-bracket paths are resolved using the Nix search path:

```nix
import <nixpkgs>           # find "nixpkgs" in NIX_PATH
import <nixpkgs/lib>       # subdirectory of the found path
```

The search path is configured via:
- The `NIX_PATH` environment variable
- The `-I` command-line flag
- The `nix.nixPath` NixOS option

Each entry maps a prefix to a path: `nixpkgs=/path/to/nixpkgs`.

Angle-bracket paths are **impure** — they depend on the environment,
making builds non-reproducible across machines. Nix flakes eliminate
them entirely in favor of explicit input declarations."#,
            },
            LanguageTopic {
                name: "Flake Inputs",
                summary: "Declarative dependency management in flakes.",
                body: r#"Nix flakes replace angle-bracket paths with explicit, locked inputs
declared in `flake.nix`:

```nix
{
  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-24.05";

  outputs = { self, nixpkgs }: {
    packages.x86_64-linux.default = nixpkgs.legacyPackages.x86_64-linux.hello;
  };
}
```

Flake inputs are:
- **Declarative**: listed in the flake file, not environment variables
- **Locked**: pinned to exact revisions in `flake.lock`
- **Pure**: the evaluator sees only declared inputs, not the host env

Inputs can reference other flakes, Git repos, tarballs, or local paths.
The `flake.lock` file records the exact content hash and revision of
each input, ensuring reproducibility."#,
            },
        ],
    },
    // ==================================================================
    // Chapter 6: Derivations
    // ==================================================================
    LanguageChapter {
        name: "Derivations",
        topics: &[
            LanguageTopic {
                name: "builtins.derivation",
                summary: "The fundamental primitive for building store paths.",
                body: r#"Everything built by Nix ultimately goes through `builtins.derivation`.
It takes an attribute set and produces a derivation — a build recipe
stored in the Nix store:

```nix
builtins.derivation {
  name = "hello";
  system = "x86_64-linux";
  builder = "/bin/sh";
  args = [ "-c" "echo hello > $out" ];
}
```

Required attributes:
- `name` — the derivation name (used in the store path)
- `system` — the platform (e.g. `"x86_64-linux"`)
- `builder` — the executable that performs the build

All other attributes are passed as environment variables to the builder.
The special variable `$out` is set to the output store path.

In practice, nobody calls `builtins.derivation` directly — everyone uses
a wrapper like `mkDerivation`."#,
            },
            LanguageTopic {
                name: "mkDerivation Pattern",
                summary: "The standard wrapper around builtins.derivation.",
                body: r#"Virtually all Nix packages use a `mkDerivation` function that wraps
`builtins.derivation` with defaults and conventions:

```nix
mkDerivation {
  pname = "hello";
  version = "2.10";
  src = fetchurl { url = "..."; hash = "sha256-..."; };
  buildDeps = [ make gcc ];
}
```

`mkDerivation` typically provides:
- Automatic source unpacking (`tar xf` on `src`)
- Standard build phases (configure, build, install)
- Dependency injection via environment variables
- Output path management

The AOS `mkDerivation` uses explicit `phases` lists and `buildDeps` /
`runtimeDeps` / `propagatedDeps` to keep builds hermetic and
transparent. Each phase is a shell script fragment executed on the
builder."#,
            },
            LanguageTopic {
                name: "Build Phases",
                summary: "The sequence of steps in a derivation build.",
                body: r#"A derivation build proceeds through a series of **phases** — shell
script fragments run in sequence by the builder. Common phases:

- **unpack** — extract the source archive
- **patch** — apply any patches
- **configure** — run `./configure` or equivalent
- **build** — compile the software (`make`, `cmake --build`, etc.)
- **install** — copy outputs to `$out` (`make install DESTDIR=$out`)
- **fixup** — strip binaries, fix RPATHs, wrap scripts

In the AOS build system, phases are explicit:

```nix
phases = [
  "tar xf $src"
  "./configure --prefix=/"
  "make -j$CORES"
  "make install DESTDIR=$out"
];
```

Each phase runs as a separate shell command on the builder. Failures
at any phase abort the build. The builder's shell is typically `/bin/sh`
(dash), so avoid bash-specific syntax."#,
            },
            LanguageTopic {
                name: "Fixed-Output Derivations",
                summary: "Derivations with known output hashes for network access.",
                body: r#"Normal derivations run in a network-isolated sandbox. **Fixed-output
derivations** (FODs) are the exception — they are allowed network
access but must declare their output hash upfront:

```nix
builtins.derivation {
  name = "source.tar.gz";
  system = "x86_64-linux";
  builder = "/bin/sh";
  args = [ "-c" "curl -o $out https://example.com/src.tar.gz" ];
  outputHash = "sha256-AAAA...";
  outputHashAlgo = "sha256";
  outputHashMode = "flat";
}
```

Since the output hash is fixed, Nix can verify that the downloaded
content matches, regardless of when or where the build runs. This is
how `fetchurl`, `fetchTarball`, and `fetchGit` work under the hood.

`outputHashMode` can be `"flat"` (hash the file directly) or
`"recursive"` (hash the NAR serialization of the output, supporting
directories)."#,
            },
            LanguageTopic {
                name: "String Context",
                summary: "How Nix tracks store path dependencies through strings.",
                body: r#"Every Nix string carries invisible **string context** — a set of store
paths that the string references. When you interpolate a derivation
into a string, its output path is added to the context:

```nix
"${pkgs.hello}/bin/hello"
```

This string has `pkgs.hello` in its context. When the string is used
in a derivation's environment, Nix automatically registers `pkgs.hello`
as a build dependency.

String context is what makes Nix's dependency tracking work. You never
have to manually declare runtime dependencies that appear in scripts
or configuration files — Nix infers them from string interpolation.

To strip context (rare, advanced usage): `builtins.unsafeDiscardStringContext`.
To inspect context: `builtins.getContext`."#,
            },
        ],
    },
];
