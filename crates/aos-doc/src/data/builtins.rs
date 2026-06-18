//! Static documentation for Nix builtins.
//!
//! Every entry corresponds to a built-in function (or value) provided by
//! the Nix evaluator.  The data is compile-time constant so it can be
//! referenced with `&'static` lifetimes throughout the codebase; it is
//! merged into the doc index as `builtins.<name>` entries by
//! [`crate::extract::build_index`].

/// Documentation for a single Nix builtin function or value.
///
/// Mirrors the fields of [`crate::model::DocEntry`] that apply to builtins,
/// but with `&'static` data so no allocation is needed until an entry is
/// actually added to an index.
pub struct BuiltinDoc {
    /// Builtin name without the `builtins.` prefix (e.g. `map`).
    pub name: &'static str,
    /// Informal Haskell-style type signature (e.g. `(a -> b) -> [a] -> [b]`).
    pub type_sig: &'static str,
    /// One-sentence description.
    pub summary: &'static str,
    /// Longer markdown description of behavior and edge cases.
    pub body: &'static str,
    /// `(name, description)` pairs for each parameter, in order.
    pub parameters: &'static [(&'static str, &'static str)],
    /// Short usage snippets, typically with a `# => result` comment.
    pub examples: &'static [&'static str],
    /// Names of related builtins.
    pub see_also: &'static [&'static str],
}

/// Returns the full table of documented Nix builtins.
pub fn builtins() -> &'static [BuiltinDoc] {
    &BUILTINS
}

/// The builtin documentation table, sorted alphabetically by name.
static BUILTINS: [BuiltinDoc; 93] = [
    // ------------------------------------------------------------------
    // abort
    // ------------------------------------------------------------------
    BuiltinDoc {
        name: "abort",
        type_sig: "string -> a",
        summary: "Abort evaluation with an error message.",
        body: "Immediately terminates Nix evaluation and prints the given string \
               as an error.  The return type is polymorphic because evaluation \
               never actually produces a value.",
        parameters: &[("msg", "The error message to display.")],
        examples: &[r#"builtins.abort "something went wrong""#],
        see_also: &["throw"],
    },
    // ------------------------------------------------------------------
    // add
    // ------------------------------------------------------------------
    BuiltinDoc {
        name: "add",
        type_sig: "number -> number -> number",
        summary: "Add two numbers.",
        body: "Returns the sum of two integers or floats.  If either argument is \
               a float the result is a float.",
        parameters: &[("a", "First operand."), ("b", "Second operand.")],
        examples: &[
            "builtins.add 3 5        # => 8",
            "builtins.add 1.5 2      # => 3.5",
        ],
        see_also: &["sub", "mul", "div"],
    },
    // ------------------------------------------------------------------
    // all
    // ------------------------------------------------------------------
    BuiltinDoc {
        name: "all",
        type_sig: "(a -> bool) -> [a] -> bool",
        summary: "Test whether all list elements satisfy a predicate.",
        body: "Returns `true` if the predicate returns `true` for every element \
               in the list.  Short-circuits on the first `false`.",
        parameters: &[
            ("pred", "Predicate function applied to each element."),
            ("list", "The list to test."),
        ],
        examples: &[
            "builtins.all (x: x > 0) [ 1 2 3 ]  # => true",
            "builtins.all (x: x > 2) [ 1 2 3 ]  # => false",
        ],
        see_also: &["any", "filter"],
    },
    // ------------------------------------------------------------------
    // any
    // ------------------------------------------------------------------
    BuiltinDoc {
        name: "any",
        type_sig: "(a -> bool) -> [a] -> bool",
        summary: "Test whether any list element satisfies a predicate.",
        body: "Returns `true` if the predicate returns `true` for at least one \
               element.  Short-circuits on the first `true`.",
        parameters: &[
            ("pred", "Predicate function applied to each element."),
            ("list", "The list to test."),
        ],
        examples: &[
            "builtins.any (x: x > 2) [ 1 2 3 ]  # => true",
            "builtins.any (x: x > 5) [ 1 2 3 ]  # => false",
        ],
        see_also: &["all", "filter"],
    },
    // ------------------------------------------------------------------
    // attrNames
    // ------------------------------------------------------------------
    BuiltinDoc {
        name: "attrNames",
        type_sig: "attrs -> [string]",
        summary: "Return attribute names as a sorted list of strings.",
        body: "Extracts the names of all attributes in the set and returns them \
               sorted lexicographically.",
        parameters: &[("set", "An attribute set.")],
        examples: &[r#"builtins.attrNames { b = 2; a = 1; }  # => [ "a" "b" ]"#],
        see_also: &["attrValues", "hasAttr", "getAttr"],
    },
    // ------------------------------------------------------------------
    // attrValues
    // ------------------------------------------------------------------
    BuiltinDoc {
        name: "attrValues",
        type_sig: "attrs -> [a]",
        summary: "Return attribute values sorted by their names.",
        body: "Returns a list of values from the attribute set, ordered by the \
               lexicographic sort of their corresponding names.",
        parameters: &[("set", "An attribute set.")],
        examples: &["builtins.attrValues { b = 2; a = 1; }  # => [ 1 2 ]"],
        see_also: &["attrNames"],
    },
    // ------------------------------------------------------------------
    // baseNameOf
    // ------------------------------------------------------------------
    BuiltinDoc {
        name: "baseNameOf",
        type_sig: "string -> string",
        summary: "Extract the filename component from a path string.",
        body: "Returns everything after the last `/` in the string.  Works on \
               both path values and plain strings.",
        parameters: &[("path", "A path or string containing a path.")],
        examples: &[
            r#"builtins.baseNameOf "/usr/bin/env"  # => "env""#,
            r#"builtins.baseNameOf ./foo/bar.nix    # => "bar.nix""#,
        ],
        see_also: &["dirOf"],
    },
    // ------------------------------------------------------------------
    // bitAnd
    // ------------------------------------------------------------------
    BuiltinDoc {
        name: "bitAnd",
        type_sig: "int -> int -> int",
        summary: "Bitwise AND of two integers.",
        body: "Returns the bitwise AND of two integers.",
        parameters: &[("a", "First operand."), ("b", "Second operand.")],
        examples: &["builtins.bitAnd 12 10  # => 8"],
        see_also: &["bitOr", "bitXor"],
    },
    // ------------------------------------------------------------------
    // bitOr
    // ------------------------------------------------------------------
    BuiltinDoc {
        name: "bitOr",
        type_sig: "int -> int -> int",
        summary: "Bitwise OR of two integers.",
        body: "Returns the bitwise OR of two integers.",
        parameters: &[("a", "First operand."), ("b", "Second operand.")],
        examples: &["builtins.bitOr 12 10  # => 14"],
        see_also: &["bitAnd", "bitXor"],
    },
    // ------------------------------------------------------------------
    // bitXor
    // ------------------------------------------------------------------
    BuiltinDoc {
        name: "bitXor",
        type_sig: "int -> int -> int",
        summary: "Bitwise XOR of two integers.",
        body: "Returns the bitwise exclusive-OR of two integers.",
        parameters: &[("a", "First operand."), ("b", "Second operand.")],
        examples: &["builtins.bitXor 12 10  # => 6"],
        see_also: &["bitAnd", "bitOr"],
    },
    // ------------------------------------------------------------------
    // catAttrs
    // ------------------------------------------------------------------
    BuiltinDoc {
        name: "catAttrs",
        type_sig: "string -> [attrs] -> [a]",
        summary: "Collect a named attribute from a list of attribute sets.",
        body: "For each set in the list that contains the named attribute, \
               includes that attribute's value in the result list.  Sets that \
               lack the attribute are silently skipped.",
        parameters: &[
            ("attr", "The attribute name to collect."),
            ("list", "A list of attribute sets."),
        ],
        examples: &[r#"builtins.catAttrs "a" [ { a = 1; } { b = 2; } { a = 3; } ]  # => [ 1 3 ]"#],
        see_also: &["getAttr", "mapAttrs"],
    },
    // ------------------------------------------------------------------
    // ceil
    // ------------------------------------------------------------------
    BuiltinDoc {
        name: "ceil",
        type_sig: "float -> int",
        summary: "Round a float up to the nearest integer.",
        body: "Returns the smallest integer greater than or equal to the argument.",
        parameters: &[("x", "A floating-point number.")],
        examples: &["builtins.ceil 1.2  # => 2", "builtins.ceil (-1.8)  # => -1"],
        see_also: &["floor"],
    },
    // ------------------------------------------------------------------
    // compareVersions
    // ------------------------------------------------------------------
    BuiltinDoc {
        name: "compareVersions",
        type_sig: "string -> string -> int",
        summary: "Compare two version strings.",
        body: "Returns -1 if the first version is older, 0 if equal, or 1 if \
               newer.  Version components are compared numerically when possible.",
        parameters: &[
            ("v1", "First version string."),
            ("v2", "Second version string."),
        ],
        examples: &[
            r#"builtins.compareVersions "1.2.3" "1.2.4"  # => -1"#,
            r#"builtins.compareVersions "2.0" "1.9"       # => 1"#,
        ],
        see_also: &["splitVersion", "parseDrvName"],
    },
    // ------------------------------------------------------------------
    // concatLists
    // ------------------------------------------------------------------
    BuiltinDoc {
        name: "concatLists",
        type_sig: "[[a]] -> [a]",
        summary: "Concatenate a list of lists into a single list.",
        body: "Flattens one level of list nesting.",
        parameters: &[("lists", "A list of lists.")],
        examples: &["builtins.concatLists [ [ 1 2 ] [ 3 ] [ 4 5 ] ]  # => [ 1 2 3 4 5 ]"],
        see_also: &["concatMap"],
    },
    // ------------------------------------------------------------------
    // concatMap
    // ------------------------------------------------------------------
    BuiltinDoc {
        name: "concatMap",
        type_sig: "(a -> [b]) -> [a] -> [b]",
        summary: "Map a function over a list and concatenate the results.",
        body: "Applies the function to each element (which must return a list), \
               then concatenates all result lists.  Equivalent to \
               `concatLists (map f list)`.",
        parameters: &[
            ("f", "Function that returns a list for each element."),
            ("list", "The input list."),
        ],
        examples: &["builtins.concatMap (x: [ x (x * 2) ]) [ 1 2 3 ]  # => [ 1 2 2 4 3 6 ]"],
        see_also: &["map", "concatLists"],
    },
    // ------------------------------------------------------------------
    // concatStringsSep
    // ------------------------------------------------------------------
    BuiltinDoc {
        name: "concatStringsSep",
        type_sig: "string -> [string] -> string",
        summary: "Join a list of strings with a separator.",
        body: "Concatenates the strings in the list, inserting the separator \
               between each pair of adjacent strings.",
        parameters: &[("sep", "Separator string."), ("list", "A list of strings.")],
        examples: &[
            r#"builtins.concatStringsSep ", " [ "a" "b" "c" ]  # => "a, b, c""#,
            r#"builtins.concatStringsSep "/" [ "usr" "bin" ]     # => "usr/bin""#,
        ],
        see_also: &["replaceStrings"],
    },
    // ------------------------------------------------------------------
    // currentSystem
    // ------------------------------------------------------------------
    BuiltinDoc {
        name: "currentSystem",
        type_sig: "string",
        summary: "The current system type.",
        body: "A string identifying the platform Nix is running on, \
               e.g. `\"x86_64-linux\"` or `\"aarch64-darwin\"`.  Commonly used \
               to select platform-specific packages.",
        parameters: &[],
        examples: &[r#"builtins.currentSystem  # => "x86_64-linux""#],
        see_also: &[],
    },
    // ------------------------------------------------------------------
    // deepSeq
    // ------------------------------------------------------------------
    BuiltinDoc {
        name: "deepSeq",
        type_sig: "a -> b -> b",
        summary: "Deeply evaluate the first argument, then return the second.",
        body: "Forces full (deep) evaluation of the first argument — including \
               nested lists and attribute sets — before returning the second \
               argument.  Useful for ensuring errors surface eagerly.",
        parameters: &[
            ("a", "Value to evaluate deeply."),
            ("b", "Value to return."),
        ],
        examples: &["builtins.deepSeq { x = 1; } \"ok\"  # => \"ok\""],
        see_also: &["seq"],
    },
    // ------------------------------------------------------------------
    // derivation
    // ------------------------------------------------------------------
    BuiltinDoc {
        name: "derivation",
        type_sig: "attrs -> derivation",
        summary: "Create a store derivation.",
        body: "The fundamental primitive for building things in Nix.  Takes an \
               attribute set with at least `name`, `system`, and `builder`, and \
               returns a derivation value.  In practice most users call a \
               wrapper like `mkDerivation` rather than this directly.",
        parameters: &[(
            "attrs",
            "Attribute set with `name`, `system`, `builder`, and optionally `args`, `outputs`, environment variables, etc.",
        )],
        examples: &[
            "derivation {\n  name = \"hello\";\n  system = \"x86_64-linux\";\n  builder = \"/bin/sh\";\n  args = [ \"-c\" \"echo hello > $out\" ];\n}",
        ],
        see_also: &["derivationStrict"],
    },
    // ------------------------------------------------------------------
    // derivationStrict
    // ------------------------------------------------------------------
    BuiltinDoc {
        name: "derivationStrict",
        type_sig: "attrs -> attrs",
        summary: "Internal strict version of derivation.",
        body: "Low-level primitive that `derivation` is built on.  Returns the \
               output paths as an attribute set rather than a derivation value. \
               Rarely used directly.",
        parameters: &[("attrs", "Same attributes as `derivation`.")],
        examples: &[],
        see_also: &["derivation"],
    },
    // ------------------------------------------------------------------
    // dirOf
    // ------------------------------------------------------------------
    BuiltinDoc {
        name: "dirOf",
        type_sig: "string -> string",
        summary: "Return the directory part of a path string.",
        body: "Returns everything before the last `/`.  The dual of `baseNameOf`.",
        parameters: &[("path", "A path or string.")],
        examples: &[r#"builtins.dirOf "/usr/bin/env"  # => "/usr/bin""#],
        see_also: &["baseNameOf"],
    },
    // ------------------------------------------------------------------
    // div
    // ------------------------------------------------------------------
    BuiltinDoc {
        name: "div",
        type_sig: "number -> number -> number",
        summary: "Divide two numbers.",
        body: "Integer division when both arguments are integers (rounds towards \
               zero).  Float division if either argument is a float.",
        parameters: &[("a", "Dividend."), ("b", "Divisor (must not be zero).")],
        examples: &["builtins.div 7 2    # => 3", "builtins.div 7.0 2  # => 3.5"],
        see_also: &["add", "sub", "mul"],
    },
    // ------------------------------------------------------------------
    // elem
    // ------------------------------------------------------------------
    BuiltinDoc {
        name: "elem",
        type_sig: "a -> [a] -> bool",
        summary: "Test whether a value is in a list.",
        body: "Returns `true` if the list contains an element equal to the \
               given value (using `==`).",
        parameters: &[
            ("x", "Value to search for."),
            ("list", "List to search in."),
        ],
        examples: &[
            "builtins.elem 3 [ 1 2 3 ]  # => true",
            "builtins.elem 4 [ 1 2 3 ]  # => false",
        ],
        see_also: &["filter", "any"],
    },
    // ------------------------------------------------------------------
    // elemAt
    // ------------------------------------------------------------------
    BuiltinDoc {
        name: "elemAt",
        type_sig: "[a] -> int -> a",
        summary: "Access a list element by zero-based index.",
        body: "Returns the element at the given index.  Throws an error if the \
               index is out of bounds.",
        parameters: &[("list", "The list."), ("index", "Zero-based index.")],
        examples: &[r#"builtins.elemAt [ "a" "b" "c" ] 1  # => "b""#],
        see_also: &["head", "tail", "length"],
    },
    // ------------------------------------------------------------------
    // fetchGit
    // ------------------------------------------------------------------
    BuiltinDoc {
        name: "fetchGit",
        type_sig: "attrs -> path",
        summary: "Fetch a Git repository.",
        body: "Clones a Git repository into the Nix store.  Accepts attributes \
               like `url`, `rev`, `ref`, `submodules`, and `shallow`.",
        parameters: &[(
            "attrs",
            "Attribute set with `url` and optional `rev`, `ref`, `submodules`, `shallow`.",
        )],
        examples: &[
            "builtins.fetchGit {\n  url = \"https://github.com/NixOS/nix\";\n  ref = \"main\";\n}",
        ],
        see_also: &["fetchTarball", "fetchurl"],
    },
    // ------------------------------------------------------------------
    // fetchTarball
    // ------------------------------------------------------------------
    BuiltinDoc {
        name: "fetchTarball",
        type_sig: "attrs -> path",
        summary: "Fetch and unpack a tarball.",
        body: "Downloads a tarball (optionally with hash verification) and \
               unpacks it into the Nix store.  Can take either a URL string \
               or an attribute set with `url`, `sha256`, and `name`.",
        parameters: &[("attrs", "URL string, or set with `url`, `sha256`, `name`.")],
        examples: &[
            r#"builtins.fetchTarball "https://github.com/NixOS/nixpkgs/archive/master.tar.gz""#,
            "builtins.fetchTarball {\n  url = \"https://example.com/src.tar.gz\";\n  sha256 = \"0000000000000000000000000000000000000000000000000000\";\n}",
        ],
        see_also: &["fetchGit", "fetchurl"],
    },
    // ------------------------------------------------------------------
    // fetchurl
    // ------------------------------------------------------------------
    BuiltinDoc {
        name: "fetchurl",
        type_sig: "string | attrs -> path",
        summary: "Download a URL into the Nix store.",
        body: "Fetches the given URL and stores the result as a fixed-output \
               store path.  Unlike `fetchTarball`, it does NOT unpack the file. \
               Can take either a URL string or an attribute set with `url`, \
               `sha256`, and `name`.  Pure evaluation requires `sha256`; \
               restricted evaluation requires network URLs to match an allowed \
               URI prefix.",
        parameters: &[("arg", "URL string, or set with `url`, `sha256`, `name`.")],
        examples: &[
            r#"builtins.fetchurl "https://example.com/data.txt""#,
            "builtins.fetchurl {\n  url = \"https://example.com/data.txt\";\n  sha256 = \"0000000000000000000000000000000000000000000000000000\";\n}",
        ],
        see_also: &["fetchTarball", "fetchGit"],
    },
    // ------------------------------------------------------------------
    // filter
    // ------------------------------------------------------------------
    BuiltinDoc {
        name: "filter",
        type_sig: "(a -> bool) -> [a] -> [a]",
        summary: "Filter a list by a predicate.",
        body: "Returns a new list containing only the elements for which the \
               predicate returns `true`.",
        parameters: &[
            ("pred", "Predicate function."),
            ("list", "The list to filter."),
        ],
        examples: &["builtins.filter (x: x > 2) [ 1 2 3 4 ]  # => [ 3 4 ]"],
        see_also: &["all", "any", "partition"],
    },
    // ------------------------------------------------------------------
    // floor
    // ------------------------------------------------------------------
    BuiltinDoc {
        name: "floor",
        type_sig: "float -> int",
        summary: "Round a float down to the nearest integer.",
        body: "Returns the largest integer less than or equal to the argument.",
        parameters: &[("x", "A floating-point number.")],
        examples: &[
            "builtins.floor 1.8  # => 1",
            "builtins.floor (-1.2)  # => -2",
        ],
        see_also: &["ceil"],
    },
    // ------------------------------------------------------------------
    // foldl'
    // ------------------------------------------------------------------
    BuiltinDoc {
        name: "foldl'",
        type_sig: "(b -> a -> b) -> b -> [a] -> b",
        summary: "Strict left fold over a list.",
        body: "Reduces a list from the left using the given function and initial \
               accumulator.  The accumulator is evaluated strictly at each step, \
               preventing space leaks on large lists.",
        parameters: &[
            (
                "f",
                "Combining function `(accumulator -> element -> accumulator)`.",
            ),
            ("init", "Initial accumulator value."),
            ("list", "The list to fold."),
        ],
        examples: &["builtins.foldl' (a: b: a + b) 0 [ 1 2 3 ]  # => 6"],
        see_also: &["map", "filter"],
    },
    // ------------------------------------------------------------------
    // fromJSON
    // ------------------------------------------------------------------
    BuiltinDoc {
        name: "fromJSON",
        type_sig: "string -> a",
        summary: "Parse a JSON string into a Nix value.",
        body: "Converts a JSON string to the corresponding Nix value.  JSON \
               objects become attribute sets, arrays become lists, etc.",
        parameters: &[("json", "A valid JSON string.")],
        examples: &[
            r#"builtins.fromJSON "{\"a\": 1}"  # => { a = 1; }"#,
            r#"builtins.fromJSON "[1, 2, 3]"   # => [ 1 2 3 ]"#,
        ],
        see_also: &["toJSON", "fromTOML"],
    },
    // ------------------------------------------------------------------
    // fromTOML
    // ------------------------------------------------------------------
    BuiltinDoc {
        name: "fromTOML",
        type_sig: "string -> a",
        summary: "Parse a TOML string into a Nix value.",
        body: "Converts a TOML document (as a string) into the corresponding \
               Nix attribute set.",
        parameters: &[("toml", "A valid TOML string.")],
        examples: &[
            r#"builtins.fromTOML "[section]\nkey = \"value\""  # => { section.key = "value"; }"#,
        ],
        see_also: &["fromJSON"],
    },
    // ------------------------------------------------------------------
    // functionArgs
    // ------------------------------------------------------------------
    BuiltinDoc {
        name: "functionArgs",
        type_sig: "function -> attrs",
        summary: "Get the named arguments of a function.",
        body: "Returns an attribute set mapping argument names to booleans \
               indicating whether they have default values.  Only works on \
               functions with a pattern argument (`{ ... }:`).",
        parameters: &[("f", "A function with a pattern argument.")],
        examples: &["builtins.functionArgs ({ a, b ? 1 }: a)  # => { a = false; b = true; }"],
        see_also: &[],
    },
    // ------------------------------------------------------------------
    // genList
    // ------------------------------------------------------------------
    BuiltinDoc {
        name: "genList",
        type_sig: "(int -> a) -> int -> [a]",
        summary: "Generate a list by applying a function to indices.",
        body: "Calls `f` with each integer from 0 to `n - 1` and collects \
               the results into a list.",
        parameters: &[
            ("f", "Function from index to element."),
            ("n", "Number of elements to generate."),
        ],
        examples: &["builtins.genList (i: i * 2) 4  # => [ 0 2 4 6 ]"],
        see_also: &["map"],
    },
    // ------------------------------------------------------------------
    // genericClosure
    // ------------------------------------------------------------------
    BuiltinDoc {
        name: "genericClosure",
        type_sig: "attrs -> [attrs]",
        summary: "Compute a transitive closure.",
        body: "Starting from an initial set of items (each with a `key`), \
               repeatedly applies an `operator` function to discover new items \
               until no new keys appear.  Used for dependency graph traversal.",
        parameters: &[(
            "attrs",
            "Set with `startSet` (list of `{key, ...}`) and `operator` (item -> list of `{key, ...}`).",
        )],
        examples: &[
            "builtins.genericClosure {\n  startSet = [ { key = 1; } ];\n  operator = item: if item.key < 3 then [ { key = item.key + 1; } ] else [];\n}  # => [ { key = 1; } { key = 2; } { key = 3; } ]",
        ],
        see_also: &[],
    },
    // ------------------------------------------------------------------
    // getAttr
    // ------------------------------------------------------------------
    BuiltinDoc {
        name: "getAttr",
        type_sig: "string -> attrs -> a",
        summary: "Get an attribute value by name.",
        body: "Returns the value of the named attribute.  Throws an error if \
               the attribute does not exist.  The string argument makes this \
               useful when the name is computed dynamically.",
        parameters: &[("name", "Attribute name."), ("set", "An attribute set.")],
        examples: &[r#"builtins.getAttr "x" { x = 42; }  # => 42"#],
        see_also: &["hasAttr", "attrNames"],
    },
    // ------------------------------------------------------------------
    // getEnv
    // ------------------------------------------------------------------
    BuiltinDoc {
        name: "getEnv",
        type_sig: "string -> string",
        summary: "Get an environment variable.",
        body: "Returns the value of the named environment variable, or the \
               empty string if it is not set.  Only available in impure \
               evaluation mode.",
        parameters: &[("var", "Name of the environment variable.")],
        examples: &[r#"builtins.getEnv "HOME"  # => "/home/user""#],
        see_also: &[],
    },
    // ------------------------------------------------------------------
    // groupBy
    // ------------------------------------------------------------------
    BuiltinDoc {
        name: "groupBy",
        type_sig: "(a -> string) -> [a] -> attrs",
        summary: "Group list elements by a key function.",
        body: "Applies the key function to each element and returns an \
               attribute set mapping each key to a list of elements that \
               produced that key.",
        parameters: &[
            ("f", "Function returning a string key for each element."),
            ("list", "The list to group."),
        ],
        examples: &[
            r#"builtins.groupBy (x: if x > 2 then "big" else "small") [ 1 2 3 4 ]
# => { big = [ 3 4 ]; small = [ 1 2 ]; }"#,
        ],
        see_also: &["partition"],
    },
    // ------------------------------------------------------------------
    // hasAttr
    // ------------------------------------------------------------------
    BuiltinDoc {
        name: "hasAttr",
        type_sig: "string -> attrs -> bool",
        summary: "Test whether an attribute set contains a given key.",
        body: "Returns `true` if the attribute set has an attribute with the \
               given name.  Equivalent to using the `?` operator.",
        parameters: &[
            ("name", "Attribute name to test."),
            ("set", "An attribute set."),
        ],
        examples: &[
            r#"builtins.hasAttr "x" { x = 1; }  # => true"#,
            r#"builtins.hasAttr "y" { x = 1; }  # => false"#,
        ],
        see_also: &["getAttr", "attrNames"],
    },
    // ------------------------------------------------------------------
    // hashFile
    // ------------------------------------------------------------------
    BuiltinDoc {
        name: "hashFile",
        type_sig: "string -> path -> string",
        summary: "Compute the hash of a file.",
        body: "Hashes the contents of the file at the given path using the \
               specified algorithm (`\"md5\"`, `\"sha1\"`, `\"sha256\"`, or \
               `\"sha512\"`).",
        parameters: &[
            ("algo", "Hash algorithm name."),
            ("path", "Path to the file."),
        ],
        examples: &[r#"builtins.hashFile "sha256" ./file.txt"#],
        see_also: &["hashString"],
    },
    // ------------------------------------------------------------------
    // hashString
    // ------------------------------------------------------------------
    BuiltinDoc {
        name: "hashString",
        type_sig: "string -> string -> string",
        summary: "Compute the hash of a string.",
        body: "Hashes the given string using the specified algorithm.",
        parameters: &[
            (
                "algo",
                "Hash algorithm (`\"md5\"`, `\"sha1\"`, `\"sha256\"`, `\"sha512\"`).",
            ),
            ("str", "The string to hash."),
        ],
        examples: &[r#"builtins.hashString "sha256" "hello""#],
        see_also: &["hashFile"],
    },
    // ------------------------------------------------------------------
    // head
    // ------------------------------------------------------------------
    BuiltinDoc {
        name: "head",
        type_sig: "[a] -> a",
        summary: "Return the first element of a list.",
        body: "Returns the first element.  Throws an error on an empty list.",
        parameters: &[("list", "A non-empty list.")],
        examples: &["builtins.head [ 1 2 3 ]  # => 1"],
        see_also: &["tail", "elemAt"],
    },
    // ------------------------------------------------------------------
    // import
    // ------------------------------------------------------------------
    BuiltinDoc {
        name: "import",
        type_sig: "path -> a",
        summary: "Import and evaluate a Nix file.",
        body: "Reads and evaluates the Nix expression in the file at the given \
               path.  If the file evaluates to a function, it is NOT \
               automatically called — you typically do `import ./file.nix { ... }` \
               to call it with arguments.",
        parameters: &[("path", "Path to a `.nix` file.")],
        examples: &["import ./lib.nix", "import ./module.nix { inherit pkgs; }"],
        see_also: &[],
    },
    // ------------------------------------------------------------------
    // intersectAttrs
    // ------------------------------------------------------------------
    BuiltinDoc {
        name: "intersectAttrs",
        type_sig: "attrs -> attrs -> attrs",
        summary: "Compute the intersection of two attribute sets.",
        body: "Returns an attribute set containing only the attributes whose \
               names appear in both sets.  The values come from the SECOND set.",
        parameters: &[
            ("a", "First attribute set (determines which keys to keep)."),
            ("b", "Second attribute set (provides the values)."),
        ],
        examples: &[
            "builtins.intersectAttrs { a = 1; b = 2; } { a = 10; c = 30; }  # => { a = 10; }",
        ],
        see_also: &["removeAttrs"],
    },
    // ------------------------------------------------------------------
    // isAttrs
    // ------------------------------------------------------------------
    BuiltinDoc {
        name: "isAttrs",
        type_sig: "a -> bool",
        summary: "Test whether a value is an attribute set.",
        body: "Returns `true` if the argument is an attribute set.",
        parameters: &[("x", "Any Nix value.")],
        examples: &[
            "builtins.isAttrs { a = 1; }  # => true",
            "builtins.isAttrs [ 1 ]       # => false",
        ],
        see_also: &[
            "isBool",
            "isFloat",
            "isFunction",
            "isInt",
            "isList",
            "isNull",
            "isPath",
            "isString",
            "typeOf",
        ],
    },
    // ------------------------------------------------------------------
    // isBool
    // ------------------------------------------------------------------
    BuiltinDoc {
        name: "isBool",
        type_sig: "a -> bool",
        summary: "Test whether a value is a boolean.",
        body: "Returns `true` if the argument is `true` or `false`.",
        parameters: &[("x", "Any Nix value.")],
        examples: &[
            "builtins.isBool true   # => true",
            "builtins.isBool 1      # => false",
        ],
        see_also: &["isAttrs", "typeOf"],
    },
    // ------------------------------------------------------------------
    // isFloat
    // ------------------------------------------------------------------
    BuiltinDoc {
        name: "isFloat",
        type_sig: "a -> bool",
        summary: "Test whether a value is a floating-point number.",
        body: "Returns `true` if the argument is a float.",
        parameters: &[("x", "Any Nix value.")],
        examples: &[
            "builtins.isFloat 1.0  # => true",
            "builtins.isFloat 1    # => false",
        ],
        see_also: &["isInt", "typeOf"],
    },
    // ------------------------------------------------------------------
    // isFunction
    // ------------------------------------------------------------------
    BuiltinDoc {
        name: "isFunction",
        type_sig: "a -> bool",
        summary: "Test whether a value is a function.",
        body: "Returns `true` if the argument is a function (lambda or primop).",
        parameters: &[("x", "Any Nix value.")],
        examples: &[
            "builtins.isFunction (x: x)  # => true",
            "builtins.isFunction 42       # => false",
        ],
        see_also: &["functionArgs", "typeOf"],
    },
    // ------------------------------------------------------------------
    // isInt
    // ------------------------------------------------------------------
    BuiltinDoc {
        name: "isInt",
        type_sig: "a -> bool",
        summary: "Test whether a value is an integer.",
        body: "Returns `true` if the argument is an integer.",
        parameters: &[("x", "Any Nix value.")],
        examples: &[
            "builtins.isInt 42    # => true",
            "builtins.isInt 1.0   # => false",
        ],
        see_also: &["isFloat", "typeOf"],
    },
    // ------------------------------------------------------------------
    // isList
    // ------------------------------------------------------------------
    BuiltinDoc {
        name: "isList",
        type_sig: "a -> bool",
        summary: "Test whether a value is a list.",
        body: "Returns `true` if the argument is a list.",
        parameters: &[("x", "Any Nix value.")],
        examples: &[
            "builtins.isList [ 1 2 ]  # => true",
            "builtins.isList { }      # => false",
        ],
        see_also: &["isAttrs", "typeOf"],
    },
    // ------------------------------------------------------------------
    // isNull
    // ------------------------------------------------------------------
    BuiltinDoc {
        name: "isNull",
        type_sig: "a -> bool",
        summary: "Test whether a value is null.",
        body: "Returns `true` if the argument is `null`.",
        parameters: &[("x", "Any Nix value.")],
        examples: &[
            "builtins.isNull null  # => true",
            "builtins.isNull 0     # => false",
        ],
        see_also: &["typeOf"],
    },
    // ------------------------------------------------------------------
    // isPath
    // ------------------------------------------------------------------
    BuiltinDoc {
        name: "isPath",
        type_sig: "a -> bool",
        summary: "Test whether a value is a path.",
        body: "Returns `true` if the argument is a path value.",
        parameters: &[("x", "Any Nix value.")],
        examples: &[
            "builtins.isPath ./foo  # => true",
            r#"builtins.isPath "/foo"  # => false  (it's a string)"#,
        ],
        see_also: &["typeOf"],
    },
    // ------------------------------------------------------------------
    // isString
    // ------------------------------------------------------------------
    BuiltinDoc {
        name: "isString",
        type_sig: "a -> bool",
        summary: "Test whether a value is a string.",
        body: "Returns `true` if the argument is a string.",
        parameters: &[("x", "Any Nix value.")],
        examples: &[
            r#"builtins.isString "hi"  # => true"#,
            "builtins.isString 42      # => false",
        ],
        see_also: &["typeOf"],
    },
    // ------------------------------------------------------------------
    // langVersion
    // ------------------------------------------------------------------
    BuiltinDoc {
        name: "langVersion",
        type_sig: "int",
        summary: "The Nix language version.",
        body: "An integer representing the version of the Nix language \
               supported by the current evaluator.",
        parameters: &[],
        examples: &["builtins.langVersion  # => 6"],
        see_also: &["nixVersion"],
    },
    // ------------------------------------------------------------------
    // length
    // ------------------------------------------------------------------
    BuiltinDoc {
        name: "length",
        type_sig: "[a] -> int",
        summary: "Return the length of a list.",
        body: "Returns the number of elements in the list.",
        parameters: &[("list", "A list.")],
        examples: &[
            "builtins.length [ 1 2 3 ]  # => 3",
            "builtins.length []          # => 0",
        ],
        see_also: &["elemAt", "head", "tail"],
    },
    // ------------------------------------------------------------------
    // lessThan
    // ------------------------------------------------------------------
    BuiltinDoc {
        name: "lessThan",
        type_sig: "number -> number -> bool",
        summary: "Test whether the first number is less than the second.",
        body: "Returns `true` if `a < b`.  Works on both integers and floats.",
        parameters: &[("a", "First number."), ("b", "Second number.")],
        examples: &[
            "builtins.lessThan 1 2  # => true",
            "builtins.lessThan 2 1  # => false",
        ],
        see_also: &[],
    },
    // ------------------------------------------------------------------
    // listToAttrs
    // ------------------------------------------------------------------
    BuiltinDoc {
        name: "listToAttrs",
        type_sig: "[{name, value}] -> attrs",
        summary: "Convert a list of name-value pairs to an attribute set.",
        body: "Each element must be an attribute set with `name` (string) and \
               `value` attributes.  If duplicate names exist, the first one wins.",
        parameters: &[("list", "List of `{ name = ...; value = ...; }` pairs.")],
        examples: &[
            r#"builtins.listToAttrs [ { name = "x"; value = 1; } { name = "y"; value = 2; } ]
# => { x = 1; y = 2; }"#,
        ],
        see_also: &["attrNames", "attrValues"],
    },
    // ------------------------------------------------------------------
    // map
    // ------------------------------------------------------------------
    BuiltinDoc {
        name: "map",
        type_sig: "(a -> b) -> [a] -> [b]",
        summary: "Apply a function to every element of a list.",
        body: "Returns a new list where each element is the result of applying \
               the function to the corresponding element of the input list.",
        parameters: &[("f", "Function to apply."), ("list", "The input list.")],
        examples: &[
            "builtins.map (x: x * 2) [ 1 2 3 ]  # => [ 2 4 6 ]",
            r#"builtins.map toString [ 1 2 ]        # => [ "1" "2" ]"#,
        ],
        see_also: &["concatMap", "mapAttrs", "filter"],
    },
    // ------------------------------------------------------------------
    // mapAttrs
    // ------------------------------------------------------------------
    BuiltinDoc {
        name: "mapAttrs",
        type_sig: "(string -> a -> b) -> attrs -> attrs",
        summary: "Apply a function to every value in an attribute set.",
        body: "Returns a new attribute set with the same keys but where each \
               value has been transformed by the function.  The function receives \
               both the attribute name and its current value.",
        parameters: &[
            ("f", "Function `(name -> value -> newValue)`."),
            ("set", "An attribute set."),
        ],
        examples: &[
            "builtins.mapAttrs (name: value: value * 2) { a = 1; b = 2; }\n# => { a = 2; b = 4; }",
        ],
        see_also: &["map", "catAttrs"],
    },
    // ------------------------------------------------------------------
    // match
    // ------------------------------------------------------------------
    BuiltinDoc {
        name: "match",
        type_sig: "string -> string -> [string] | null",
        summary: "Match a string against a POSIX extended regular expression.",
        body: "If the regex matches the ENTIRE string, returns a list of \
               captured groups (or an empty list if there are no groups).  \
               Returns `null` on no match.  The regex is implicitly anchored \
               at both ends.",
        parameters: &[
            ("regex", "POSIX extended regular expression."),
            ("str", "String to match against."),
        ],
        examples: &[
            r#"builtins.match "([a-z]+)-([0-9]+)" "hello-42"  # => [ "hello" "42" ]"#,
            r#"builtins.match "([a-z]+)" "HELLO"               # => null"#,
        ],
        see_also: &["split", "replaceStrings"],
    },
    // ------------------------------------------------------------------
    // mul
    // ------------------------------------------------------------------
    BuiltinDoc {
        name: "mul",
        type_sig: "number -> number -> number",
        summary: "Multiply two numbers.",
        body: "Returns the product of two numbers.  Float if either is float.",
        parameters: &[("a", "First operand."), ("b", "Second operand.")],
        examples: &["builtins.mul 3 4  # => 12"],
        see_also: &["add", "sub", "div"],
    },
    // ------------------------------------------------------------------
    // nixPath
    // ------------------------------------------------------------------
    BuiltinDoc {
        name: "nixPath",
        type_sig: "[{ path, prefix }]",
        summary: "The current Nix search path.",
        body: "A list of attribute sets describing the entries in the Nix \
               search path (NIX_PATH / -I).  Each entry has `path` and \
               `prefix` attributes.",
        parameters: &[],
        examples: &[
            "builtins.nixPath  # => [ { path = \"/nix/var/...\"; prefix = \"nixpkgs\"; } ... ]",
        ],
        see_also: &[],
    },
    // ------------------------------------------------------------------
    // nixVersion
    // ------------------------------------------------------------------
    BuiltinDoc {
        name: "nixVersion",
        type_sig: "string",
        summary: "The version string of the Nix evaluator.",
        body: "A string like `\"2.18.1\"` identifying the running Nix version.",
        parameters: &[],
        examples: &[r#"builtins.nixVersion  # => "2.18.1""#],
        see_also: &["langVersion"],
    },
    // ------------------------------------------------------------------
    // null
    // ------------------------------------------------------------------
    BuiltinDoc {
        name: "null",
        type_sig: "null",
        summary: "The null value.",
        body: "The singleton null value in Nix.  `builtins.null` is identical \
               to the literal `null`.",
        parameters: &[],
        examples: &["builtins.null == null  # => true"],
        see_also: &["isNull"],
    },
    // ------------------------------------------------------------------
    // parseDrvName
    // ------------------------------------------------------------------
    BuiltinDoc {
        name: "parseDrvName",
        type_sig: "string -> { name, version }",
        summary: "Split a derivation name into name and version parts.",
        body: "Splits at the first dash followed by a digit.",
        parameters: &[("drvName", "A derivation name string.")],
        examples: &[
            r#"builtins.parseDrvName "hello-2.10"  # => { name = "hello"; version = "2.10"; }"#,
        ],
        see_also: &["compareVersions", "splitVersion"],
    },
    // ------------------------------------------------------------------
    // partition
    // ------------------------------------------------------------------
    BuiltinDoc {
        name: "partition",
        type_sig: "(a -> bool) -> [a] -> { right, wrong }",
        summary: "Partition a list into elements that match and those that don't.",
        body: "Returns an attribute set with `right` (elements where the \
               predicate is `true`) and `wrong` (elements where it is `false`).",
        parameters: &[
            ("pred", "Predicate function."),
            ("list", "The list to partition."),
        ],
        examples: &[
            "builtins.partition (x: x > 2) [ 1 2 3 4 ]\n# => { right = [ 3 4 ]; wrong = [ 1 2 ]; }",
        ],
        see_also: &["filter", "groupBy"],
    },
    // ------------------------------------------------------------------
    // path
    // ------------------------------------------------------------------
    BuiltinDoc {
        name: "path",
        type_sig: "attrs -> path",
        summary: "Add a path to the store with optional filtering.",
        body: "Copies a local path to the Nix store, optionally applying a \
               filter function and/or name override.  Useful for controlling \
               which files are included in the store path.",
        parameters: &[(
            "attrs",
            "Attribute set with `path`, optional `name`, `filter`, `recursive`, `sha256`.",
        )],
        examples: &[
            "builtins.path {\n  path = ./src;\n  name = \"source\";\n  filter = path: type: type != \"directory\" || baseNameOf path != \".git\";\n}",
        ],
        see_also: &["filterSource"],
    },
    // ------------------------------------------------------------------
    // pathExists
    // ------------------------------------------------------------------
    BuiltinDoc {
        name: "pathExists",
        type_sig: "path -> bool",
        summary: "Test whether a path exists.",
        body: "Returns `true` if the given path exists on disk.  Only usable \
               in impure evaluation mode or with known store paths.",
        parameters: &[("path", "The path to check.")],
        examples: &["builtins.pathExists /etc/passwd  # => true"],
        see_also: &["readDir", "readFile"],
    },
    // ------------------------------------------------------------------
    // placeholder
    // ------------------------------------------------------------------
    BuiltinDoc {
        name: "placeholder",
        type_sig: "string -> string",
        summary: "Return the placeholder string for a derivation output.",
        body: "Returns the placeholder hash string for the named output.  Used \
               in fixed-output derivations and spliced string contexts.  The \
               placeholder is replaced with the actual store path during \
               realisation.",
        parameters: &[("output", "Output name, typically `\"out\"`.")],
        examples: &[r#"builtins.placeholder "out""#],
        see_also: &["derivation"],
    },
    // ------------------------------------------------------------------
    // readDir
    // ------------------------------------------------------------------
    BuiltinDoc {
        name: "readDir",
        type_sig: "path -> attrs",
        summary: "List the contents of a directory.",
        body: "Returns an attribute set mapping entry names to their types \
               (`\"regular\"`, `\"directory\"`, `\"symlink\"`, or `\"unknown\"`).",
        parameters: &[("path", "Path to a directory.")],
        examples: &[
            "builtins.readDir /etc  # => { hostname = \"regular\"; hosts = \"regular\"; ... }",
        ],
        see_also: &["readFile", "pathExists"],
    },
    // ------------------------------------------------------------------
    // readFile
    // ------------------------------------------------------------------
    BuiltinDoc {
        name: "readFile",
        type_sig: "path -> string",
        summary: "Read the contents of a file as a string.",
        body: "Returns the entire contents of the file at the given path as a \
               Nix string.  The file must be valid UTF-8.",
        parameters: &[("path", "Path to a file.")],
        examples: &["builtins.readFile ./version.txt"],
        see_also: &["readDir", "toFile"],
    },
    // ------------------------------------------------------------------
    // removeAttrs
    // ------------------------------------------------------------------
    BuiltinDoc {
        name: "removeAttrs",
        type_sig: "attrs -> [string] -> attrs",
        summary: "Remove named attributes from an attribute set.",
        body: "Returns a copy of the attribute set with the listed attributes \
               removed.  Attributes in the list that don't exist are ignored.",
        parameters: &[
            ("set", "An attribute set."),
            ("names", "List of attribute names to remove."),
        ],
        examples: &[
            r#"builtins.removeAttrs { a = 1; b = 2; c = 3; } [ "a" "c" ]  # => { b = 2; }"#,
        ],
        see_also: &["intersectAttrs"],
    },
    // ------------------------------------------------------------------
    // replaceStrings
    // ------------------------------------------------------------------
    BuiltinDoc {
        name: "replaceStrings",
        type_sig: "[string] -> [string] -> string -> string",
        summary: "Perform simultaneous string replacements.",
        body: "Replaces every occurrence of each pattern in `from` with the \
               corresponding string in `to`.  Replacements happen left-to-right, \
               and the first matching pattern wins at each position.",
        parameters: &[
            ("from", "List of patterns to search for."),
            ("to", "List of replacement strings (same length as `from`)."),
            ("str", "The input string."),
        ],
        examples: &[
            r#"builtins.replaceStrings [ "o" "l" ] [ "0" "L" ] "hello world"
# => "heLL0 w0rLd""#,
        ],
        see_also: &["concatStringsSep", "match"],
    },
    // ------------------------------------------------------------------
    // seq
    // ------------------------------------------------------------------
    BuiltinDoc {
        name: "seq",
        type_sig: "a -> b -> b",
        summary: "Evaluate the first argument shallowly, then return the second.",
        body: "Forces evaluation of the first argument to weak head normal form \
               (top-level value, but not nested structures), then returns the \
               second argument.  For deep evaluation, use `deepSeq`.",
        parameters: &[("a", "Value to evaluate."), ("b", "Value to return.")],
        examples: &["builtins.seq 1 \"ok\"  # => \"ok\""],
        see_also: &["deepSeq"],
    },
    // ------------------------------------------------------------------
    // sort
    // ------------------------------------------------------------------
    BuiltinDoc {
        name: "sort",
        type_sig: "(a -> a -> bool) -> [a] -> [a]",
        summary: "Sort a list using a comparison function.",
        body: "Returns a sorted copy of the list.  The comparison function \
               should return `true` if the first argument should come before \
               the second.  The sort is stable.",
        parameters: &[
            ("cmp", "Comparison function returning `true` if `a < b`."),
            ("list", "The list to sort."),
        ],
        examples: &[
            "builtins.sort builtins.lessThan [ 3 1 2 ]  # => [ 1 2 3 ]",
            "builtins.sort (a: b: a > b) [ 3 1 2 ]      # => [ 3 2 1 ]",
        ],
        see_also: &["lessThan"],
    },
    // ------------------------------------------------------------------
    // split
    // ------------------------------------------------------------------
    BuiltinDoc {
        name: "split",
        type_sig: "string -> string -> [string]",
        summary: "Split a string by a regular expression.",
        body: "Splits the string at each match of the regex.  The result \
               alternates between non-matched segments (strings) and lists of \
               captured groups from the matched segments.",
        parameters: &[
            ("regex", "POSIX extended regular expression."),
            ("str", "String to split."),
        ],
        examples: &[r#"builtins.split ":" "a:b:c"  # => [ "a" [] "b" [] "c" ]"#],
        see_also: &["match"],
    },
    // ------------------------------------------------------------------
    // splitVersion
    // ------------------------------------------------------------------
    BuiltinDoc {
        name: "splitVersion",
        type_sig: "string -> [string]",
        summary: "Split a version string into components.",
        body: "Splits at boundaries between digits and non-digits.",
        parameters: &[("version", "A version string.")],
        examples: &[r#"builtins.splitVersion "1.2.3"  # => [ "1" "." "2" "." "3" ]"#],
        see_also: &["compareVersions", "parseDrvName"],
    },
    // ------------------------------------------------------------------
    // storeDir
    // ------------------------------------------------------------------
    BuiltinDoc {
        name: "storeDir",
        type_sig: "string",
        summary: "The path of the Nix store directory.",
        body: "Typically `\"/nix/store\"`.  Useful for programmatically \
               constructing store paths.",
        parameters: &[],
        examples: &[r#"builtins.storeDir  # => "/nix/store""#],
        see_also: &[],
    },
    // ------------------------------------------------------------------
    // storePath
    // ------------------------------------------------------------------
    BuiltinDoc {
        name: "storePath",
        type_sig: "string -> path",
        summary: "Convert a store path string to a path with context.",
        body: "Marks a string as a store path, adding appropriate string context \
               so that it is tracked as a dependency.  Only works in impure mode.",
        parameters: &[("path", "A Nix store path string.")],
        examples: &[r#"builtins.storePath "/nix/store/abc...-hello""#],
        see_also: &["storeDir"],
    },
    // ------------------------------------------------------------------
    // stringLength
    // ------------------------------------------------------------------
    BuiltinDoc {
        name: "stringLength",
        type_sig: "string -> int",
        summary: "Return the length of a string in bytes.",
        body: "Returns the number of bytes in the string.  Note that this is \
               byte length, not character count, for multi-byte UTF-8 strings.",
        parameters: &[("str", "A string.")],
        examples: &[
            r#"builtins.stringLength "hello"  # => 5"#,
            "builtins.stringLength \"\"        # => 0",
        ],
        see_also: &["substring"],
    },
    // ------------------------------------------------------------------
    // sub
    // ------------------------------------------------------------------
    BuiltinDoc {
        name: "sub",
        type_sig: "number -> number -> number",
        summary: "Subtract two numbers.",
        body: "Returns `a - b`.  Float if either operand is a float.",
        parameters: &[("a", "First operand."), ("b", "Second operand.")],
        examples: &["builtins.sub 10 3  # => 7"],
        see_also: &["add", "mul", "div"],
    },
    // ------------------------------------------------------------------
    // substring
    // ------------------------------------------------------------------
    BuiltinDoc {
        name: "substring",
        type_sig: "int -> int -> string -> string",
        summary: "Extract a substring.",
        body: "Returns a substring starting at the given byte offset with the \
               given length.  If the length extends past the end, returns \
               everything from the offset to the end.",
        parameters: &[
            ("start", "Start byte offset (0-based)."),
            ("len", "Maximum number of bytes to extract."),
            ("str", "The source string."),
        ],
        examples: &[r#"builtins.substring 0 5 "hello world"  # => "hello""#],
        see_also: &["stringLength", "replaceStrings"],
    },
    // ------------------------------------------------------------------
    // tail
    // ------------------------------------------------------------------
    BuiltinDoc {
        name: "tail",
        type_sig: "[a] -> [a]",
        summary: "Return all elements except the first.",
        body: "Returns the list with its first element removed.  Throws an error \
               on an empty list.",
        parameters: &[("list", "A non-empty list.")],
        examples: &["builtins.tail [ 1 2 3 ]  # => [ 2 3 ]"],
        see_also: &["head", "elemAt"],
    },
    // ------------------------------------------------------------------
    // throw
    // ------------------------------------------------------------------
    BuiltinDoc {
        name: "throw",
        type_sig: "string -> a",
        summary: "Throw an error that can be caught by tryEval.",
        body: "Like `abort`, but the error can be caught by `tryEval`.  Use \
               `throw` for recoverable errors and `abort` for fatal ones.",
        parameters: &[("msg", "The error message.")],
        examples: &[
            r#"builtins.throw "something is wrong""#,
            r#"builtins.tryEval (builtins.throw "x")  # => { success = false; value = false; }"#,
        ],
        see_also: &["abort", "tryEval"],
    },
    // ------------------------------------------------------------------
    // toFile
    // ------------------------------------------------------------------
    BuiltinDoc {
        name: "toFile",
        type_sig: "string -> string -> path",
        summary: "Write a string to a file in the Nix store.",
        body: "Creates a file in the Nix store with the given name and contents. \
               The file contents must not reference any store paths indirectly \
               (through string context) — for that, use a derivation.",
        parameters: &[
            ("name", "Filename for the store path."),
            ("contents", "The file contents."),
        ],
        examples: &[r#"builtins.toFile "hello.txt" "Hello, world!""#],
        see_also: &["readFile"],
    },
    // ------------------------------------------------------------------
    // toJSON
    // ------------------------------------------------------------------
    BuiltinDoc {
        name: "toJSON",
        type_sig: "a -> string",
        summary: "Serialize a Nix value to a JSON string.",
        body: "Converts attribute sets, lists, strings, integers, floats, \
               booleans, and null to their JSON representation.  Derivations \
               are serialized by their store path.",
        parameters: &[("value", "The Nix value to serialize.")],
        examples: &[r#"builtins.toJSON { a = 1; b = [ 2 3 ]; }  # => "{\"a\":1,\"b\":[2,3]}""#],
        see_also: &["fromJSON"],
    },
    // ------------------------------------------------------------------
    // toString
    // ------------------------------------------------------------------
    BuiltinDoc {
        name: "toString",
        type_sig: "a -> string",
        summary: "Convert a value to a string.",
        body: "Converts various Nix types to strings: paths become store paths, \
               integers and floats become decimal strings, booleans become `\"1\"` \
               or `\"\"`, null becomes `\"\"`, lists have elements converted and \
               space-separated, and derivations yield their store path.",
        parameters: &[("value", "The value to convert.")],
        examples: &[
            r#"builtins.toString 42       # => "42""#,
            r#"builtins.toString [ 1 2 ]  # => "1 2""#,
        ],
        see_also: &["toJSON"],
    },
    // ------------------------------------------------------------------
    // toXML
    // ------------------------------------------------------------------
    BuiltinDoc {
        name: "toXML",
        type_sig: "a -> string",
        summary: "Serialize a Nix value to an XML string.",
        body: "Produces an XML representation of the Nix expression.  Primarily \
               used internally by Nix for build-time data passing.",
        parameters: &[("value", "The Nix value to serialize.")],
        examples: &["builtins.toXML { a = 1; }"],
        see_also: &["toJSON"],
    },
    // ------------------------------------------------------------------
    // trace
    // ------------------------------------------------------------------
    BuiltinDoc {
        name: "trace",
        type_sig: "a -> b -> b",
        summary: "Print a trace message and return the second argument.",
        body: "Prints the first argument to stderr (for debugging) and returns \
               the second argument unchanged.  The traced value is printed \
               using `toString`.",
        parameters: &[
            ("msg", "Value to print (for debugging)."),
            ("value", "Value to return."),
        ],
        examples: &[r#"builtins.trace "debug info" 42  # prints "trace: debug info", returns 42"#],
        see_also: &["traceVerbose"],
    },
    // ------------------------------------------------------------------
    // traceVerbose
    // ------------------------------------------------------------------
    BuiltinDoc {
        name: "traceVerbose",
        type_sig: "a -> b -> b",
        summary: "Conditionally print a verbose trace message.",
        body: "Like `trace`, but only prints when the `--trace-verbose` flag \
               is enabled.  Useful for detailed debugging that would be too \
               noisy in normal operation.",
        parameters: &[
            ("msg", "Value to print if verbose tracing is on."),
            ("value", "Value to return."),
        ],
        examples: &[r#"builtins.traceVerbose "details" result"#],
        see_also: &["trace"],
    },
    // ------------------------------------------------------------------
    // tryEval
    // ------------------------------------------------------------------
    BuiltinDoc {
        name: "tryEval",
        type_sig: "a -> { success, value }",
        summary: "Try to evaluate a value, catching errors from throw.",
        body: "Attempts to evaluate the argument.  If evaluation succeeds, \
               returns `{ success = true; value = <result>; }`.  If the \
               expression calls `throw`, returns \
               `{ success = false; value = false; }`.  Does NOT catch `abort` \
               or assertion failures.",
        parameters: &[("expr", "Expression to evaluate.")],
        examples: &[
            "builtins.tryEval 42                      # => { success = true; value = 42; }",
            "builtins.tryEval (builtins.throw \"x\")  # => { success = false; value = false; }",
        ],
        see_also: &["throw", "abort"],
    },
    // ------------------------------------------------------------------
    // typeOf
    // ------------------------------------------------------------------
    BuiltinDoc {
        name: "typeOf",
        type_sig: "a -> string",
        summary: "Return the type name of a value.",
        body: "Returns one of: `\"int\"`, `\"float\"`, `\"bool\"`, `\"string\"`, \
               `\"path\"`, `\"null\"`, `\"set\"`, `\"list\"`, `\"lambda\"`.",
        parameters: &[("value", "Any Nix value.")],
        examples: &[
            r#"builtins.typeOf 42        # => "int""#,
            r#"builtins.typeOf "hello"   # => "string""#,
            r#"builtins.typeOf { }       # => "set""#,
        ],
        see_also: &[
            "isAttrs",
            "isBool",
            "isFloat",
            "isFunction",
            "isInt",
            "isList",
            "isNull",
            "isPath",
            "isString",
        ],
    },
    // ------------------------------------------------------------------
    // zipAttrsWith
    // ------------------------------------------------------------------
    BuiltinDoc {
        name: "zipAttrsWith",
        type_sig: "(string -> [a] -> b) -> [attrs] -> attrs",
        summary: "Merge attribute sets using a combining function.",
        body: "For each unique attribute name across all input sets, collects \
               all values with that name into a list and applies the combining \
               function.  The function receives the attribute name and the list \
               of values.",
        parameters: &[
            ("f", "Combining function `(name -> values -> result)`."),
            ("list", "List of attribute sets to merge."),
        ],
        examples: &[
            "builtins.zipAttrsWith (name: vals: vals) [ { a = 1; } { a = 2; b = 3; } ]\n# => { a = [ 1 2 ]; b = [ 3 ]; }",
        ],
        see_also: &["intersectAttrs", "mapAttrs"],
    },
];
