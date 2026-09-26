// Copyright 2016 Mozilla Foundation
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Adapted from sccache 8396f0209d74d496b7cb27cdf323cd3ff8d4a291.

use super::args::*;
use super::{ColorMode, CompilerArguments};
use crate::util::OsStrExt;
use std::{collections::HashSet, ffi::OsString, fmt, fs::{self,File}, io::{Read, BufReader}, path::{Path,PathBuf}, sync::LazyLock};

#[derive(Debug,PartialEq)]
pub struct ParsedArguments {
    /// The full commandline, with all parsed arguments
    arguments: Vec<Argument<ArgData>>,
    /// The location of compiler outputs.
    pub output_dir: PathBuf,
    /// Paths to extern crates used in the compile.
    pub externs: Vec<PathBuf>,
    /// The directories searched for rlibs
    pub crate_link_paths: Vec<PathBuf>,
    /// Static libraries linked to in the compile.
    pub staticlibs: Vec<PathBuf>,
    /// The crate name passed to --crate-name.
    pub crate_name: String,
    /// The crate types that will be generated
    pub crate_types: CrateTypes,
    /// If dependency info is being emitted, the name of the dep info file.
    pub dep_info: Option<PathBuf>,
    /// If profile info is being emitted, the path of the profile.
    ///
    /// This could be filled while `-Cprofile-use` been enabled.
    ///
    /// We need to add the profile into our outputs to enable distributed compilation.
    /// We don't need to track `profile-generate` since it's users work to make sure
    /// the `profdata` been generated from profraw files.
    ///
    /// For more information, see https://doc.rust-lang.org/rustc/profile-guided-optimization.html
    pub profile: Option<PathBuf>,
    /// If `-Z profile` has been enabled, we will use a GCC-compatible, gcov-based
    /// coverage implementation.
    ///
    /// This is not supported in latest stable rust anymore, but we still keep it here
    /// for the old nightly rustc.
    ///
    /// We need to add the profile into our outputs to enable distributed compilation.
    ///
    /// For more information, see https://doc.rust-lang.org/rustc/instrument-coverage.html
    pub gcno: Option<PathBuf>,
    /// rustc says that emits .rlib for --emit=metadata
    /// https://github.com/rust-lang/rust/issues/54852
    pub emit: HashSet<String>,
    /// The value of any `--color` option passed on the commandline.
    pub color_mode: ColorMode,
    /// Whether `--json` was passed to this invocation.
    pub has_json: bool,
    /// A `--target` parameter that specifies a path to a JSON file.
    pub target_json: Option<PathBuf>,
}

// The selection of crate types for this compilation
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CrateTypes {
    pub rlib: bool,
    pub staticlib: bool,
}

/// Emit types that we will cache.
static ALLOWED_EMIT: LazyLock<HashSet<&'static str>> =
    LazyLock::new(|| ["link", "metadata", "dep-info"].iter().copied().collect());

macro_rules! make_os_string {
    ($( $v:expr ),*) => {{
        let mut s = OsString::new();
        $(
            s.push($v);
        )*
        s
    }};
}

#[derive(Clone, Debug, PartialEq)]
struct ArgCrateTypes {
    rlib: bool,
    staticlib: bool,
    others: HashSet<String>,
}
impl FromArg for ArgCrateTypes {
    fn process(arg: OsString) -> ArgParseResult<Self> {
        let arg = String::process(arg)?;
        let mut crate_types = ArgCrateTypes {
            rlib: false,
            staticlib: false,
            others: HashSet::new(),
        };
        for ty in arg.split(',') {
            match ty {
                // It is assumed that "lib" always refers to "rlib", which
                // is true right now but may not be in the future
                "lib" | "rlib" => crate_types.rlib = true,
                "staticlib" => crate_types.staticlib = true,
                other => {
                    crate_types.others.insert(other.to_owned());
                }
            }
        }
        Ok(crate_types)
    }
}
impl IntoArg for ArgCrateTypes {
    fn into_arg_os_string(self) -> OsString {
        let ArgCrateTypes {
            rlib,
            staticlib,
            others,
        } = self;
        let mut types: Vec<_> = others
            .iter()
            .map(String::as_str)
            .chain(if rlib { Some("rlib") } else { None })
            .chain(if staticlib { Some("staticlib") } else { None })
            .collect();
        types.sort_unstable();
        let types_string = types.join(",");
        types_string.into()
    }
    fn into_arg_string(self, _transformer: PathTransformerFn<'_>) -> ArgToStringResult {
        let ArgCrateTypes {
            rlib,
            staticlib,
            others,
        } = self;
        let mut types: Vec<_> = others
            .iter()
            .map(String::as_str)
            .chain(if rlib { Some("rlib") } else { None })
            .chain(if staticlib { Some("staticlib") } else { None })
            .collect();
        types.sort_unstable();
        let types_string = types.join(",");
        Ok(types_string)
    }
}

#[derive(Clone, Debug, PartialEq)]
struct ArgLinkLibrary {
    kind: String,
    name: String,
}
impl FromArg for ArgLinkLibrary {
    fn process(arg: OsString) -> ArgParseResult<Self> {
        let (kind, name) = match split_os_string_arg(arg, "=")? {
            (kind, Some(name)) => (kind, name),
            // If no kind is specified, the default is dylib.
            (name, None) => ("dylib".to_owned(), name),
        };
        Ok(ArgLinkLibrary { kind, name })
    }
}
impl IntoArg for ArgLinkLibrary {
    fn into_arg_os_string(self) -> OsString {
        let ArgLinkLibrary { kind, name } = self;
        make_os_string!(kind, "=", name)
    }
    fn into_arg_string(self, _transformer: PathTransformerFn<'_>) -> ArgToStringResult {
        let ArgLinkLibrary { kind, name } = self;
        Ok(format!("{}={}", kind, name))
    }
}

#[derive(Clone, Debug, PartialEq)]
struct ArgLinkPath {
    kind: String,
    path: PathBuf,
}
impl FromArg for ArgLinkPath {
    fn process(arg: OsString) -> ArgParseResult<Self> {
        let (kind, path) = match split_os_string_arg(arg, "=")? {
            (kind, Some(path)) => (kind, path),
            // If no kind is specified, the path is used to search for all kinds
            (path, None) => ("all".to_owned(), path),
        };
        Ok(ArgLinkPath {
            kind,
            path: path.into(),
        })
    }
}
impl IntoArg for ArgLinkPath {
    fn into_arg_os_string(self) -> OsString {
        let ArgLinkPath { kind, path } = self;
        make_os_string!(kind, "=", path)
    }
    fn into_arg_string(self, transformer: PathTransformerFn<'_>) -> ArgToStringResult {
        let ArgLinkPath { kind, path } = self;
        Ok(format!("{}={}", kind, path.into_arg_string(transformer)?))
    }
}

#[derive(Clone, Debug, PartialEq)]
struct ArgCodegen {
    opt: String,
    value: Option<String>,
}
impl FromArg for ArgCodegen {
    fn process(arg: OsString) -> ArgParseResult<Self> {
        let (opt, value) = split_os_string_arg(arg, "=")?;
        Ok(ArgCodegen { opt, value })
    }
}
impl IntoArg for ArgCodegen {
    fn into_arg_os_string(self) -> OsString {
        let ArgCodegen { opt, value } = self;
        if let Some(value) = value {
            make_os_string!(opt, "=", value)
        } else {
            make_os_string!(opt)
        }
    }
    fn into_arg_string(self, transformer: PathTransformerFn<'_>) -> ArgToStringResult {
        let ArgCodegen { opt, value } = self;
        Ok(if let Some(value) = value {
            format!("{}={}", opt, value.into_arg_string(transformer)?)
        } else {
            opt
        })
    }
}

#[derive(Clone, Debug, PartialEq)]
struct ArgUnstable {
    opt: String,
    value: Option<String>,
}
impl FromArg for ArgUnstable {
    fn process(arg: OsString) -> ArgParseResult<Self> {
        let (opt, value) = split_os_string_arg(arg, "=")?;
        Ok(ArgUnstable { opt, value })
    }
}
impl IntoArg for ArgUnstable {
    fn into_arg_os_string(self) -> OsString {
        let ArgUnstable { opt, value } = self;
        if let Some(value) = value {
            make_os_string!(opt, "=", value)
        } else {
            make_os_string!(opt)
        }
    }
    fn into_arg_string(self, transformer: PathTransformerFn<'_>) -> ArgToStringResult {
        let ArgUnstable { opt, value } = self;
        Ok(if let Some(value) = value {
            format!("{}={}", opt, value.into_arg_string(transformer)?)
        } else {
            opt
        })
    }
}

#[derive(Clone, Debug, PartialEq)]
struct ArgExtern {
    name: String,
    path: PathBuf,
}
impl FromArg for ArgExtern {
    fn process(arg: OsString) -> ArgParseResult<Self> {
        if let (name, Some(path)) = split_os_string_arg(arg, "=")? {
            Ok(ArgExtern {
                name,
                path: path.into(),
            })
        } else {
            Err(ArgParseError::Other("no path for extern"))
        }
    }
}
impl IntoArg for ArgExtern {
    fn into_arg_os_string(self) -> OsString {
        let ArgExtern { name, path } = self;
        make_os_string!(name, "=", path)
    }
    fn into_arg_string(self, transformer: PathTransformerFn<'_>) -> ArgToStringResult {
        let ArgExtern { name, path } = self;
        Ok(format!("{}={}", name, path.into_arg_string(transformer)?))
    }
}

#[derive(Clone, Debug, PartialEq)]
enum ArgTarget {
    Name(String),
    Path(PathBuf),
    Unsure(OsString),
}
impl FromArg for ArgTarget {
    fn process(arg: OsString) -> ArgParseResult<Self> {
        // Is it obviously a json file path?
        if Path::new(&arg)
            .extension()
            .map(|ext| ext == "json")
            .unwrap_or(false)
        {
            return Ok(ArgTarget::Path(arg.into()));
        }
        // Time for clever detection - if we append .json (even if it's clearly
        // a directory, i.e. resulting in /my/dir/.json), does the path exist?
        let mut path = arg.clone();
        path.push(".json");
        if Path::new(&path).is_file() {
            // Unfortunately, we're now not sure what will happen without having
            // a list of all the built-in targets handy, as they don't get .json
            // auto-added for target json discovery
            return Ok(ArgTarget::Unsure(arg));
        }
        // The file doesn't exist so it can't be a path, safe to assume it's a name
        Ok(ArgTarget::Name(
            arg.into_string().map_err(ArgParseError::InvalidUnicode)?,
        ))
    }
}
impl IntoArg for ArgTarget {
    fn into_arg_os_string(self) -> OsString {
        match self {
            ArgTarget::Name(s) => s.into(),
            ArgTarget::Path(p) => p.into(),
            ArgTarget::Unsure(s) => s,
        }
    }
    fn into_arg_string(self, transformer: PathTransformerFn<'_>) -> ArgToStringResult {
        Ok(match self {
            ArgTarget::Name(s) => s,
            ArgTarget::Path(p) => p.into_arg_string(transformer)?,
            ArgTarget::Unsure(s) => s.into_arg_string(transformer)?,
        })
    }
}

ArgData! {
    TooHardFlag,
    TooHardPath(PathBuf),
    NotCompilationFlag,
    NotCompilation(OsString),
    LinkLibrary(ArgLinkLibrary),
    LinkPath(ArgLinkPath),
    Emit(String),
    Extern(ArgExtern),
    Color(String),
    Json(String),
    CrateName(String),
    CrateType(ArgCrateTypes),
    OutDir(PathBuf),
    CodeGen(ArgCodegen),
    PassThrough(OsString),
    Target(ArgTarget),
    Unstable(ArgUnstable),
}

use self::ArgData::*;



// These are taken from https://github.com/rust-lang/rust/blob/b671c32ddc8c36d50866428d83b7716233356721/src/librustc/session/config.rs#L1186
counted_array!(static ARGS: [ArgInfo<ArgData>; _] = [
    flag!("-", TooHardFlag),
    take_arg!("--allow", OsString, CanBeSeparated(b'='), PassThrough),
    take_arg!("--cap-lints", OsString, CanBeSeparated(b'='), PassThrough),
    take_arg!("--cfg", OsString, CanBeSeparated(b'='), PassThrough),
    take_arg!("--check-cfg", OsString, CanBeSeparated(b'='), PassThrough),
    take_arg!("--codegen", ArgCodegen, CanBeSeparated(b'='), CodeGen),
    take_arg!("--color", String, CanBeSeparated(b'='), Color),
    take_arg!("--crate-name", String, CanBeSeparated(b'='), CrateName),
    take_arg!("--crate-type", ArgCrateTypes, CanBeSeparated(b'='), CrateType),
    take_arg!("--deny", OsString, CanBeSeparated(b'='), PassThrough),
    take_arg!("--diagnostic-width", OsString, CanBeSeparated(b'='), PassThrough),
    take_arg!("--emit", String, CanBeSeparated(b'='), Emit),
    take_arg!("--error-format", OsString, CanBeSeparated(b'='), PassThrough),
    take_arg!("--explain", OsString, CanBeSeparated(b'='), NotCompilation),
    take_arg!("--extern", ArgExtern, CanBeSeparated(b'='), Extern),
    take_arg!("--forbid", OsString, CanBeSeparated(b'='), PassThrough),
    flag!("--help", NotCompilationFlag),
    take_arg!("--json", String, CanBeSeparated(b'='), Json),
    take_arg!("--out-dir", PathBuf, CanBeSeparated(b'='), OutDir),
    take_arg!("--pretty", OsString, CanBeSeparated(b'='), NotCompilation),
    take_arg!("--print", OsString, CanBeSeparated(b'='), NotCompilation),
    take_arg!("--remap-path-prefix", OsString, CanBeSeparated(b'='), PassThrough),
    take_arg!("--sysroot", PathBuf, CanBeSeparated(b'='), TooHardPath),
    take_arg!("--target", ArgTarget, CanBeSeparated(b'='), Target),
    take_arg!("--unpretty", OsString, CanBeSeparated(b'='), NotCompilation),
    flag!("--version", NotCompilationFlag),
    take_arg!("--warn", OsString, CanBeSeparated(b'='), PassThrough),
    take_arg!("-A", OsString, CanBeSeparated, PassThrough),
    take_arg!("-C", ArgCodegen, CanBeSeparated, CodeGen),
    take_arg!("-D", OsString, CanBeSeparated, PassThrough),
    take_arg!("-F", OsString, CanBeSeparated, PassThrough),
    take_arg!("-L", ArgLinkPath, CanBeSeparated, LinkPath),
    flag!("-V", NotCompilationFlag),
    take_arg!("-W", OsString, CanBeSeparated, PassThrough),
    take_arg!("-Z", ArgUnstable, CanBeSeparated, Unstable),
    take_arg!("-l", ArgLinkLibrary, CanBeSeparated, LinkLibrary),
    take_arg!("-o", PathBuf, CanBeSeparated, TooHardPath),
]);

/// Split the contents of a rustc `@response` file into arguments.
///
/// rustc reads response files by splitting on newlines, trimming whitespace,
/// and skipping empty lines.  It does not support quoting or backslash escaping
/// (unlike GCC), and does not recursively expand `@file` directives found
/// inside a response file.
///
/// Rustc reference: https://github.com/rust-lang/rust/blob/main/compiler/rustc_driver_impl/src/args.rs
pub fn split_rust_response_file_args(contents: &str) -> Vec<OsString> {
    contents
        .lines()
        .map(|line| line.trim())
        .filter(|line| !line.is_empty())
        .map(OsString::from)
        .collect()
}

/// Splits a rustc `@shell:path` file using its opt-in POSIX quoting rules.
pub fn split_rust_shell_response_file_args(contents: &str) -> Option<Vec<OsString>> {
    shlex::split(contents).map(|args| args.into_iter().map(OsString::from).collect())
}

struct ResponseArgument {
    value: OsString,
    literal: bool,
}

pub struct ExpandResponseFile<'a> {
    cwd: &'a Path,
    stack: Vec<ResponseArgument>,
    shell_argfiles: bool,
    next_is_unstable_option: bool,
}

impl<'a> ExpandResponseFile<'a> {
    pub fn new(cwd: &'a Path, args: &[OsString]) -> Self {
        ExpandResponseFile {
            stack: args.iter().rev().map(|arg| ResponseArgument {
                value: arg.to_owned(),
                literal: false,
            }).collect(),
            cwd,
            shell_argfiles: false,
            next_is_unstable_option: false,
        }
    }

    fn observed_argument(&mut self, arg: OsString) -> OsString {
        // rustc enables shell argfiles when it encounters this unstable flag,
        // so the flag must precede the @shell:path that uses it.
        if let Some(option) = arg.to_str() {
            if self.next_is_unstable_option {
                self.shell_argfiles |= option == "shell-argfiles";
                self.next_is_unstable_option = false;
            } else if option == "-Z" {
                self.next_is_unstable_option = true;
            } else {
                self.shell_argfiles |= option == "-Zshell-argfiles";
            }
        } else {
            self.next_is_unstable_option = false;
        }
        arg
    }
}

impl Iterator for ExpandResponseFile<'_> {
    type Item = OsString;

    fn next(&mut self) -> Option<OsString> {
        loop {
            let ResponseArgument { value: arg, literal } = self.stack.pop()?;
            if literal {
                return Some(self.observed_argument(arg));
            }
            let path = match arg.split_prefix("@") {
                Some(path) => path,
                None => return Some(self.observed_argument(arg)),
            };

            if self.shell_argfiles
                && let Some(path) = arg.to_str().and_then(|text| text.strip_prefix("@shell:"))
            {
                let shell_file = self.cwd.join(path);
                let contents = match fs::read_to_string(&shell_file) {
                    Ok(contents) => contents,
                    Err(error) => {
                        debug!("failed to read @shell-file `{}`: {}", shell_file.display(), error);
                        return Some(self.observed_argument(arg));
                    }
                };
                let Some(arguments) = split_rust_shell_response_file_args(&contents) else {
                    debug!("failed to parse @shell-file `{}`", shell_file.display());
                    return Some(self.observed_argument(arg));
                };
                // rustc does not recursively expand @file tokens produced by
                // an argfile. Keep those tokens literal in the execution argv.
                self.stack.extend(arguments.into_iter().rev().map(|arg| ResponseArgument {
                    value: arg,
                    literal: true,
                }));
                continue;
            }

            let file = self.cwd.join(path);
            let mut contents = String::new();
            let res = fs::File::open(&file)
                .and_then(|f| BufReader::new(f).read_to_string(&mut contents));
            if let Err(e) = res {
                debug!("failed to read @-file `{}`: {}", file.display(), e);
                return Some(arg);
            }
            let new_args = split_rust_response_file_args(&contents);
            self.stack.extend(new_args.into_iter().rev().map(|arg| ResponseArgument {
                value: arg,
                literal: false,
            }));
        }
    }
}

pub fn parse_arguments(arguments: &[OsString], cwd: &Path) -> CompilerArguments<ParsedArguments> {
    let mut args = vec![];

    let mut emit: Option<HashSet<String>> = None;
    let mut input = None;
    let mut output_dir = None;
    let mut crate_name = None;
    let mut crate_types = CrateTypes {
        rlib: false,
        staticlib: false,
    };
    let mut extra_filename = None;
    let mut externs = vec![];
    let mut crate_link_paths = vec![];
    let mut static_lib_names = vec![];
    let mut static_link_paths: Vec<PathBuf> = vec![];
    let mut color_mode = ColorMode::Auto;
    let mut has_json = false;
    let mut profile = None;
    let mut gcno = false;
    let mut target_json = None;

    // Custom iterator to expand `@` arguments which stand for reading a file
    // and interpreting it as a list of more arguments.
    let it = ExpandResponseFile::new(cwd, arguments);

    for (idx, arg) in ArgsIter::new(it, &ARGS[..]).enumerate() {
        let arg = try_or_cannot_cache!(arg, "argument parse");
        match arg.get_data() {
            Some(TooHardFlag) | Some(TooHardPath(_)) => {
                cannot_cache!(arg.flag_str().expect("Can't be Argument::Raw/UnknownFlag",))
            }
            Some(NotCompilationFlag) | Some(NotCompilation(_)) => {
                return CompilerArguments::NotCompilation;
            }
            Some(LinkLibrary(ArgLinkLibrary { kind, name })) => {
                if kind == "static" {
                    static_lib_names.push(name.to_owned());
                }
            }
            Some(LinkPath(ArgLinkPath { kind, path })) => {
                // "crate" is not typically necessary as cargo will normally
                // emit explicit --extern arguments
                if kind == "crate" || kind == "dependency" || kind == "all" {
                    crate_link_paths.push(cwd.join(path));
                }
                if kind == "native" || kind == "all" {
                    static_link_paths.push(cwd.join(path));
                }
            }
            Some(Emit(value)) => {
                if emit.is_some() {
                    // We don't support passing --emit more than once.
                    cannot_cache!("more than one --emit");
                }
                emit = Some(value.split(',').map(str::to_owned).collect());
            }
            Some(CrateType(ArgCrateTypes {
                rlib,
                staticlib,
                others,
            })) => {
                // We can't cache non-rlib/staticlib crates, because rustc invokes the
                // system linker to link them, and we don't know about all the linker inputs.
                if !others.is_empty() {
                    let others: Vec<&str> = others.iter().map(String::as_str).collect();
                    let others_string = others.join(",");
                    cannot_cache!("crate-type", others_string)
                }
                crate_types.rlib |= rlib;
                crate_types.staticlib |= staticlib;
            }
            Some(CrateName(value)) => crate_name = Some(value.clone()),
            Some(OutDir(value)) => output_dir = Some(value.clone()),
            Some(Extern(ArgExtern { path, .. })) => externs.push(path.clone()),
            Some(CodeGen(ArgCodegen { opt, value })) => {
                match (opt.as_ref(), value) {
                    ("extra-filename", Some(value)) => extra_filename = Some(value.to_owned()),
                    ("extra-filename", None) => cannot_cache!("extra-filename"),
                    ("profile-use", Some(v)) => profile = Some(v.clone()),
                    // Incremental compilation makes a mess of sccache's entire world
                    // view. It produces additional compiler outputs that we don't cache,
                    // and just letting rustc do its work in incremental mode is likely
                    // to be faster than trying to fetch a result from cache anyway, so
                    // don't bother caching compiles where it's enabled currently.
                    // Longer-term we would like to figure out better integration between
                    // sccache and rustc in the incremental scenario:
                    // https://github.com/mozilla/sccache/issues/236
                    ("incremental", _) => cannot_cache!("incremental"),
                    (_, _) => (),
                }
            }
            Some(Unstable(ArgUnstable { opt, value })) => match value.as_deref() {
                Some("y") | Some("yes") | Some("on") | None if opt == "profile" => {
                    gcno = true;
                }
                _ => (),
            },
            Some(Color(value)) => {
                // We'll just assume the last specified value wins.
                color_mode = match value.as_ref() {
                    "always" => ColorMode::On,
                    "never" => ColorMode::Off,
                    _ => ColorMode::Auto,
                };
            }
            Some(Json(_)) => {
                has_json = true;
            }
            Some(PassThrough(_)) => (),
            Some(Target(target)) => match target {
                ArgTarget::Path(json_path) => target_json = Some(json_path.to_owned()),
                ArgTarget::Unsure(_) => cannot_cache!("target unsure"),
                ArgTarget::Name(_) => (),
            },
            None => {
                match arg {
                    Argument::Raw(ref val) => {
                        if idx == 0
                            && let Some(value) = val.to_str()
                            && value == "rustc"
                        {
                            // If the first argument is rustc, it's likely called via clippy-driver,
                            // so it's not actually an input file, which means we should discount it.
                            continue;
                        }
                        if input.is_some() {
                            // Can't cache compilations with multiple inputs.
                            cannot_cache!(
                                "multiple input files",
                                format!("prev = {input:?}, next = {arg:?}")
                            );
                        }
                        input = Some(val.clone());
                    }
                    Argument::UnknownFlag(_) => {}
                    _ => unreachable!(),
                }
            }
        }
        // We'll drop --color arguments, we're going to pass --color=always and the client will
        // strip colors if necessary.
        match arg.get_data() {
            Some(Color(_)) => {}
            _ => args.push(arg.normalize(NormalizedDisposition::Separated)),
        }
    }

    // Unwrap required values.
    macro_rules! req {
        ($x:ident) => {
            let $x = if let Some($x) = $x {
                $x
            } else {
                debug!("Can't cache compilation, missing `{}`", stringify!($x));
                cannot_cache!(concat!("missing ", stringify!($x)));
            };
        };
    }
    // We don't actually save the input value, but there needs to be one.
    req!(input);
    drop(input);
    req!(output_dir);
    req!(emit);
    req!(crate_name);
    // We won't cache invocations that are not producing
    // binary output.
    if !emit.is_empty() && !emit.contains("link") && !emit.contains("metadata") {
        return CompilerArguments::NotCompilation;
    }
    // If it's not an rlib and not a staticlib then crate-type wasn't passed,
    // so it will usually be inferred as a binary, though the `#![crate_type`
    // annotation may dictate otherwise - either way, we don't know what to do.
    if let CrateTypes {
        rlib: false,
        staticlib: false,
    } = crate_types
    {
        cannot_cache!("crate-type", "No crate-type passed".to_owned())
    }
    // We won't cache invocations that are outputting anything but
    // linker output and dep-info.
    if emit.iter().any(|e| !ALLOWED_EMIT.contains(e.as_str())) {
        cannot_cache!("unsupported --emit");
    }

    // Figure out the dep-info filename, if emitting dep-info.
    let dep_info = if emit.contains("dep-info") {
        let mut dep_info = crate_name.clone();
        if let Some(extra_filename) = extra_filename.clone() {
            dep_info.push_str(&extra_filename[..]);
        }
        dep_info.push_str(".d");
        Some(dep_info)
    } else {
        None
    };

    // Ignore profile is `link` is not in emit which means we are running `cargo check`.
    let profile = if emit.contains("link") { profile } else { None };

    // Figure out the gcno filename, if producing gcno files with `-Zprofile`.
    let gcno = if gcno && emit.contains("link") {
        let mut gcno = crate_name.clone();
        if let Some(extra_filename) = extra_filename {
            gcno.push_str(&extra_filename[..]);
        }
        gcno.push_str(".gcno");
        Some(gcno)
    } else {
        None
    };

    // Locate all static libs specified on the commandline.
    let staticlibs = static_lib_names
        .into_iter()
        .filter_map(|name| {
            for path in static_link_paths.iter() {
                for f in &[
                    format_args!("lib{}.a", name),
                    format_args!("{}.lib", name),
                    format_args!("{}.a", name),
                ] {
                    let lib_path = path.join(fmt::format(*f));
                    if lib_path.exists() {
                        return Some(lib_path);
                    }
                }
            }
            // rustc will just error if there's a missing static library, so don't worry about
            // it too much.
            None
        })
        .collect();
    // We'll figure out the source files and outputs later in
    // `generate_hash_key` where we can run rustc.
    // Cargo doesn't deterministically order --externs, and we need the hash inputs in a
    // deterministic order.
    externs.sort();
    CompilerArguments::Ok(ParsedArguments {
        arguments: args,
        output_dir,
        crate_types,
        externs,
        crate_link_paths,
        staticlibs,
        crate_name,
        dep_info: dep_info.map(|s| s.into()),
        profile: profile.map(|s| s.into()),
        gcno: gcno.map(|s| s.into()),
        emit,
        color_mode,
        has_json,
        target_json,
    })
}


impl ParsedArguments {
    /// Returns expanded compiler arguments, preserving option values.
    pub fn command_args(&self, discovery: bool) -> Vec<OsString> {
        self.arguments.iter().filter(|arg| !discovery || !matches!(arg.get_data(), Some(ArgData::Emit(_)) | Some(ArgData::OutDir(_))))
            .flat_map(|arg| arg.iter_os_strings()).collect()
    }
}

#[cfg(test)]
mod test {
    use super::*;
use itertools::Itertools;
use std::ffi::OsStr;
use std::io::{self,Write};
    fn _parse_arguments(arguments: &[String]) -> CompilerArguments<ParsedArguments> {
        let arguments = arguments.iter().map(OsString::from).collect::<Vec<_>>();
        parse_arguments(&arguments, ".".as_ref())
    }

    macro_rules! parses {
        ( $( $s:expr ),* ) => {
            match _parse_arguments(&[ $( $s.to_string(), )* ]) {
                CompilerArguments::Ok(a) => a,
                o => panic!("Got unexpected parse result: {:?}", o),
            }
        }
    }

    macro_rules! fails {
        ( $( $s:expr ),* ) => {
            match _parse_arguments(&[ $( $s.to_string(), )* ]) {
                CompilerArguments::Ok(_) => panic!("Should not have parsed ok: `{}`", stringify!($( $s, )*)),

                o => o,
            }
        }
    }

    #[test]
    fn test_parse_arguments_simple() {
        let h = parses!(
            "--emit",
            "link",
            "foo.rs",
            "--out-dir",
            "out",
            "--crate-name",
            "foo",
            "--crate-type",
            "lib"
        );
        assert_eq!(h.output_dir.to_str(), Some("out"));
        assert!(h.dep_info.is_none());
        assert!(h.externs.is_empty());
        let h = parses!(
            "--emit=link",
            "foo.rs",
            "--out-dir",
            "out",
            "--crate-name=foo",
            "--crate-type=lib"
        );
        assert_eq!(h.output_dir.to_str(), Some("out"));
        assert!(h.dep_info.is_none());
        let h = parses!(
            "--emit",
            "link",
            "foo.rs",
            "--out-dir=out",
            "--crate-name=foo",
            "--crate-type=lib"
        );
        assert_eq!(h.output_dir.to_str(), Some("out"));
        assert_eq!(
            parses!(
                "--emit",
                "link",
                "-C",
                "opt-level=1",
                "foo.rs",
                "--out-dir",
                "out",
                "--crate-name",
                "foo",
                "--crate-type",
                "lib"
            ),
            parses!(
                "--emit=link",
                "-Copt-level=1",
                "foo.rs",
                "--out-dir=out",
                "--crate-name=foo",
                "--crate-type=lib"
            )
        );
        let h = parses!(
            "--emit",
            "link,dep-info",
            "foo.rs",
            "--out-dir",
            "out",
            "--crate-name",
            "my_crate",
            "--crate-type",
            "lib",
            "-C",
            "extra-filename=-abcxyz"
        );
        assert_eq!(h.output_dir.to_str(), Some("out"));
        assert_eq!(h.dep_info.unwrap().to_str().unwrap(), "my_crate-abcxyz.d");
        fails!(
            "--emit",
            "link",
            "--out-dir",
            "out",
            "--crate-name=foo",
            "--crate-type=lib"
        );
        fails!(
            "--emit",
            "link",
            "foo.rs",
            "--crate-name=foo",
            "--crate-type=lib"
        );
        fails!(
            "--emit",
            "asm",
            "foo.rs",
            "--out-dir",
            "out",
            "--crate-name=foo",
            "--crate-type=lib"
        );
        fails!(
            "--emit",
            "asm,link",
            "foo.rs",
            "--out-dir",
            "out",
            "--crate-name=foo",
            "--crate-type=lib"
        );
        fails!(
            "--emit",
            "asm,link,dep-info",
            "foo.rs",
            "--out-dir",
            "out",
            "--crate-name=foo",
            "--crate-type=lib"
        );
        fails!(
            "--emit",
            "link",
            "foo.rs",
            "--out-dir",
            "out",
            "--crate-name=foo"
        );
        fails!(
            "--emit",
            "link",
            "foo.rs",
            "--out-dir",
            "out",
            "--crate-type=lib"
        );
        // From an actual cargo compilation, with some args shortened:
        let h = parses!(
            "--crate-name",
            "foo",
            "src/lib.rs",
            "--crate-type",
            "lib",
            "--emit=dep-info,link",
            "-C",
            "debuginfo=2",
            "-C",
            "metadata=d6ae26f5bcfb7733",
            "-C",
            "extra-filename=-d6ae26f5bcfb7733",
            "--out-dir",
            "/foo/target/debug/deps",
            "-L",
            "dependency=/foo/target/debug/deps",
            "--extern",
            "libc=/foo/target/debug/deps/liblibc-89a24418d48d484a.rlib",
            "--extern",
            "log=/foo/target/debug/deps/liblog-2f7366be74992849.rlib"
        );
        assert_eq!(h.output_dir.to_str(), Some("/foo/target/debug/deps"));
        assert_eq!(h.crate_name, "foo");
        assert_eq!(
            h.dep_info.unwrap().to_str().unwrap(),
            "foo-d6ae26f5bcfb7733.d"
        );
        assert_eq!(
            h.externs,
            ovec![
                "/foo/target/debug/deps/liblibc-89a24418d48d484a.rlib",
                "/foo/target/debug/deps/liblog-2f7366be74992849.rlib"
            ]
        );
    }


    #[test]
    fn test_parse_arguments_incremental() {
        parses!(
            "--emit",
            "link",
            "foo.rs",
            "--out-dir",
            "out",
            "--crate-name",
            "foo",
            "--crate-type",
            "lib"
        );
        let r = fails!(
            "--emit",
            "link",
            "foo.rs",
            "--out-dir",
            "out",
            "--crate-name",
            "foo",
            "--crate-type",
            "lib",
            "-C",
            "incremental=/foo"
        );
        assert_eq!(r, CompilerArguments::CannotCache("incremental", None));
    }


    #[test]
    fn test_parse_arguments_dep_info_no_extra_filename() {
        let h = parses!(
            "--crate-name",
            "foo",
            "--crate-type",
            "lib",
            "src/lib.rs",
            "--emit=dep-info,link",
            "--out-dir",
            "/out"
        );
        assert_eq!(h.dep_info, Some("foo.d".into()));
    }


    #[test]
    fn test_parse_arguments_native_libs() {
        parses!(
            "--crate-name",
            "foo",
            "--crate-type",
            "lib,staticlib",
            "--emit",
            "link",
            "-l",
            "bar",
            "foo.rs",
            "--out-dir",
            "out"
        );
        parses!(
            "--crate-name",
            "foo",
            "--crate-type",
            "lib,staticlib",
            "--emit",
            "link",
            "-l",
            "static=bar",
            "foo.rs",
            "--out-dir",
            "out"
        );
        parses!(
            "--crate-name",
            "foo",
            "--crate-type",
            "lib,staticlib",
            "--emit",
            "link",
            "-l",
            "dylib=bar",
            "foo.rs",
            "--out-dir",
            "out"
        );
    }


    #[test]
    fn test_parse_arguments_non_rlib_crate() {
        parses!(
            "--crate-type",
            "rlib",
            "--emit",
            "link",
            "foo.rs",
            "--out-dir",
            "out",
            "--crate-name",
            "foo"
        );
        parses!(
            "--crate-type",
            "lib",
            "--emit",
            "link",
            "foo.rs",
            "--out-dir",
            "out",
            "--crate-name",
            "foo"
        );
        parses!(
            "--crate-type",
            "staticlib",
            "--emit",
            "link",
            "foo.rs",
            "--out-dir",
            "out",
            "--crate-name",
            "foo"
        );
        parses!(
            "--crate-type",
            "rlib,staticlib",
            "--emit",
            "link",
            "foo.rs",
            "--out-dir",
            "out",
            "--crate-name",
            "foo"
        );
        fails!(
            "--crate-type",
            "bin",
            "--emit",
            "link",
            "foo.rs",
            "--out-dir",
            "out",
            "--crate-name",
            "foo"
        );
        fails!(
            "--crate-type",
            "rlib,dylib",
            "--emit",
            "link",
            "foo.rs",
            "--out-dir",
            "out",
            "--crate-name",
            "foo"
        );
    }


    #[test]
    fn test_parse_arguments_color() {
        let h = parses!(
            "--emit",
            "link",
            "foo.rs",
            "--out-dir",
            "out",
            "--crate-name",
            "foo",
            "--crate-type",
            "lib"
        );
        assert_eq!(h.color_mode, ColorMode::Auto);
        let h = parses!(
            "--emit",
            "link",
            "foo.rs",
            "--out-dir",
            "out",
            "--crate-name",
            "foo",
            "--crate-type",
            "lib",
            "--color=always"
        );
        assert_eq!(h.color_mode, ColorMode::On);
        let h = parses!(
            "--emit",
            "link",
            "foo.rs",
            "--out-dir",
            "out",
            "--crate-name",
            "foo",
            "--crate-type",
            "lib",
            "--color=never"
        );
        assert_eq!(h.color_mode, ColorMode::Off);
        let h = parses!(
            "--emit",
            "link",
            "foo.rs",
            "--out-dir",
            "out",
            "--crate-name",
            "foo",
            "--crate-type",
            "lib",
            "--color=auto"
        );
        assert_eq!(h.color_mode, ColorMode::Auto);
    }


    #[test]
    fn test_parse_arguments_multiple_inputs() {
        fails!(
            "huh.rs",
            "--emit",
            "link",
            "foo.rs",
            "--out-dir",
            "out",
            "--crate-name",
            "foo",
            "--crate-type",
            "lib"
        );

        // Having `rustc` as the first argument is indicative of clippy
        parses!(
            "rustc",
            "--emit",
            "link",
            "foo.rs",
            "--out-dir",
            "out",
            "--crate-name",
            "foo",
            "--crate-type",
            "lib"
        );
    }



    #[test]
    fn test_split_rust_response_file_args() {
        // Simple one arg per line.
        assert_eq!(
            ovec!["--emit", "link", "foo.rs"],
            split_rust_response_file_args("--emit\nlink\nfoo.rs\n")
        );
        // Lines are trimmed.
        assert_eq!(
            ovec!["--emit", "link", "foo.rs"],
            split_rust_response_file_args("  --emit  \n\tlink\n  foo.rs\n")
        );
        // Empty lines are skipped.
        assert_eq!(
            ovec!["--emit", "foo.rs"],
            split_rust_response_file_args("--emit\n\n\nfoo.rs\n")
        );
        // Empty input.
        assert!(split_rust_response_file_args("").is_empty());
        assert!(split_rust_response_file_args("\n\n  \n\t\n").is_empty());
        // Carriage returns are trimmed.
        assert_eq!(
            ovec!["--emit", "foo.rs"],
            split_rust_response_file_args("--emit\r\nfoo.rs\r\n")
        );
    }


    #[test]
    fn test_parse_arguments_response_file() {
        let td = tempfile::Builder::new()
            .prefix("sccache")
            .tempdir()
            .unwrap();
        File::create(td.path().join("args"))
            .unwrap()
            .write_all(b"--emit\nlink,dep-info\nfoo.rs\n--out-dir\nout\n--crate-name\nfoo\n--crate-type\nlib\n")
            .unwrap();
        let arg = format!("@{}", td.path().join("args").display());
        let args: Vec<OsString> = vec![OsString::from(arg)];
        let result = parse_arguments(&args, td.path());
        let parsed = match result {
            CompilerArguments::Ok(args) => args,
            o => panic!("Got unexpected parse result: {:?}", o),
        };
        assert_eq!(parsed.output_dir.to_str(), Some("out"));
        assert!(parsed.dep_info.is_some());
        assert!(parsed.externs.is_empty());
    }


    #[test]
    fn test_parse_shell_argfile_with_quoted_path() {
        let td = tempfile::tempdir().unwrap();
        File::create(td.path().join("args"))
            .unwrap()
            .write_all(b"--emit link,dep-info --crate-name example --crate-type lib --out-dir 'target files' foo.rs\n")
            .unwrap();
        let shell_file = OsString::from(format!("@shell:{}", td.path().join("args").display()));

        for flags in [ovec!["-Zshell-argfiles"], ovec!["-Z", "shell-argfiles"]] {
            let mut arguments = flags;
            arguments.push(shell_file.clone());
            let expanded: Vec<_> = ExpandResponseFile::new(td.path(), &arguments).collect();
            assert!(expanded.contains(&OsString::from("target files")));

            let result = parse_arguments(&arguments, td.path());
            let parsed = match result {
                CompilerArguments::Ok(args) => args,
                other => panic!("Got unexpected parse result: {other:?}"),
            };
            assert_eq!(parsed.output_dir, PathBuf::from("target files"));
            assert!(parsed.dep_info.is_some());
        }
    }


    #[test]
    fn test_parse_arguments_response_file_missing() {
        // When the @file cannot be read, the raw @-arg passes through.
        // Without other required flags it becomes the input file, leading
        // to missing --out-dir / --emit etc.
        let cwd = Path::new("/nonexistent");
        let args: Vec<OsString> = vec![OsString::from("@missing_file")];
        let result = parse_arguments(&args, cwd);
        assert!(matches!(result, CompilerArguments::CannotCache(..)));
    }

}
