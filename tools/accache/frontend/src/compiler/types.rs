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

use std::path::Path;
use serde::{Serialize, Deserialize};

/// Possible results of parsing compiler arguments.
#[derive(Debug, PartialEq, Eq)]
pub enum CompilerArguments<T> {
    /// Commandline can be handled.
    Ok(T),
    /// Cannot cache this compilation.
    CannotCache(&'static str, Option<String>),
    /// This commandline is not a compile.
    NotCompilation,
}

macro_rules! cannot_cache {
    ($why:expr) => {
        return CompilerArguments::CannotCache($why, None)
    };
    ($why:expr, $extra_info:expr) => {
        return CompilerArguments::CannotCache($why, Some($extra_info))
    };
}

macro_rules! try_or_cannot_cache {
    ($arg:expr, $why:expr) => {{
        match $arg {
            Ok(arg) => arg,
            Err(e) => cannot_cache!($why, e.to_string()),
        }
    }};
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum Language {
    AssemblerToPreprocess,
    Assembler,
    C,
    Cxx,
    GenericHeader,
    CHeader,
    CPreprocessed,
    CxxHeader,
    CxxPreprocessed,
    ObjectiveC,
    ObjectiveCHeader,
    ObjectiveCPreprocessed,
    ObjectiveCxx,
    ObjectiveCxxPreprocessed,
    ObjectiveCxxHeader,
    Cuda,
    CudaFE,
    Ptx,
    Cubin,
    Rust,
    Hip,
    CxxModule,
}

impl Language {
    pub fn from_file_name(file: &Path) -> Option<Self> {
        match file.extension().and_then(|e| e.to_str()) {
            // gcc: https://gcc.gnu.org/onlinedocs/gcc/Overall-Options.html
            Some("s") => Some(Language::Assembler),
            Some("S") | Some("sx") => Some(Language::AssemblerToPreprocess),
            Some("c") => Some(Language::C),
            // Could be C or C++
            Some("h") => Some(Language::GenericHeader),
            Some("i") => Some(Language::CPreprocessed),
            Some("C") | Some("cc") | Some("cp") | Some("cpp") | Some("CPP") | Some("cxx")
            | Some("c++") => Some(Language::Cxx),
            Some("ii") => Some(Language::CxxPreprocessed),
            Some("H") | Some("hh") | Some("hp") | Some("hpp") | Some("HPP") | Some("hxx")
            | Some("h++") | Some("tcc") => Some(Language::CxxHeader),
            Some("cppm") | Some("ixx") => Some(Language::CxxModule),
            Some("m") => Some(Language::ObjectiveC),
            Some("mi") => Some(Language::ObjectiveCPreprocessed),
            Some("M") | Some("mm") => Some(Language::ObjectiveCxx),
            Some("mii") => Some(Language::ObjectiveCxxPreprocessed),
            Some("cu") => Some(Language::Cuda),
            Some("ptx") => Some(Language::Ptx),
            Some("cubin") => Some(Language::Cubin),
            // TODO cy
            Some("rs") => Some(Language::Rust),
            Some("hip") => Some(Language::Hip),
            e => {
                trace!("Unknown source extension: {}", e.unwrap_or("(None)"));
                None
            }
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Language::AssemblerToPreprocess => "assemblerToPreprocess",
            Language::Assembler => "assembler",
            Language::C => "c",
            Language::CHeader => "cHeader",
            Language::CPreprocessed => "cPreprocessed",
            Language::Cxx => "c++",
            Language::CxxHeader => "c++Header",
            Language::CxxPreprocessed => "c++Preprocessed",
            Language::GenericHeader => "c/c++",
            Language::ObjectiveC | Language::ObjectiveCHeader => "objc",
            Language::ObjectiveCPreprocessed => "objcPreprocessed",
            Language::ObjectiveCxx | Language::ObjectiveCxxHeader => "objc++",
            Language::ObjectiveCxxPreprocessed => "objc++Preprocessed",
            Language::Cuda => "cuda",
            Language::CudaFE => "cuda",
            Language::Ptx => "ptx",
            Language::Cubin => "cubin",
            Language::Rust => "rust",
            Language::Hip => "hip",
            Language::CxxModule => "c++-module",
        }
    }

    pub fn needs_c_preprocessing(self) -> bool {
        !matches!(
            self,
            Language::Assembler
                | Language::CPreprocessed
                | Language::CxxPreprocessed
                | Language::ObjectiveCPreprocessed
                | Language::ObjectiveCxxPreprocessed
                | Language::Rust
        )
    }

    pub fn is_c_like_header(self) -> bool {
        matches!(
            self,
            Language::CHeader
                | Language::CxxHeader
                | Language::ObjectiveCHeader
                | Language::ObjectiveCxxHeader
                | Language::GenericHeader
        )
    }

    pub fn to_c_preprocessed_language(self) -> Option<Language> {
        match self {
            Language::AssemblerToPreprocess => Some(Language::Assembler),
            Language::C => Some(Language::CPreprocessed),
            Language::Cxx => Some(Language::CxxPreprocessed),
            Language::ObjectiveC => Some(Language::ObjectiveCPreprocessed),
            Language::ObjectiveCxx => Some(Language::ObjectiveCxxPreprocessed),
            _ => None,
        }
    }

    /// Common implementation for GCC and Clang language argument mapping
    fn to_compiler_arg(self, cuda_arg: &'static str) -> Option<&'static str> {
        match self {
            Language::AssemblerToPreprocess => Some("assembler-with-cpp"),
            Language::Assembler => Some("assembler"),
            Language::C => Some("c"),
            Language::CHeader => Some("c-header"),
            Language::CPreprocessed => Some("cpp-output"),
            Language::Cxx => Some("c++"),
            Language::CxxHeader => Some("c++-header"),
            Language::CxxPreprocessed => Some("c++-cpp-output"),
            Language::ObjectiveC => Some("objective-c"),
            Language::ObjectiveCHeader => Some("objective-c-header"),
            Language::ObjectiveCPreprocessed => Some("objective-c-cpp-output"),
            Language::ObjectiveCxx => Some("objective-c++"),
            Language::ObjectiveCxxHeader => Some("objective-c++-header"),
            Language::ObjectiveCxxPreprocessed => Some("objective-c++-cpp-output"),
            Language::Cuda => Some(cuda_arg),
            Language::CudaFE => None,
            Language::Ptx => None,
            Language::Cubin => None,
            Language::Rust => None, // Let the compiler decide
            Language::Hip => Some("hip"),
            Language::GenericHeader => None, // Let the compiler decide
            Language::CxxModule => Some("c++-module"),
        }
    }

    /// Returns the GCC-specific language argument for the `-x` flag
    /// https://gcc.gnu.org/onlinedocs/gcc/Overall-Options.html
    pub fn to_gcc_arg(self) -> Option<&'static str> {
        self.to_compiler_arg("cu")
    }

    /// Returns the Clang-specific language argument for the `-x` flag
    /// https://github.com/llvm/llvm-project/blob/main/clang/include/clang/Driver/Types.def
    pub fn to_clang_arg(self) -> Option<&'static str> {
        self.to_compiler_arg("cuda")
    }
}

/// The state of `--color` options passed to a compiler.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum ColorMode {
    Off,
    On,
    #[default]
    Auto,
}
