//! Local REAPI v2 wire subset. Field numbers follow remote_execution.proto.
//!
//! Only regular-file outputs are accepted. Unsupported protobuf fields cause
//! an entry to be rejected through canonical re-encoding before restoration.
//! The local action input is an inventory, not a remote-executable filesystem;
//! remote execution will require a separate platform and input-tree adapter.

use prost::Message;

/// Identifies content by SHA-256 and byte length.
#[derive(Clone, PartialEq, Message)]
pub struct Digest {
    /// Lowercase hexadecimal SHA-256 digest.
    #[prost(string, tag = "1")]
    pub hash: String,
    /// Exact content length.
    #[prost(int64, tag = "2")]
    pub size_bytes: i64,
}

/// References the command and local inventory tree for an action.
#[derive(Clone, PartialEq, Message)]
pub struct Action {
    /// Digest of the serialized command.
    #[prost(message, optional, tag = "1")]
    pub command_digest: Option<Digest>,
    /// Digest of the local inventory directory.
    #[prost(message, optional, tag = "2")]
    pub input_root_digest: Option<Digest>,
}

/// Records arguments, effective environment, and encoded output names.
#[derive(Clone, PartialEq, Message)]
pub struct Command {
    /// Compiler executable followed by its original arguments.
    #[prost(string, repeated, tag = "1")]
    pub arguments: Vec<String>,
    /// Effective execution environment, with actual values.
    #[prost(message, repeated, tag = "2")]
    pub environment_variables: Vec<EnvironmentVariable>,
    /// Working directory encoded relative to the filesystem root.
    #[prost(string, tag = "6")]
    pub working_directory: String,
    /// Encoded output names mapped through the current invocation.
    #[prost(string, repeated, tag = "7")]
    pub output_paths: Vec<String>,
}

/// Stores an effective environment variable in the command blob.
#[derive(Clone, PartialEq, Message)]
pub struct EnvironmentVariable {
    /// Entry name within its containing message.
    #[prost(string, tag = "1")]
    pub name: String,
    /// Environment value visible to the compiler.
    #[prost(string, tag = "2")]
    pub value: String,
}

/// Contains the files of the local inventory root.
#[derive(Clone, PartialEq, Message)]
pub struct Directory {
    /// Regular files contained by this directory.
    #[prost(message, repeated, tag = "1")]
    pub files: Vec<FileNode>,
}

/// References a named inventory file in the CAS.
#[derive(Clone, PartialEq, Message)]
pub struct FileNode {
    /// Entry name within its containing message.
    #[prost(string, tag = "1")]
    pub name: String,
    /// Content digest of this file.
    #[prost(message, optional, tag = "2")]
    pub digest: Option<Digest>,
    /// Whether any executable mode bit is present.
    #[prost(bool, tag = "4")]
    pub is_executable: bool,
}

/// References an output blob through an invocation-validated wire name.
#[derive(Clone, PartialEq, Message)]
pub struct OutputFile {
    /// Encoded output name; never used directly as a destination.
    #[prost(string, tag = "1")]
    pub path: String,
    /// Content digest of this file.
    #[prost(message, optional, tag = "2")]
    pub digest: Option<Digest>,
    /// Whether any executable mode bit is present.
    #[prost(bool, tag = "4")]
    pub is_executable: bool,
}

/// References the command and local inventory tree for an action.
/// Stores successful output references and replayable compiler diagnostics.
#[derive(Clone, PartialEq, Message)]
pub struct ActionResult {
    /// Complete set of present regular outputs.
    #[prost(message, repeated, tag = "2")]
    pub output_files: Vec<OutputFile>,
    /// Compiler exit code; local publication only stores success.
    #[prost(int32, tag = "4")]
    pub exit_code: i32,
    /// Exact captured standard output.
    #[prost(bytes = "vec", tag = "5")]
    pub stdout_raw: Vec<u8>,
    /// Exact captured standard error.
    #[prost(bytes = "vec", tag = "7")]
    pub stderr_raw: Vec<u8>,
}
