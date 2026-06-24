//! Shared `.drv` diff test fixtures.

use super::structural::{NIX_STORE_DIR, rewrite_store_dir_in_path_sections};
use super::*;
use std::collections::BTreeMap;

pub(super) struct FakeEval {
    result: Result<PathBuf>,
    closure: Option<Result<DrvClosure>>,
}

impl FakeEval {
    pub(super) fn path(path: PathBuf) -> Self {
        Self {
            result: Ok(path),
            closure: None,
        }
    }

    pub(super) fn path_with_bytes(path: PathBuf, drv_bytes: BTreeMap<PathBuf, Vec<u8>>) -> Self {
        let closure = DrvClosure::new(path.clone(), drv_bytes);
        Self {
            result: Ok(path),
            closure: Some(Ok(closure)),
        }
    }

    pub(super) fn path_with_closure_error(path: PathBuf, message: &str) -> Self {
        Self {
            result: Ok(path),
            closure: Some(Err(anyhow::anyhow!(message.to_string()))),
        }
    }

    pub(super) fn error(message: &str) -> Self {
        Self {
            result: Err(anyhow::anyhow!(message.to_string())),
            closure: None,
        }
    }
}

impl NixEval for FakeEval {
    fn instantiate(&self, _file: &Path, _attr: &str) -> Result<PathBuf> {
        self.result
            .as_ref()
            .map(PathBuf::clone)
            .map_err(|error| anyhow::anyhow!(error.to_string()))
    }

    fn instantiate_expr(&self, _expr: &str) -> Result<PathBuf> {
        self.instantiate(Path::new("expr"), "")
    }

    fn instantiate_closure(&self, _file: &Path, _attr: &str) -> Result<Option<DrvClosure>> {
        match &self.closure {
            Some(Ok(closure)) => Ok(Some(closure.clone())),
            Some(Err(error)) => Err(anyhow::anyhow!(error.to_string())),
            None => Ok(None),
        }
    }

    fn eval_expr(&self, _expr: &str) -> Result<String> {
        Ok("null".to_string())
    }

    fn name(&self) -> &'static str {
        "fake"
    }
}

pub(super) fn path_str(path: &Path) -> Result<&str> {
    path.to_str()
        .with_context(|| format!("drv path is not UTF-8: {}", path.display()))
}

pub(super) fn drv(outputs: &[(&str, &[&str])], marker: &str) -> String {
    String::from_utf8(drv_bytes(outputs, marker, None)).expect("fixture is UTF-8")
}

pub(super) fn drv_bytes(
    outputs: &[(&str, &[&str])],
    marker: &str,
    extra_env: Option<&[u8]>,
) -> Vec<u8> {
    let inputs = outputs
        .iter()
        .map(|(path, names)| {
            let names = names
                .iter()
                .map(|name| format!(r#""{name}""#))
                .collect::<Vec<_>>()
                .join(",");
            format!(r#"("{path}",[{names}])"#)
        })
        .collect::<Vec<_>>()
        .join(",");
    let mut out = format!(
        r#"Derive([("out","/nix/store/cccccccccccccccccccccccccccccccc-{marker}-out","","")],[{inputs}],[],"x86_64-linux","/nix/store/bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb-bash",[],[("builder","/nix/store/bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb-bash"),("name","{marker}"),("out","/nix/store/cccccccccccccccccccccccccccccccc-{marker}-out"),("system","x86_64-linux")"#
    )
    .into_bytes();
    if let Some(extra_env) = extra_env {
        out.extend_from_slice(br#",("raw",""#);
        out.extend_from_slice(extra_env);
        out.extend_from_slice(br#"")"#);
    }
    out.extend_from_slice(b"])");
    out
}

pub(super) fn drv_input_section_only_bytes(inputs: &[(&str, &[&str])]) -> Vec<u8> {
    let inputs = inputs
        .iter()
        .map(|(path, names)| {
            let names = names
                .iter()
                .map(|name| format!(r#""{name}""#))
                .collect::<Vec<_>>()
                .join(",");
            format!(r#"("{path}",[{names}])"#)
        })
        .collect::<Vec<_>>()
        .join(",");
    format!(r#"Derive([],[{inputs}])"#).into_bytes()
}

pub(super) fn drv_with_malformed_tail_bytes(inputs: &[(&str, &[&str])]) -> Vec<u8> {
    let inputs = inputs
        .iter()
        .map(|(path, names)| {
            let names = names
                .iter()
                .map(|name| format!(r#""{name}""#))
                .collect::<Vec<_>>()
                .join(",");
            format!(r#"("{path}",[{names}])"#)
        })
        .collect::<Vec<_>>()
        .join(",");
    format!(r#"Derive([],[{inputs}],[],[unterminated"#).into_bytes()
}

pub(super) fn structural_drv(name: &str) -> String {
    const OUT: &str = "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-shared";
    const BUILDER: &str = "/nix/store/bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb-bash";
    structural_drv_with_output_and_extra_env(name, OUT, BUILDER, &[])
}

pub(super) fn structural_drv_with_extra_env(name: &str, extra_env: &[(&str, &str)]) -> String {
    const OUT: &str = "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-shared";
    const BUILDER: &str = "/nix/store/bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb-bash";
    structural_drv_with_output_and_extra_env(name, OUT, BUILDER, extra_env)
}

pub(super) fn structural_drv_with_output_and_extra_env(
    name: &str,
    output: &str,
    builder: &str,
    extra_env: &[(&str, &str)],
) -> String {
    let extra_env = extra_env
        .iter()
        .map(|(key, value)| format!(r#",("{key}","{value}")"#))
        .collect::<String>();
    format!(
        r#"Derive([("out","{output}","","")],[],[],"x86_64-linux","{builder}",[],[("builder","{builder}"),("name","{name}"),("out","{output}"),("system","x86_64-linux"){extra_env}])"#
    )
}

pub(super) fn structural_drv_with_input(input: &str, name: &str) -> String {
    structural_drv_with_input_and_output(
        input,
        "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-shared",
        name,
    )
}

pub(super) fn structural_placeholder_drv_with_input(input: &str, name: &str) -> String {
    const BUILDER: &str = "/nix/store/bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb-bash";
    const PLACEHOLDER: &str = "/0xxkxgc4srd2mmak361la1ixni9jpyradxq3h9sgjxryvlv12gx4";
    format!(
        r#"Derive([("out","{PLACEHOLDER}","","")],[("{input}",["out"])],[],"x86_64-linux","{BUILDER}",[],[("builder","{BUILDER}"),("name","{name}"),("out","{PLACEHOLDER}"),("system","x86_64-linux")])"#
    )
}

pub(super) fn structural_drv_with_input_and_output(
    input: &str,
    output: &str,
    name: &str,
) -> String {
    const BUILDER: &str = "/nix/store/bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb-bash";
    format!(
        r#"Derive([("out","{output}","","")],[("{input}",["out"])],[],"x86_64-linux","{BUILDER}",[],[("builder","{BUILDER}"),("name","{name}"),("out","{output}"),("system","x86_64-linux")])"#
    )
}

pub(super) fn custom_store_drv(drv: String, store: &str) -> Vec<u8> {
    rewrite_store_dir_in_path_sections(drv.as_bytes(), NIX_STORE_DIR.as_bytes(), store.as_bytes())
        .expect("fixture should have valid drv shape")
        .into_owned()
}
