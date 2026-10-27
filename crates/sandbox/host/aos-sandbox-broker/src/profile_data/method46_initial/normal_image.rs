//! Defines normal-owner command and immutable runtime comparison DATA.
//!
//! The enclosing initial profile version commits this nested JSON inventory:
//!
//! ```text
//! executable + loader + sorted runtime_files + sorted closure_roots + argv
//! ```
//!
//! Shape checks admit neither a process nor a key. Genuine startup owners must
//! separately retain and compare PID1 configuration and actual immutable files.

use super::*;

const MAXIMUM_ARGUMENTS: usize = 128;
const MAXIMUM_ARGUMENT_BYTES: usize = 32 * 1024;

/// Describes the selected normal command without executing or admitting it.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Method46NormalImageDataV1 {
    /// Pins the selected normal Controller or Storage executable.
    pub executable: ImagePinV1,
    /// Pins its native dynamic loader.
    pub loader: ImagePinV1,
    /// Lists strictly sorted immutable runtime-file pins, including both images.
    #[serde(deserialize_with = "deserialize_bounded_profile_sequence_v1")]
    pub runtime_files: Vec<ImagePinV1>,
    /// Lists strictly sorted canonical store roots containing every runtime pin.
    #[serde(deserialize_with = "deserialize_bounded_profile_sequence_v1")]
    pub closure_roots: Vec<String>,
    /// Names the exact command arguments, with the executable as argument zero.
    #[serde(deserialize_with = "deserialize_bounded_profile_sequence_v1")]
    pub argv: Vec<String>,
}

impl Method46NormalImageDataV1 {
    /// Compares bounded command and inventory shape for the selected purpose.
    ///
    /// # Errors
    /// Refuses another role's executable, unbounded or malformed argv, empty,
    /// unsorted or foreign runtime inventories, sentinel digests, missing image
    /// pins and paths outside their canonical declared store roots.
    pub fn require_shape_data_v1(
        &self,
        role: Method46InitialServiceRoleV1,
    ) -> Result<(), Method46InitialProfileDataErrorV3> {
        let executable = match role {
            Method46InitialServiceRoleV1::ControllerStorageClient => "/bin/aos-sandboxd",
            Method46InitialServiceRoleV1::StorageBroker => "/bin/aos-storaged",
        };
        if !self.executable.path.ends_with(executable)
            || self.executable.path == self.loader.path
            || self.runtime_files.is_empty()
            || self.runtime_files.len() > MAXIMUM_RUNTIME_FILES
            || self.closure_roots.is_empty()
            || self.closure_roots.len() > MAXIMUM_RUNTIME_FILES
            || self
                .runtime_files
                .windows(2)
                .any(|pair| pair[0].path >= pair[1].path)
            || self.closure_roots.windows(2).any(|pair| pair[0] >= pair[1])
            || self.argv.is_empty()
            || self.argv.len() > MAXIMUM_ARGUMENTS
            || self.argv.first() != Some(&self.executable.path)
            || self
                .argv
                .iter()
                .any(|argument| argument.len() > 1024 || argument.contains('\0'))
            || self
                .argv
                .iter()
                .try_fold(0_usize, |sum, argument| sum.checked_add(argument.len()))
                .is_none_or(|bytes| bytes > MAXIMUM_ARGUMENT_BYTES)
        {
            return Err(Method46InitialProfileDataErrorV3);
        }

        for root in &self.closure_roots {
            require_store_path(root).map_err(|_| Method46InitialProfileDataErrorV3)?;
            if Path::new(root).components().count() != 4 {
                return Err(Method46InitialProfileDataErrorV3);
            }
        }
        for pin in self
            .runtime_files
            .iter()
            .chain([&self.executable, &self.loader])
        {
            require_store_path(&pin.path).map_err(|_| Method46InitialProfileDataErrorV3)?;
            if pin.sha256 == [0; 32]
                || !self.closure_roots.iter().any(|root| {
                    Path::new(&pin.path)
                        .strip_prefix(root)
                        .is_ok_and(|suffix| suffix.components().count() > 0)
                })
            {
                return Err(Method46InitialProfileDataErrorV3);
            }
        }
        for required in [&self.executable, &self.loader] {
            if !self
                .runtime_files
                .iter()
                .any(|pin| pin.path == required.path && pin.sha256 == required.sha256)
            {
                return Err(Method46InitialProfileDataErrorV3);
            }
        }
        Ok(())
    }
}

#[cfg(test)]
pub(super) fn test_fixture(role: Method46InitialServiceRoleV1) -> serde_json::Value {
    use serde_json::json;

    let package = "/nix/store/77777777777777777777777777777777-aos-sandbox-services-0.1.0";
    let command = match role {
        Method46InitialServiceRoleV1::ControllerStorageClient => "aos-sandboxd",
        Method46InitialServiceRoleV1::StorageBroker => "aos-storaged",
    };
    let executable = json!({"path": format!("{package}/bin/{command}"), "sha256": ([1_u8; 32])});
    let loader = json!({"path": format!("{package}/lib/ld.so"), "sha256": ([2_u8; 32])});
    json!({
        "executable": executable,
        "loader": loader,
        "runtime_files": [executable, loader],
        "closure_roots": [package],
        "argv": [format!("{package}/bin/{command}"), "913", "913"],
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn normal_runtime_pins_require_the_selected_complete_inventory() {
        let role = Method46InitialServiceRoleV1::StorageBroker;
        let decode = |value| serde_json::from_value::<Method46NormalImageDataV1>(value).unwrap();
        assert!(
            decode(test_fixture(role))
                .require_shape_data_v1(role)
                .is_ok()
        );
        assert!(
            decode(test_fixture(role))
                .require_shape_data_v1(Method46InitialServiceRoleV1::ControllerStorageClient)
                .is_err()
        );

        for changed in [
            "missing-loader",
            "wrong-digest",
            "foreign-root",
            "duplicate-pin",
            "aliased-loader",
        ] {
            let mut value = test_fixture(role);
            match changed {
                "missing-loader" => {
                    value["runtime_files"].as_array_mut().unwrap().pop();
                }
                "wrong-digest" => value["loader"]["sha256"] = json!(([3_u8; 32])),
                "foreign-root" => {
                    value["closure_roots"] =
                        json!(["/nix/store/88888888888888888888888888888888-foreign"])
                }
                "duplicate-pin" => value["runtime_files"][1] = value["runtime_files"][0].clone(),
                "aliased-loader" => value["loader"] = value["executable"].clone(),
                _ => unreachable!(),
            }
            assert!(decode(value).require_shape_data_v1(role).is_err());
        }
    }

    #[test]
    fn normal_command_rejects_foreign_argv_and_all_overflow_shapes() {
        let role = Method46InitialServiceRoleV1::StorageBroker;
        let original = test_fixture(role);
        let command = original["argv"][0].clone();
        for argv in [
            json!([]),
            json!(["/foreign/image"]),
            json!([command, "bad\u{0}argument"]),
            json!([command, "x".repeat(1025)]),
            json!(vec![command.clone(); MAXIMUM_ARGUMENTS + 1]),
            json!(([vec![command.clone()], vec![json!("x".repeat(1024)); 33]].concat())),
        ] {
            let mut value = original.clone();
            value["argv"] = argv;
            let decoded: Method46NormalImageDataV1 = serde_json::from_value(value).unwrap();
            assert!(decoded.require_shape_data_v1(role).is_err());
        }
    }

    #[test]
    fn nested_normal_schema_rejects_unknown_fields_and_unbounded_sequence_decoding() {
        let role = Method46InitialServiceRoleV1::StorageBroker;
        let mut unknown = test_fixture(role);
        unknown["alternate_executable"] = json!("/foreign/image");
        assert!(serde_json::from_value::<Method46NormalImageDataV1>(unknown).is_err());

        let mut excessive = test_fixture(role);
        let mut arguments = vec![json!("argument"); MAXIMUM_RUNTIME_FILES];
        arguments.push(json!(17));
        excessive["argv"] = json!(arguments);
        let error = serde_json::from_value::<Method46NormalImageDataV1>(excessive)
            .err()
            .unwrap();
        assert!(error.to_string().contains("exceeds512"));
        assert!(!error.to_string().contains("expected a string"));
    }
}
