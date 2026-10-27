//! Compares the selected stopped owner's original PID1 command and MAC subject.
//!
//! These predicates borrow the finite native before/after samples. Historical
//! ExecStart execution metadata is not a live PID assertion: the surrounding
//! stopped-phase reader independently requires inactive/dead and MainPID zero.
//! No command is executed, and complete unit configuration remains separate.

use super::*;
use crate::systemd_property_data::{explicit_context, single_exec_start};
use aos_sandbox_broker::profile_data::method46_initial::normal_image::Method46NormalImageDataV1;

pub(super) fn require_command(
    values: &[aos_systemd_client::OwnedValue],
    role: Method46InitialServiceRoleV1,
    profile: &Method46NormalImageDataV1,
) -> Result<(), Method46InitialStartupClosedV1> {
    let [command, subject] = values else {
        return Err(Method46InitialStartupClosedV1);
    };
    let expected_context = match role {
        Method46InitialServiceRoleV1::ControllerStorageClient => {
            "system_u:system_r:aos_sandbox_controller_t"
        }
        Method46InitialServiceRoleV1::StorageBroker => "system_u:system_r:aos_sandbox_storage_t",
    };
    let command = single_exec_start(command).ok_or(Method46InitialStartupClosedV1)?;
    if command.path != profile.executable.path
        || command.argv.len() != profile.argv.len()
        || !command.argv.iter().zip(&profile.argv).all(
            |(actual, expected)| matches!(actual, Value::Str(value) if value.as_str() == expected),
        )
        || explicit_context(subject) != Some(expected_context)
    {
        return Err(Method46InitialStartupClosedV1);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use aos_sandbox_broker::profile_data::schema::ImagePinV1;
    use aos_systemd_client::OwnedValue;

    fn value(input: impl Into<Value<'static>>) -> OwnedValue {
        OwnedValue::try_from(input.into()).unwrap()
    }

    fn profile() -> Method46NormalImageDataV1 {
        let image = ImagePinV1 {
            path: "/nix/store/77777777777777777777777777777777-aos-sandbox-services-0.1.0/bin/aos-storaged".into(),
            sha256: [1; 32],
        };
        Method46NormalImageDataV1 {
            executable: image.clone(),
            loader: image.clone(),
            runtime_files: vec![image.clone()],
            closure_roots: Vec::new(),
            argv: vec![image.path, "913".into(), "913".into()],
        }
    }

    fn properties(profile: &Method46NormalImageDataV1, pid: u32) -> [OwnedValue; 2] {
        [
            value(vec![(
                profile.executable.path.clone(),
                profile.argv.clone(),
                false,
                1_u64,
                2_u64,
                3_u64,
                4_u64,
                pid,
                0_i32,
                0_i32,
            )]),
            value((false, "system_u:system_r:aos_sandbox_storage_t".to_owned())),
        ]
    }

    #[test]
    fn selected_command_accepts_historical_pid_without_treating_it_as_a_live_owner() {
        let profile = profile();
        for pid in [0, 42, u32::MAX] {
            assert!(
                require_command(
                    &properties(&profile, pid),
                    Method46InitialServiceRoleV1::StorageBroker,
                    &profile
                )
                .is_ok()
            );
        }
    }

    #[test]
    fn selected_command_rejects_changed_arguments_executable_subject_and_tuple_shapes() {
        let profile = profile();
        let role = Method46InitialServiceRoleV1::StorageBroker;
        let original = properties(&profile, 42);
        assert!(
            require_command(
                &original,
                Method46InitialServiceRoleV1::ControllerStorageClient,
                &profile
            )
            .is_err()
        );
        for subject in [
            value((false, "system_u:system_r:init_t".to_owned())),
            value((true, "system_u:system_r:aos_sandbox_storage_t".to_owned())),
            value("system_u:system_r:aos_sandbox_storage_t".to_owned()),
        ] {
            assert!(
                require_command(&[original[0].try_clone().unwrap(), subject], role, &profile)
                    .is_err()
            );
        }
        for (path, argv, ignore) in [
            ("/foreign/image".to_owned(), profile.argv.clone(), false),
            (
                profile.executable.path.clone(),
                vec![profile.executable.path.clone()],
                false,
            ),
            (profile.executable.path.clone(), profile.argv.clone(), true),
        ] {
            let command = value(vec![(
                path, argv, ignore, 0_u64, 0_u64, 0_u64, 0_u64, 0_u32, 0_i32, 0_i32,
            )]);
            assert!(
                require_command(&[command, original[1].try_clone().unwrap()], role, &profile)
                    .is_err()
            );
        }
        assert!(require_command(&[], role, &profile).is_err());
        assert!(
            require_command(
                &[
                    value(Vec::<String>::new()),
                    original[1].try_clone().unwrap()
                ],
                role,
                &profile
            )
            .is_err()
        );
    }
}
