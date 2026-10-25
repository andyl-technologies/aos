# Native prerequisite builder

This environment runs ordinary Nix build and check derivations inside an AOS
microVM. It provides a guest execution path for the native package checks needed
by the full-system Terrane fixture. The package checks retain their original
derivations, features and test commands. The manager fixture still needs its own
successful execution and artifact review.

The VM has no external network interface. A private Firecracker Unix socket
carries the worker protocol to its real Nix daemon through vsock. Nix's
`ssh-ng://localhost` store runs a configured local stdio program; that program
only relays protocol bytes into the VM. This uses the full remote store protocol,
including output import. Nix's Unix daemon store assumes a shared filesystem and
cannot return these guest-only outputs. These behaviors are defined in the
[SSH transport implementation](https://raw.githubusercontent.com/NixOS/nix/2.34.9/src/libstore/ssh.cc)
and [store implementations](https://raw.githubusercontent.com/NixOS/nix/2.34.9/src/libstore/ssh-store.cc).

All guest store, build and temporary data resides on a private ext4 disk.
The daemon uses the ordinary sandbox with fallback disabled and actual guest
build users 30001 through 30016. The controller requires `--max-jobs 0` and one
explicit private builder, so this command has no local-host build fallback.
The probe also requires the `terrane-native-builder` feature.

From the repository root, build the environment and run a fresh probe:

```bash
native_builder_environment=$(aos-dev --release build check \
  terrane.integration.native-builder-environment --no-out-link)
native_builder_nonce=$("$native_builder_environment/python3" -c \
  'import uuid; print(uuid.uuid4().hex)')

"$native_builder_environment/python3" "$native_builder_environment/run.py" \
  --environment "$native_builder_environment" \
  --work-dir "/tmp/tnb-$native_builder_nonce" \
  --verify-probe --timeout 300 -- \
  bash tools/dev/aos-dev --release build check \
  terrane.integration.native-builder-environment.passthru.probe \
  --argstr nonce "$native_builder_nonce" \
  --no-out-link --max-jobs 0 --builders '@BUILDER@' --keep-failed
```

The nonce prevents an earlier output from satisfying this run. The controller
checks the imported original marker and kernel UID-map record, original guest
UID and namespace UID, empty effective capabilities, ext4 build/temporary/store
filesystems, nonce and exact boot identity against this VM's serial readiness
record. Success requires the build, output import and orderly VM shutdown to
finish. A serial shutdown marker alone never proves that the build succeeded.

To build the manager fixture's exact disk and the probe in the same VM, add
`-A checks.terrane.integration.native-configured-maintenance-systemd.passthru.systemDisk`
to the Nix arguments and select a suitable controller timeout and disk size.
The disk passthru uses the same image constructor and system as the original
manager test. This builds the package prerequisites without requiring nested KVM.
Run the original manager test on the KVM host after those outputs are available.

The work directory must be a new, short absolute path containing ASCII letters,
numbers, slashes, underscores and hyphens. Its parent must reside on disk.
Successful runs remove their owned VM disks and relay, retaining logs and a
receipt for review. Failed runs preserve their disks and diagnostics. Inspect
the failure, retain the required evidence, and remove these owned resources
after diagnosis. The controller creates no host mounts or persistent host
daemon configuration.
