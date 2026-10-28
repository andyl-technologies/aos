# Package service sandbox

A package service's confinement is declared in its `serviceManagement` effect
input and rendered by the systemd handler. There is no separate permission
manifest: the typed service declaration is the only source of the unit's
privilege, and the generated reference documents it. The operator view is
[Understand native package runtime policy](../../users/aos/package-sandbox.md);
the ability machinery is described in [runtime abilities](../abilities/README.md).

| Piece | Location |
| --- | --- |
| Service input schema and feature records | `pkgs/system/_service-management/types.nix`, `policy.nix` |
| `serviceManagement` operations (`realize`, `resourceGroup`) | `pkgs/system/_service-management/module.nix` |
| Unit renderer and handler | `pkgs/system/_systemd-abilities/service-handler.py` |
| Resource-group handler | `pkgs/system/_systemd-abilities/resource-handlers.nix` |
| Preset policy | `pkgs/system/_systemd-abilities/platform/presets.nix`, `manager.nix` |

## Rendering

`realize_service` in `service-handler.py` turns one checked input into unit
text. Each optional feature record maps to a fixed set of directives; a feature
that is absent emits nothing, so unrestricted behavior is always the result of
an explicit choice in the input.

The `isolation` record selects the coarse sandbox:

| Input | Directives |
| --- | --- |
| `network` (`host`, `private`, `none`) | `PrivateNetwork=`; `none` also sets `IPAddressDeny=any` |
| `temporary_directory` | `PrivateTmp=` (`no`, `yes`, or `disconnected`) |
| `filesystem` | `ProtectSystem=` (`no`, `strict`, or `full`) |
| `home_access` | `ProtectHome=` |
| `termination_scope` | `KillMode=` (`control-group`, `process`, or `mixed`) |
| `permit_core_dumps` | `LimitCORE=` |
| `temporary_filesystems`, `host_paths` | `TemporaryFileSystem=`, `BindPaths=`, `BindReadOnlyPaths=` |
| `root_directory` | `RootDirectory=` |
| `devices` | `DevicePolicy=closed` plus one `DeviceAllow=` per device |
| `privilege = "unprivileged"` | `NoNewPrivileges=yes` |

The `policy.hardening` record carries the finer controls:

| Input | Directives |
| --- | --- |
| `privilege_bounds`, `ambient_privileges` | `CapabilityBoundingSet=`, `AmbientCapabilities=`; ambient privileges must lie within the bounds |
| `allow_privilege_escalation = false` | `NoNewPrivileges=yes` |
| `resource_control_delegation`, `resource_control_access` | `Delegate=`, `ProtectControlGroups=` |
| `device_access_scope` | `PrivateDevices=` |
| host clock, hostname, kernel log, module, and tunable access | `ProtectClock=`, `ProtectHostname=`, `ProtectKernelLogs=`, `ProtectKernelModules=`, `ProtectKernelTunables=` |
| `writable_executable_memory`, `permit_realtime`, `permit_elevated_file_identity` | `MemoryDenyWriteExecute=`, `RestrictRealtime=`, `RestrictSUIDSGID=` |
| `isolation_domains`, `isolated_identity_mapping` | `PrivateIPC=`, `PrivateMounts=`, `PrivateNetwork=`, `PrivatePIDs=`, `PrivateUsers=` |
| `network_families` | `RestrictAddressFamilies=` |
| `isolation_domain_creation` | `RestrictNamespaces=` |
| `process_visibility`, `process_filesystem_scope` | `ProtectProc=`, `ProcSubset=` |
| `operation_profile`, `operation_allow`, `operation_deny`, `denied_operation_action` | `SystemCallFilter=` (profile, then exclusions, then explicit exceptions) and `SystemCallErrorNumber=EPERM` |
| `operation_architectures` | `SystemCallArchitectures=` |
| `security_label` | `SELinuxContext=` |

The renderer rejects inconsistent requests rather than guessing: ambient
privileges outside the bounding set and overlapping allow and deny sets both
fail before any unit is written.

Other features feed the same unit. `identity` sets `User=`, `Group=`,
`SupplementaryGroups=`, `DynamicUser=`, and `UMask=`. `storage.mounts` either
asks systemd to own a standard managed directory (with one mode per directory
kind) or grants `ReadOnlyPaths=`/`ReadWritePaths=` to a path produced by a
filesystem effect. `credentials.views` become `LoadCredential=` or
`LoadCredentialEncrypted=` entries, optionally exported through an environment
variable pointing into `%d`; see [Manage secrets on AOS](../../users/aos/secrets.md).

## Resource groups

A package's services may share a resource group through the
`serviceManagement.resourceGroup` operation, which renders a slice. Group names
must match `aos-pkg-[a-z0-9-]+`. The service handler accepts a group only when
the authenticated producer reference names the declaring package and the group
is `aos-pkg-<package>` or a descendant of it, so a package cannot place its
services in another package's group.

## Enablement

Installing a package payload does not start anything. Services exist only when
enabled configuration produces `serviceManagement` effects, and the handler
publishes their units and `multi-user.target.wants` links as part of the
transaction.

The image also ships systemd preset policy. `manager.nix` writes
`99-aos-default.preset` containing `disable *`, plus
`50-aos-image-packages.preset` from `systemd.systemPresetRules` when the image
selects any rules. Host-specific preset files under `/etc/systemd/system-preset/`
can enable targets ahead of the default. Targets named `aos-pkg-<name>.target`
with no explicit `wantedBy` render `[Install] WantedBy=multi-user.target`, so
preset policy alone decides whether they start. `checks.package-preset`
(`tests/packages/preset.nix`) boots an image with one enabled and one disabled
package target and checks that only the enabled one runs, across reboots.

## High-privilege packages

The same mechanism expresses workloads that cannot be confined. K3s
(`pkgs/kubernetes/_k3s-config/module.nix`) declares unrestricted privilege
bounds, resource-control delegation, no isolation domains, and host networking,
because CNI configures host routes and the kubelet manages host cgroups. Its
service is a lifecycle wrapper, not a security boundary; the isolation boundary
for its workloads is the kubelet's pod sandbox. The privilege is visible in the
declaration and the generated reference rather than hidden in a special case.
