# Understand native package runtime policy

AOS activates package services through typed abilities selected in the final
system module fixed point. A package publishes a checked module and a derived
package contract. The system selects providers, validates their requests, and
hands concrete effects to native resource adapters.

Runtime policy is therefore owned by the same declaration that owns the
resource. There is no separate runtime-policy metadata artifact or generated
package target. Registry verification authenticates the package and its
contract; the selected provider and host policy determine the realized units,
network rules, credentials, and other effects.

## Know when runtime policy applies

A package payload by itself is inert. Installing an executable into a profile
does not start a service or confer access to host resources. Runtime effects
exist only when the system selects an implementation and a typed request
contributes desired resources to the final fixed point.

Inspect the selected package contract and the evaluated system before enabling
a workload. The contract identifies the interfaces, implementations,
requirements, guarantees, handlers, and artifact selectors that the package
can contribute. The final system views identify which provider was selected and
which concrete resources it owns.

## Keep policy with its native owner

Declare each resource through its typed interface:

- service lifecycle and unit configuration belong to the service-management
  provider;
- listener and firewall intent belongs to the network-policy provider;
- configuration files and credentials belong to the configuration provider;
- kernel, storage, and boot effects belong to their corresponding native
  providers.

The provider translates those declarations into backend-specific effects. Do
not copy a unit catalog, permission list, credential table, or activation graph
into package metadata. A second inventory can diverge from the final module
configuration and cannot be an authority for runtime behavior.

Host-wide effects deserve the same review as direct service privileges. A
firewall change affects other workloads, a writable path can carry control
data, and a kernel setting changes a shared boundary. Review the concrete
selected resource and its native adapter rather than inferring policy from the
package name.

## Keep configuration and secrets separate

Public configuration is checked against typed options from authenticated
package modules. Secret values use opaque references and systemd credentials;
they are not evaluated as Nix values or retained in package contracts.
Permission to consume one credential does not imply access to another
package's credentials or to general secret storage.

See [Manage secrets on AOS](secrets.md) for supported delivery paths. Never put
secret bytes in a package option, environment value rendered into the store, or
package metadata.

## Verify the active system

Start with the selected package and module views:

```sh
apm list --installed --system
apm show PACKAGE --system
systemctl status UNIT.service
systemctl cat UNIT.service
```

Then inspect the native subsystem that owns the resource. For example, inspect
`nft list ruleset` for firewall effects and `systemctl show` for service
hardening and credentials. Check service logs and behavior as well as static
settings.

Registry signatures prove which owner authorized exact package bytes. They do
not prove that the program is benign, that the selected host policy is suitable
for a deployment, or that a running host has not been compromised. Treat
registry admission, source provenance, typed resource policy, boot integrity,
monitoring, and recovery as separate controls.
