# Packages in AOS containers

Each AOS system variation has a default container projection built through the
same image backend. The golden container provides AOS/APM, a shell, basic
utilities, and runtime dependencies. Pull the published image and install
additional packages through APM. Building a derived image is optional.

Packages use the same payload and native module declarations on machines and
in containers. The target selects handlers for their abilities. Packages can
install files and configuration independently of optional managed services.
Explicitly enabling a managed service requires a service-management handler.
Use generated package documentation to inspect each package's options and
the abilities it consumes or exposes.

Container policy preserves the runtime's hostname and networking by default
and leaves host-kernel tuning to the host. Installing an init implementation
does not enable those host defaults. Explicit kernel or network configuration
still declares effects that must have suitable handlers and runtime support.
Configuration files are reconciled directly in the writable layer;
image-overlay declarations require a handler supplied by the target.

## Installing while building an image

For a derived image, package installation runs in ordinary Dockerfile steps.
Replace `package-name` with the package you want to install:

```dockerfile
FROM registry.example.com/aos:stable
RUN apm install package-name
```

APM initializes the embedded local package/store state when the entrypoint has
not run yet. It evaluates the proposed package set before activation. An enabled
effect with no handler rejects the transaction, identifying the missing
operation; unrelated effects are not applied as a fallback.

Installation effects establish files and configuration immediately. Startup
effects remain explicitly pending. Consecutive `RUN apm install` steps compose
the latest desired package configuration without starting daemons in the
builder. Pending outputs are not available as if their operations had executed.

## Selecting an init implementation

An init implementation consumes `initSystem.install` and can provide other
abilities, including service management. It does not need an external service
handler to run as init. Install the chosen init package through APM during the
image build and configure it through its native module options.

The init effect prepares the retained executable and arguments. The inherited
AOS entrypoint reads that configuration when the finished container starts and
executes the selected init. Service activation resumes when that manager is
ready. Packages can leave their optional managed services disabled when no
manager is selected; use their generated options documentation to configure
service enablement.

Local accounts and groups are installation effects: they are available before
the selected manager starts early services. Their normal ownership receipts
remain authoritative during startup, reconfiguration, and removal.

Each writable directory has one active owner. A managed service delegates its
storage to the service manager; standalone configuration uses filesystem
effects. When service management is removed, the manager preserves persistent
data and releases its directory layout before standalone effects resume.

The container launcher must provide the environment required by the selected
init and service features. Installation during a Docker build does not establish
that those runtime features are available. Explicit workload arguments override
the default init selection, so the same image can run a specific command.

## Installed state and recovery

Package publication records real installation results and the exact startup
effects that remain pending. Startup converges the latest desired generation;
it does not replay obsolete service configurations from earlier build steps.
Interrupted installation and startup use the normal durable journals.

Changing init in a running container prepares its next startup. Restart retains
the container's writable state; recreating it requires retaining package/store
state explicitly or using a derived image that already contains it. Read-only
containers can use installed packages but cannot mutate package state.

Service readiness identifies the current PID-1 lifetime and exact selected init
command. Selecting a different executable or arguments leaves startup effects
pending until the selected init is running.

The [runtime ability guide](runtime-abilities.md) describes native declarations,
typed output dependencies, handler composition, and missing-handler errors.
