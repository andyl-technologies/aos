# Phase 1: Docker Environment and Guix Bootstrap

**Phase Number:** 1

## Objective

Set up a reproducible Docker-based Guix build environment on macOS using the standard Guix binary tarball, configure persistent store volumes with overlay caching, create the initial ANDYL channel skeleton, and verify that `guix-daemon` runs correctly inside the container.

## Prerequisites

- macOS workstation with Docker Desktop (or OrbStack) installed
- At minimum 8 CPU cores, 16 GB RAM, 100 GB disk allocated to Docker
- Git configured with GPG signing capability
- Basic familiarity with GNU Guix and Guile Scheme

## Deliverables

- `docker/Dockerfile` -- Single-stage Dockerfile that installs the Guix binary tarball from ftp.gnu.org into a `debian:bookworm-slim` base image (pinned by digest)
- `docker/entrypoint.sh` -- Entrypoint script that sets up OverlayFS on `/gnu/store` and starts `guix-daemon`
- `docker/docker-compose.yml` -- Compose file with named volumes, overlay mount, and resource limits
- `channel/.guix-channel` -- Channel metadata file
- `channel/.guix-authorizations` -- GPG-authorized committer list
- `channel/andyl/packages/` -- Empty package module directory structure
- `justfile` -- Initial build orchestration targets (`docker-build`, `docker-shell`, `docker-up`, `docker-down`)
- `.env` -- Default environment variable configuration
- Passing CI smoke test: `guix describe` returns valid output inside the container

## Detailed Task Checklist

### 1.1 Docker Environment Setup

- [ ] Verify Docker Desktop resource allocation (8+ CPUs, 16+ GB RAM, 100+ GB disk)
- [ ] Confirm Docker is using VirtioFS for file sharing (macOS 12.5+) or switch to OrbStack
- [ ] Confirm Docker can run linux/amd64 containers (check `docker info --format '{{.OSType}}'`)
- [ ] If on Apple Silicon, decide target architecture strategy (native aarch64 vs. x86_64 emulation vs. remote builder)

### 1.2 Dockerfile -- Guix Binary Tarball Installation

- [ ] Create `docker/` directory at project root
- [ ] Write Dockerfile based on `debian:bookworm-slim`
- [ ] Pin the Debian base image by digest (`@sha256:...`)
- [ ] Add build arg `GUIX_VERSION` for the tarball version
- [ ] Add build arg `GUIX_ARCH` for the target architecture (e.g. `x86_64-linux`)
- [ ] Install runtime dependencies: `bash`, `ca-certificates`, `coreutils`, `curl`, `git`, `gnupg`, `less`, `locales`, `nscd`, `wget`, `xz-utils`
- [ ] Generate `en_US.UTF-8` locale
- [ ] Download the Guix binary tarball from `ftp.gnu.org/gnu/guix/`
- [ ] Extract the tarball to populate `/gnu/store` and `/var/guix`
- [ ] Create guix profile symlinks (`/usr/local/bin/guix`, `/usr/local/bin/guix-daemon`)
- [ ] Create `guixbuild` system group
- [ ] Create 10 build users (`guixbuilder01` through `guixbuilder10`) in the `guixbuild` group
- [ ] Set `GUIX_DAEMON_OPTS` to `--no-substitutes --max-jobs=4 --cores=0`
- [ ] Copy and chmod the entrypoint script
- [ ] Set `ENTRYPOINT` and `CMD`

### 1.3 Entrypoint Script

- [ ] Create `docker/entrypoint.sh`
- [ ] If `GUIX_STORE_OVERLAY=1`, set up OverlayFS on `/gnu/store` before starting the daemon (image's store as lower layer, Docker volume as upper layer)
- [ ] Start `guix-daemon` in the background with `--build-users-group=guixbuild`, `--no-substitutes`, and configurable `--max-jobs` / `--cores` from environment variables
- [ ] Implement a 30-second readiness loop that checks `guix describe`
- [ ] If `/andyl-channel` is mounted, write a `channels.scm` file to `~/.config/guix/channels.scm` pointing to `file:///andyl-channel`
- [ ] Run `guix pull` with the custom channels file
- [ ] `exec "$@"` to hand off to the user-specified command

### 1.4 Docker Compose Configuration

- [ ] Create `docker/docker-compose.yml`
- [ ] Define the `guix-builder` service referencing the Dockerfile
- [ ] Define named volume `gnu-store` mounted at `/gnu/store`
- [ ] Define named volume `guix-var` mounted at `/var/guix`
- [ ] Define bind mount `../channel:/andyl-channel:ro`
- [ ] Set environment variables `GUIX_MAX_JOBS=4` and `GUIX_CORES=0`
- [ ] Add `cap_add: SYS_ADMIN` and `security_opt: seccomp:unconfined` for namespace isolation and OverlayFS mount
- [ ] Set resource limits: 8 CPUs, 16 GB memory
- [ ] Define the named volumes with `driver: local`
- [ ] Create `docker/docker-compose.overlay.yml` with overlay-specific configuration
- [ ] Define named volume `store-upper` for OverlayFS upper layer
- [ ] Set `GUIX_STORE_OVERLAY=1` environment variable in overlay compose file

### 1.5 Channel Skeleton

- [ ] Create `channel/` directory at project root
- [ ] Create `channel/.guix-channel` with channel metadata (name `andyl`, version 0, no dependencies)
- [ ] Create `channel/.guix-authorizations` with placeholder GPG fingerprints
- [ ] Create directory structure:
  - [ ] `channel/andyl/packages/` (for package definitions)
  - [ ] `channel/andyl/system/` (for system configuration)
  - [ ] `channel/andyl/build/` (for optional custom build systems)
- [ ] Create a placeholder `channel/andyl/packages/hello.scm` with a trivial package definition to verify the channel loads
- [ ] Initialize `channel/` as a Git repository (or subdirectory of main repo)
- [ ] Make an initial signed commit

### 1.6 GPG Key Setup for Channel Authentication

- [ ] Generate an RSA 4096 GPG key for the project (or designate an existing key)
- [ ] Record the key fingerprint
- [ ] Update `channel/.guix-authorizations` with the real fingerprint
- [ ] Configure Git to sign commits with this key (`git config commit.gpgsign true`)
- [ ] Document key management procedure

### 1.7 justfile Initial Targets

- [ ] Create `justfile` at project root
- [ ] Add `default` recipe that runs `just --list`
- [ ] Add `docker-build` recipe: `docker compose -f docker/docker-compose.yml build`
- [ ] Add `docker-shell` recipe: interactive bash shell in the builder container
- [ ] Add `docker-shell-overlay` recipe: interactive shell with overlay-backed `/gnu/store`
- [ ] Add `docker-up` recipe: start builder detached
- [ ] Add `docker-down` recipe: stop builder
- [ ] Add `docker-volumes` recipe: show volume sizes
- [ ] Add `store-overlay-diff` recipe: show newly built packages in overlay upper layer
- [ ] Add `store-overlay-reset` recipe: discard all cached builds from overlay
- [ ] Add `repl` recipe: `guix repl` inside the container
- [ ] Add `channel-pull` recipe: run `guix pull` with the custom channel
- [ ] Add `store-size` recipe: `du -sh /gnu/store/`

### 1.8 Environment Configuration

- [ ] Create `.env` file with defaults: `GUIX_MAX_JOBS=4`, `GUIX_CORES=0`, `COMPOSE_PROJECT_NAME=andyl-os`
- [ ] Document environment variables in the justfile or a README

### 1.9 Verification and Smoke Tests

- [ ] Build the Docker image: `just docker-build`
- [ ] Start the container: `just docker-up`
- [ ] Verify `guix-daemon` is running: `guix describe` succeeds
- [ ] Verify the channel is loaded: `guix describe` shows the `andyl` channel
- [ ] Build the placeholder package: `guix build -L /andyl-channel/andyl/packages/ andyl-hello`
- [ ] Verify named volumes persist: stop container, restart, confirm `/gnu/store` contents survive
- [ ] Verify overlay mount: run `just docker-shell-overlay`, build a package, confirm it appears in the overlay upper layer with `just store-overlay-diff`
- [ ] Verify `--no-substitutes` is enforced: attempt to build a package that would require upstream substitutes and confirm it builds from source
- [ ] Run `just store-size` and confirm output

## Acceptance Criteria

1. `just docker-build` completes without errors (installs Guix binary tarball)
2. `just docker-shell` drops into a bash shell where `guix describe` shows the Guix version and the ANDYL channel
3. A trivial package can be built from the custom channel inside the container
4. Docker volumes `gnu-store` and `guix-var` persist across container restarts
5. No upstream Guix substitutes are used (all builds from source via `--no-substitutes`)
6. OverlayFS overlay mount on `/gnu/store` works correctly with the shared volume

## Risks and Mitigations

| Risk | Likelihood | Impact | Mitigation |
|------|-----------|--------|------------|
| Guix binary tarball version incompatibility | Low | Blocks progress | Pin the tarball version via build arg; test with known-good version |
| Docker Desktop resource limits too low | Medium | Build OOMs or is extremely slow | Document minimum requirements; add resource checks to justfile |
| Apple Silicon aarch64 vs. x86_64 mismatch | High (if on M-series Mac) | Slow builds via QEMU emulation | Start with native aarch64 builds; plan remote x86_64 builder for production images |
| `/gnu/store` volume grows beyond available disk | Low | Build failures | Add `store-size` monitoring; document disk requirements; use overlay to separate image store from build cache |
| Channel authentication failure (GPG) | Medium | `guix pull` fails | Test signed commits early; keep key management documented |

## Estimated Complexity

**M (Medium)**

This phase installs the Guix binary tarball in Docker, which is straightforward. The OverlayFS setup adds some complexity. Most risk comes from Docker resource configuration and channel authentication setup.
