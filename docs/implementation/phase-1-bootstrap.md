# Phase 1: Docker Environment and Guix Bootstrap

**Phase Number:** 1

## Objective

Set up a reproducible Docker-based Guix build environment on macOS using the full hex0 source bootstrap, configure persistent store volumes with overlay caching, create the initial ANDYL channel skeleton, and verify that `guix-daemon` runs correctly inside the container.

## Prerequisites

- macOS workstation with Docker Desktop (or OrbStack) installed
- At minimum 8 CPU cores, 16 GB RAM, 100 GB disk allocated to Docker
- Git configured with GPG signing capability
- Basic familiarity with GNU Guix and Guile Scheme

## Deliverables

- `docker/Dockerfile` -- Multi-stage Dockerfile implementing the full hex0 bootstrap chain from `scratch` (hex0 -> hex1 -> hex2 -> M0 -> M1 -> M2-Planet -> Mes -> MesCC -> TinyCC -> GCC 4.6 -> GCC 7 -> GCC 13 -> glibc -> Guix)
- `docker/entrypoint.sh` -- Entrypoint script that sets up OverlayFS on `/gnu/store` and starts `guix-daemon`
- `docker/docker-compose.yml` -- Compose file with named volumes, overlay mount, and resource limits
- `channel/.guix-channel` -- Channel metadata file
- `channel/.guix-authorizations` -- GPG-authorized committer list
- `channel/andyl/packages/` -- Empty package module directory structure
- `justfile` -- Initial build orchestration targets (`docker-build`, `docker-build-stage`, `docker-shell`, `docker-up`, `docker-down`)
- `.env` -- Default environment variable configuration
- Passing CI smoke test: `guix describe` returns valid output inside the container

## Detailed Task Checklist

### 1.1 Docker Environment Setup

- [ ] Verify Docker Desktop resource allocation (8+ CPUs, 16+ GB RAM, 100+ GB disk)
- [ ] Confirm Docker is using VirtioFS for file sharing (macOS 12.5+) or switch to OrbStack
- [ ] Confirm Docker can run linux/amd64 containers (check `docker info --format '{{.OSType}}'`)
- [ ] If on Apple Silicon, decide target architecture strategy (native aarch64 vs. x86_64 emulation vs. remote builder)

### 1.2 Dockerfile -- Hex0 Full-Source Bootstrap Stages

- [ ] Create `docker/` directory at project root
- [ ] Write Dockerfile Stage 1 (`hex0-seeds`) based on `debian:bookworm-slim`
- [ ] Pin the Debian base image by digest (`@sha256:...`)
- [ ] Add build arg `SEEDS_VERSION` for bootstrap-seeds release tag
- [ ] Install minimal fetch dependencies: `wget`, `ca-certificates`, `xz-utils`, `patch`, `make`, `gcc`, `libc6-dev`
- [ ] Download and extract bootstrap-seeds archive from GitHub (oriansj/bootstrap-seeds)
- [ ] Write Dockerfile Stage 2 (`mescc-tools`): build hex0 -> hex1 -> hex2 -> M0 -> M1 -> M2-Planet
- [ ] Structure each compilation step as a separate `RUN` instruction for Docker layer caching
- [ ] Write Dockerfile Stage 3 (`mes-build`): build GNU Mes with M2-Planet
- [ ] Write Dockerfile Stage 4 (`tinycc-build`): build TinyCC with MesCC
- [ ] Write Dockerfile Stage 5 (`gcc4-build`): build GCC 4.6.4 with TinyCC
- [ ] Write Dockerfile Stage 6 (`gcc7-build`): build GCC 7.x with GCC 4.6.4
- [ ] Write Dockerfile Stage 7 (`gcc13-build`): build GCC 13.x with GCC 7.x
- [ ] Write Dockerfile Stage 8 (`glibc-build`): build glibc with modern GCC
- [ ] Write Dockerfile Stage 9 (`guix-from-source`): build Guix daemon and CLI from source
- [ ] Write Dockerfile Stage 10 (`guix-clean`): `FROM scratch`, copy only `/gnu` and `/var/guix`
- [ ] Verify each bootstrap stage builds successfully with `docker build --target <stage>`
- [ ] Verify Docker layer caching works: rebuild and confirm earlier stages show `CACHED`

### 1.3 Dockerfile -- Runtime Environment Stage

- [ ] Write Dockerfile Stage 11 (`guix-builder`) based on `debian:bookworm-slim`
- [ ] Pin the same Debian digest as Stage 1
- [ ] Install runtime dependencies: `bash`, `coreutils`, `curl`, `git`, `gnupg`, `less`, `locales`, `nscd`, `xz-utils`
- [ ] Generate `en_US.UTF-8` locale
- [ ] Set `LANG` and `LC_ALL` environment variables
- [ ] Copy `/gnu` and `/var/guix` from the `guix-clean` scratch stage (not from any Debian stage)
- [ ] Create symlink: `/usr/local/bin/guix` pointing to the current-guix profile binary
- [ ] Create `guixbuild` system group
- [ ] Create 10 build users (`guixbuilder01` through `guixbuilder10`) in the `guixbuild` group
- [ ] Set `GUIX_DAEMON_OPTS` to `--no-substitutes --max-jobs=4 --cores=0`
- [ ] Copy and chmod the entrypoint script
- [ ] Set `ENTRYPOINT` and `CMD`

### 1.4 Entrypoint Script

- [ ] Create `docker/entrypoint.sh`
- [ ] If `GUIX_STORE_OVERLAY=1`, set up OverlayFS on `/gnu/store` before starting the daemon (image's store as lower layer, Docker volume as upper layer)
- [ ] Start `guix-daemon` in the background with `--build-users-group=guixbuild`, `--no-substitutes`, and configurable `--max-jobs` / `--cores` from environment variables
- [ ] Implement a 30-second readiness loop that checks `guix describe`
- [ ] If `/andyl-channel` is mounted, write a `channels.scm` file to `~/.config/guix/channels.scm` pointing to `file:///andyl-channel`
- [ ] Run `guix pull` with the custom channels file
- [ ] `exec "$@"` to hand off to the user-specified command

### 1.5 Docker Compose Configuration

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

### 1.6 Channel Skeleton

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

### 1.7 GPG Key Setup for Channel Authentication

- [ ] Generate an RSA 4096 GPG key for the project (or designate an existing key)
- [ ] Record the key fingerprint
- [ ] Update `channel/.guix-authorizations` with the real fingerprint
- [ ] Configure Git to sign commits with this key (`git config commit.gpgsign true`)
- [ ] Document key management procedure

### 1.8 justfile Initial Targets

- [ ] Create `justfile` at project root
- [ ] Add `default` recipe that runs `just --list`
- [ ] Add `docker-build` recipe: `docker compose -f docker/docker-compose.yml build` (runs full hex0 bootstrap)
- [ ] Add `docker-build-stage STAGE` recipe: build a specific intermediate bootstrap stage for debugging
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

### 1.9 Environment Configuration

- [ ] Create `.env` file with defaults: `GUIX_MAX_JOBS=4`, `GUIX_CORES=0`, `COMPOSE_PROJECT_NAME=andyl-os`
- [ ] Document environment variables in the justfile or a README

### 1.10 Verification and Smoke Tests

- [ ] Build the Docker image: `just docker-build` (full hex0 bootstrap -- expect many hours on first run)
- [ ] Verify each intermediate bootstrap stage individually: `just docker-build-stage mescc-tools`, `just docker-build-stage gcc4-build`, etc.
- [ ] Verify Docker layer caching: rebuild and confirm earlier stages show `CACHED` in `--progress=plain` output
- [ ] Start the container: `just docker-up`
- [ ] Verify `guix-daemon` is running: `guix describe` succeeds
- [ ] Verify the channel is loaded: `guix describe` shows the `andyl` channel
- [ ] Build the placeholder package: `guix build -L /andyl-channel/andyl/packages/ andyl-hello`
- [ ] Verify named volumes persist: stop container, restart, confirm `/gnu/store` contents survive
- [ ] Verify overlay mount: run `just docker-shell-overlay`, build a package, confirm it appears in the overlay upper layer with `just store-overlay-diff`
- [ ] Verify `--no-substitutes` is enforced: attempt to build a package that would require upstream substitutes and confirm it builds from source
- [ ] Verify no binary tarball artifacts exist: confirm the image contains no pre-built Guix binaries other than what was bootstrapped from hex0
- [ ] Run `just store-size` and confirm output

## Acceptance Criteria

1. `just docker-build` completes without errors (full hex0 bootstrap chain from `scratch`)
2. `just docker-shell` drops into a bash shell where `guix describe` shows the Guix version and the ANDYL channel
3. A trivial package can be built from the custom channel inside the container
4. Docker volumes `gnu-store` and `guix-var` persist across container restarts
5. No upstream Guix substitutes are used (all builds from source)
6. No binary tarball is downloaded -- the entire toolchain is bootstrapped from the hex0 seed inside Docker
7. Docker layer caching works: rebuilding after a change to a late stage does not rebuild early stages
8. OverlayFS overlay mount on `/gnu/store` works correctly with the shared volume

## Risks and Mitigations

| Risk | Likelihood | Impact | Mitigation |
|------|-----------|--------|------------|
| Full hex0 bootstrap takes many hours (4-8+) on first run | High | Slow initial iteration | Use Docker layer caching aggressively; each bootstrap stage is a separate Docker stage. Only rebuild what changed. |
| Bootstrap stage failure (obscure build error in early stages) | High | Blocks all progress | Study upstream commencement.scm; build and verify each stage individually with `docker-build-stage` |
| Docker Desktop resource limits too low | Medium | Build OOMs or is extremely slow | Document minimum requirements; add resource checks to justfile |
| Apple Silicon aarch64 vs. x86_64 mismatch | High (if on M-series Mac) | Slow builds via QEMU emulation | Start with native aarch64 builds; plan remote x86_64 builder for production images |
| `/gnu/store` volume grows beyond available disk | Low | Build failures | Add `store-size` monitoring; document disk requirements; use overlay to separate image store from build cache |
| Docker layer cache invalidation | Medium | Forces full rebuild of intermediate stages | Pin all source URLs and versions via build args; avoid changes to early stages |
| Channel authentication failure (GPG) | Medium | `guix pull` fails | Test signed commits early; keep key management documented |

## Estimated Complexity

**L (Large)**

This phase now includes the full hex0 source bootstrap inside Docker, which is significantly more complex than downloading a pre-built tarball. The multi-stage Dockerfile has 11 stages, each bootstrap compilation step must be carefully ordered, and Docker layer caching must be verified. The OverlayFS setup adds additional complexity. Most risk comes from bootstrap stage failures (compiler build errors in early stages) and the long initial build time (4-8+ hours).
