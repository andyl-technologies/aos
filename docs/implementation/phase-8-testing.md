# Phase 8: QEMU Test Framework, CI Pipeline, and Binary Cache

**Phase Number:** 8

## Objective

Build a comprehensive integration test framework using QEMU and pytest, set up the CI/CD pipeline (GitHub Actions or equivalent), establish the binary cache infrastructure for build acceleration, and create the full test suite covering boot, services, ZFS, Kubernetes, Ignition, updates, and rollback.

## Prerequisites

- Phase 4 complete: Bootable images that can be tested
- Phase 5 complete (or nearly): Update/rollback mechanisms to test
- Phase 6 complete: Ignition configs to validate
- Phase 7 complete: Kubernetes functionality to test
- QEMU installed on development machines and CI runners
- Python 3.10+ with pytest available

## Deliverables

- `tests/conftest.py` -- pytest fixtures for QEMU VM lifecycle management
- `tests/lib/vm.py` -- QEMUInstance class (start, stop, SSH exec, monitor commands, snapshot)
- `tests/test_boot.py` -- Boot success and systemd health tests
- `tests/test_services.py` -- Critical service verification tests
- `tests/test_zfs.py` -- ZFS pool, snapshot, and rollback tests
- `tests/test_k8s.py` -- Kubernetes readiness and pod scheduling tests
- `tests/test_ignition.py` -- First-boot configuration verification tests
- `tests/test_update.py` -- Update and rollback end-to-end tests
- `tests/test_gc.py` -- Garbage collection tests
- `tests/test_security.py` -- Security hardening verification tests
- `tests/fixtures/` -- Test Ignition configs, SSH keys, certificates
- `.github/workflows/ci.yml` -- CI pipeline (lint -> build -> test -> publish)
- Binary cache infrastructure (guix publish + nginx)
- `pytest.ini` or `pyproject.toml` -- pytest configuration with timeouts and markers

## Detailed Task Checklist

### 8.1 QEMUInstance Class

- [ ] Create `tests/lib/vm.py` with `QEMUInstance` class:
  - [ ] Constructor: image_path, ignition_path, memory (4096), cpus (2), ssh_port
  - [ ] `start()`: launch QEMU process with correct acceleration:
    - [ ] Auto-detect: KVM (Linux CI), HVF (macOS Intel), TCG (fallback)
    - [ ] Virtio disk, virtio-net with port forwarding
    - [ ] Serial console to file
    - [ ] QEMU monitor on Unix socket
    - [ ] Ignition config via fw_cfg (if provided)
    - [ ] OVMF UEFI firmware
  - [ ] `wait_for_ssh(timeout=120)`: poll SSH until available
  - [ ] `ssh_exec(command)`: execute command via SSH, return (stdout, stderr, exit_code)
  - [ ] `monitor_cmd(command)`: send command to QEMU monitor socket
  - [ ] `snapshot_save(name)`: save VM snapshot via monitor
  - [ ] `snapshot_load(name)`: restore VM snapshot
  - [ ] `stop()`: graceful shutdown via monitor `quit`
  - [ ] `cleanup()`: remove temp files, sockets, logs
- [ ] Add qcow2 overlay support for per-test isolation:
  - [ ] `create_overlay()`: `qemu-img create -f qcow2 -b <base> -F qcow2 <overlay>`
  - [ ] Each test gets a fresh overlay (copy-on-write, doesn't modify base)

### 8.2 pytest Fixtures

- [ ] Create `tests/conftest.py`:
  - [ ] `vm` fixture (session-scoped): boots VM once, shared across all tests in a session
  - [ ] `fresh_vm` fixture (function-scoped): per-test VM with qcow2 overlay
  - [ ] `vm_pool` fixture: manage multiple VMs for multi-node tests
  - [ ] `test_ssh_key` fixture (session-scoped, autouse): generate ephemeral Ed25519 SSH key
  - [ ] Artifact collection on failure: serial log, journal dump, screenshot
  - [ ] Worker-aware port allocation for pytest-xdist parallel execution

### 8.3 pytest Configuration

- [ ] Create `pyproject.toml` or `pytest.ini`:
  - [ ] Default timeout: 300 seconds (5 minutes)
  - [ ] Timeout method: signal
  - [ ] Markers: `slow` (>5 min), `flaky` (known intermittent)
  - [ ] JUnit XML output
  - [ ] HTML report output
- [ ] Create `requirements-test.txt`:
  - [ ] pytest, paramiko, pexpect, pytest-timeout, pytest-html
  - [ ] pytest-xdist (parallel execution)
  - [ ] pytest-rerunfailures (flaky test retry)

### 8.4 Boot Tests

- [ ] Create `tests/test_boot.py`:
  - [ ] `test_system_running`: `systemctl is-system-running` returns `running` or `degraded`
  - [ ] `test_no_failed_units`: no systemd units in failed state
  - [ ] `test_kernel_version`: correct kernel version reported by `uname -r`
  - [ ] `test_os_release`: `/etc/os-release` contains correct ANDYL OS fields
  - [ ] `test_boot_time`: system boots within 60 seconds (configurable)
  - [ ] `test_serial_console`: kernel messages appear on serial console
  - [ ] `test_cgroup_v2`: cgroups v2 unified hierarchy is active

### 8.5 Service Tests

- [ ] Create `tests/test_services.py`:
  - [ ] Parameterized test for critical services:
    - [ ] sshd.service, systemd-journald.service, systemd-networkd.service
    - [ ] systemd-resolved.service, systemd-timesyncd.service
    - [ ] (role-dependent: containerd.service, kubelet.service, etc.)
  - [ ] `test_service_active(service)`: service is `active`
  - [ ] `test_service_no_restarts(service)`: NRestarts == 0
  - [ ] `test_service_no_errors(service)`: no ERROR lines in last 50 journal entries

### 8.6 Filesystem Tests

- [ ] Create `tests/test_filesystem.py`:
  - [ ] `test_store_readonly`: `/gnu/store` is mounted read-only
  - [ ] `test_var_writable`: `/var` is writable
  - [ ] `test_etc_overlay`: `/etc` is an overlay mount
  - [ ] `test_tmp_tmpfs`: `/tmp` is tmpfs
  - [ ] `test_run_tmpfs`: `/run` is tmpfs
  - [ ] `test_etc_persistence`: write to `/etc`, reboot, verify change persists
  - [ ] `test_var_persistence`: write to `/var/lib`, reboot, verify data persists

### 8.7 Network Tests

- [ ] Create `tests/test_network.py`:
  - [ ] `test_dns_resolution`: `getent hosts` resolves public domains
  - [ ] `test_outbound_https`: `curl -sf https://httpbin.org/get` succeeds
  - [ ] `test_networkd_online`: `networkctl status` shows online interfaces
  - [ ] `test_ntp_sync`: NTP synchronized (may need timeout for initial sync)
  - [ ] `test_ssh_access`: SSH connection to VM works

### 8.8 ZFS Tests

- [ ] Create `tests/test_zfs.py`:
  - [ ] `test_zfs_pool_online`: `zpool status` shows ONLINE
  - [ ] `test_zfs_read_write`: write file, sync, read back, verify
  - [ ] `test_zfs_snapshot_create`: create snapshot, verify exists
  - [ ] `test_zfs_snapshot_rollback`: write, snapshot, modify, rollback, verify original
  - [ ] `test_zfs_compression`: verify zstd compression is active
  - [ ] `test_zfs_checksumming`: verify checksum policy is sha256 or fletcher4
  - [ ] Note: ZFS tests require a second virtio disk passed to QEMU

### 8.9 Kubernetes Tests

- [ ] Create `tests/test_k8s.py`:
  - [ ] `test_containerd_active`: containerd service is active
  - [ ] `test_containerd_responsive`: `crictl info` succeeds
  - [ ] `test_kubelet_active`: kubelet service is active
  - [ ] `test_node_ready`: node reaches Ready state (poll with 60s timeout)
  - [ ] `test_pod_scheduling`: run a busybox pod, verify it reaches Running
  - [ ] `test_pod_dns`: pod can resolve DNS
  - [ ] `test_cni_plugins_exist`: `/opt/cni/bin/` contains expected plugins
  - [ ] `test_kubelet_healthz`: `curl localhost:10248/healthz` returns ok

### 8.10 Ignition Tests

- [ ] Create `tests/test_ignition.py`:
  - [ ] `test_hostname_set`: `/etc/hostname` matches Ignition config
  - [ ] `test_role_set`: `/etc/andyl-os/role` matches expected role
  - [ ] `test_ssh_keys_installed`: authorized_keys contains expected public key
  - [ ] `test_network_config_applied`: networkd config files present
  - [ ] `test_tls_certs_installed`: CA and node certificates at correct paths with correct permissions
  - [ ] `test_ignition_first_boot_only`: Ignition marker consumed after first boot
  - [ ] `test_custom_units_enabled`: Ignition-created systemd units are enabled

### 8.11 Update and Rollback Tests

- [ ] Create `tests/test_update.py`:
  - [ ] `test_update_check`: agent reports update available
  - [ ] `test_update_download`: agent downloads bundle
  - [ ] `test_update_verify`: agent verifies signature and NAR hashes
  - [ ] `test_update_apply`: agent installs new generation
  - [ ] `test_update_reboot`: system boots into new generation
  - [ ] `test_boot_counting`: boot entry shows correct count
  - [ ] `test_boot_verified`: after health check, boot entry marked good
  - [ ] `test_rollback_manual`: `andyl-os-agent rollback` switches to previous generation
  - [ ] `test_rollback_automatic`: simulate health check failure, verify automatic rollback after 3 attempts
  - [ ] Use QEMU snapshots for efficient rollback testing

### 8.12 Garbage Collection Tests

- [ ] Create `tests/test_gc.py`:
  - [ ] `test_gc_removes_old_paths`: GC deletes store paths from removed generations
  - [ ] `test_gc_preserves_current`: current generation's paths are not deleted
  - [ ] `test_gc_dry_run`: dry-run mode reports but doesn't delete
  - [ ] `test_gc_process_safety`: paths used by running processes are not deleted
  - [ ] `test_gc_esp_cleanup`: old kernel/initrd images removed from ESP
  - [ ] `test_gc_locking`: GC and update agent don't run concurrently

### 8.13 Security Tests

- [ ] Create `tests/test_security.py`:
  - [ ] `test_store_readonly`: cannot write to `/gnu/store`
  - [ ] `test_no_root_login_password`: root has no password (SSH key only)
  - [ ] `test_selinux_loaded`: SELinux is active and in enforcing (or permissive) mode
  - [ ] `test_seccomp_available`: seccomp filter is available
  - [ ] `test_kernel_hardening`: stack protector, RELRO, etc.
  - [ ] `test_no_unnecessary_services`: no unexpected listening ports
  - [ ] `test_boot_editor_disabled`: systemd-boot editor is disabled

### 8.14 CI Pipeline

- [ ] Create `.github/workflows/ci.yml`:
  - [ ] **Stage 1: Lint**
    - [ ] Validate Guile Scheme syntax for all package definitions
    - [ ] Run `guix lint` on all ANDYL packages
    - [ ] Validate system configurations with `guix system -n build`
  - [ ] **Stage 2: Build Packages**
    - [ ] Run on self-hosted runner with persistent `/gnu/store` volume
    - [ ] Build all ANDYL packages
    - [ ] Push to binary cache
  - [ ] **Stage 3: Build Images**
    - [ ] Matrix: [k8s-worker, k8s-control, storage, gateway]
    - [ ] Build qcow2 image for each role
    - [ ] Record SHA256 hash
    - [ ] Upload as build artifact
  - [ ] **Stage 4: Integration Tests**
    - [ ] Download image artifact
    - [ ] Verify SHA256
    - [ ] Run pytest suite with QEMU (requires KVM on Linux runner)
    - [ ] Upload test results (JUnit XML, HTML report, serial logs)
    - [ ] Fail-fast disabled: run all role tests even if one fails
  - [ ] **Stage 5: Publish** (main branch and tags only)
    - [ ] Upload images to artifact storage (S3/MinIO)
    - [ ] Generate release manifest
  - [ ] **Stage 6: Release** (tags only)
    - [ ] Create GitHub Release with release notes
    - [ ] Attach SHA256 checksums
- [ ] Configure pipeline triggers: push to main, pull requests, tags, nightly schedule, manual dispatch
- [ ] Set up self-hosted runner with:
  - [ ] KVM access (`/dev/kvm`)
  - [ ] Persistent Docker volumes for Guix store
  - [ ] OVMF UEFI firmware installed

### 8.15 Binary Cache Infrastructure

- [ ] Set up `guix publish` server:
  - [ ] Generate signing key pair: `guix archive --generate-key`
  - [ ] Store private key securely (CI secrets manager)
  - [ ] Configure `guix publish --port=8080 --compression=zstd:6 --cache=/var/cache/guix/publish --ttl=30d`
- [ ] Set up nginx reverse proxy:
  - [ ] TLS termination
  - [ ] Cache headers for narinfo (1 hour) and NAR (1 day)
  - [ ] `nix-cache-info` endpoint
- [ ] Distribute public key to all build machines:
  - [ ] `guix archive --authorize < andyl-cache.pub`
- [ ] Configure CI to push build results: `guix copy --to=ssh://cache@cache.andyl.internal`
- [ ] Configure CI to pull from cache: `guix build --substitute-urls=https://cache.andyl.internal`
- [ ] Set up cache cleanup: delete entries older than 90 days
- [ ] Document cache population workflow

### 8.16 Test Reporting

- [ ] JUnit XML output for CI integration
- [ ] HTML reports for human review
- [ ] Artifact retention: test results for 14 days, images for 7 days
- [ ] CI status badges in README
- [ ] Failure notifications to Slack/email (optional)

### 8.17 justfile Targets

- [ ] Update `test ROLE` target: run pytest against specified role image
- [ ] Update `test-all` target: test all roles
- [ ] Add `test-smoke ROLE` target: quick boot-only test
- [ ] Add `lint` target: validate package definitions
- [ ] Add `check-reproducibility` target: build twice and compare hashes
- [ ] Add `cache-push` target: push builds to binary cache
- [ ] Add `cache-serve` target: start local cache for development

## Acceptance Criteria

1. All test suites pass: boot, services, filesystem, network, ZFS, k8s, ignition, update, rollback, GC, security
2. CI pipeline runs end-to-end: lint -> build -> image -> test -> publish
3. Binary cache accelerates builds (cache hit rate >80% for unchanged packages)
4. Test results are accessible as CI artifacts (JUnit XML, HTML, serial logs)
5. Tests run in QEMU with KVM acceleration on CI runners
6. Tests complete within 30 minutes per role
7. Flaky test rate is below 5%
8. Test framework supports parallel execution across roles (CI matrix)

## Risks and Mitigations

| Risk | Likelihood | Impact | Mitigation |
|------|-----------|--------|------------|
| KVM not available on CI runners | Medium | Tests fall back to TCG (10-20x slower) | Require self-hosted runners with KVM; GCP instances with nested virt |
| QEMU tests are inherently slow | High | Long CI feedback loop | Session-scoped VM fixture (boot once per role); parallel role testing in CI matrix |
| Flaky tests due to timing (k8s readiness, NTP sync) | High | False failures erode CI trust | Polling with generous timeouts; pytest-rerunfailures for known flaky tests |
| Binary cache storage grows unbounded | Medium | Disk full | Cache cleanup cron (90-day TTL); content-addressing prevents true duplication |
| Test SSH key management | Low | Security leak | Generate ephemeral keys per test session; never commit real keys |
| QEMU + OVMF firmware availability | Medium | Tests can't boot UEFI | Package OVMF as a test dependency; document installation |

## Estimated Complexity

**XL (Extra Large)**

This phase encompasses the entire testing and CI infrastructure. The QEMU test framework requires deep integration with VM lifecycle management, SSH automation, and QEMU monitor control. The test suite must cover every major system function. The CI pipeline ties all previous phases together. The binary cache adds infrastructure complexity. The sheer number of tests and the need for reliability make this a large effort.
