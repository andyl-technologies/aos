# RFC-0019 Phase-0 evidence

This record ties the checked Phase-0 claims to reproducible repository inputs.
The executable evidence is `checks.container.phase0`, defined in
`tests/containers/phase0.nix`.

## Automated contract check

Run:

```text
nix-build -A checks.container.phase0
```

The derivation performs all of the following with AOS-built packages:

1. builds the fixed layer fixture twice after changing source mtimes;
2. compares the tar and gzip bytes;
3. verifies the frozen DiffID and compressed-blob SHA-256 vectors;
4. obtains the golden roots directly from
   `systems.server.config.environment.systemPackages`;
5. verifies that `pkgs.aos` is one of those roots;
6. copies the structured closure into an isolated `local?root=` Nix store;
7. initializes the database and loads the generated registration stream;
8. creates baked-root symlinks and runs Nix garbage collection;
9. verifies every golden root remains physically present and DB-valid;
10. runs `aos --version`, `apm --help`, and `apr --help` with the isolated local
    store and no daemon.

The frozen layer vector is:

```text
tar  6e30729d0413d5fb0dba4d0573093a4950e81cd45d7a9ebc2f62f09746b07ea5
gzip 1ec9791d8b0b3458830e5156881293d288941e793bb73790f85ad35f168a51d0
```

`nix-build -A checks.eval` also passed after the RFC and check were added.

## Manual Docker compatibility observation

The development host exposed Docker Engine 29.7.2, API 1.55, on
`linux/amd64`. A scratch OCI layout was assembled with the AOS-built tar 1.35,
gzip 1.13, jq 1.8.1, and coreutils 9.5 packages. Its layer contained the 66-path
`pkgs.aos` closure and a `/usr/bin/aos` facade.

Observed immutable identities were:

```text
layer blob sha256:4cb31df383405d1d590df5f30435a1b3ec4ad1047a1f2b46b7bbd6c93eaa5718
manifest   sha256:f926ee3bb9ec130fb7a54a3775c713a48b7bf9e56d4e92c872fe9179821bc204
```

The exact runtime commands were:

```text
docker image load --input /tmp/tmp.xzDy0wcBZM/aos-spike.oci.tar
docker image inspect sha256:f926ee3bb9ec130fb7a54a3775c713a48b7bf9e56d4e92c872fe9179821bc204
docker image tag sha256:f926ee3bb9ec130fb7a54a3775c713a48b7bf9e56d4e92c872fe9179821bc204 docker.io/library/aos-spike:latest
docker run --rm docker.io/library/aos-spike:latest --version
```

The container printed:

```text
aos 0.1.0
```

The temporary tag and image were removed after the observation. This is a
compatibility observation, not a hermetic gate. Phase 2 replaces the hand-built
layout with the checked Nix builder and runs it under AOS-built containerd,
runc, and nerdctl in a privileged Nix VM.
