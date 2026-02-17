# APM Worked Examples

> **Note:** `apm` is a symlink alias for `aos package`. Every `apm` command
> below can also be written as `aos package`. For example:
>
> ```console
> $ apm install curl          # shorthand
> $ aos package install curl  # canonical — identical behavior
> ```

## 1. First-Time Setup

### Adding the default registry

```console
$ apm registry add https://registry.aos.dev/core --priority=500
Adding registry 'aos-core' from https://registry.aos.dev/core ...
Downloading snapshot bundle v2026.02 (148 KB) ... done
Signing key: aos-core:Ed25519:Xk9m2...Qp4= (new key)
Trust this key? [y/N] y
Applying delta v2026.02 → v2026.02.2 (6 KB) ... done
Registry 'aos-core' added with priority 500 (143 packages for x86_64-linux)
```

### Adding a secondary registry

```console
$ apm registry add https://registry.aos.dev/extra --priority=400
Adding registry 'aos-extra' from https://registry.aos.dev/extra ...
Downloading snapshot bundle v2026.02 (312 KB) ... done
Registry 'aos-extra' added with priority 400 (891 packages for x86_64-linux)
```

### Listing registries

```console
$ apm registry list
NAME        PRIORITY  URL                                      PACKAGES  UPDATED
aos-core    500       https://registry.aos.dev/core             143       2026-02-13
aos-extra   400       https://registry.aos.dev/extra            891       2026-02-13
```

---

## 2. Installing a Package

### Simple install

```console
$ apm install curl
Reading registry metadata...
Resolving closure...

The following NEW packages will be installed:
  curl  nghttp2  cacert

The following closure paths are already in store:
  openssl (3.2.0)  zlib (1.3.1)

3 paths to download, 1.6 MiB to download (52 MiB closure).
Do you want to continue? [Y/n] y

Downloading:
  [################] curl-8.5.0          1.0 MiB / 1.0 MiB  done
  [################] nghttp2-1.58.0      384 KiB / 384 KiB   done
  [################] cacert-2024.01      256 KiB / 256 KiB   done

Verifying hashes... done
Importing to store... done
Creating GC roots in profile... done
Rebuilding profile (/var/lib/profiles/per-user/$USER/gen-42 → gen-43)... done

3 packages installed successfully.
```

### Install from a specific registry

```console
$ apm install --registry=aos-extra nginx
Reading registry metadata...
Resolving closure...

The following NEW packages will be installed:
  nginx  pcre2

2 paths to download, 2.1 MiB to download.
Do you want to continue? [Y/n] y

Downloading:
  [################] nginx-1.25.3        1.8 MiB / 1.8 MiB  done
  [################] pcre2-10.42         312 KiB / 312 KiB   done

Verifying hashes... done
Importing to store... done
Creating GC roots in profile... done
Rebuilding profile (/var/lib/profiles/per-user/$USER/gen-43 → gen-44)... done

2 packages installed successfully.
```

---

## 3. Querying Packages

### Search

```console
$ apm search ssl
openssl/aos-core 3.2.0 - TLS/SSL and general-purpose cryptography library
lib-ssh2/aos-extra 1.11.0 - Client-side SSH2 library
wolfssl/aos-extra 5.6.4 - Embedded TLS library
```

### Show package details

```console
$ apm show curl
Package: curl
Version: 8.5.0
Registry: aos-core
Description: Command-line tool and library for URL transfers
Homepage: https://curl.se
License: MIT
Platform: x86_64-linux
Installed: yes
Store path: /var/lib/store/h7j3k8l2m9n4...-curl-8.5.0
NAR size: 3.0 MiB
Dependencies: openssl, zlib, nghttp2, cacert
Source drv: /var/lib/store/i8k4l9m3n0o5...-curl-8.5.0.drv
Maintainer: aos-team
```

### Show closure tree

```console
$ apm depends curl
curl (8.5.0)                             [aos-core]
├── openssl (3.2.0)                      (store ref: xr5is7by)
│   ├── zlib (1.3.1)                     (store ref: r4q1m2kp)
│   └── cacert (2024.01)                 (store ref: kl9m3n0o)
├── zlib (1.3.1)                         (store ref: r4q1m2kp)
├── nghttp2 (1.58.0)                     (store ref: q8mn2pv7)
│   └── zlib (1.3.1)                     (store ref: r4q1m2kp)
└── cacert (2024.01)                     (store ref: kl9m3n0o)

5 unique store paths in closure (52 MiB total).
```

Dependencies are resolved from store references embedded in each NAR, not
from explicit dependency lists. The tree mirrors `nix-store -q --tree`.

### Show reverse dependencies

```console
$ apm rdepends openssl
openssl (3.2.0) is required by:
  curl (8.5.0)
  nginx (1.25.3)
  python3 (3.12.1)
```

### List installed packages

```console
$ apm list --installed
bash/aos-core 5.2.21 [installed]
coreutils/aos-core 9.4 [installed]
curl/aos-core 8.5.0 [installed]
openssl/aos-core 3.2.0 [installed]
zlib/aos-core 1.3.1 [installed]
...
```

### Check policy (multi-registry)

```console
$ apm policy openssl
openssl:
  Installed: 3.2.0
  Candidate: 3.2.0
  Version table:
 *** 3.2.0  500  aos-core
     3.1.4  400  aos-extra
```

---

## 4. Updating and Upgrading

### Update registries

```console
$ apm update
Fetching registry 'aos-core' ... done (143 packages, 5 updated)
Fetching registry 'aos-extra' ... done (891 packages, 23 updated)
7 packages can be upgraded. Run 'apm upgrade' to upgrade them.
```

### List upgradable packages

```console
$ apm list --upgradable
curl/aos-core 8.5.0 -> 8.6.0
bash/aos-core 5.2.21 -> 5.2.26
nghttp2/aos-core 1.58.0 -> 1.59.0
```

### Upgrade all

```console
$ apm upgrade
The following packages will be UPGRADED:
  curl (8.5.0 -> 8.6.0)
  bash (5.2.21 -> 5.2.26)
  nghttp2 (1.58.0 -> 1.59.0)

3 packages to upgrade, 4.7 MiB to download.
Do you want to continue? [Y/n] y

Downloading:
  [################] curl-8.6.0          1.1 MiB / 1.1 MiB  done
  [################] bash-5.2.26         1.8 MiB / 1.8 MiB  done
  [################] nghttp2-1.59.0      392 KiB / 392 KiB   done

Verifying hashes... done
Importing to store... done
Updating GC roots... done
Rebuilding profile (/var/lib/profiles/per-user/$USER/gen-44 → gen-45)... done

3 packages upgraded successfully.
```

Upgrade atomically creates a new profile generation with updated symlinks:

```
/var/lib/profiles/per-user/$USER/gen-45/bin/curl -> /var/lib/store/{hash}-curl-8.6.0/bin/curl
```

The symlink is a direct executable symlink in the new generation. The old store
path remains until garbage collection. Note that the new curl version may
reference different dependency versions (e.g., a newer openssl) — both closures
coexist in the store until the old roots are removed.

---

## 5. Removing Packages

### Simple remove

```console
$ apm remove curl
The following packages will be REMOVED:
  curl

The following packages are no longer required:
  nghttp2  cacert

1 package to remove.
Do you want to continue? [Y/n] y

Removing GC roots... done

1 package removed. 2 packages are now orphaned.
Use 'apm autoremove' to remove orphaned packages.
```

### Autoremove orphans

```console
$ apm autoremove
The following packages will be REMOVED (no longer required):
  nghttp2  cacert

2 orphaned packages to remove.
Do you want to continue? [Y/n] y

Removing GC roots... done
2 packages removed.
```

### Garbage collect store

```console
$ apm gc
Running aos gc --collect...
Deleted 147 store paths, freeing 892 MiB.
```

---

## 6. Holding Packages

### Hold a package

```console
$ apm hold openssl
openssl set on hold.

$ apm held
openssl (3.2.0) [held]
```

### Upgrade with hold

```console
$ apm upgrade
The following packages will be UPGRADED:
  curl (8.5.0 -> 8.6.0)
  bash (5.2.21 -> 5.2.26)

The following packages are HELD BACK:
  openssl (3.2.0 held, 3.3.0 available)

2 packages to upgrade, 2.9 MiB to download.
Do you want to continue? [Y/n]
```

### Unhold

```console
$ apm unhold openssl
Cancelled hold on openssl.
```

---

## 7. Verifying Package Integrity

### Verify installed package

```console
$ apm verify openssl
Verifying openssl (3.2.0)...
  Store path: /var/lib/store/xr5is7by89v3q...-openssl-3.2.0  OK
  NAR hash: sha256:a1b2c3d4e5f6...  OK
Package openssl verified successfully.
```

### Verify from source (reproducible build check)

```console
$ apm source --verify openssl
Fetching source derivation for openssl 3.2.0...
  Downloading source drv NAR... done
  Downloading source tarball (openssl-3.2.0.tar.gz)... done
  Downloading build dependencies... done (12 derivations)
Building from source (this may take a while)...
  Configuring... done
  Compiling... done
  Installing... done
Comparing output:
  Built:     /var/lib/store/xr5is7by89v3q...-openssl-3.2.0
  Installed: /var/lib/store/xr5is7by89v3q...-openssl-3.2.0
  MATCH - Binary is reproducible from source.
```

---

## 8. Using a Pinned Registry (Production)

### Pin to a specific release

```toml
# ~/.config/apm/registries.d/aos-core.toml
[registry]
name = "aos-core"
url = "https://registry.aos.dev/core"
pin = "v2026.02"
priority = 500
enabled = true
```

### Update behavior with pin

```console
$ apm update
Fetching registry 'aos-core' ... pinned at v2026.02 (no changes)
Fetching registry 'aos-extra' ... done (891 packages, 12 updated)
```

To advance the pin:

```console
$ vim ~/.config/apm/registries.d/aos-core.toml
# Change: pin = "v2026.03"
$ apm update
Fetching registry 'aos-core' ... advancing from v2026.02 to v2026.03 (7 updated)
```

---

## 9. Adding an Internal/Override Registry

### Company internal registry

```console
$ apm registry add https://registry.internal.co/aos-custom --priority=600
Adding registry 'aos-custom' from https://registry.internal.co/aos-custom ...
Registry 'aos-custom' added with priority 600 (12 packages for x86_64-linux)
```

### Overlay behavior

```console
$ apm policy openssl
openssl:
  Installed: 3.2.0
  Candidate: 3.2.0-custom1    <-- from internal registry
  Version table:
     3.2.0-custom1  600  aos-custom     <-- wins (highest priority)
 *** 3.2.0          500  aos-core
     3.1.4          400  aos-extra

$ apm upgrade
The following packages will be UPGRADED:
  openssl (3.2.0 -> 3.2.0-custom1 from aos-custom)
...
```

---

## 10. Dry Run and JSON Output

### Dry run

```console
$ apm install --dry-run vim
The following NEW packages will be installed:
  vim  ncurses
2 packages, 8.1 MiB to download.
(dry run — no changes made)
```

### JSON output

```console
$ apm show --json curl
{
  "name": "curl",
  "version": "8.5.0",
  "registry": "aos-core",
  "description": "Command-line tool and library for URL transfers",
  "homepage": "https://curl.se",
  "license": "MIT",
  "platform": "x86_64-linux",
  "installed": true,
  "store_path": "/var/lib/store/h7j3k8l2m9n4...-curl-8.5.0",
  "nar_size": 3145728,
  "dependencies": ["openssl", "zlib", "nghttp2", "cacert"],
  "source_drv": "/var/lib/store/i8k4l9m3n0o5...-curl-8.5.0.drv",
  "maintainer": "aos-team"
}
```

---

## 11. Profile Rollback

```console
$ apm rollback
Rolling back profile: /var/lib/profiles/per-user/$USER/gen-45 → gen-44
Profile switched. Package changes:
  - curl (8.6.0)
  + curl (8.5.0)

Run 'apm list --installed' to see current state.
```
