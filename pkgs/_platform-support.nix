##! Package target-platform inventory.
##!
##! This file is deliberately excluded from package auto-discovery by its
##! leading underscore.  It is the fail-closed policy boundary used to decide
##! which package roots belong in a target-platform build and publication
##! matrix.  Build dependencies are selected through package-set splicing;
##! `selectTargetPackages` filters only the roots advertised for a target.
let
  darwinSystems = [
    "x86_64-darwin"
    "aarch64-darwin"
  ];

  # Wave 1: target-independent inputs and small leaf packages.  These establish
  # the data and low-level library closure used by later Darwin packages.
  independentWave1 = [
    "aos-hub-console-dist"
    "aos-hub-worker-dist"
    "ca-certificates"
    "docbook-xml"
    "docbook-xsl"
    "edk2"
    "firmware"
    "gnu-efi"
    "nvidia-gsp-firmware"
    "qemu-crucible-source"
    "darwin-sdk"
    "secure-boot-test-keys"
    "server-initrd-firmware"
    "tla-plus"
    "tzdata"
  ];

  targetWave1 = [
    "abseil-cpp"
    "autoconf"
    "automake"
    "bash"
    "bc"
    "bison"
    "boost"
    "brotli"
    "bzip2"
    "coreutils"
    "cpio"
    "diffutils"
    "editline"
    "expat"
    "file"
    "findutils"
    "flex"
    "gawk"
    "gc"
    "gettext"
    "gmp"
    "gnumake"
    "gperf"
    "grep"
    "gzip"
    "inih"
    "jansson"
    "json-c"
    "libffi"
    "libmpc"
    "libtool"
    "libyaml"
    "lowdown"
    "lz4"
    "m4"
    "mpfr"
    "ncurses"
    "nlohmann-json"
    "oniguruma"
    "patch"
    "pcre2"
    "pkg-config"
    "popt"
    "sed"
    "snappy"
    "tar"
    "tcl"
    "texinfo"
    "toml11"
    "treecc"
    "unzip"
    "which"
    "xz"
    "zip"
    "zlib"
    "zstd"
  ];

  # Target runtime surfaces have no meaningful Linux-hosted package output,
  # but are first-class publication roots for both Darwin architectures.
  darwinOnly = [
    "darwin-runtimes"
  ];

  # Wave 2: portable native libraries and conventional Unix tools.  Most need
  # build/host triples and Mach-O-aware fixup, but do not need a target runtime
  # to execute during their build.
  targetWave2 = [
    "acpica"
    "cups"
    "curl"
    "cyrus-sasl"
    "dbus"
    "dosfstools"
    "dtc"
    "e2fsprogs"
    "fakeroot"
    "fontconfig"
    "freetype"
    "glib"
    "gnupg"
    "gnutls"
    "gptfdisk"
    "icu"
    "ipmitool"
    "jemalloc"
    "jq"
    "json-glib"
    "krb5"
    "less"
    "libarchive"
    "libassuan"
    "libburn"
    "libevent"
    "libgcrypt"
    "libgit2"
    "libgpg-error"
    "libisoburn"
    "libisofs"
    "libksba"
    "libpcap"
    "libqcow"
    "libslirp"
    "libsodium"
    "libssh2"
    "libtasn1"
    "libtirpc"
    "libtpms"
    "libusb1"
    "libxcrypt"
    "libxml2"
    "libxslt"
    "lsof"
    "minisign"
    "mtools"
    "nettle"
    "nghttp2"
    "nginx"
    "npth"
    "openldap"
    "openpam"
    "openssh"
    "openssl"
    "perl"
    "pigz"
    "pixman"
    "protobuf"
    "readline"
    "remove-references-to"
    "rpcsvc-proto"
    "rsync"
    "sbsigntools"
    "smartmontools"
    "socat"
    "sqlite"
    "swtpm"
    "tcpdump"
    "tpm2-tools"
    "tpm2-tss"
    "xorg-stubs"
  ];

  # Wave 3: compilers, interpreters and build systems.  These require a native
  # Linux compiler/interpreter package set distinct from Darwin target outputs.
  targetWave3 = [
    "alejandra"
    "ant"
    "ant-bootstrap"
    "binutils"
    "cargo-hakari"
    "cargo-nextest"
    "cc"
    "classpath-0_93"
    "classpath-0_99"
    "cmake"
    "cython"
    "distlib"
    "ecj-bootstrap"
    "fastjar"
    "gcc"
    "gcc-libs"
    "gccUnwrapped"
    "gdb"
    "git"
    "git-2_42"
    "git-minimal"
    "gjavah"
    "go"
    "go-1_17"
    "go-1_20"
    "go-1_22"
    "go-1_24"
    "go-1_4"
    "jamvm-1_5"
    "jamvm-2_0"
    "jikes"
    "just"
    "llvm"
    "llvm-17"
    "llvm-18"
    "llvm-19"
    "llvm-20"
    "llvm-21"
    "llvm-22"
    "meson"
    "nasm"
    "ninja"
    "nix"
    "nodejs"
    "nuke-references"
    "python3"
    "python3-3_12"
    "python3-pefile"
    "python3-pyelftools"
    "rust"
    "rust-1_74"
    "rust-1_75"
    "rust-1_76"
    "rust-1_77"
    "rust-1_78"
    "rust-1_79"
    "rust-1_80"
    "rust-1_81"
    "rust-1_82"
    "rust-1_83"
    "rust-1_84"
    "rust-1_85"
    "rust-1_86"
    "rust-1_87"
    "rust-1_88"
    "rust-1_89"
    "rust-1_90"
    "rust-1_91"
    "rust-1_92"
    "setuptools"
    "wasm-bindgen-cli"
    "worker-build"
  ];

  # Wave 4: portable applications after their language and native dependency
  # graphs are available.
  targetWave4 = [
    "aos"
    "aos-agent-rpc"
    "aos-hub"
    "aos-hub-cloudflare"
    "aos-test-driver"
    "aos-vm"
    "chrony"
    "crictl"
    "crucible-controller"
    "crucible-fleet-store"
    "etcd"
    "garage"
    "hubble"
    "kubectl"
    "mariadb"
    "miniflare"
    "nerdctl"
    "opkssh"
    "postgresql"
    "pyrefly"
    "qemu"
    "qemu-img"
    "test-http-server"
    "test-static-cache-server"
    "workerd"
    "workerd-source"
  ];

  # Wave 5: very large or bootstrap-sensitive graphs.  They are eligible, not
  # optional; the later wave records implementation order rather than support.
  targetWave5 = [
    "bazel"
    "bazel-7"
    "bazel-8"
    "bazel-9"
    "envoy"
    "openjdk"
    "openjdk-10"
    "openjdk-11"
    "openjdk-12"
    "openjdk-13"
    "openjdk-14"
    "openjdk-15"
    "openjdk-16"
    "openjdk-17"
    "openjdk-18"
    "openjdk-19"
    "openjdk-20"
    "openjdk-21"
    "openjdk-22"
    "openjdk-23"
    "openjdk-24"
    "openjdk-7"
    "openjdk-8"
    "openjdk-9"
  ];

  # Linux-native seeds and AOS test artifacts may be used by Linux builders,
  # but they do not represent a Darwin package root and must not be published
  # under a Darwin platform key.
  buildOnly = [
    "aos-hub-dialect-tests"
    "aos-hub-e2e"
    "aos-hub-worker-do-e2e"
    "aos-secret-reference-test"
    "aos-system-image-e2e-fixture"
    "aos-test-agent"
    "apm-systemd-client-test"
    "bazel-bootstrap"
    "config-module-smoke"
    "crucible-fixtures"
    "desired-config-test"
    "desired-prune-test"
    "expose-smoke"
    "landlock-argv-test"
  ];

  # These outputs implement Linux kernel, userspace, guest or service
  # interfaces and have no Darwin execution contract.  A portable sub-tool
  # must be split into its own package before it can leave this list.
  linuxOnly = [
    "acl"
    "alsa-lib"
    "aos-boot-identity"
    "aos-ebpf-lsm-policy"
    "aos-ebpf-net-policy"
    "aos-landlock"
    "aos-recovery"
    "aos-registry-server"
    "aos-selinux-run"
    "aos-var-policy-migrate"
    "aos-verity-root-guard"
    "attr"
    "audit"
    "checkpolicy"
    "cilium"
    "cloudcore"
    "cni-plugins"
    "composefs"
    "conntrack-tools"
    "containerd"
    "crucible"
    "crucible-guest"
    "crucible-qemu-plugin"
    "crucible-qemu-trace-plugin"
    "cryptsetup"
    "device-mapper"
    "dwarves"
    "edgecore"
    "efitools"
    "elfutils"
    "erofs-utils"
    "ethtool"
    "firecracker"
    "getent"
    "glibc"
    "hdparm"
    "iproute2"
    "ipset"
    "iptables"
    "k3s"
    "k3s-combined"
    "k3s-control-plane"
    "k3s-worker"
    "kmod"
    "kubelet"
    "libaio"
    "libbpf"
    "libcap"
    "libmnl"
    "libnetfilter_conntrack"
    "libnetfilter_cthelper"
    "libnetfilter_cttimeout"
    "libnetfilter_queue"
    "libnfnetlink"
    "libnftnl"
    "libnl"
    "libseccomp"
    "libselinux"
    "libsemanage"
    "libsepol"
    "liburcu"
    "liburing"
    "linux"
    "linux-crucible"
    "linux-headers"
    "linux-pam"
    "longhorn-engine"
    "longhorn-instance-manager"
    "longhorn-manager"
    "lvm2"
    "nftables"
    "numactl"
    "nvidia-open"
    "patchelf"
    "policycoreutils"
    "procps-ng"
    "qemu-crucible"
    "qemu-crucible-reference"
    "refpolicy"
    "runc"
    "semodule-utils"
    "setools"
    "strace"
    "systemd"
    "util-linux"
    "xfsprogs"
    "zfs"
  ];

  classificationGroups = [
    independentWave1
    targetWave1
    targetWave2
    targetWave3
    targetWave4
    targetWave5
    buildOnly
    linuxOnly
  ];
  assignmentCounts = builtins.foldl' (
    counts: name:
      counts
      // {
        ${name} = (counts.${name} or 0) + 1;
      }
  ) {} (builtins.concatLists classificationGroups);
  duplicateAssignments = builtins.filter (
    name: assignmentCounts.${name} != 1
  ) (builtins.attrNames assignmentCounts);

  mkEntries = disposition: wave: blockers: names:
    builtins.listToAttrs (
      map (name: {
        inherit name;
        value = {
          inherit disposition wave blockers;
          architectures = [
            "x86_64"
            "aarch64"
          ];
        };
      })
      names
    );

  inventory =
    mkEntries "independent" 1 ["native-build-tools"] independentWave1
    // mkEntries "target" 1 ["darwin-sdk" "mach-o-fixup"] targetWave1
    // mkEntries "darwin-only" 1 ["darwin-runtime"] darwinOnly
    // mkEntries "target" 2 ["cross-configure" "mach-o-fixup"] targetWave2
    // mkEntries "target" 3 ["build-host-target-splicing" "target-runtime-tests"] targetWave3
    // mkEntries "target" 4 ["language-cross-build" "target-runtime-tests"] targetWave4
    // mkEntries "target" 5 ["canadian-cross" "target-runtime-tests"] targetWave5
    // mkEntries "build-only" null ["linux-native-build-input"] buildOnly
    // mkEntries "linux-only" null ["linux-interface"] linuxOnly;

  criticalOverrides = {
    aos = {
      blockers = ["darwin-runtime-tool-closure" "cargo-target" "target-runtime-tests"];
      note = "Split construct/registry tooling from Linux activation, SELinux, systemd and image runtime tools.";
    };
    bazel = {
      blockers = ["darwin-jni" "embedded-jdk" "target-runtime-tests"];
      note = "Build Bazel with Linux-native Java tools while targeting Darwin JNI launchers.";
    };
    binutils = {
      blockers = ["cctools-replacement" "mach-o-target"];
      note = "GNU binutils is not the Darwin system linker; expose cctools/ld64 through the Darwin toolchain.";
    };
    gcc = {
      blockers = ["cctools" "darwin-gcc-runtime" "canadian-cross"];
      note = "Build a Darwin-hosted GCC using Linux build tools, the source SDK and cctools linker.";
    };
    go = {
      blockers = ["goos-darwin" "cgo-cross-compiler" "target-runtime-tests"];
      note = "Use Linux-native Go for bootstrap and emit a Darwin-hosted toolchain plus standard library.";
    };
    llvm = {
      blockers = ["llvm-tblgen-native" "darwin-runtimes" "target-runtime-tests"];
      note = "Use native table generators and emit Clang, compiler-rt, libc++ and lld/ld64 integration for Darwin.";
    };
    nodejs = {
      blockers = ["native-code-generators" "darwin-v8" "target-runtime-tests"];
      note = "Cross-build V8/Node with native generators and Darwin target libraries.";
    };
    openjdk = {
      blockers = ["build-jdk" "darwin-hotspot" "target-runtime-tests"];
      note = "Use a Linux build JDK and cross-build a Darwin HotSpot/JDK image.";
    };
    python3 = {
      blockers = ["build-python" "configure-cache" "target-runtime-tests"];
      note = "Use a Linux build Python for generators and cross-build the Darwin interpreter and extension modules.";
    };
    qemu = {
      blockers = ["disable-kvm" "enable-hvf" "darwin-dependency-selection" "target-runtime-tests"];
      note = "Select HVF/TCG and Darwin host APIs instead of the Linux KVM configuration.";
    };
    rust = {
      blockers = ["build-rustc" "darwin-std" "darwin-linker" "target-runtime-tests"];
      note = "Use Linux-native rustc/cargo for bootstrap and emit Darwin-hosted rustc/cargo plus both Darwin stdlibs.";
    };
    workerd = {
      blockers = ["remove-linux-binary-seed" "darwin-bazel" "target-runtime-tests"];
      note = "Replace the x86_64 Linux npm binary seed with the from-source workerd build.";
    };
  };

  architectureOverrides = {
    "go-1_4" = ["x86_64"];
    "openjdk-7" = ["x86_64"];
    "openjdk-8" = ["x86_64"];
    "openjdk-9" = ["x86_64"];
    "openjdk-10" = ["x86_64"];
    "openjdk-11" = ["x86_64"];
    "openjdk-12" = ["x86_64"];
    "openjdk-13" = ["x86_64"];
    "openjdk-14" = ["x86_64"];
    "openjdk-15" = ["x86_64"];
    "openjdk-16" = ["x86_64"];
  };

  packageInventory =
    builtins.mapAttrs (
      name: entry:
        entry
        // (criticalOverrides.${name} or {})
        // {
          architectures = architectureOverrides.${name} or entry.architectures;
        }
    )
    inventory;

  helperInventory = {
    "_platform-support.nix" = "platform-policy";
    "build-support/_cargo-artifacts.nix" = "native-build-helper";
    "build-support/_config-module-renderer.nix" = "native-build-helper";
    "build-support/_expose-module.nix" = "target-independent-source";
    "build-support/_expose-renderer.nix" = "native-build-helper";
    "build-support/_generated-expose-config-module.nix" = "target-independent-source";
    "darwin/_darwin-binutils.nix" = "cross-build-helper";
    "darwin/_darwin-cc.nix" = "cross-build-helper";
    "darwin/_darwin-gcc.nix" = "cross-build-helper";
    "emulation/qemu-patches/_series.nix" = "linux-only-source";
    "kernel/_source.nix" = "linux-only-source";
    "kubernetes/_k3s-common.nix" = "linux-only-build-helper";
    "kubernetes/_k3s-expose-package.nix" = "linux-only-build-helper";
    "kubernetes/_kubeedge-source.nix" = "linux-only-source";
    "kubernetes/_source.nix" = "mixed-source";
    "toolchain/_bazel.nix" = "native-build-helper";
    "toolchain/go/_go-darwin.nix" = "cross-build-helper";
    "toolchain/java/_openjdk-bootstrap.nix" = "native-build-helper";
    "toolchain/llvm/_llvm.nix" = "cross-build-helper";
    "toolchain/rust/_rust-darwin-build-tool.nix" = "cross-build-helper";
    "toolchain/rust/_rust-darwin.nix" = "cross-build-helper";
    "toolchain/rust/_rust-bootstrap.nix" = "native-build-helper";
    "tools/aos/_tests.nix" = "native-test-helper";
    "tools/aos/_workspace-source.nix" = "target-independent-source";
    "tools/crucible/_cargo-deps-hash.nix" = "target-independent-source";
    "tools/crucible/_packages.nix" = "target-independent-source";
    "tools/crucible/_release-manifest.nix" = "linux-only-release-helper";
    "tools/crucible/_source.nix" = "mixed-source";
  };

  # Callable expressions retained in `pkgs` but intentionally omitted from the
  # buildable package-root list.
  factoryInventory = {
    "boot/aos-uki.nix" = "linux-only-package-factory";
    "build-support/trivial-builders.nix" = "native-build-helper-factory";
    "system/dbus-conf.nix" = "target-independent-package-factory";
  };

  # Source fragments kept below underscore-prefixed directories are also
  # excluded from discovery, but are consumed by package factories.
  resourceInventory = {
    "system/_dbus-conf-xsl/make-session-conf.xsl" = "target-independent-source";
    "system/_dbus-conf-xsl/make-system-conf.xsl" = "target-independent-source";
    "tests/_aos-test-agent-config/module.nix" = "linux-only-test-source";
    "tests/_config-module-smoke/module.nix" = "linux-only-test-source";
    "tests/_config-module-smoke/private.nix" = "linux-only-test-source";
  };

  isLinux = system: builtins.match "[a-zA-Z0-9_]+-linux" system != null;
  isDarwin = system: builtins.match "[a-zA-Z0-9_]+-darwin" system != null;
  systemCpu = system: let
    matched = builtins.match "([a-zA-Z0-9_]+)-[a-zA-Z0-9_]+" system;
  in
    if matched == null
    then throw "package platform support: invalid Nix system '${system}'"
    else builtins.head matched;
in rec {
  schema = "aos.package-platform-support/v1";
  inherit darwinSystems packageInventory helperInventory factoryInventory resourceInventory;

  packageSupport = name:
    packageInventory.${name}
    or (throw "package platform support: unclassified package '${name}'");

  supportsTarget = system: name: let
    entry = packageSupport name;
  in
    if isLinux system
    then entry.disposition != "darwin-only"
    else if isDarwin system
    then
      builtins.elem entry.disposition ["target" "independent" "darwin-only"]
      && builtins.elem (systemCpu system) entry.architectures
    else throw "package platform support: unsupported target system '${system}'";

  targetPackageNames = system: names: builtins.filter (supportsTarget system) names;

  publicationMatrix = names:
    builtins.listToAttrs (
      map (system: {
        name = system;
        value = targetPackageNames system names;
      })
      darwinSystems
    );

  selectTargetPackages = system: packages: names:
    builtins.listToAttrs (
      map (name: {
        inherit name;
        value = packages.${name};
      })
      (targetPackageNames system names)
    );

  annotate = name: package: let
    support = packageSupport name;
  in
    package
    // {
      meta =
        (package.meta or {})
        // {
          aos =
            (package.meta.aos or {})
            // {
              platformSupport = support;
            };
        };
    };

  validate = names: let
    missing = builtins.filter (name: !(builtins.hasAttr name packageInventory)) names;
    stale = builtins.filter (name: !(builtins.elem name names)) (builtins.attrNames packageInventory);
    staleCriticalOverrides = builtins.filter (
      name: !(builtins.hasAttr name inventory)
    ) (builtins.attrNames criticalOverrides);
    staleArchitectureOverrides = builtins.filter (
      name: !(builtins.hasAttr name inventory)
    ) (builtins.attrNames architectureOverrides);
    validDispositions = [
      "target"
      "independent"
      "darwin-only"
      "build-only"
      "linux-only"
    ];
    validArchitectures = [
      "x86_64"
      "aarch64"
    ];
    invalid = builtins.filter (
      name: let
        entry = packageInventory.${name};
        architectureSet = builtins.listToAttrs (
          map (architecture: {
            name = architecture;
            value = true;
          })
          entry.architectures
        );
        publishesDarwin = builtins.elem entry.disposition ["target" "independent" "darwin-only"];
      in
        !(builtins.elem entry.disposition validDispositions)
        || !(builtins.isList entry.architectures)
        || entry.architectures == []
        || !(builtins.all builtins.isString entry.architectures)
        || !(builtins.all (architecture: builtins.elem architecture validArchitectures) entry.architectures)
        || builtins.length (builtins.attrNames architectureSet) != builtins.length entry.architectures
        || !(builtins.isList entry.blockers)
        || !(builtins.all builtins.isString entry.blockers)
        || (
          if publishesDarwin
          then !(builtins.isInt entry.wave) || entry.wave < 1 || entry.wave > 5
          else entry.wave != null
        )
    ) (builtins.attrNames packageInventory);
  in
    if duplicateAssignments != []
    then throw "package platform support: packages assigned more than once: ${builtins.toJSON duplicateAssignments}"
    else if missing != []
    then throw "package platform support: missing classifications for ${builtins.toJSON missing}"
    else if stale != []
    then throw "package platform support: stale classifications for ${builtins.toJSON stale}"
    else if staleCriticalOverrides != []
    then throw "package platform support: stale critical overrides for ${builtins.toJSON staleCriticalOverrides}"
    else if staleArchitectureOverrides != []
    then throw "package platform support: stale architecture overrides for ${builtins.toJSON staleArchitectureOverrides}"
    else if invalid != []
    then throw "package platform support: invalid classifications for ${builtins.toJSON invalid}"
    else true;

  validateHelpers = paths: let
    classified = builtins.attrNames helperInventory;
    missing = builtins.filter (path: !(builtins.hasAttr path helperInventory)) paths;
    stale = builtins.filter (path: !(builtins.elem path paths)) classified;
  in
    if missing != []
    then throw "package platform support: missing helper classifications for ${builtins.toJSON missing}"
    else if stale != []
    then throw "package platform support: stale helper classifications for ${builtins.toJSON stale}"
    else true;

  validateExpressions = expressions: let
    missing =
      builtins.filter (
        expression:
          !(builtins.hasAttr expression.packageName packageInventory)
          && !(builtins.hasAttr expression.path factoryInventory)
      )
      expressions;
    expressionPaths = map (expression: expression.path) expressions;
    staleFactories = builtins.filter (
      path: !(builtins.elem path expressionPaths)
    ) (builtins.attrNames factoryInventory);
  in
    if missing != []
    then throw "package platform support: missing package-expression classifications for ${builtins.toJSON missing}"
    else if staleFactories != []
    then throw "package platform support: stale package-factory classifications for ${builtins.toJSON staleFactories}"
    else true;

  validateResources = paths: let
    missing = builtins.filter (path: !(builtins.hasAttr path resourceInventory)) paths;
    stale = builtins.filter (
      path: !(builtins.elem path paths)
    ) (builtins.attrNames resourceInventory);
  in
    if missing != []
    then throw "package platform support: missing excluded-resource classifications for ${builtins.toJSON missing}"
    else if stale != []
    then throw "package platform support: stale excluded-resource classifications for ${builtins.toJSON stale}"
    else true;
}
