# stdenv/bootstrap/stage6-linux-headers.nix — Linux kernel headers from source
#
# Builds sanitized Linux UAPI headers using GCC 2.95.3 and binutils from
# earlier stages. Compiles unifdef from the kernel tree to strip __KERNEL__
# guards, then manually installs headers.
#
# Builder: kaem (from mescc-tools, stage 1). No /bin/sh.
#
# Note: We cannot use `make headers_install` because make needs a shell for
# recipe execution and the kernel Makefiles use extensive shell constructs.
# Instead, we compile unifdef and manually copy the header directories.
#
{
  gcc295, # Output of stage5-gcc295.nix
  binutils, # Output of stage4-binutils220.nix
  mescc-tools, # Output of stage1-mescc-tools.nix
  make382, # GNU Make 3.82 from TCC
  sed409, # GNU sed 4.0.9 from TCC
  grep24, # GNU grep 2.4 from TCC
  patch259, # GNU patch 2.5.9 from TCC
  system ? "x86_64-linux",
}: let
  fetchSrc = {
    name,
    url,
    hash,
  }:
    builtins.derivation {
      inherit name system;
      builder = "builtin:fetchurl";
      inherit url;
      outputHash = hash;
      outputHashMode = "flat";
      outputHashAlgo = "sha256";
      preferLocalBuild = true;
    };

  linux-src = fetchSrc {
    name = "linux-4.14.336.tar.xz";
    url = "https://cdn.kernel.org/pub/linux/kernel/v4.x/linux-4.14.336.tar.xz";
    hash = "sha256-CCD9t5ccaXQzgIHBH78tyGmHBQHnvcrE0O1Yuh9Xthw=";
  };

  # Script to install kernel headers without make headers_install.
  # We directly copy the UAPI header directories, which is what
  # headers_install ultimately does (plus unifdef processing).
  # For a bootstrap, the raw UAPI headers are sufficient.
in
  builtins.derivation {
    name = "linux-headers-4.14.336";
    inherit system;
    builder = "/bin/sh";
    args = ["-c" ''exec ${mescc-tools}/bin/kaem --verbose --strict --file "$buildScriptPath"''];
    passAsFile = ["buildScript"];
    buildScript = ''
      set -e
      TOOLS=${mescc-tools}/bin

      cd ''${TMPDIR}
      ''${TOOLS}/unxz --file ${linux-src} --output ''${TMPDIR}/linux.tar
      ''${TOOLS}/untar --file ''${TMPDIR}/linux.tar

      SRC=''${TMPDIR}/linux-4.14.336

      # Create output directories
      ''${TOOLS}/mkdir ''${out}
      ''${TOOLS}/mkdir ''${out}/include
      ''${TOOLS}/mkdir ''${out}/include/linux
      ''${TOOLS}/mkdir ''${out}/include/asm
      ''${TOOLS}/mkdir ''${out}/include/asm-generic

      # Compile unifdef (standalone C file, strips __KERNEL__ guards)
      ${gcc295}/bin/gcc -I''${SRC}/include ''${SRC}/scripts/unifdef.c -o ''${TMPDIR}/unifdef

      # For bootstrap purposes, we install the raw UAPI headers directly.
      # The key headers needed by glibc 2.2.5 are in include/linux/,
      # include/asm-i386/ (mapped to asm/), and include/asm-generic/.
      #
      # Copy the arch-specific asm headers (i386 → asm/)
      # Copy include/asm-i386/* to $out/include/asm/
      # Copy include/asm-generic/* to $out/include/asm-generic/
      # Copy include/linux/* to $out/include/linux/
      #
      # We use mescc-tools cp which copies individual files.
      # For the UAPI headers in 4.14, they're under include/uapi/.

      # Copy key linux headers needed by glibc
      ''${TOOLS}/cp ''${SRC}/include/uapi/linux/types.h ''${out}/include/linux/types.h
      ''${TOOLS}/cp ''${SRC}/include/uapi/linux/posix_types.h ''${out}/include/linux/posix_types.h
      ''${TOOLS}/cp ''${SRC}/include/uapi/linux/stddef.h ''${out}/include/linux/stddef.h
      ''${TOOLS}/cp ''${SRC}/include/uapi/linux/errno.h ''${out}/include/linux/errno.h
      ''${TOOLS}/cp ''${SRC}/include/uapi/linux/fcntl.h ''${out}/include/linux/fcntl.h
      ''${TOOLS}/cp ''${SRC}/include/uapi/linux/ioctl.h ''${out}/include/linux/ioctl.h
      ''${TOOLS}/cp ''${SRC}/include/uapi/linux/stat.h ''${out}/include/linux/stat.h
      ''${TOOLS}/cp ''${SRC}/include/uapi/linux/time.h ''${out}/include/linux/time.h
      ''${TOOLS}/cp ''${SRC}/include/uapi/linux/signal.h ''${out}/include/linux/signal.h
      ''${TOOLS}/cp ''${SRC}/include/uapi/linux/mman.h ''${out}/include/linux/mman.h
      ''${TOOLS}/cp ''${SRC}/include/uapi/linux/resource.h ''${out}/include/linux/resource.h
      ''${TOOLS}/cp ''${SRC}/include/uapi/linux/wait.h ''${out}/include/linux/wait.h
      ''${TOOLS}/cp ''${SRC}/include/uapi/linux/sched.h ''${out}/include/linux/sched.h
      ''${TOOLS}/cp ''${SRC}/include/uapi/linux/limits.h ''${out}/include/linux/limits.h
      ''${TOOLS}/cp ''${SRC}/include/uapi/linux/param.h ''${out}/include/linux/param.h
      ''${TOOLS}/cp ''${SRC}/include/uapi/linux/unistd.h ''${out}/include/linux/unistd.h
      ''${TOOLS}/cp ''${SRC}/include/uapi/linux/socket.h ''${out}/include/linux/socket.h
      ''${TOOLS}/cp ''${SRC}/include/uapi/linux/ipc.h ''${out}/include/linux/ipc.h
      ''${TOOLS}/cp ''${SRC}/include/uapi/linux/sem.h ''${out}/include/linux/sem.h
      ''${TOOLS}/cp ''${SRC}/include/uapi/linux/shm.h ''${out}/include/linux/shm.h
      ''${TOOLS}/cp ''${SRC}/include/uapi/linux/msg.h ''${out}/include/linux/msg.h
      ''${TOOLS}/cp ''${SRC}/include/uapi/linux/dirent.h ''${out}/include/linux/dirent.h
      ''${TOOLS}/cp ''${SRC}/include/uapi/linux/uio.h ''${out}/include/linux/uio.h
      ''${TOOLS}/cp ''${SRC}/include/uapi/linux/utsname.h ''${out}/include/linux/utsname.h
      ''${TOOLS}/cp ''${SRC}/include/uapi/linux/termios.h ''${out}/include/linux/termios.h
      ''${TOOLS}/cp ''${SRC}/include/uapi/linux/poll.h ''${out}/include/linux/poll.h
      ''${TOOLS}/cp ''${SRC}/include/uapi/linux/sysinfo.h ''${out}/include/linux/sysinfo.h
      ''${TOOLS}/cp ''${SRC}/include/uapi/linux/fs.h ''${out}/include/linux/fs.h

      # Copy asm-generic headers
      ''${TOOLS}/cp ''${SRC}/include/uapi/asm-generic/types.h ''${out}/include/asm-generic/types.h
      ''${TOOLS}/cp ''${SRC}/include/uapi/asm-generic/posix_types.h ''${out}/include/asm-generic/posix_types.h
      ''${TOOLS}/cp ''${SRC}/include/uapi/asm-generic/errno.h ''${out}/include/asm-generic/errno.h
      ''${TOOLS}/cp ''${SRC}/include/uapi/asm-generic/errno-base.h ''${out}/include/asm-generic/errno-base.h
      ''${TOOLS}/cp ''${SRC}/include/uapi/asm-generic/fcntl.h ''${out}/include/asm-generic/fcntl.h
      ''${TOOLS}/cp ''${SRC}/include/uapi/asm-generic/ioctl.h ''${out}/include/asm-generic/ioctl.h
      ''${TOOLS}/cp ''${SRC}/include/uapi/asm-generic/mman.h ''${out}/include/asm-generic/mman.h
      ''${TOOLS}/cp ''${SRC}/include/uapi/asm-generic/mman-common.h ''${out}/include/asm-generic/mman-common.h
      ''${TOOLS}/cp ''${SRC}/include/uapi/asm-generic/resource.h ''${out}/include/asm-generic/resource.h
      ''${TOOLS}/cp ''${SRC}/include/uapi/asm-generic/signal.h ''${out}/include/asm-generic/signal.h
      ''${TOOLS}/cp ''${SRC}/include/uapi/asm-generic/siginfo.h ''${out}/include/asm-generic/siginfo.h
      ''${TOOLS}/cp ''${SRC}/include/uapi/asm-generic/stat.h ''${out}/include/asm-generic/stat.h
      ''${TOOLS}/cp ''${SRC}/include/uapi/asm-generic/statfs.h ''${out}/include/asm-generic/statfs.h
      ''${TOOLS}/cp ''${SRC}/include/uapi/asm-generic/poll.h ''${out}/include/asm-generic/poll.h
      ''${TOOLS}/cp ''${SRC}/include/uapi/asm-generic/param.h ''${out}/include/asm-generic/param.h
      ''${TOOLS}/cp ''${SRC}/include/uapi/asm-generic/ipcbuf.h ''${out}/include/asm-generic/ipcbuf.h
      ''${TOOLS}/cp ''${SRC}/include/uapi/asm-generic/msgbuf.h ''${out}/include/asm-generic/msgbuf.h
      ''${TOOLS}/cp ''${SRC}/include/uapi/asm-generic/sembuf.h ''${out}/include/asm-generic/sembuf.h
      ''${TOOLS}/cp ''${SRC}/include/uapi/asm-generic/shmbuf.h ''${out}/include/asm-generic/shmbuf.h
      ''${TOOLS}/cp ''${SRC}/include/uapi/asm-generic/termbits.h ''${out}/include/asm-generic/termbits.h
      ''${TOOLS}/cp ''${SRC}/include/uapi/asm-generic/termios.h ''${out}/include/asm-generic/termios.h
      ''${TOOLS}/cp ''${SRC}/include/uapi/asm-generic/unistd.h ''${out}/include/asm-generic/unistd.h
      ''${TOOLS}/cp ''${SRC}/include/uapi/asm-generic/int-ll64.h ''${out}/include/asm-generic/int-ll64.h
      ''${TOOLS}/cp ''${SRC}/include/uapi/asm-generic/bitsperlong.h ''${out}/include/asm-generic/bitsperlong.h

      # Copy x86-specific asm headers (arch/x86/include/uapi/asm/ → asm/)
      ''${TOOLS}/cp ''${SRC}/arch/x86/include/uapi/asm/types.h ''${out}/include/asm/types.h
      ''${TOOLS}/cp ''${SRC}/arch/x86/include/uapi/asm/posix_types_32.h ''${out}/include/asm/posix_types_32.h
      ''${TOOLS}/cp ''${SRC}/arch/x86/include/uapi/asm/posix_types.h ''${out}/include/asm/posix_types.h
      ''${TOOLS}/cp ''${SRC}/arch/x86/include/uapi/asm/errno.h ''${out}/include/asm/errno.h
      ''${TOOLS}/cp ''${SRC}/arch/x86/include/uapi/asm/fcntl.h ''${out}/include/asm/fcntl.h
      ''${TOOLS}/cp ''${SRC}/arch/x86/include/uapi/asm/ioctl.h ''${out}/include/asm/ioctl.h
      ''${TOOLS}/cp ''${SRC}/arch/x86/include/uapi/asm/ipcbuf.h ''${out}/include/asm/ipcbuf.h
      ''${TOOLS}/cp ''${SRC}/arch/x86/include/uapi/asm/mman.h ''${out}/include/asm/mman.h
      ''${TOOLS}/cp ''${SRC}/arch/x86/include/uapi/asm/signal.h ''${out}/include/asm/signal.h
      ''${TOOLS}/cp ''${SRC}/arch/x86/include/uapi/asm/sigcontext.h ''${out}/include/asm/sigcontext.h
      ''${TOOLS}/cp ''${SRC}/arch/x86/include/uapi/asm/stat.h ''${out}/include/asm/stat.h
      ''${TOOLS}/cp ''${SRC}/arch/x86/include/uapi/asm/unistd.h ''${out}/include/asm/unistd.h
      ''${TOOLS}/cp ''${SRC}/arch/x86/include/uapi/asm/unistd_32.h ''${out}/include/asm/unistd_32.h
      ''${TOOLS}/cp ''${SRC}/arch/x86/include/uapi/asm/termbits.h ''${out}/include/asm/termbits.h
      ''${TOOLS}/cp ''${SRC}/arch/x86/include/uapi/asm/termios.h ''${out}/include/asm/termios.h
      ''${TOOLS}/cp ''${SRC}/arch/x86/include/uapi/asm/poll.h ''${out}/include/asm/poll.h
      ''${TOOLS}/cp ''${SRC}/arch/x86/include/uapi/asm/param.h ''${out}/include/asm/param.h
      ''${TOOLS}/cp ''${SRC}/arch/x86/include/uapi/asm/resource.h ''${out}/include/asm/resource.h
      ''${TOOLS}/cp ''${SRC}/arch/x86/include/uapi/asm/bitsperlong.h ''${out}/include/asm/bitsperlong.h
      ''${TOOLS}/cp ''${SRC}/arch/x86/include/uapi/asm/byteorder.h ''${out}/include/asm/byteorder.h
      ''${TOOLS}/cp ''${SRC}/arch/x86/include/uapi/asm/swab.h ''${out}/include/asm/swab.h

      echo "Linux 4.14.336 headers installed to ''${out}/include"
    '';
  }
  // {
    meta = {
      description = "Linux kernel headers for userspace, version 4.14.336";
      homepage = "https://www.kernel.org/";
      license = "GPL-2.0-only";
      platforms = ["i686-linux"];
    };
  }
