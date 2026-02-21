# stdenv/bootstrap/stage5-linux-headers.nix — Linux kernel headers from source
#
# Builds sanitized Linux UAPI headers. Manually installs headers needed
# by glibc 2.2.5.
#
# Builder: bash 2.05b (from stage 4 TCC build). The build script uses
# posix-tools (cp, mkdir) for file operations.
#
# Note: We cannot use `make headers_install` because kernel 4.14's
# headers_install needs perl for sanitization scripts, which is not
# available at this stage. The UAPI headers in 4.14+ are already
# separated from kernel-internal headers, so we can copy them directly
# without stripping __KERNEL__ guards.
#
{
  posix-tools, # Output of stage1-posix-tools.nix
  bash, # Output of stage4-bash.nix (bash 2.05b built with TCC)
  gnumake, # GNU Make 3.79.1 from TCC
  buildPlatform,
  ...
}:
let
  system = buildPlatform.system;

  src = builtins.fetchTarball {
    url = "https://cdn.kernel.org/pub/linux/kernel/v4.x/linux-4.14.336.tar.xz";
    sha256 = "sha256-yY2ahTYhcwjUg26E6/kPfer4SQSxldZ1y63Eo39yCDo=";
  };

in
builtins.derivation {
  name = "linux-headers-4.14.336";
  inherit system;
  builder = "${bash}/bin/bash";
  args = [
    "-c"
    ''
      set -eu

      export PATH="${
        builtins.concatStringsSep ":" (
          builtins.map (p: "${p}/bin") [
            bash
            gnumake
            posix-tools
          ]
        )
      }"

      SRC=${src}

      # Create output directories
      mkdir $out
      mkdir $out/include
      mkdir $out/include/linux
      mkdir $out/include/asm
      mkdir $out/include/asm-generic

      # Note: unifdef compilation skipped — the UAPI headers in 4.14+ are
      # already separated from kernel-internal headers, so we can copy them
      # directly without stripping __KERNEL__ guards.

      # Copy key linux headers needed by glibc (include/uapi/linux/ -> linux/)
      for h in types.h posix_types.h stddef.h errno.h fcntl.h ioctl.h \
               stat.h time.h signal.h mman.h resource.h wait.h sched.h \
               limits.h param.h unistd.h socket.h ipc.h sem.h shm.h \
               msg.h uio.h utsname.h termios.h poll.h sysinfo.h fs.h; do
        cp $SRC/include/uapi/linux/$h $out/include/linux/$h
      done

      # Copy asm-generic headers (include/uapi/asm-generic/ -> asm-generic/)
      for h in types.h posix_types.h errno.h errno-base.h fcntl.h ioctl.h \
               mman.h mman-common.h resource.h signal.h siginfo.h stat.h \
               statfs.h poll.h param.h ipcbuf.h msgbuf.h sembuf.h shmbuf.h \
               termbits.h termios.h unistd.h int-ll64.h bitsperlong.h; do
        cp $SRC/include/uapi/asm-generic/$h $out/include/asm-generic/$h
      done

      # Copy x86-specific asm headers (arch/x86/include/uapi/asm/ -> asm/)
      # unistd_32.h is generated at kernel build time — not in source tree
      for h in types.h posix_types_32.h posix_types.h errno.h fcntl.h \
               ioctl.h ipcbuf.h mman.h signal.h sigcontext.h stat.h \
               unistd.h termbits.h termios.h poll.h param.h resource.h \
               bitsperlong.h byteorder.h swab.h; do
        cp $SRC/arch/x86/include/uapi/asm/$h $out/include/asm/$h
      done

      echo "Linux 4.14.336 headers installed to $out/include"
    ''
  ];
}
// {
  meta = {
    description = "Linux kernel headers for userspace, version 4.14.336";
    homepage = "https://www.kernel.org/";
    license = "GPL-2.0-only";
    platforms = [ "i686-linux" ];
  };
}
