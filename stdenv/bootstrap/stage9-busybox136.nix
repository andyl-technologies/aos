# stdenv/bootstrap/stage9-busybox136.nix — BusyBox 1.36.1
#
# Single-binary POSIX toolbox providing sh, ash, cat, cp, chmod, mkdir, ln,
# mv, rm, touch, ls, find, xargs, grep, sed, awk, diff, tar, gzip, bunzip2,
# sort, tr, wc, head, tail, cut, basename, dirname, echo, env, expr, printf,
# test, true, false, date, uname, install, readlink, sleep, nproc, and more.
#
# Built with GCC 3.4.6 + glibc 2.2.5 + binutils 2.20.1a as a static binary.
#
# Builder: kaem (from mescc-tools, stage 1). No /bin/sh.
# This is the LAST stage using kaem as builder.
#
# Strategy: BusyBox has its own build system based on make + kconfig.
# Since we can't run make or configure under kaem, we use make382 with
# a pre-generated .config, and set SHELL in the make invocation to use
# a minimal script runner. The BusyBox Makefile recipes are simple enough
# to work with kaem-compatible command execution.
#
# However, make internally needs a shell for recipe execution. Since we
# cannot use /bin/sh (by design), we compile a tiny shell wrapper from C
# that can execute simple one-line commands — sufficient for make recipes.
#
{
  gcc346, # Output of stage8-gcc346.nix
  glibc225, # Output of stage7-glibc225.nix
  binutils220, # Output of stage4-binutils220.nix
  mescc-tools, # mescc-tools (kaem builder, extraction tools)
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

  busybox-src = fetchSrc {
    name = "busybox-1.36.1.tar.bz2";
    url = "https://www.busybox.net/downloads/busybox-1.36.1.tar.bz2";
    hash = "sha256-sGsR6JOL1JCjnJKT6XcJwxDnA2sIY7ZRBRgBsozo/rY=";
  };

  # Minimal shell implementation for make recipe execution.
  # make invokes SHELL with "-c" "recipe line" — this program just
  # passes the recipe string to system() which is implemented in glibc.
  # Since glibc's system() also needs /bin/sh, we instead parse the
  # command ourselves with simple exec.
  #
  # Actually, glibc 2.2.5's system() calls /bin/sh which doesn't exist
  # in a pure kaem build. Instead, we implement a minimal command executor
  # that parses whitespace-separated argv and calls execvp.
  mini-sh-src = builtins.toFile "mini-sh.c" ''
    #include <stdlib.h>
    #include <string.h>
    #include <unistd.h>
    #include <sys/wait.h>
    #include <stdio.h>

    /* Minimal shell for make recipe execution.
     * Supports: simple commands, ; chaining, && chaining.
     * Does NOT support: pipes, redirects, backticks, variable expansion.
     * This is sufficient for most BusyBox Makefile recipes. */

    static int run_cmd(const char *line) {
      char buf[4096];
      char *argv[256];
      int argc = 0;
      char *p;
      pid_t pid;
      int status;

      if (strlen(line) >= sizeof(buf)) return 1;
      strcpy(buf, line);

      /* Skip leading whitespace */
      p = buf;
      while (*p == ' ' || *p == '\t') p++;
      if (*p == '\0' || *p == '#') return 0;

      /* Handle echo specially — just print everything after "echo " */
      if (strncmp(p, "echo ", 5) == 0) {
        printf("%s\n", p + 5);
        return 0;
      }

      /* Handle cd */
      if (strncmp(p, "cd ", 3) == 0) {
        return chdir(p + 3);
      }

      /* Split into argv */
      while (*p && argc < 255) {
        while (*p == ' ' || *p == '\t') p++;
        if (*p == '\0') break;
        argv[argc++] = p;
        while (*p && *p != ' ' && *p != '\t') p++;
        if (*p) *p++ = '\0';
      }
      argv[argc] = NULL;
      if (argc == 0) return 0;

      /* Handle test/true/false builtins */
      if (strcmp(argv[0], "true") == 0) return 0;
      if (strcmp(argv[0], "false") == 0) return 1;

      pid = fork();
      if (pid == 0) {
        execvp(argv[0], argv);
        _exit(127);
      }
      waitpid(pid, &status, 0);
      if (WIFEXITED(status)) return WEXITSTATUS(status);
      return 1;
    }

    int main(int argc, char **argv) {
      const char *cmd;
      char buf[8192];
      char *p, *start;
      int ret = 0;

      if (argc < 3 || strcmp(argv[1], "-c") != 0) {
        fprintf(stderr, "mini-sh: usage: mini-sh -c 'command'\n");
        return 1;
      }
      cmd = argv[2];
      if (strlen(cmd) >= sizeof(buf)) return 1;
      strcpy(buf, cmd);

      /* Execute commands separated by ; or && */
      start = buf;
      for (p = buf; ; p++) {
        if (*p == ';' || *p == '\0' || (*p == '&' && *(p+1) == '&')) {
          char sep = *p;
          char next = *(p+1);
          *p = '\0';
          ret = run_cmd(start);
          if (sep == '\0') break;
          if (sep == '&') {
            p++; /* skip second & */
            if (ret != 0) return ret;
          }
          start = p + 1;
        }
      }
      return ret;
    }
  '';

  # Pre-generated BusyBox .config for a minimal but useful build.
  # We enable only the applets needed by the toolchain.
  busybox-config = builtins.toFile "busybox-config" ''
    CONFIG_STATIC=y
    CONFIG_FEATURE_SH_IS_ASH=y
    CONFIG_ASH=y
    CONFIG_ASH_JOB_CONTROL=y
    CONFIG_ASH_ALIAS=y
    CONFIG_ASH_EXPAND_PRMT=y
    CONFIG_ASH_BASH_COMPAT=y
    CONFIG_ASH_TEST=y
    CONFIG_ASH_GETOPTS=y
    CONFIG_FEATURE_SH_MATH=y
    CONFIG_FEATURE_SH_MATH_64=y
    CONFIG_HUSH=n
    CONFIG_CAT=y
    CONFIG_CHMOD=y
    CONFIG_CHOWN=y
    CONFIG_CP=y
    CONFIG_CUT=y
    CONFIG_DATE=y
    CONFIG_DD=y
    CONFIG_DIRNAME=y
    CONFIG_DU=y
    CONFIG_ECHO=y
    CONFIG_ENV=y
    CONFIG_EXPR=y
    CONFIG_FALSE=y
    CONFIG_HEAD=y
    CONFIG_ID=y
    CONFIG_INSTALL=y
    CONFIG_LN=y
    CONFIG_LS=y
    CONFIG_MKDIR=y
    CONFIG_MV=y
    CONFIG_OD=y
    CONFIG_PRINTF=y
    CONFIG_PWD=y
    CONFIG_READLINK=y
    CONFIG_RM=y
    CONFIG_RMDIR=y
    CONFIG_SEQ=y
    CONFIG_SLEEP=y
    CONFIG_SORT=y
    CONFIG_STAT=y
    CONFIG_STTY=y
    CONFIG_TAIL=y
    CONFIG_TEE=y
    CONFIG_TEST=y
    CONFIG_TOUCH=y
    CONFIG_TR=y
    CONFIG_TRUE=y
    CONFIG_UNAME=y
    CONFIG_UNIQ=y
    CONFIG_WC=y
    CONFIG_YES=y
    CONFIG_BASENAME=y
    CONFIG_FIND=y
    CONFIG_XARGS=y
    CONFIG_GREP=y
    CONFIG_SED=y
    CONFIG_AWK=y
    CONFIG_DIFF=y
    CONFIG_CMP=y
    CONFIG_PATCH=y
    CONFIG_TAR=y
    CONFIG_GZIP=y
    CONFIG_BUNZIP2=y
    CONFIG_NPROC=y
    CONFIG_FEATURE_HAVE_RPC=n
    CONFIG_FEATURE_INETD_RPC=n
    CONFIG_FEATURE_MODPROBE_BLACKLIST=n
  '';

in
  builtins.derivation {
    name = "busybox-1.36.1";
    inherit system;
    builder = "/bin/sh";
    args = ["-c" ''exec ${mescc-tools}/bin/kaem --verbose --strict --file "$buildScriptPath"''];
    passAsFile = ["buildScript"];
    buildScript = ''
      set -e
      TOOLS=${mescc-tools}/bin
      CC=${gcc346}/bin/gcc

      cd ''${TMPDIR}
      ''${TOOLS}/unbz2 --file ${busybox-src} --output ''${TMPDIR}/busybox.tar
      ''${TOOLS}/untar --file ''${TMPDIR}/busybox.tar
      cd ''${TMPDIR}/busybox-1.36.1

      # Build mini-sh first (needed as make's SHELL)
      ''${CC} -I${glibc225}/include -L${glibc225}/lib -static -o ''${TMPDIR}/mini-sh ${mini-sh-src}

      # Install the pre-generated .config
      ''${TOOLS}/cp ${busybox-config} ''${TMPDIR}/busybox-1.36.1/.config

      # Run make with our mini-sh as SHELL
      ${make382}/bin/make SHELL=''${TMPDIR}/mini-sh CC="${gcc346}/bin/gcc" HOSTCC="${gcc346}/bin/gcc" CFLAGS="-I${glibc225}/include" LDFLAGS="-L${glibc225}/lib -static" SKIP_STRIP=y

      # Install
      ''${TOOLS}/mkdir ''${out}
      ''${TOOLS}/mkdir ''${out}/bin
      ''${TOOLS}/cp busybox ''${out}/bin/busybox
      ''${TOOLS}/chmod ''${out}/bin/busybox

      # Create symlinks for key applets using mescc-tools
      # mescc-tools doesn't have 'ln' — but we compiled a symlink tool in stage 1.
      # For now, the busybox binary is installed and applets can be accessed as
      # "busybox <applet>" or via the wrapper pattern.
      # The toolchain stage (which uses BusyBox sh as its builder) will create
      # proper symlinks using BusyBox itself.

      echo "BusyBox 1.36.1 installed to ''${out}"
    '';
  }
  // {
    meta = {
      description = "BusyBox 1.36.1 — single-binary POSIX toolbox";
      homepage = "https://www.busybox.net/";
      license = "GPL-2.0-only";
      platforms = ["i686-linux" "x86_64-linux"];
    };
  }
