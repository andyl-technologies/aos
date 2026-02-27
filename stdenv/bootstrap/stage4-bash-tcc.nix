# stdenv/bootstrap/stage4-bash.nix — bash 2.05b from TCC (Mes libc)
#
# First shell in the bootstrap chain. Built with TCC 0.9.27 against Mes libc.
# This is the LAST kaem-based build — all subsequent stages use bash as builder.
#
# bash 2.05b is compiled without any shell (kaem as builder). This bash
# will serve as the builder/shell for binutils, GCC 2.95.3, and everything after.
#
# Features disabled for Mes libc: readline, history, job control, locale, wchar.
# Uses nojobs.c instead of jobs.c. No termcap/readline libraries.
#
# Based on live-bootstrap's approach to building bash with TCC + Mes libc.
#
# Builder: kaemNix -> full kaem. No /bin/sh dependency.
#
{
  tinycc, # Output of stage3-tinycc.nix (TCC with Mes libc)
  posix-tools, # Output of stage1-posix-tools.nix
  seeds, # Output of stage0-seeds.nix (provides kaemNix)
  buildPlatform,
  ...
}:
let
  system = buildPlatform.system;
  sources = import ./sources.nix;

  bash-src = builtins.derivation {
    name = "bash-${sources.bash.version}.tar.gz";
    inherit system;
    builder = "builtin:fetchurl";
    url = sources.bash.url;
    outputHash = sources.bash.tarballHash;
    outputHashMode = "flat";
    outputHashAlgo = "sha256";
    preferLocalBuild = true;
  };

  # Pre-generated config.h for bash 2.05b on i686-linux with Mes libc (TCC)
  # Based on live-bootstrap's defines for TCC + Mes libc
  config-h = builtins.toFile "bash-config.h" ''
    /* config.h -- pre-generated for bash 2.05b bootstrap with TCC + Mes libc */
    #ifndef _CONFIG_H_
    #define _CONFIG_H_

    /* System headers available in Mes libc */
    #define HAVE_DIRENT_H 1
    #define STRUCT_DIRENT_HAS_D_INO 1
    #define HAVE_STDINT_H 1
    #define HAVE_LIMITS_H 1
    #define HAVE_STRING_H 1
    #define HAVE_INTTYPES_H 1
    #define HAVE_UNISTD_H 1
    #define HAVE_STDLIB_H 1
    #define HAVE_STDARG_H 1
    #define HAVE_SYS_TYPES_H 1
    #define HAVE_SYS_STAT_H 1
    #define HAVE_SYS_WAIT_H 1
    #define HAVE_SYS_TIME_H 1
    #define HAVE_FCNTL_H 1
    #define HAVE_ERRNO_H 1
    #define HAVE_SIGNAL_H 1
    #define HAVE_ALLOCA_H 1
    #define HAVE_ALLOCA 1
    #define STDC_HEADERS 1

    /* Signal handling */
    #define RETSIGTYPE void
    #define VOID_SIGHANDLER 1
    #define HAVE_POSIX_SIGNALS 1
    #define HAVE_SYS_SIGLIST 1

    /* Terminal — use older termio interface (Mes libc does not have termios) */
    #define TERMIO_TTY_DRIVER 1

    /* Varargs */
    #define PREFER_STDARG 1

    /* Floating point fallback */
    #define HUGE_VAL 10000000000.0

    /* Available functions in Mes libc */
    #define HAVE_STRERROR 1
    #define HAVE_MEMSET 1
    #define HAVE_DUP2 1
    #define HAVE_STRTOUL 1
    #define HAVE_STRTOULL 1
    #define HAVE_STRCHR 1
    #define HAVE_BCOPY 1
    #define HAVE_BZERO 1
    #define HAVE_GETCWD 1
    #define HAVE_RENAME 1
    #define HAVE_PIPE 1
    #define HAVE_WAITPID 1
    #define HAVE_SIGACTION 1
    #define HAVE_DECL_STRTOL 1
    #define HAVE_DECL_STRTOLL 1
    #define HAVE_DECL_STRTOUL 1
    #define HAVE_DECL_STRTOULL 1
    #define HAVE_TZNAME 1

    /* Type sizes (i686 — 32-bit) */
    #define SIZEOF_INT 4
    #define SIZEOF_LONG 4
    #define SIZEOF_CHAR_P 4
    #define SIZEOF_DOUBLE 8

    /* Groups */
    #define GETGROUPS_T int

    /* Pipe size */
    #define PIPESIZE 4096

    /* Shell features — minimal set for Mes libc */
    #define COND_COMMAND 1
    #define DPAREN_ARITHMETIC 1
    #define ARITH_FOR_COMMAND 1
    #define ALIAS 1
    #define BRACE_EXPANSION 1
    #define EXTENDED_GLOB 1
    #define SELECT_COMMAND 1
    #define HELP_BUILTIN 1
    #define ARRAY_VARS 1
    #define PUSHD_AND_POPD 1
    #define COMMAND_TIMING 1
    #define PROMPT_STRING_DECODE 1

    /* Explicitly DISABLED features (no readline, no history, no job control) */
    /* JOB_CONTROL — not defined, use nojobs.c */
    /* READLINE — not defined */
    /* HISTORY — not defined */
    /* BANG_HISTORY — not defined */
    /* PROCESS_SUBSTITUTION — not defined */
    /* PROGRAMMABLE_COMPLETION — not defined */
    /* RESTRICTED_SHELL — not defined (leave undefined to skip restricted code) */
    /* DEBUGGER — not defined */

    /* Shell identity */
    #define SHELL 1
    #define PROGRAM "bash"
    #define CONF_HOSTTYPE "i386"
    #define CONF_OSTYPE "linux"
    #define CONF_MACHTYPE "i386-linux"
    #define CONF_VENDOR "unknown"
    #define PACKAGE "bash"
    #define PACKAGE_VERSION "2.05b"
    #define DISTVERSION "2.05b"
    #define BUILDVERSION 0
    #define SCCSVERSION "2.05b"
    /* LC_ALL — defined by locale.h as an integer constant, not here */

    /* Path defaults */
    #define DEFAULT_PATH_VALUE "/bin"
    #define STANDARD_UTILS_PATH "/bin"
    #define DEFAULT_MAIL_DIRECTORY "/fake-mail"
    #define LOCALEDIR "/usr/share/locale"
    #define SYS_PROFILE "/etc/profile"
    #define SYS_BASHRC "/etc/bash.bashrc"

    /* Prompt strings */
    #define PPROMPT "$ "
    #define SPROMPT "$ "

    /* POSIX version — needed so posixwait.h defines WAIT as int, not union wait */
    #if !defined(_POSIX_VERSION)
    #define _POSIX_VERSION 199309L
    #endif

    /* Linux-specific */
    #define HAVE_DEV_FD 1
    #define DEV_FD_PREFIX "/dev/fd/"
    #define HAVE_DEV_STDIN 1

    /* Hash bang exec */
    #define HAVE_HASH_BANG_EXEC 1
    #define RECYCLES_PIDS 1

    /* Stub for unavailable functions */
    #define endpwent(x) 0
    #define enable_hostname_completion(on_or_off) 0

    #endif /* _CONFIG_H_ */
  '';

  # Pre-generated pathnames.h
  pathnames-h = builtins.toFile "pathnames.h" ''
    #ifndef _PATHNAMES_H
    #define _PATHNAMES_H
    #define DEFAULT_MAIL_DIRECTORY "/fake-mail"
    #endif
  '';

  # Minimal POSIX getopt() — mksyntax.c needs standard getopt/optarg/optind
  # which Mes libc does not provide. bash's builtins/getopt.c uses sh_getopt()
  # prefixed names and cannot be used here.
  getopt-c = builtins.toFile "getopt.c" ''
    /* Minimal POSIX getopt() for bootstrap build tools */
    #include <string.h>
    #include <stdio.h>

    char *optarg = 0;
    int optind = 1;
    int opterr = 1;
    int optopt = 0;

    static int optpos = 0;

    int getopt(int argc, char * const argv[], const char *optstring)
    {
      const char *p;
      if (optind >= argc || !argv[optind] || argv[optind][0] != '-' || !argv[optind][1])
        return -1;
      if (argv[optind][1] == '-' && !argv[optind][2]) {
        optind++;
        return -1;
      }
      if (!optpos) optpos = 1;
      optopt = argv[optind][optpos];
      p = strchr(optstring, optopt);
      if (!p || optopt == ':') {
        if (opterr) fprintf(stderr, "%s: unknown option '-%c'\n", argv[0], optopt);
        if (!argv[optind][++optpos]) { optind++; optpos = 0; }
        return '?';
      }
      if (p[1] == ':') {
        if (argv[optind][optpos + 1]) {
          optarg = &argv[optind][optpos + 1];
        } else if (optind + 1 < argc) {
          optarg = argv[++optind];
        } else {
          if (opterr) fprintf(stderr, "%s: option '-%c' requires an argument\n", argv[0], optopt);
          optind++;
          optpos = 0;
          return optstring[0] == ':' ? ':' : '?';
        }
        optind++;
        optpos = 0;
      } else {
        if (!argv[optind][++optpos]) { optind++; optpos = 0; }
      }
      return optopt;
    }
  '';

  # Pre-generated signames.h for i686-linux
  # Matches the format generated by bash's mksignames: defines signal_names[]
  # array directly with initialization, and initialize_signames() is a no-op.
  # NSIG guarded to avoid redefinition warning from system headers.
  signames-h = builtins.toFile "signames.h" ''
    /* signames.h -- pre-generated for i686-linux */
    /* This file was automatically created by mksignames. Do not edit. */
    #if !defined (_SIGNAMES_H_)
    #define _SIGNAMES_H_

    #undef NSIG
    #define NSIG 33

    char *signal_names[NSIG + 4] = {
      "EXIT",
      "SIGHUP",
      "SIGINT",
      "SIGQUIT",
      "SIGILL",
      "SIGTRAP",
      "SIGABRT",
      "SIGBUS",
      "SIGFPE",
      "SIGKILL",
      "SIGUSR1",
      "SIGSEGV",
      "SIGUSR2",
      "SIGPIPE",
      "SIGALRM",
      "SIGTERM",
      "SIGSTKFLT",
      "SIGCHLD",
      "SIGCONT",
      "SIGSTOP",
      "SIGTSTP",
      "SIGTTIN",
      "SIGTTOU",
      "SIGURG",
      "SIGXCPU",
      "SIGXFSZ",
      "SIGVTALRM",
      "SIGPROF",
      "SIGWINCH",
      "SIGIO",
      "SIGPWR",
      "SIGSYS",
      "DEBUG",
      (char *)0x0,
      (char *)0x0,
      (char *)0x0,
      (char *)0x0
    };

    #define initialize_signames()

    #endif /* _SIGNAMES_H_ */
  '';

  # ── Build script (run by full kaem) ──────────────────────────────────
  buildKaem = builtins.toFile "build-bash-tcc.kaem" ''
    TOOLS=''${POSIX_TOOLS}/bin
    CC=''${TINYCC}/bin/tcc

    cd ''${TMPDIR}
    ''${TOOLS}/ungz --file ''${BASH_SRC} --output ''${TMPDIR}/bash.tar
    ''${TOOLS}/untar --file ''${TMPDIR}/bash.tar

    SRC=''${TMPDIR}/bash-2.05b
    BUILD=''${TMPDIR}/build

    ''${TOOLS}/mkdir ''${BUILD}
    ''${TOOLS}/mkdir ''${BUILD}/objs
    ''${TOOLS}/mkdir ''${BUILD}/objs/builtins
    ''${TOOLS}/mkdir ''${BUILD}/objs/lib
    ''${TOOLS}/mkdir ''${BUILD}/objs/lib/glob
    ''${TOOLS}/mkdir ''${BUILD}/objs/lib/tilde
    ''${TOOLS}/mkdir ''${BUILD}/objs/lib/sh

    # Create output directories
    ''${TOOLS}/mkdir ''${out}
    ''${TOOLS}/mkdir ''${out}/bin

    # ── Install pre-generated headers ────────────────────────────────────
    ''${TOOLS}/cp ${config-h} ''${SRC}/config.h
    ''${TOOLS}/cp ${pathnames-h} ''${SRC}/pathnames.h
    ''${TOOLS}/cp ${signames-h} ''${SRC}/signames.h

    # Create empty version.h and pipesize.h (normally generated by configure)
    ''${TOOLS}/catm ''${SRC}/include/version.h
    ''${TOOLS}/catm ''${SRC}/include/pipesize.h

    # ── Patch: fix setlocale empty-macro in bashintl.h ───────────────────
    # When HAVE_SETLOCALE is not defined, bashintl.h defines setlocale(cat,loc)
    # as an empty macro, which breaks locale.c:193 where the result is compared.
    # Change it to expand to ((char *)0) so the expression is valid C.
    ''${TOOLS}/replace --file ''${SRC}/bashintl.h --output ''${SRC}/bashintl.h --match-on "#  define setlocale(cat, loc)" --replace-with "#  define setlocale(cat, loc) ((char *)0)"

    # ── Patch: fix gethostname K&R declaration in oslib.c ────────────────
    # The fallback branch has "int name, namelen;" which should be
    # "char *name; int namelen;" — TCC doesn't handle this K&R mismatch
    ''${TOOLS}/replace --file ''${SRC}/lib/sh/oslib.c --output ''${SRC}/lib/sh/oslib.c --match-on "     int name, namelen;" --replace-with "     char *name; int namelen;"

    # ══════════════════════════════════════════════════════════════════════
    # Generate syntax.c: compile mksyntax, run it
    # ══════════════════════════════════════════════════════════════════════
    echo "==> Generating syntax.c"

    ''${CC} -DHAVE_CONFIG_H -I''${SRC} -I''${SRC}/include -static -o ''${BUILD}/mksyntax ''${SRC}/mksyntax.c ${getopt-c}
    ''${BUILD}/mksyntax -o ''${SRC}/syntax.c

    # ══════════════════════════════════════════════════════════════════════
    # Generate builtins: compile mkbuiltins, run it on .def files
    # ══════════════════════════════════════════════════════════════════════
    echo "==> Building mkbuiltins"

    cd ''${SRC}/builtins
    ''${CC} -DHAVE_CONFIG_H -I''${SRC} -I''${SRC}/include -static -o ''${BUILD}/mkbuiltins mkbuiltins.c

    echo "==> Running mkbuiltins on .def files"

    # Generate individual .c files from .def files (e.g., alias.def -> alias.c)
    ''${BUILD}/mkbuiltins -D . alias.def bind.def break.def builtin.def cd.def colon.def command.def declare.def echo.def enable.def eval.def exec.def exit.def fc.def fg_bg.def getopts.def hash.def help.def history.def jobs.def kill.def let.def pushd.def read.def return.def set.def setattr.def shift.def shopt.def source.def suspend.def test.def times.def trap.def type.def ulimit.def umask.def wait.def printf.def

    # Generate builtins.c dispatch table and builtext.h extern declarations
    ''${BUILD}/mkbuiltins -externfile builtext.h -structfile builtins.c -noproduction -D . alias.def bind.def break.def builtin.def cd.def colon.def command.def declare.def echo.def enable.def eval.def exec.def exit.def fc.def fg_bg.def getopts.def hash.def help.def history.def jobs.def kill.def let.def pushd.def read.def return.def set.def setattr.def shift.def shopt.def source.def suspend.def test.def times.def trap.def type.def ulimit.def umask.def wait.def printf.def

    # ══════════════════════════════════════════════════════════════════════
    # lib/glob — glob/fnmatch library
    # ══════════════════════════════════════════════════════════════════════
    echo "==> Building lib/glob"

    cd ''${SRC}
    ''${CC} -c -DHAVE_CONFIG_H -DSHELL -D_GNU_SOURCE -I''${SRC} -I''${SRC}/include -I''${SRC}/lib/glob -static -o ''${BUILD}/objs/lib/glob/glob.o ''${SRC}/lib/glob/glob.c
    ''${CC} -c -DHAVE_CONFIG_H -DSHELL -D_GNU_SOURCE -I''${SRC} -I''${SRC}/include -I''${SRC}/lib/glob -static -o ''${BUILD}/objs/lib/glob/strmatch.o ''${SRC}/lib/glob/strmatch.c
    ''${CC} -c -DHAVE_CONFIG_H -DSHELL -D_GNU_SOURCE -I''${SRC} -I''${SRC}/include -I''${SRC}/lib/glob -static -o ''${BUILD}/objs/lib/glob/smatch.o ''${SRC}/lib/glob/smatch.c
    ''${CC} -c -DHAVE_CONFIG_H -DSHELL -D_GNU_SOURCE -I''${SRC} -I''${SRC}/include -I''${SRC}/lib/glob -static -o ''${BUILD}/objs/lib/glob/xmbsrtowcs.o ''${SRC}/lib/glob/xmbsrtowcs.c

    ''${CC} -ar cr ''${BUILD}/libglob.a ''${BUILD}/objs/lib/glob/glob.o ''${BUILD}/objs/lib/glob/strmatch.o ''${BUILD}/objs/lib/glob/smatch.o ''${BUILD}/objs/lib/glob/xmbsrtowcs.o

    # ══════════════════════════════════════════════════════════════════════
    # lib/tilde — tilde expansion
    # ══════════════════════════════════════════════════════════════════════
    echo "==> Building lib/tilde"

    ''${CC} -c -DHAVE_CONFIG_H -DSHELL -D_GNU_SOURCE -I''${SRC} -I''${SRC}/include -I''${SRC}/lib/tilde -static -o ''${BUILD}/objs/lib/tilde/tilde.o ''${SRC}/lib/tilde/tilde.c

    ''${CC} -ar cr ''${BUILD}/libtilde.a ''${BUILD}/objs/lib/tilde/tilde.o

    # ══════════════════════════════════════════════════════════════════════
    # lib/sh — shell utility library (extended set for Mes libc)
    # ══════════════════════════════════════════════════════════════════════
    echo "==> Building lib/sh"

    ''${CC} -c -DHAVE_CONFIG_H -DSHELL -D_GNU_SOURCE -I''${SRC} -I''${SRC}/include -I''${SRC}/lib -I''${SRC}/lib/sh -static -o ''${BUILD}/objs/lib/sh/clktck.o ''${SRC}/lib/sh/clktck.c
    ''${CC} -c -DHAVE_CONFIG_H -DSHELL -D_GNU_SOURCE -I''${SRC} -I''${SRC}/include -I''${SRC}/lib -I''${SRC}/lib/sh -static -o ''${BUILD}/objs/lib/sh/getcwd.o ''${SRC}/lib/sh/getcwd.c
    ''${CC} -c -DHAVE_CONFIG_H -DSHELL -D_GNU_SOURCE -I''${SRC} -I''${SRC}/include -I''${SRC}/lib -I''${SRC}/lib/sh -static -o ''${BUILD}/objs/lib/sh/getenv.o ''${SRC}/lib/sh/getenv.c
    ''${CC} -c -DHAVE_CONFIG_H -DSHELL -D_GNU_SOURCE -I''${SRC} -I''${SRC}/include -I''${SRC}/lib -I''${SRC}/lib/sh -static -o ''${BUILD}/objs/lib/sh/oslib.o ''${SRC}/lib/sh/oslib.c
    ''${CC} -c -DHAVE_CONFIG_H -DSHELL -D_GNU_SOURCE -I''${SRC} -I''${SRC}/include -I''${SRC}/lib -I''${SRC}/lib/sh -static -o ''${BUILD}/objs/lib/sh/setlinebuf.o ''${SRC}/lib/sh/setlinebuf.c
    ''${CC} -c -DHAVE_CONFIG_H -DSHELL -D_GNU_SOURCE -I''${SRC} -I''${SRC}/include -I''${SRC}/lib -I''${SRC}/lib/sh -static -o ''${BUILD}/objs/lib/sh/strcasecmp.o ''${SRC}/lib/sh/strcasecmp.c
    ''${CC} -c -DHAVE_CONFIG_H -DSHELL -D_GNU_SOURCE -I''${SRC} -I''${SRC}/include -I''${SRC}/lib -I''${SRC}/lib/sh -static -o ''${BUILD}/objs/lib/sh/strerror.o ''${SRC}/lib/sh/strerror.c
    # strtod.o — omitted, Mes libc provides strtod
    ''${CC} -c -DHAVE_CONFIG_H -DSHELL -D_GNU_SOURCE -I''${SRC} -I''${SRC}/include -I''${SRC}/lib -I''${SRC}/lib/sh -static -o ''${BUILD}/objs/lib/sh/vprint.o ''${SRC}/lib/sh/vprint.c
    ''${CC} -c -DHAVE_CONFIG_H -DSHELL -D_GNU_SOURCE -I''${SRC} -I''${SRC}/include -I''${SRC}/lib -I''${SRC}/lib/sh -static -o ''${BUILD}/objs/lib/sh/itos.o ''${SRC}/lib/sh/itos.c
    ''${CC} -c -DHAVE_CONFIG_H -DSHELL -D_GNU_SOURCE -I''${SRC} -I''${SRC}/include -I''${SRC}/lib -I''${SRC}/lib/sh -static -o ''${BUILD}/objs/lib/sh/rename.o ''${SRC}/lib/sh/rename.c
    ''${CC} -c -DHAVE_CONFIG_H -DSHELL -D_GNU_SOURCE -I''${SRC} -I''${SRC}/include -I''${SRC}/lib -I''${SRC}/lib/sh -static -o ''${BUILD}/objs/lib/sh/zread.o ''${SRC}/lib/sh/zread.c
    ''${CC} -c -DHAVE_CONFIG_H -DSHELL -D_GNU_SOURCE -I''${SRC} -I''${SRC}/include -I''${SRC}/lib -I''${SRC}/lib/sh -static -o ''${BUILD}/objs/lib/sh/zwrite.o ''${SRC}/lib/sh/zwrite.c
    ''${CC} -c -DHAVE_CONFIG_H -DSHELL -D_GNU_SOURCE -I''${SRC} -I''${SRC}/include -I''${SRC}/lib -I''${SRC}/lib/sh -static -o ''${BUILD}/objs/lib/sh/shtty.o ''${SRC}/lib/sh/shtty.c
    ''${CC} -c -DHAVE_CONFIG_H -DSHELL -D_GNU_SOURCE -I''${SRC} -I''${SRC}/include -I''${SRC}/lib -I''${SRC}/lib/sh -static -o ''${BUILD}/objs/lib/sh/inet_aton.o ''${SRC}/lib/sh/inet_aton.c
    ''${CC} -c -DHAVE_CONFIG_H -DSHELL -D_GNU_SOURCE -I''${SRC} -I''${SRC}/include -I''${SRC}/lib -I''${SRC}/lib/sh -static -o ''${BUILD}/objs/lib/sh/netopen.o ''${SRC}/lib/sh/netopen.c
    ''${CC} -c -DHAVE_CONFIG_H -DSHELL -D_GNU_SOURCE -I''${SRC} -I''${SRC}/include -I''${SRC}/lib -I''${SRC}/lib/sh -static -o ''${BUILD}/objs/lib/sh/strpbrk.o ''${SRC}/lib/sh/strpbrk.c
    ''${CC} -c -DHAVE_CONFIG_H -DSHELL -D_GNU_SOURCE -I''${SRC} -I''${SRC}/include -I''${SRC}/lib -I''${SRC}/lib/sh -static -o ''${BUILD}/objs/lib/sh/timeval.o ''${SRC}/lib/sh/timeval.c
    # clock.o — omitted, needs timezone functions not in Mes libc
    ''${CC} -c -DHAVE_CONFIG_H -DSHELL -D_GNU_SOURCE -I''${SRC} -I''${SRC}/include -I''${SRC}/lib -I''${SRC}/lib/sh -static -o ''${BUILD}/objs/lib/sh/makepath.o ''${SRC}/lib/sh/makepath.c
    ''${CC} -c -DHAVE_CONFIG_H -DSHELL -D_GNU_SOURCE -I''${SRC} -I''${SRC}/include -I''${SRC}/lib -I''${SRC}/lib/sh -static -o ''${BUILD}/objs/lib/sh/pathcanon.o ''${SRC}/lib/sh/pathcanon.c
    ''${CC} -c -DHAVE_CONFIG_H -DSHELL -D_GNU_SOURCE -I''${SRC} -I''${SRC}/include -I''${SRC}/lib -I''${SRC}/lib/sh -static -o ''${BUILD}/objs/lib/sh/pathphys.o ''${SRC}/lib/sh/pathphys.c
    ''${CC} -c -DHAVE_CONFIG_H -DSHELL -D_GNU_SOURCE -I''${SRC} -I''${SRC}/include -I''${SRC}/lib -I''${SRC}/lib/sh -static -o ''${BUILD}/objs/lib/sh/stringlist.o ''${SRC}/lib/sh/stringlist.c
    ''${CC} -c -DHAVE_CONFIG_H -DSHELL -D_GNU_SOURCE -I''${SRC} -I''${SRC}/include -I''${SRC}/lib -I''${SRC}/lib/sh -static -o ''${BUILD}/objs/lib/sh/stringvec.o ''${SRC}/lib/sh/stringvec.c
    ''${CC} -c -DHAVE_CONFIG_H -DSHELL -D_GNU_SOURCE -I''${SRC} -I''${SRC}/include -I''${SRC}/lib -I''${SRC}/lib/sh -static -o ''${BUILD}/objs/lib/sh/tmpfile.o ''${SRC}/lib/sh/tmpfile.c
    ''${CC} -c -DHAVE_CONFIG_H -DSHELL -D_GNU_SOURCE -I''${SRC} -I''${SRC}/include -I''${SRC}/lib -I''${SRC}/lib/sh -static -o ''${BUILD}/objs/lib/sh/spell.o ''${SRC}/lib/sh/spell.c
    ''${CC} -c -DHAVE_CONFIG_H -DSHELL -D_GNU_SOURCE -I''${SRC} -I''${SRC}/include -I''${SRC}/lib -I''${SRC}/lib/sh -static -o ''${BUILD}/objs/lib/sh/strtrans.o ''${SRC}/lib/sh/strtrans.c
    ''${CC} -c -DHAVE_CONFIG_H -DSHELL -D_GNU_SOURCE -I''${SRC} -I''${SRC}/include -I''${SRC}/lib -I''${SRC}/lib/sh -static -o ''${BUILD}/objs/lib/sh/strindex.o ''${SRC}/lib/sh/strindex.c
    ''${CC} -c -DHAVE_CONFIG_H -DSHELL -D_GNU_SOURCE -I''${SRC} -I''${SRC}/include -I''${SRC}/lib -I''${SRC}/lib/sh -static -o ''${BUILD}/objs/lib/sh/shquote.o ''${SRC}/lib/sh/shquote.c
    ''${CC} -c -DHAVE_CONFIG_H -DSHELL -D_GNU_SOURCE -I''${SRC} -I''${SRC}/include -I''${SRC}/lib -I''${SRC}/lib/sh -static -o ''${BUILD}/objs/lib/sh/snprintf.o ''${SRC}/lib/sh/snprintf.c
    ''${CC} -c -DHAVE_CONFIG_H -DSHELL -D_GNU_SOURCE -I''${SRC} -I''${SRC}/include -I''${SRC}/lib -I''${SRC}/lib/sh -static -o ''${BUILD}/objs/lib/sh/mailstat.o ''${SRC}/lib/sh/mailstat.c
    ''${CC} -c -DHAVE_CONFIG_H -DSHELL -D_GNU_SOURCE -I''${SRC} -I''${SRC}/include -I''${SRC}/lib -I''${SRC}/lib/sh -static -o ''${BUILD}/objs/lib/sh/fmtulong.o ''${SRC}/lib/sh/fmtulong.c
    ''${CC} -c -DHAVE_CONFIG_H -DSHELL -D_GNU_SOURCE -I''${SRC} -I''${SRC}/include -I''${SRC}/lib -I''${SRC}/lib/sh -static -o ''${BUILD}/objs/lib/sh/fmtullong.o ''${SRC}/lib/sh/fmtullong.c
    ''${CC} -c -DHAVE_CONFIG_H -DSHELL -D_GNU_SOURCE -I''${SRC} -I''${SRC}/include -I''${SRC}/lib -I''${SRC}/lib/sh -static -o ''${BUILD}/objs/lib/sh/strtoll.o ''${SRC}/lib/sh/strtoll.c
    ''${CC} -c -DHAVE_CONFIG_H -DSHELL -D_GNU_SOURCE -I''${SRC} -I''${SRC}/include -I''${SRC}/lib -I''${SRC}/lib/sh -static -o ''${BUILD}/objs/lib/sh/strtoull.o ''${SRC}/lib/sh/strtoull.c
    ''${CC} -c -DHAVE_CONFIG_H -DSHELL -D_GNU_SOURCE -I''${SRC} -I''${SRC}/include -I''${SRC}/lib -I''${SRC}/lib/sh -static -o ''${BUILD}/objs/lib/sh/strtoimax.o ''${SRC}/lib/sh/strtoimax.c
    ''${CC} -c -DHAVE_CONFIG_H -DSHELL -D_GNU_SOURCE -I''${SRC} -I''${SRC}/include -I''${SRC}/lib -I''${SRC}/lib/sh -static -o ''${BUILD}/objs/lib/sh/strtoumax.o ''${SRC}/lib/sh/strtoumax.c
    ''${CC} -c -DHAVE_CONFIG_H -DSHELL -D_GNU_SOURCE -I''${SRC} -I''${SRC}/include -I''${SRC}/lib -I''${SRC}/lib/sh -static -o ''${BUILD}/objs/lib/sh/fmtumax.o ''${SRC}/lib/sh/fmtumax.c
    ''${CC} -c -DHAVE_CONFIG_H -DSHELL -D_GNU_SOURCE -I''${SRC} -I''${SRC}/include -I''${SRC}/lib -I''${SRC}/lib/sh -static -o ''${BUILD}/objs/lib/sh/netconn.o ''${SRC}/lib/sh/netconn.c
    # mktime.o — omitted, Mes libc provides mktime / needs timezone
    # strftime.o — omitted, Mes libc provides strftime / needs timezone
    ''${CC} -c -DHAVE_CONFIG_H -DSHELL -D_GNU_SOURCE -I''${SRC} -I''${SRC}/include -I''${SRC}/lib -I''${SRC}/lib/sh -static -o ''${BUILD}/objs/lib/sh/xstrchr.o ''${SRC}/lib/sh/xstrchr.c
    ''${CC} -c -DHAVE_CONFIG_H -DSHELL -D_GNU_SOURCE -I''${SRC} -I''${SRC}/include -I''${SRC}/lib -I''${SRC}/lib/sh -static -o ''${BUILD}/objs/lib/sh/zcatfd.o ''${SRC}/lib/sh/zcatfd.c

    ''${CC} -ar cr ''${BUILD}/libsh.a ''${BUILD}/objs/lib/sh/clktck.o ''${BUILD}/objs/lib/sh/getcwd.o ''${BUILD}/objs/lib/sh/getenv.o ''${BUILD}/objs/lib/sh/oslib.o ''${BUILD}/objs/lib/sh/setlinebuf.o ''${BUILD}/objs/lib/sh/strcasecmp.o ''${BUILD}/objs/lib/sh/strerror.o ''${BUILD}/objs/lib/sh/vprint.o ''${BUILD}/objs/lib/sh/itos.o ''${BUILD}/objs/lib/sh/rename.o ''${BUILD}/objs/lib/sh/zread.o ''${BUILD}/objs/lib/sh/zwrite.o ''${BUILD}/objs/lib/sh/shtty.o ''${BUILD}/objs/lib/sh/inet_aton.o ''${BUILD}/objs/lib/sh/netopen.o ''${BUILD}/objs/lib/sh/strpbrk.o ''${BUILD}/objs/lib/sh/timeval.o ''${BUILD}/objs/lib/sh/makepath.o ''${BUILD}/objs/lib/sh/pathcanon.o ''${BUILD}/objs/lib/sh/pathphys.o ''${BUILD}/objs/lib/sh/stringlist.o ''${BUILD}/objs/lib/sh/stringvec.o ''${BUILD}/objs/lib/sh/tmpfile.o ''${BUILD}/objs/lib/sh/spell.o ''${BUILD}/objs/lib/sh/strtrans.o ''${BUILD}/objs/lib/sh/strindex.o ''${BUILD}/objs/lib/sh/shquote.o ''${BUILD}/objs/lib/sh/snprintf.o ''${BUILD}/objs/lib/sh/mailstat.o ''${BUILD}/objs/lib/sh/fmtulong.o ''${BUILD}/objs/lib/sh/fmtullong.o ''${BUILD}/objs/lib/sh/strtoll.o ''${BUILD}/objs/lib/sh/strtoull.o ''${BUILD}/objs/lib/sh/strtoimax.o ''${BUILD}/objs/lib/sh/strtoumax.o ''${BUILD}/objs/lib/sh/fmtumax.o ''${BUILD}/objs/lib/sh/netconn.o ''${BUILD}/objs/lib/sh/xstrchr.o ''${BUILD}/objs/lib/sh/zcatfd.o

    # ══════════════════════════════════════════════════════════════════════
    # builtins/ — compile the mkbuiltins-generated .c files
    # ══════════════════════════════════════════════════════════════════════
    echo "==> Building builtins"

    ''${CC} -c -DHAVE_CONFIG_H -DSHELL -D_GNU_SOURCE -I''${SRC} -I''${SRC}/include -I''${SRC}/lib -I''${SRC}/builtins -static -o ''${BUILD}/objs/builtins/builtins.o ''${SRC}/builtins/builtins.c
    ''${CC} -c -DHAVE_CONFIG_H -DSHELL -D_GNU_SOURCE -I''${SRC} -I''${SRC}/include -I''${SRC}/lib -I''${SRC}/builtins -static -o ''${BUILD}/objs/builtins/common.o ''${SRC}/builtins/common.c
    ''${CC} -c -DHAVE_CONFIG_H -DSHELL -D_GNU_SOURCE -I''${SRC} -I''${SRC}/include -I''${SRC}/lib -I''${SRC}/builtins -static -o ''${BUILD}/objs/builtins/evalfile.o ''${SRC}/builtins/evalfile.c
    ''${CC} -c -DHAVE_CONFIG_H -DSHELL -D_GNU_SOURCE -I''${SRC} -I''${SRC}/include -I''${SRC}/lib -I''${SRC}/builtins -static -o ''${BUILD}/objs/builtins/evalstring.o ''${SRC}/builtins/evalstring.c
    ''${CC} -c -DHAVE_CONFIG_H -DSHELL -D_GNU_SOURCE -I''${SRC} -I''${SRC}/include -I''${SRC}/lib -I''${SRC}/builtins -static -o ''${BUILD}/objs/builtins/getopt.o ''${SRC}/builtins/getopt.c
    ''${CC} -c -DHAVE_CONFIG_H -DSHELL -D_GNU_SOURCE -I''${SRC} -I''${SRC}/include -I''${SRC}/lib -I''${SRC}/builtins -static -o ''${BUILD}/objs/builtins/bashgetopt.o ''${SRC}/builtins/bashgetopt.c
    ''${CC} -c -DHAVE_CONFIG_H -DSHELL -D_GNU_SOURCE -I''${SRC} -I''${SRC}/include -I''${SRC}/lib -I''${SRC}/builtins -static -o ''${BUILD}/objs/builtins/alias.o ''${SRC}/builtins/alias.c
    ''${CC} -c -DHAVE_CONFIG_H -DSHELL -D_GNU_SOURCE -I''${SRC} -I''${SRC}/include -I''${SRC}/lib -I''${SRC}/builtins -static -o ''${BUILD}/objs/builtins/bind.o ''${SRC}/builtins/bind.c
    ''${CC} -c -DHAVE_CONFIG_H -DSHELL -D_GNU_SOURCE -I''${SRC} -I''${SRC}/include -I''${SRC}/lib -I''${SRC}/builtins -static -o ''${BUILD}/objs/builtins/break.o ''${SRC}/builtins/break.c
    ''${CC} -c -DHAVE_CONFIG_H -DSHELL -D_GNU_SOURCE -I''${SRC} -I''${SRC}/include -I''${SRC}/lib -I''${SRC}/builtins -static -o ''${BUILD}/objs/builtins/builtin.o ''${SRC}/builtins/builtin.c
    ''${CC} -c -DHAVE_CONFIG_H -DSHELL -D_GNU_SOURCE -I''${SRC} -I''${SRC}/include -I''${SRC}/lib -I''${SRC}/builtins -static -o ''${BUILD}/objs/builtins/cd.o ''${SRC}/builtins/cd.c
    ''${CC} -c -DHAVE_CONFIG_H -DSHELL -D_GNU_SOURCE -I''${SRC} -I''${SRC}/include -I''${SRC}/lib -I''${SRC}/builtins -static -o ''${BUILD}/objs/builtins/colon.o ''${SRC}/builtins/colon.c
    ''${CC} -c -DHAVE_CONFIG_H -DSHELL -D_GNU_SOURCE -I''${SRC} -I''${SRC}/include -I''${SRC}/lib -I''${SRC}/builtins -static -o ''${BUILD}/objs/builtins/command.o ''${SRC}/builtins/command.c
    ''${CC} -c -DHAVE_CONFIG_H -DSHELL -D_GNU_SOURCE -I''${SRC} -I''${SRC}/include -I''${SRC}/lib -I''${SRC}/builtins -static -o ''${BUILD}/objs/builtins/declare.o ''${SRC}/builtins/declare.c
    ''${CC} -c -DHAVE_CONFIG_H -DSHELL -D_GNU_SOURCE -I''${SRC} -I''${SRC}/include -I''${SRC}/lib -I''${SRC}/builtins -static -o ''${BUILD}/objs/builtins/echo.o ''${SRC}/builtins/echo.c
    ''${CC} -c -DHAVE_CONFIG_H -DSHELL -D_GNU_SOURCE -I''${SRC} -I''${SRC}/include -I''${SRC}/lib -I''${SRC}/builtins -static -o ''${BUILD}/objs/builtins/enable.o ''${SRC}/builtins/enable.c
    ''${CC} -c -DHAVE_CONFIG_H -DSHELL -D_GNU_SOURCE -I''${SRC} -I''${SRC}/include -I''${SRC}/lib -I''${SRC}/builtins -static -o ''${BUILD}/objs/builtins/eval.o ''${SRC}/builtins/eval.c
    ''${CC} -c -DHAVE_CONFIG_H -DSHELL -D_GNU_SOURCE -I''${SRC} -I''${SRC}/include -I''${SRC}/lib -I''${SRC}/builtins -static -o ''${BUILD}/objs/builtins/exec.o ''${SRC}/builtins/exec.c
    ''${CC} -c -DHAVE_CONFIG_H -DSHELL -D_GNU_SOURCE -I''${SRC} -I''${SRC}/include -I''${SRC}/lib -I''${SRC}/builtins -static -o ''${BUILD}/objs/builtins/exit.o ''${SRC}/builtins/exit.c
    ''${CC} -c -DHAVE_CONFIG_H -DSHELL -D_GNU_SOURCE -I''${SRC} -I''${SRC}/include -I''${SRC}/lib -I''${SRC}/builtins -static -o ''${BUILD}/objs/builtins/fc.o ''${SRC}/builtins/fc.c
    ''${CC} -c -DHAVE_CONFIG_H -DSHELL -D_GNU_SOURCE -I''${SRC} -I''${SRC}/include -I''${SRC}/lib -I''${SRC}/builtins -static -o ''${BUILD}/objs/builtins/fg_bg.o ''${SRC}/builtins/fg_bg.c
    ''${CC} -c -DHAVE_CONFIG_H -DSHELL -D_GNU_SOURCE -I''${SRC} -I''${SRC}/include -I''${SRC}/lib -I''${SRC}/builtins -static -o ''${BUILD}/objs/builtins/getopts.o ''${SRC}/builtins/getopts.c
    ''${CC} -c -DHAVE_CONFIG_H -DSHELL -D_GNU_SOURCE -I''${SRC} -I''${SRC}/include -I''${SRC}/lib -I''${SRC}/builtins -static -o ''${BUILD}/objs/builtins/hash.o ''${SRC}/builtins/hash.c
    ''${CC} -c -DHAVE_CONFIG_H -DSHELL -D_GNU_SOURCE -I''${SRC} -I''${SRC}/include -I''${SRC}/lib -I''${SRC}/builtins -static -o ''${BUILD}/objs/builtins/help.o ''${SRC}/builtins/help.c
    ''${CC} -c -DHAVE_CONFIG_H -DSHELL -D_GNU_SOURCE -I''${SRC} -I''${SRC}/include -I''${SRC}/lib -I''${SRC}/builtins -static -o ''${BUILD}/objs/builtins/history.o ''${SRC}/builtins/history.c
    ''${CC} -c -DHAVE_CONFIG_H -DSHELL -D_GNU_SOURCE -I''${SRC} -I''${SRC}/include -I''${SRC}/lib -I''${SRC}/builtins -static -o ''${BUILD}/objs/builtins/jobs.o ''${SRC}/builtins/jobs.c
    ''${CC} -c -DHAVE_CONFIG_H -DSHELL -D_GNU_SOURCE -I''${SRC} -I''${SRC}/include -I''${SRC}/lib -I''${SRC}/builtins -static -o ''${BUILD}/objs/builtins/kill.o ''${SRC}/builtins/kill.c
    ''${CC} -c -DHAVE_CONFIG_H -DSHELL -D_GNU_SOURCE -I''${SRC} -I''${SRC}/include -I''${SRC}/lib -I''${SRC}/builtins -static -o ''${BUILD}/objs/builtins/let.o ''${SRC}/builtins/let.c
    ''${CC} -c -DHAVE_CONFIG_H -DSHELL -D_GNU_SOURCE -I''${SRC} -I''${SRC}/include -I''${SRC}/lib -I''${SRC}/builtins -static -o ''${BUILD}/objs/builtins/pushd.o ''${SRC}/builtins/pushd.c
    ''${CC} -c -DHAVE_CONFIG_H -DSHELL -D_GNU_SOURCE -I''${SRC} -I''${SRC}/include -I''${SRC}/lib -I''${SRC}/builtins -static -o ''${BUILD}/objs/builtins/read.o ''${SRC}/builtins/read.c
    ''${CC} -c -DHAVE_CONFIG_H -DSHELL -D_GNU_SOURCE -I''${SRC} -I''${SRC}/include -I''${SRC}/lib -I''${SRC}/builtins -static -o ''${BUILD}/objs/builtins/return.o ''${SRC}/builtins/return.c
    ''${CC} -c -DHAVE_CONFIG_H -DSHELL -D_GNU_SOURCE -I''${SRC} -I''${SRC}/include -I''${SRC}/lib -I''${SRC}/builtins -static -o ''${BUILD}/objs/builtins/set.o ''${SRC}/builtins/set.c
    ''${CC} -c -DHAVE_CONFIG_H -DSHELL -D_GNU_SOURCE -I''${SRC} -I''${SRC}/include -I''${SRC}/lib -I''${SRC}/builtins -static -o ''${BUILD}/objs/builtins/setattr.o ''${SRC}/builtins/setattr.c
    ''${CC} -c -DHAVE_CONFIG_H -DSHELL -D_GNU_SOURCE -I''${SRC} -I''${SRC}/include -I''${SRC}/lib -I''${SRC}/builtins -static -o ''${BUILD}/objs/builtins/shift.o ''${SRC}/builtins/shift.c
    ''${CC} -c -DHAVE_CONFIG_H -DSHELL -D_GNU_SOURCE -I''${SRC} -I''${SRC}/include -I''${SRC}/lib -I''${SRC}/builtins -static -o ''${BUILD}/objs/builtins/shopt.o ''${SRC}/builtins/shopt.c
    ''${CC} -c -DHAVE_CONFIG_H -DSHELL -D_GNU_SOURCE -I''${SRC} -I''${SRC}/include -I''${SRC}/lib -I''${SRC}/builtins -static -o ''${BUILD}/objs/builtins/source.o ''${SRC}/builtins/source.c
    ''${CC} -c -DHAVE_CONFIG_H -DSHELL -D_GNU_SOURCE -I''${SRC} -I''${SRC}/include -I''${SRC}/lib -I''${SRC}/builtins -static -o ''${BUILD}/objs/builtins/suspend.o ''${SRC}/builtins/suspend.c
    ''${CC} -c -DHAVE_CONFIG_H -DSHELL -D_GNU_SOURCE -I''${SRC} -I''${SRC}/include -I''${SRC}/lib -I''${SRC}/builtins -static -o ''${BUILD}/objs/builtins/test.o ''${SRC}/builtins/test.c
    ''${CC} -c -DHAVE_CONFIG_H -DSHELL -D_GNU_SOURCE -I''${SRC} -I''${SRC}/include -I''${SRC}/lib -I''${SRC}/builtins -static -o ''${BUILD}/objs/builtins/times.o ''${SRC}/builtins/times.c
    ''${CC} -c -DHAVE_CONFIG_H -DSHELL -D_GNU_SOURCE -I''${SRC} -I''${SRC}/include -I''${SRC}/lib -I''${SRC}/builtins -static -o ''${BUILD}/objs/builtins/trap.o ''${SRC}/builtins/trap.c
    ''${CC} -c -DHAVE_CONFIG_H -DSHELL -D_GNU_SOURCE -I''${SRC} -I''${SRC}/include -I''${SRC}/lib -I''${SRC}/builtins -static -o ''${BUILD}/objs/builtins/type.o ''${SRC}/builtins/type.c
    ''${CC} -c -DHAVE_CONFIG_H -DSHELL -D_GNU_SOURCE -I''${SRC} -I''${SRC}/include -I''${SRC}/lib -I''${SRC}/builtins -static -o ''${BUILD}/objs/builtins/ulimit.o ''${SRC}/builtins/ulimit.c
    ''${CC} -c -DHAVE_CONFIG_H -DSHELL -D_GNU_SOURCE -I''${SRC} -I''${SRC}/include -I''${SRC}/lib -I''${SRC}/builtins -static -o ''${BUILD}/objs/builtins/umask.o ''${SRC}/builtins/umask.c
    ''${CC} -c -DHAVE_CONFIG_H -DSHELL -D_GNU_SOURCE -I''${SRC} -I''${SRC}/include -I''${SRC}/lib -I''${SRC}/builtins -static -o ''${BUILD}/objs/builtins/wait.o ''${SRC}/builtins/wait.c
    ''${CC} -c -DHAVE_CONFIG_H -DSHELL -D_GNU_SOURCE -I''${SRC} -I''${SRC}/include -I''${SRC}/lib -I''${SRC}/builtins -static -o ''${BUILD}/objs/builtins/printf.o ''${SRC}/builtins/printf.c
    # complete.o — omitted, needs PROGRAMMABLE_COMPLETION + readline

    # ══════════════════════════════════════════════════════════════════════
    # Core shell source files (nojobs.c instead of jobs.c, + siglist.c)
    # ══════════════════════════════════════════════════════════════════════
    echo "==> Building core shell"

    ''${CC} -c -DHAVE_CONFIG_H -DSHELL -D_GNU_SOURCE -I''${SRC} -I''${SRC}/include -I''${SRC}/lib -I''${SRC}/builtins -static -o ''${BUILD}/objs/shell.o ''${SRC}/shell.c
    ''${CC} -c -DHAVE_CONFIG_H -DSHELL -D_GNU_SOURCE -I''${SRC} -I''${SRC}/include -I''${SRC}/lib -I''${SRC}/builtins -static -o ''${BUILD}/objs/eval.o ''${SRC}/eval.c
    ''${CC} -c -DHAVE_CONFIG_H -DSHELL -D_GNU_SOURCE -I''${SRC} -I''${SRC}/include -I''${SRC}/lib -I''${SRC}/builtins -static -o ''${BUILD}/objs/y.tab.o ''${SRC}/y.tab.c
    ''${CC} -c -DHAVE_CONFIG_H -DSHELL -D_GNU_SOURCE -I''${SRC} -I''${SRC}/include -I''${SRC}/lib -I''${SRC}/builtins -static -o ''${BUILD}/objs/general.o ''${SRC}/general.c
    ''${CC} -c -DHAVE_CONFIG_H -DSHELL -D_GNU_SOURCE -I''${SRC} -I''${SRC}/include -I''${SRC}/lib -I''${SRC}/builtins -static -o ''${BUILD}/objs/make_cmd.o ''${SRC}/make_cmd.c
    ''${CC} -c -DHAVE_CONFIG_H -DSHELL -D_GNU_SOURCE -I''${SRC} -I''${SRC}/include -I''${SRC}/lib -I''${SRC}/builtins -static -o ''${BUILD}/objs/print_cmd.o ''${SRC}/print_cmd.c
    ''${CC} -c -DHAVE_CONFIG_H -DSHELL -D_GNU_SOURCE -I''${SRC} -I''${SRC}/include -I''${SRC}/lib -I''${SRC}/builtins -static -o ''${BUILD}/objs/dispose_cmd.o ''${SRC}/dispose_cmd.c
    ''${CC} -c -DHAVE_CONFIG_H -DSHELL -D_GNU_SOURCE -I''${SRC} -I''${SRC}/include -I''${SRC}/lib -I''${SRC}/builtins -static -o ''${BUILD}/objs/execute_cmd.o ''${SRC}/execute_cmd.c
    ''${CC} -c -DHAVE_CONFIG_H -DSHELL -D_GNU_SOURCE -I''${SRC} -I''${SRC}/include -I''${SRC}/lib -I''${SRC}/builtins -static -o ''${BUILD}/objs/variables.o ''${SRC}/variables.c
    ''${CC} -c -DHAVE_CONFIG_H -DSHELL -D_GNU_SOURCE -I''${SRC} -I''${SRC}/include -I''${SRC}/lib -I''${SRC}/builtins -static -o ''${BUILD}/objs/copy_cmd.o ''${SRC}/copy_cmd.c
    ''${CC} -c -DHAVE_CONFIG_H -DSHELL -D_GNU_SOURCE -I''${SRC} -I''${SRC}/include -I''${SRC}/lib -I''${SRC}/builtins -static -o ''${BUILD}/objs/error.o ''${SRC}/error.c
    ''${CC} -c -DHAVE_CONFIG_H -DSHELL -D_GNU_SOURCE -I''${SRC} -I''${SRC}/include -I''${SRC}/lib -I''${SRC}/builtins -static -o ''${BUILD}/objs/expr.o ''${SRC}/expr.c
    ''${CC} -c -DHAVE_CONFIG_H -DSHELL -D_GNU_SOURCE -I''${SRC} -I''${SRC}/include -I''${SRC}/lib -I''${SRC}/builtins -static -o ''${BUILD}/objs/flags.o ''${SRC}/flags.c
    ''${CC} -c -DHAVE_CONFIG_H -DSHELL -D_GNU_SOURCE -I''${SRC} -I''${SRC}/include -I''${SRC}/lib -I''${SRC}/builtins -static -o ''${BUILD}/objs/nojobs.o ''${SRC}/nojobs.c
    ''${CC} -c -DHAVE_CONFIG_H -DSHELL -D_GNU_SOURCE -I''${SRC} -I''${SRC}/include -I''${SRC}/lib -I''${SRC}/builtins -static -o ''${BUILD}/objs/subst.o ''${SRC}/subst.c
    ''${CC} -c -DHAVE_CONFIG_H -DSHELL -D_GNU_SOURCE -I''${SRC} -I''${SRC}/include -I''${SRC}/lib -I''${SRC}/builtins -static -o ''${BUILD}/objs/hashcmd.o ''${SRC}/hashcmd.c
    ''${CC} -c -DHAVE_CONFIG_H -DSHELL -D_GNU_SOURCE -I''${SRC} -I''${SRC}/include -I''${SRC}/lib -I''${SRC}/builtins -static -o ''${BUILD}/objs/hashlib.o ''${SRC}/hashlib.c
    ''${CC} -c -DHAVE_CONFIG_H -DSHELL -D_GNU_SOURCE -I''${SRC} -I''${SRC}/include -I''${SRC}/lib -I''${SRC}/builtins -static -o ''${BUILD}/objs/mailcheck.o ''${SRC}/mailcheck.c
    ''${CC} -c -DHAVE_CONFIG_H -DSHELL -D_GNU_SOURCE -I''${SRC} -I''${SRC}/include -I''${SRC}/lib -I''${SRC}/builtins -static -o ''${BUILD}/objs/trap.o ''${SRC}/trap.c
    ''${CC} -c -DHAVE_CONFIG_H -DSHELL -D_GNU_SOURCE -I''${SRC} -I''${SRC}/include -I''${SRC}/lib -I''${SRC}/builtins -static -o ''${BUILD}/objs/input.o ''${SRC}/input.c
    ''${CC} -c -DHAVE_CONFIG_H -DSHELL -D_GNU_SOURCE -I''${SRC} -I''${SRC}/include -I''${SRC}/lib -I''${SRC}/builtins -static -o ''${BUILD}/objs/unwind_prot.o ''${SRC}/unwind_prot.c
    ''${CC} -c -DHAVE_CONFIG_H -DSHELL -D_GNU_SOURCE -I''${SRC} -I''${SRC}/include -I''${SRC}/lib -I''${SRC}/builtins -static -o ''${BUILD}/objs/pathexp.o ''${SRC}/pathexp.c
    ''${CC} -c -DHAVE_CONFIG_H -DSHELL -D_GNU_SOURCE -I''${SRC} -I''${SRC}/include -I''${SRC}/lib -I''${SRC}/builtins -static -o ''${BUILD}/objs/sig.o ''${SRC}/sig.c
    ''${CC} -c -DHAVE_CONFIG_H -DSHELL -D_GNU_SOURCE -I''${SRC} -I''${SRC}/include -I''${SRC}/lib -I''${SRC}/builtins -static -o ''${BUILD}/objs/test.o ''${SRC}/test.c
    ''${CC} -c -DHAVE_CONFIG_H -DSHELL -D_GNU_SOURCE -I''${SRC} -I''${SRC}/include -I''${SRC}/lib -I''${SRC}/builtins -static -o ''${BUILD}/objs/version.o ''${SRC}/version.c
    ''${CC} -c -DHAVE_CONFIG_H -DSHELL -D_GNU_SOURCE -I''${SRC} -I''${SRC}/include -I''${SRC}/lib -I''${SRC}/builtins -static -o ''${BUILD}/objs/alias.o ''${SRC}/alias.c
    ''${CC} -c -DHAVE_CONFIG_H -DSHELL -D_GNU_SOURCE -I''${SRC} -I''${SRC}/include -I''${SRC}/lib -I''${SRC}/builtins -static -o ''${BUILD}/objs/array.o ''${SRC}/array.c
    ''${CC} -c -DHAVE_CONFIG_H -DSHELL -D_GNU_SOURCE -I''${SRC} -I''${SRC}/include -I''${SRC}/lib -I''${SRC}/builtins -static -o ''${BUILD}/objs/arrayfunc.o ''${SRC}/arrayfunc.c
    ''${CC} -c -DHAVE_CONFIG_H -DSHELL -D_GNU_SOURCE -I''${SRC} -I''${SRC}/include -I''${SRC}/lib -I''${SRC}/builtins -static -o ''${BUILD}/objs/braces.o ''${SRC}/braces.c
    ''${CC} -c -DHAVE_CONFIG_H -DSHELL -D_GNU_SOURCE -I''${SRC} -I''${SRC}/include -I''${SRC}/lib -I''${SRC}/builtins -static -o ''${BUILD}/objs/bracecomp.o ''${SRC}/bracecomp.c
    ''${CC} -c -DHAVE_CONFIG_H -DSHELL -D_GNU_SOURCE -I''${SRC} -I''${SRC}/include -I''${SRC}/lib -I''${SRC}/builtins -static -o ''${BUILD}/objs/bashhist.o ''${SRC}/bashhist.c
    # bashline.o — omitted, readline integration not needed
    ''${CC} -c -DHAVE_CONFIG_H -DSHELL -D_GNU_SOURCE -I''${SRC} -I''${SRC}/include -I''${SRC}/lib -I''${SRC}/builtins -static -o ''${BUILD}/objs/list.o ''${SRC}/list.c
    ''${CC} -c -DHAVE_CONFIG_H -DSHELL -D_GNU_SOURCE -I''${SRC} -I''${SRC}/include -I''${SRC}/lib -I''${SRC}/builtins -static -o ''${BUILD}/objs/stringlib.o ''${SRC}/stringlib.c
    ''${CC} -c -DHAVE_CONFIG_H -DSHELL -D_GNU_SOURCE -I''${SRC} -I''${SRC}/include -I''${SRC}/lib -I''${SRC}/builtins -static -o ''${BUILD}/objs/locale.o ''${SRC}/locale.c
    ''${CC} -c -DHAVE_CONFIG_H -DSHELL -D_GNU_SOURCE -I''${SRC} -I''${SRC}/include -I''${SRC}/lib -I''${SRC}/builtins -static -o ''${BUILD}/objs/findcmd.o ''${SRC}/findcmd.c
    ''${CC} -c -DHAVE_CONFIG_H -DSHELL -D_GNU_SOURCE -I''${SRC} -I''${SRC}/include -I''${SRC}/lib -I''${SRC}/builtins -static -o ''${BUILD}/objs/redir.o ''${SRC}/redir.c
    # pcomplete.o, pcomplib.o — omitted, programmable completion not needed
    ''${CC} -c -DHAVE_CONFIG_H -DSHELL -D_GNU_SOURCE -I''${SRC} -I''${SRC}/include -I''${SRC}/lib -I''${SRC}/builtins -static -o ''${BUILD}/objs/syntax.o ''${SRC}/syntax.c
    ''${CC} -c -DHAVE_CONFIG_H -DSHELL -D_GNU_SOURCE -I''${SRC} -I''${SRC}/include -I''${SRC}/lib -I''${SRC}/builtins -static -o ''${BUILD}/objs/xmalloc.o ''${SRC}/xmalloc.c
    ''${CC} -c -DHAVE_CONFIG_H -DSHELL -D_GNU_SOURCE -I''${SRC} -I''${SRC}/include -I''${SRC}/lib -I''${SRC}/builtins -static -o ''${BUILD}/objs/siglist.o ''${SRC}/siglist.c

    # ══════════════════════════════════════════════════════════════════════
    # Link bash
    # ══════════════════════════════════════════════════════════════════════
    echo "==> Linking bash"

    ''${CC} -static -o ''${out}/bin/bash ''${BUILD}/objs/shell.o ''${BUILD}/objs/eval.o ''${BUILD}/objs/y.tab.o ''${BUILD}/objs/general.o ''${BUILD}/objs/make_cmd.o ''${BUILD}/objs/print_cmd.o ''${BUILD}/objs/dispose_cmd.o ''${BUILD}/objs/execute_cmd.o ''${BUILD}/objs/variables.o ''${BUILD}/objs/copy_cmd.o ''${BUILD}/objs/error.o ''${BUILD}/objs/expr.o ''${BUILD}/objs/flags.o ''${BUILD}/objs/nojobs.o ''${BUILD}/objs/subst.o ''${BUILD}/objs/hashcmd.o ''${BUILD}/objs/hashlib.o ''${BUILD}/objs/mailcheck.o ''${BUILD}/objs/trap.o ''${BUILD}/objs/input.o ''${BUILD}/objs/unwind_prot.o ''${BUILD}/objs/pathexp.o ''${BUILD}/objs/sig.o ''${BUILD}/objs/test.o ''${BUILD}/objs/version.o ''${BUILD}/objs/alias.o ''${BUILD}/objs/array.o ''${BUILD}/objs/arrayfunc.o ''${BUILD}/objs/braces.o ''${BUILD}/objs/bracecomp.o ''${BUILD}/objs/bashhist.o ''${BUILD}/objs/list.o ''${BUILD}/objs/stringlib.o ''${BUILD}/objs/locale.o ''${BUILD}/objs/findcmd.o ''${BUILD}/objs/redir.o ''${BUILD}/objs/syntax.o ''${BUILD}/objs/xmalloc.o ''${BUILD}/objs/siglist.o ''${BUILD}/objs/builtins/builtins.o ''${BUILD}/objs/builtins/common.o ''${BUILD}/objs/builtins/evalfile.o ''${BUILD}/objs/builtins/evalstring.o ''${BUILD}/objs/builtins/getopt.o ''${BUILD}/objs/builtins/bashgetopt.o ''${BUILD}/objs/builtins/alias.o ''${BUILD}/objs/builtins/bind.o ''${BUILD}/objs/builtins/break.o ''${BUILD}/objs/builtins/builtin.o ''${BUILD}/objs/builtins/cd.o ''${BUILD}/objs/builtins/colon.o ''${BUILD}/objs/builtins/command.o ''${BUILD}/objs/builtins/declare.o ''${BUILD}/objs/builtins/echo.o ''${BUILD}/objs/builtins/enable.o ''${BUILD}/objs/builtins/eval.o ''${BUILD}/objs/builtins/exec.o ''${BUILD}/objs/builtins/exit.o ''${BUILD}/objs/builtins/fc.o ''${BUILD}/objs/builtins/fg_bg.o ''${BUILD}/objs/builtins/getopts.o ''${BUILD}/objs/builtins/hash.o ''${BUILD}/objs/builtins/help.o ''${BUILD}/objs/builtins/history.o ''${BUILD}/objs/builtins/jobs.o ''${BUILD}/objs/builtins/kill.o ''${BUILD}/objs/builtins/let.o ''${BUILD}/objs/builtins/pushd.o ''${BUILD}/objs/builtins/read.o ''${BUILD}/objs/builtins/return.o ''${BUILD}/objs/builtins/set.o ''${BUILD}/objs/builtins/setattr.o ''${BUILD}/objs/builtins/shift.o ''${BUILD}/objs/builtins/shopt.o ''${BUILD}/objs/builtins/source.o ''${BUILD}/objs/builtins/suspend.o ''${BUILD}/objs/builtins/test.o ''${BUILD}/objs/builtins/times.o ''${BUILD}/objs/builtins/trap.o ''${BUILD}/objs/builtins/type.o ''${BUILD}/objs/builtins/ulimit.o ''${BUILD}/objs/builtins/umask.o ''${BUILD}/objs/builtins/wait.o ''${BUILD}/objs/builtins/printf.o ''${BUILD}/libsh.a ''${BUILD}/libglob.a ''${BUILD}/libtilde.a

    # Create sh symlink
    ''${TOOLS}/cp ''${out}/bin/bash ''${out}/bin/sh
    ''${TOOLS}/chmod 750 ''${out}/bin/bash
    ''${TOOLS}/chmod 750 ''${out}/bin/sh

    echo "bash 2.05b (TCC/Mes libc) installed to ''${out}"
    echo "  ''${out}/bin/bash"
    echo "  ''${out}/bin/sh"
  '';
in
builtins.derivation {
  name = "bash-2.05b-tcc";
  inherit system;
  builder = "${seeds.kaemNix}";
  passAsFile = [ "buildScript" ];
  buildScript = "${posix-tools}/bin/kaem --verbose --strict --file ${buildKaem}\n";
  POSIX_TOOLS = "${posix-tools}";
  TINYCC = "${tinycc}";
  BASH_SRC = "${bash-src}";
}
// {
  meta = {
    description = "GNU Bourne-Again SHell 2.05b (TCC/Mes libc, minimal)";
    homepage = "https://www.gnu.org/software/bash/";
    license = "GPL-2.0-or-later";
    platforms = [ "i686-linux" ];
  };
}
