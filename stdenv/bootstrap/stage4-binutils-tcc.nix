# stdenv/bootstrap/stage4-binutils-tcc.nix — binutils 2.20.1a via configure+make
#
# Provides GNU as, ld, ar, nm, objcopy, objdump, ranlib, readelf, strip.
# Built with TCC 0.9.27 against Mes libc using configure+make, matching
# the Guix/live-bootstrap approach.
#
# Builder: bash-tcc + TCC-compiled tools (stage 4).
#
{
  tinycc, # Output of stage3-tinycc.nix (TCC with Mes libc)
  bash, # Output of stage4-bash-tcc.nix (bash shell)
  sed, # Output of stage4-sed-tcc.nix
  grep, # Output of stage4-grep-tcc.nix
  patch, # Output of stage4-patch-tcc.nix
  coreutils, # Output of stage4-coreutils-tcc.nix
  diffutils, # Output of stage4-diffutils-tcc.nix
  gnumake, # GNU Make 3.79.1 from TCC
  gawk, # GNU awk 3.0.6 from TCC
  buildPlatform,
  ...
}: let
  lib = import ./lib.nix;
  system = buildPlatform.system;
  sources = import ./sources.nix;

  src = builtins.fetchTarball {
    url = sources.binutils.url;
    sha256 = sources.binutils.sha256;
  };

  # Shell script to replace broken sed pipeline in autoconf-generated configure.
  # Our sed-tcc has a bug in the hold space / branch / N commands that breaks
  # the complex sed pipeline autoconf uses to generate awk substitution data
  # for config.status. Our gawk-tcc also has broken FS/index() functions.
  # This shell script uses bash parameter expansion instead.
  #
  # Usage: $CONFIG_SHELL fix-subs.sh "$ac_delim" < conf$$subs.awk >> $CONFIG_STATUS
  # Input: lines of form VARNAME!value$ac_delim
  # Output: S["VARNAME"]="value"
  fixSubsScript = builtins.toFile "fix-subs.sh" ''
    delim="$1"
    while IFS='!' read -r name rest; do
      val="''${rest%$delim}"
      printf 'S["%s"]="%s"\n' "$name" "$val"
    done
  '';

  # AWK wrapper script: replaces gawk for config.status @VAR@ substitution.
  # gawk-tcc's split()/length()/substr() all return 0 due to TCC's
  # double-in-struct bug. This bash script implements the same logic:
  # reads subs.awk to extract S[] and F[] entries, reads stdin, and
  # replaces @VAR@ patterns.
  #
  # Usage: gawk-wrapper -f subs.awk [other args...]
  # Reads template from stdin, writes substituted output to stdout.
  awkWrapper = builtins.toFile "gawk-wrapper.sh" ''
    # Find the -f argument (awk program file)
    awk_prog=""
    prev=""
    for arg; do
      case "$prev" in
        -f) awk_prog="$arg" ;;
      esac
      prev="$arg"
    done

    # Check what kind of awk program this is
    has_S=false
    has_D=false
    if test -n "$awk_prog"; then
      grep -q '^S\["' "$awk_prog" 2>/dev/null && has_S=true
      grep -q '^D\["' "$awk_prog" 2>/dev/null && has_D=true
    fi

    # If neither S[] nor D[], fall through to real gawk
    if ! $has_S && ! $has_D; then
      exec GAWK_REAL_PATH "$@"
    fi

    # ═══ MODE 1: S[] substitution (config.status CONFIG_FILE) ═══════════
    if $has_S; then
      # Extract S["VAR"]="value" and F["VAR"]="file" entries
      subs_file="$TMPDIR/awk_subs_$$"
      frags_file="$TMPDIR/awk_frags_$$"
      > "$subs_file"
      > "$frags_file"
      while IFS= read -r entry; do
        case "$entry" in
          'S["'*)
            tmp1=''${entry#S[\"}
            var=''${tmp1%%\"]*}
            tmp2=''${entry#*\"]=\"}
            val=''${tmp2%\"}
            printf '%s\n' "$var=$val" >> "$subs_file"
            ;;
          'F["'*)
            tmp1=''${entry#F[\"}
            var=''${tmp1%%\"]*}
            tmp2=''${entry#*\"]=\"}
            file=''${tmp2%\"}
            printf '%s\n' "$var=$file" >> "$frags_file"
            ;;
        esac
      done < "$awk_prog"

      # Save stdin (bash-tcc pipe read bug workaround)
      cat > "$TMPDIR/awk_stdin_$$"

      # Process: replace @VAR@ patterns
      while IFS= read -r line; do
        case "$line" in
          *@*@*)
            result="$line"
            while IFS='=' read -r svar sval; do
              case "$result" in
                *"@''${svar}@"*)
                  result="''${result//@''${svar}@/$sval}"
                  ;;
              esac
            done < "$subs_file"
            case "$result" in
              *@*@*)
                while IFS='=' read -r fvar ffile; do
                  case "$result" in
                    *"@''${fvar}@"*)
                      if test -f "$ffile"; then
                        cat "$ffile"
                      fi
                      result=""
                      break
                      ;;
                  esac
                done < "$frags_file"
                ;;
            esac
            if test -n "$result"; then
              printf '%s\n' "$result"
            fi
            ;;
          *)
            printf '%s\n' "$line"
            ;;
        esac
      done < "$TMPDIR/awk_stdin_$$"

      rm -f "$subs_file" "$frags_file" "$TMPDIR/awk_stdin_$$"
      exit 0
    fi

    # ═══ MODE 2: D[] substitution (config.status CONFIG_HEADER) ═════════
    # Replaces: #undef VAR → #define VAR value (if D["VAR"] is set)
    #           #undef VAR → /* #undef VAR */ (if D["VAR"] is not set)
    if $has_D; then
      # Collect remaining positional args (after -f awk_prog) — these are input files
      input_files=""
      skip_next=false
      for arg; do
        if $skip_next; then skip_next=false; continue; fi
        case "$arg" in
          -f) skip_next=true ;;
          -*) ;; # skip other flags
          *) input_files="$input_files $arg" ;;
        esac
      done

      defs_file="$TMPDIR/awk_defs_$$"
      > "$defs_file"
      while IFS= read -r entry; do
        case "$entry" in
          'D["'*)
            tmp1=''${entry#D[\"}
            var=''${tmp1%%\"]*}
            tmp2=''${entry#*\"]=\"}
            val=''${tmp2%\"}
            printf '%s\n' "$var=$val" >> "$defs_file"
            ;;
        esac
      done < "$awk_prog"
      # Unescape awk string literals in defs file: \" → " and \\ → backslash
      sed -i 's/\\"/"/g' "$defs_file"
      sed -i 's/\\\\/\\/g' "$defs_file"

      # Determine input source: positional files or stdin
      if test -n "$input_files"; then
        cat $input_files > "$TMPDIR/awk_stdin_$$"
      else
        cat > "$TMPDIR/awk_stdin_$$"
      fi

      # Process: transform #undef/#define lines
      while IFS= read -r line; do
        case "$line" in
          *'#'*undef\ *|*'#'*define\ *)
            # Extract the macro name (after #undef or #define)
            rest="$line"
            # Strip leading whitespace and # prefix
            case "$rest" in
              *'#'*undef\ *)
                macro=''${rest#*undef }
                macro=''${macro%%[	 (*}
                ;;
              *'#'*define\ *)
                macro=''${rest#*define }
                macro=''${macro%%[	 (*}
                ;;
            esac
            # Check if D[macro] is set
            found=false
            while IFS='=' read -r dvar dval; do
              if test "$dvar" = "$macro"; then
                printf '#define %s%s\n' "$macro" "$dval"
                found=true
                break
              fi
            done < "$defs_file"
            if ! $found; then
              printf '/* %s */\n' "$line"
            fi
            ;;
          *)
            printf '%s\n' "$line"
            ;;
        esac
      done < "$TMPDIR/awk_stdin_$$"

      rm -f "$defs_file" "$TMPDIR/awk_stdin_$$"
      exit 0
    fi
  '';

  # Bash script to patch configure: replaces the broken sed pipeline
  # (from "sed -n '" through ">>$CONFIG_STATUS || ac_write_fail=1")
  # with a call to fixSubsScript.
  #
  # gawk-tcc has broken numerics so we can't use awk for patching.
  # This uses pure bash with a state machine.
  #
  # Usage: $CONFIG_SHELL patch-configure.sh REPLACEMENT < configure > configure.patched
  patchConfigureScript = builtins.toFile "patch-configure.sh" ''
        replacement="$1"
        state=0
        buf=""
        has_subs=no
        lines=0
        while IFS= read -r line; do
          case "$state" in
            0)
              case "$line" in
                "sed -n "*)
                  state=1
                  buf="$line"
                  has_subs=no
                  lines=1
                  ;;
                *)
                  printf '%s\n' "$line"
                  ;;
              esac
              ;;
            1)
              buf="$buf
    $line"
              lines=$((lines + 1))
              case "$line" in
                *subs.awk*|*subs\.awk*) has_subs=yes ;;
              esac
              case "$line" in
                *ac_write_fail*)
                  if test "$has_subs" = yes; then
                    printf '%s\n' "$replacement"
                  else
                    printf '%s\n' "$buf"
                  fi
                  state=0
                  buf=""
                  ;;
              esac
              # Safety: if block exceeds 80 lines, dump verbatim
              if test "$lines" -gt 80 2>/dev/null; then
                printf '%s\n' "$buf"
                state=0
                buf=""
              fi
              ;;
          esac
        done
        # Flush any remaining buffered content
        if test "$state" = 1; then
          printf '%s\n' "$buf"
        fi
  '';
in
  builtins.derivation {
    name = "binutils-${sources.binutils.version}";
    inherit system;
    builder = "${bash}/bin/bash";
    args = [
      "-c"
      ''
        set -eu

        export PATH="${
          builtins.concatStringsSep ":" (
            builtins.map (p: "${p}/bin") [
              coreutils
              sed
              grep
              patch
              diffutils
              gawk
              bash
              tinycc
              gnumake
            ]
          )
        }"
        export CONFIG_SHELL="${bash}/bin/bash"
        export SHELL="${bash}/bin/bash"

        # ── Set up gawk wrapper (bypass TCC double-in-struct bug) ─────────
        # gawk-tcc's split()/length()/substr() return 0 because TCC can't
        # store doubles in structs. Install a bash-based wrapper that
        # intercepts config.status's @VAR@ substitution calls and uses
        # bash parameter expansion instead.
        mkdir -p $TMPDIR/wrappers
        {
          echo "#!${bash}/bin/bash"
          cat ${awkWrapper}
        } > $TMPDIR/wrappers/gawk
        sed -i "s|GAWK_REAL_PATH|${gawk}/bin/gawk|g" $TMPDIR/wrappers/gawk
        chmod +x $TMPDIR/wrappers/gawk
        ln -s gawk $TMPDIR/wrappers/awk
        export PATH="$TMPDIR/wrappers:$PATH"

        # Copy source to writable directory (store files are read-only)
        cp -r ${src} $TMPDIR/src
        chmod -R u+w $TMPDIR/src
        cd $TMPDIR/src

        ${lib.freezeAutotoolsMtimes}

        # ── Apply TCC compatibility patch (from Guix, verified upstream) ──
        patch -p1 < ${./patches/binutils-boot-2.20.1a.patch}

        # ── Fix dwarf.c: Mes libc's unistd.h doesn't declare optarg ────────
        # dwarf.c uses optarg but only includes sysdep.h→unistd.h, not getopt.h.
        # POSIX allows optarg in unistd.h but Mes libc doesn't have it there.
        # The bundled include/getopt.h does declare it.
        {
          echo '#include <getopt.h>'
          cat binutils/dwarf.c
        } > binutils/dwarf.c.tmp
        mv binutils/dwarf.c.tmp binutils/dwarf.c

        # ── Patch ALL configure scripts: replace broken sed pipeline ───────
        # Our sed-tcc has bugs in hold space/branch/N commands that corrupt
        # the autoconf substitution pipeline. Our gawk-tcc has broken numerics
        # (TCC double-in-struct bug). Use pure bash for patching.
        # Must patch ALL configure scripts (top-level + subdirectories like
        # bfd, gas, ld, libiberty) since make invokes sub-configures.
        REPLACEMENT='$CONFIG_SHELL ${fixSubsScript} "$ac_delim" <conf$$subs.awk >>$CONFIG_STATUS || ac_write_fail=1'

        # Patch top-level configure
        $CONFIG_SHELL ${patchConfigureScript} "$REPLACEMENT" \
          < configure > configure.patched
        mv configure.patched configure
        chmod +x configure
        echo "  patched: configure"

        # Patch subdirectory configures (bash-tcc glob */configure is broken)
        for d in */; do
          if test -f "$d/configure"; then
            $CONFIG_SHELL ${patchConfigureScript} "$REPLACEMENT" \
              < "$d/configure" > "$d/configure.patched"
            mv "$d/configure.patched" "$d/configure"
            chmod +x "$d/configure"
            echo "  patched: $d/configure"
          fi
        done

        # ── Configure ──────────────────────────────────────────────────────
        $CONFIG_SHELL ./configure \
          CC=tcc \
          CPPFLAGS="-D__GLIBC_MINOR__=6 -DMES_BOOTSTRAP=1" \
          AR="tcc -ar" \
          RANLIB=true \
          LDFLAGS="-static" \
          --build=i686-unknown-linux-gnu \
          --host=i686-unknown-linux-gnu \
          --disable-nls \
          --disable-shared \
          --disable-werror \
          --prefix=$out

        # ── Verify @VAR@ substitution worked ──────────────────────────────
        echo "==> Verifying Makefile substitution"
        for mf in Makefile bfd/Makefile gas/Makefile ld/Makefile libiberty/Makefile opcodes/Makefile binutils/Makefile gprof/Makefile; do
          if test -f "$mf"; then
            remaining=$(grep -c '@[A-Za-z_][A-Za-z_0-9]*@' "$mf" || true)
            echo "  $mf: $remaining remaining @VAR@"
          fi
        done

        # ── Build ──────────────────────────────────────────────────────────
        make

        # ── Install ────────────────────────────────────────────────────────
        make install

        # ── Post-install: symlink target-dir binaries into $out/bin ──────
        # binutils installs some tools to $out/<target>/bin/ instead of $out/bin/.
        # Create symlinks so they're all in PATH.
        target=i686-unknown-linux-gnu
        if test -d "$out/$target/bin"; then
          for tool in $out/$target/bin/*; do
            name=$(basename "$tool")
            if ! test -e "$out/bin/$name"; then
              ln -s "../$target/bin/$name" "$out/bin/$name"
            fi
          done
        fi
        # Also create ld → ld-new symlink if needed
        if test -f "$out/bin/ld-new" && ! test -e "$out/bin/ld"; then
          ln -s ld-new "$out/bin/ld"
        fi

        echo "binutils 2.20.1 installed to $out"
      ''
    ];
  }
  // {
    meta = {
      description = "GNU tools for manipulating binaries (linker, assembler, etc.), version 2.20.1a";
      homepage = "https://www.gnu.org/software/binutils/";
      license = "GPL-3.0-or-later";
      build = {
        os = "linux";
        cpu = [
          "x86_64"
          "i686"
        ];
      };
      execute = {
        os = "linux";
        cpu = "i686";
      };
    };
  }
