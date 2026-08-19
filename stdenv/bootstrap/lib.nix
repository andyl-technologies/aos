# stdenv/bootstrap/lib.nix — shared utilities for bootstrap stages
#
# Helpers that multiple stage5 packages need, extracted here to avoid
# code duplication.
{
  # Script to bypass the automake "build environment is sane" check.
  #
  # coreutils-tcc's ls -t doesn't sort correctly (Mes libc stat() returns
  # wrong timestamps), causing the check to fail. sed-tcc's -i flag is
  # unreliable, so we use bash line-by-line processing instead.
  #
  # Handles both automake 1.4 (`conftestfile`) and 1.7+ (`conftest.file`).
  #
  # Usage: ${bash}/bin/bash ${lib.bypassSanityCheck} configure
  bypassSanityCheck = builtins.toFile "bypass-sanity-check.sh" ''
    src="$1"
    while IFS= read -r line; do
      case "$line" in
        *'test "$2" = conftest'*)
          printf '%s\n' "true"
          ;;
        *)
          printf '%s\n' "$line"
          ;;
      esac
    done < "$src" > "$src.new"
    mv "$src.new" "$src"
    chmod +x "$src"
  '';

  # ── Workarounds for autoconf 2.5x+ with sed-tcc/gawk-tcc bugs ──────────
  #
  # Packages using autoconf 2.5x+ (sed 4.0.9, patch 2.5.9, coreutils 5.0,
  # bash 2.05b, binutils 2.20.1a) have a complex sed→awk pipeline in
  # config.status that breaks with TCC-compiled sed (pipe/EPIPE bugs) and
  # gawk (double-in-struct bug, split()/length()/substr() return 0).
  #
  # Three scripts work together:
  #   1. fixSubsScript — replaces the broken sed pipeline
  #   2. awkWrapper — replaces gawk for S[]/D[] substitution
  #   3. patchConfigureScript — patches configure to use fixSubsScript

  # Shell script to replace broken sed pipeline in autoconf-generated configure.
  # sed-tcc has pipe/hold-space bugs that corrupt the sed→awk pipeline.
  # This uses bash read+printf instead.
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

  # AWK wrapper: replaces gawk for config.status @VAR@ substitution.
  # gawk-tcc's split()/length()/substr() return 0 due to TCC's
  # double-in-struct bug. This bash script implements the same logic.
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

      cat > "$TMPDIR/awk_stdin_$$"

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
    if $has_D; then
      input_files=""
      skip_next=false
      for arg; do
        if $skip_next; then skip_next=false; continue; fi
        case "$arg" in
          -f) skip_next=true ;;
          -*) ;;
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
      sed -i 's/\\"/"/g' "$defs_file"
      sed -i 's/\\\\/\\/g' "$defs_file"

      if test -n "$input_files"; then
        cat $input_files > "$TMPDIR/awk_stdin_$$"
      else
        cat > "$TMPDIR/awk_stdin_$$"
      fi

      while IFS= read -r line; do
        case "$line" in
          *'#'*undef\ *|*'#'*define\ *)
            rest="$line"
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
  # with a call to fixSubsScript.
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
              if test "$lines" -gt 80 2>/dev/null; then
                printf '%s\n' "$buf"
                state=0
                buf=""
              fi
              ;;
          esac
        done
        if test "$state" = 1; then
          printf '%s\n' "$buf"
        fi
  '';
  # ── Defuse autotools regeneration after cp -r ─────────────────────────────────────
  #
  # Stages copy their source with `cp -r $src $TMPDIR/src`, which
  # stamps the copies with fresh mtimes in readdir order — whether
  # configure.in ends up newer than the pre-generated autotools outputs
  # (configure, config.h.in, stamp-h.in, Makefile.in) is a per-machine
  # coin flip. Generated package-specific files have the same problem:
  # coreutils 5.0 regenerates doc/version.texi and tests/*/Makefile.am
  # when their source templates happen to be copied later. Those rules
  # require date and perl, which intentionally do not exist in the
  # bootstrap closure.
  #
  # Interpolate this after `cd`-ing into the copied tree. It recursively
  # pins every copied file and directory to configure's timestamp, making
  # the writable tree match the equal-mtime semantics of its immutable
  # Nix store source. Symlinks are skipped so an absolute link cannot
  # mutate a store target. This uses a Bash 2.05-compatible recursive
  # function because find(1) is not on the bootstrap PATH.
  freezeAutotoolsMtimes = ''
    freeze_tree_mtimes() {
      local freeze_dir="$1"
      local freeze_path
      for freeze_path in "$freeze_dir"/* "$freeze_dir"/.[!.]* "$freeze_dir"/..?*; do
        if test ! -e "$freeze_path" && test ! -L "$freeze_path"; then
          continue
        fi
        if test -L "$freeze_path"; then
          continue
        fi
        if test -d "$freeze_path"; then
          freeze_tree_mtimes "$freeze_path"
        fi
        touch -r ./configure "$freeze_path"
      done
    }
    freeze_tree_mtimes .
    unset -f freeze_tree_mtimes
  '';
}
