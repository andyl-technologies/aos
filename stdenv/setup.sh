# stdenv/setup.sh — Standard build environment setup script
#
# Sourced by all AOS builds. Sets up the build environment,
# defines helper functions, and provides phase support.
#
# Environment variables expected:
#   $out              — output directory
#   $src              — source path/directory
#   $buildDeps        — space-separated list of build-time dependency paths
#   $runtimeDeps      — space-separated list of runtime dependency paths
#   $propagatedDeps   — space-separated list of propagated dependency paths
#   $NIX_BUILD_CORES  — number of parallel build jobs

set -eu
set -o pipefail 2>/dev/null || true

# Initialize common build variables (safe for set -u / nounset)
: "${CFLAGS:=}"
: "${CPPFLAGS:=}"
: "${LDFLAGS:=}"

# Ensure binaries and shared libraries can find sibling .so files within the
# same package at runtime.  Matches the Nixpkgs _addRpathPrefix mechanism.
if [ -n "${out:-}" ]; then
  export NIX_LDFLAGS="-Wl,-rpath,$out/lib ${NIX_LDFLAGS:-}"
fi

# The derivation builder supplies dependency search paths in the correct order.
# Keep its native executable path intact: target runtime inputs can contain a
# different architecture's tools, and global loader paths mix library tiers.

# Determine number of build cores
if [ -z "${NIX_BUILD_CORES:-}" ]; then
  if [ -f /proc/cpuinfo ]; then
    NIX_BUILD_CORES=$(grep -c ^processor /proc/cpuinfo 2>/dev/null || echo 1)
  else
    NIX_BUILD_CORES=1
  fi
fi
export NIX_BUILD_CORES

# Source stdenv setup variables if available
if [ -n "${stdenv:-}" ] && [ -f "$stdenv/setup-vars.sh" ]; then
  source "$stdenv/setup-vars.sh"
fi

# Create every declared output directory. Structured derivations expose
# `outputs` as an associative array; the generated phase driver normalizes
# both representations into AOS_OUTPUT_NAMES before sourcing this file.
for o in ${AOS_OUTPUT_NAMES:-${outputs:-out}}; do
  eval "p=\"\${$o:-}\""
  [ -n "$p" ] && mkdir -p "$p"
done

# ---------------------------------------------------------------------------
# Helper functions
# ---------------------------------------------------------------------------

patchShebangs() {
  local dir="$1"
  echo "patchShebangs: patching scripts in $dir"
  find "$dir" -type f \( -perm -0100 -o -perm -0010 -o -perm -0001 \) -print0 | while IFS= read -r -d '' f; do
    local magic shebang command arguments interpreter
    magic=$(head -c 2 "$f" 2>/dev/null) || continue
    [ "$magic" = "#!" ] || continue

    shebang=$(head -n 1 "$f")
    command=$(printf '%s\n' "${shebang#\#!}" | sed 's/^[[:space:]]*//; s/[[:space:]].*$//')
    arguments=${shebang#*"$command"}
    if [ "$command" = /usr/bin/env ]; then
      arguments=$(printf '%s\n' "$arguments" | sed 's/^[[:space:]]*//; s/^-S[[:space:]]*//')
      command=${arguments%%[[:space:]]*}
      arguments=${arguments#"$command"}
    fi

    interpreter=""
    case "$command" in
      sh|bash|/bin/sh|/bin/bash|/usr/bin/sh|/usr/bin/bash)
        interpreter=${CONFIG_SHELL:?CONFIG_SHELL must name the AOS runtime shell}
        ;;
      /usr/bin/perl)
        interpreter=$(type -P perl 2>/dev/null || true)
        ;;
      /*)
        # Already qualified interpreters belong to the package's own runtime.
        ;;
      *)
        interpreter=$(type -P "$command" 2>/dev/null || true)
        ;;
    esac

    if [ -n "$interpreter" ] && [ -x "$interpreter" ]; then
      echo "  patching $f: $shebang -> #!$interpreter$arguments"
      sed -i "1c\\#!$interpreter$arguments" "$f"
    fi
  done
}

substituteInPlace() {
  local file="$1"
  shift
  if [ ! -f "$file" ]; then
    echo "substituteInPlace: file '$file' not found"
    return 1
  fi
  while [ $# -gt 0 ]; do
    case "$1" in
      --replace-fail)
        local pattern="$2"
        local replacement="$3"
        shift 3
        if ! grep -qF "$pattern" "$file"; then
          echo "substituteInPlace: pattern '$pattern' not found in '$file'"
          return 1
        fi
        perl -pi -e "
          \$pat = quotemeta('$pattern');
          \$rep = '$replacement';
          s/\$pat/\$rep/g;
        " "$file"
        ;;
      --replace-warn)
        local pattern="$2"
        local replacement="$3"
        shift 3
        if ! grep -qF "$pattern" "$file"; then
          echo "substituteInPlace: WARNING: pattern '$pattern' not found in '$file'"
        else
          perl -pi -e "
            \$pat = quotemeta('$pattern');
            \$rep = '$replacement';
            s/\$pat/\$rep/g;
          " "$file"
        fi
        ;;
      --replace-quiet)
        local pattern="$2"
        local replacement="$3"
        shift 3
        perl -pi -e "
          \$pat = quotemeta('$pattern');
          \$rep = '$replacement';
          s/\$pat/\$rep/g;
        " "$file" 2>/dev/null || true
        ;;
      --subst-var)
        local varName="$2"
        shift 2
        local varValue="${!varName:-}"
        perl -pi -e "s/\@$varName\@/$varValue/g" "$file"
        ;;
      *)
        echo "substituteInPlace: unknown argument '$1'"
        return 1
        ;;
    esac
  done
}

wrapProgram() {
  local prog="$1"
  shift
  if [ ! -f "$prog" ]; then
    echo "wrapProgram: program '$prog' not found"
    return 1
  fi
  local real="${prog}.real"
  mv "$prog" "$real"
  {
    printf '#!%s\n' "${CONFIG_SHELL:?CONFIG_SHELL must name the AOS runtime shell}"
    echo '# Wrapper generated by AOS stdenv wrapProgram'
    while [ $# -gt 0 ]; do
      case "$1" in
        --set)
          echo "export $2=\"$3\""
          shift 3
          ;;
        --set-default)
          echo "export $2=\"\${$2:-$3}\""
          shift 3
          ;;
        --prefix)
          echo "export $2=\"$4\${$2:+$3\$$2}\""
          shift 4
          ;;
        --suffix)
          echo "export $2=\"\${$2:+\$$2$3}$4\""
          shift 4
          ;;
        --unset)
          echo "unset $2"
          shift 2
          ;;
        --add-flags)
          shift 2
          ;;
        *)
          echo "wrapProgram: unknown argument '$1'"
          return 1
          ;;
      esac
    done
    echo "exec \"$real\" \"\$@\""
  } > "$prog"
  chmod +x "$prog"
}

makeWrapper() {
  local real="$1"
  local wrapper="$2"
  shift 2
  {
    printf '#!%s\n' "${CONFIG_SHELL:?CONFIG_SHELL must name the AOS runtime shell}"
    echo '# Wrapper generated by AOS stdenv makeWrapper'
    while [ $# -gt 0 ]; do
      case "$1" in
        --set) echo "export $2=\"$3\""; shift 3 ;;
        --set-default) echo "export $2=\"\${$2:-$3}\""; shift 3 ;;
        --prefix) echo "export $2=\"$4\${$2:+$3\$$2}\""; shift 4 ;;
        --suffix) echo "export $2=\"\${$2:+\$$2$3}$4\""; shift 4 ;;
        --unset) echo "unset $2"; shift 2 ;;
        *) shift ;;
      esac
    done
    echo "exec \"$real\" \"\$@\""
  } > "$wrapper"
  chmod +x "$wrapper"
}

addToSearchPath() {
  local varName="$1"
  local dir="$2"
  if [ -d "$dir" ]; then
    eval "export $varName=\"\${$varName:+\$$varName:}$dir\""
  fi
}

stripDirs() {
  local dir="$1"
  echo "stripping binaries in $dir"
  find "$dir" -type f \( -name '*.so*' -o -name '*.a' -o -executable \) | while IFS= read -r f; do
    if file "$f" 2>/dev/null | grep -q "ELF"; then
      strip --strip-unneeded "$f" 2>/dev/null || true
    fi
  done
}

_fixupPhase() {
  if [ -d "$out/bin" ]; then patchShebangs "$out/bin"; fi
  if [ -d "$out/lib" ]; then patchShebangs "$out/lib"; fi
  if [ -d "$out/libexec" ]; then patchShebangs "$out/libexec"; fi
  if [ "${dontStrip:-0}" != "1" ]; then
    if [ -d "$out/bin" ]; then stripDirs "$out/bin"; fi
    if [ -d "$out/lib" ]; then stripDirs "$out/lib"; fi
  fi
  find "$out" -type d -empty -delete 2>/dev/null || true
  find "$out" -name '*.la' -delete 2>/dev/null || true
}

echo "AOS stdenv setup complete (NIX_BUILD_CORES=$NIX_BUILD_CORES)"
