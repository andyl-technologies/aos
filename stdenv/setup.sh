#!/bin/bash
# stdenv/setup.sh — Standard build environment setup script
#
# This script is sourced by all AOS builds. It sets up the build environment,
# defines helper functions, and runs the build phases.
#
# Environment variables expected:
#   $out              — output directory
#   $src              — source path/directory
#   $buildDeps        — space-separated list of build-time dependency paths
#   $runtimeDeps      — space-separated list of runtime dependency paths
#   $propagatedDeps   — space-separated list of propagated dependency paths
#   $NIX_BUILD_CORES  — number of parallel build jobs
#   $phases           — (optional) space-separated list of phase names
#

set -euo pipefail

# ---------------------------------------------------------------------------
# Basic environment
# ---------------------------------------------------------------------------

# Set up PATH from build dependencies
if [ -n "${buildInputs:-}" ]; then
  for dep in $buildInputs; do
    if [ -d "$dep/bin" ]; then
      export PATH="$dep/bin${PATH:+:$PATH}"
    fi
  done
fi

if [ -n "${nativeBuildInputs:-}" ]; then
  for dep in $nativeBuildInputs; do
    if [ -d "$dep/bin" ]; then
      export PATH="$dep/bin${PATH:+:$PATH}"
    fi
  done
fi

# Set up C_INCLUDE_PATH, LIBRARY_PATH, PKG_CONFIG_PATH from dependencies
for dep in ${buildInputs:-} ${propagatedBuildInputs:-}; do
  if [ -d "$dep/include" ]; then
    export C_INCLUDE_PATH="$dep/include${C_INCLUDE_PATH:+:$C_INCLUDE_PATH}"
    export CPLUS_INCLUDE_PATH="$dep/include${CPLUS_INCLUDE_PATH:+:$CPLUS_INCLUDE_PATH}"
  fi
  if [ -d "$dep/lib" ]; then
    export LIBRARY_PATH="$dep/lib${LIBRARY_PATH:+:$LIBRARY_PATH}"
    export LD_LIBRARY_PATH="$dep/lib${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
  fi
  if [ -d "$dep/lib/pkgconfig" ]; then
    export PKG_CONFIG_PATH="$dep/lib/pkgconfig${PKG_CONFIG_PATH:+:$PKG_CONFIG_PATH}"
  fi
done

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

# Create the output directory
if [ -n "${out:-}" ]; then
  mkdir -p "$out"
fi

# ---------------------------------------------------------------------------
# Helper functions
# ---------------------------------------------------------------------------

# patchShebangs <dir>
# Replace #!/usr/bin/env, #!/bin/sh, etc. shebangs with store paths.
patchShebangs() {
  local dir="$1"
  local interpreter

  echo "patchShebangs: patching scripts in $dir"

  find "$dir" -type f -executable | while IFS= read -r f; do
    # Read the first two bytes to check for #!
    local magic
    magic=$(head -c 2 "$f" 2>/dev/null) || continue
    if [ "$magic" != "#!" ]; then
      continue
    fi

    local shebang
    shebang=$(head -n 1 "$f")

    # Extract the interpreter from the shebang
    interpreter=""
    case "$shebang" in
      "#!/usr/bin/env bash"|"#!/usr/bin/env sh")
        interpreter=$(type -P bash 2>/dev/null || type -P sh 2>/dev/null || echo "/bin/sh")
        ;;
      "#!/usr/bin/env python3"*)
        interpreter=$(type -P python3 2>/dev/null || echo "")
        ;;
      "#!/usr/bin/env python"*)
        interpreter=$(type -P python 2>/dev/null || echo "")
        ;;
      "#!/usr/bin/env perl"*)
        interpreter=$(type -P perl 2>/dev/null || echo "")
        ;;
      "#!/usr/bin/env "*)
        local cmd
        cmd=$(echo "$shebang" | sed 's|#!/usr/bin/env ||' | awk '{print $1}')
        interpreter=$(type -P "$cmd" 2>/dev/null || echo "")
        ;;
      "#!/bin/sh"|"#!/bin/bash")
        interpreter=$(type -P bash 2>/dev/null || type -P sh 2>/dev/null || echo "/bin/sh")
        ;;
      "#!/usr/bin/sh"|"#!/usr/bin/bash")
        interpreter=$(type -P bash 2>/dev/null || type -P sh 2>/dev/null || echo "/bin/sh")
        ;;
      "#!/usr/bin/perl"*)
        interpreter=$(type -P perl 2>/dev/null || echo "")
        ;;
    esac

    if [ -n "$interpreter" ] && [ -x "$interpreter" ]; then
      echo "  patching $f: $shebang -> #!$interpreter"
      sed -i "1s|#!.*|#!$interpreter|" "$f"
    fi
  done
}

# substituteInPlace <file> <args...>
# Replace strings in a file in-place.
# Usage: substituteInPlace file.txt --replace-fail "old" "new"
#        substituteInPlace file.txt --subst-var VAR_NAME
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

        # Use perl for reliable string replacement (avoids sed delimiter issues)
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

# wrapProgram <exe> <args...>
# Create a wrapper script around an executable that sets environment variables.
# Usage: wrapProgram $out/bin/foo \
#          --prefix PATH : $out/bin:$dep/bin \
#          --set FOO bar \
#          --suffix LD_LIBRARY_PATH : $dep/lib
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
    echo '#!/bin/sh'
    echo '# Wrapper generated by AOS stdenv wrapProgram'

    while [ $# -gt 0 ]; do
      case "$1" in
        --set)
          local varName="$2"
          local varValue="$3"
          shift 3
          echo "export $varName=\"$varValue\""
          ;;
        --set-default)
          local varName="$2"
          local varValue="$3"
          shift 3
          echo "export $varName=\"\${$varName:-$varValue}\""
          ;;
        --prefix)
          local varName="$2"
          local sep="$3"
          local values="$4"
          shift 4
          echo "export $varName=\"$values\${$varName:+$sep\$$varName}\""
          ;;
        --suffix)
          local varName="$2"
          local sep="$3"
          local values="$4"
          shift 4
          echo "export $varName=\"\${$varName:+\$$varName$sep}$values\""
          ;;
        --unset)
          local varName="$2"
          shift 2
          echo "unset $varName"
          ;;
        --add-flags)
          local flags="$2"
          shift 2
          # Flags will be added to the exec line below
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

# makeWrapper <real-exe> <wrapper-path> <args...>
# Like wrapProgram but creates the wrapper at a different path,
# leaving the original untouched.
makeWrapper() {
  local real="$1"
  local wrapper="$2"
  shift 2

  {
    echo '#!/bin/sh'
    echo '# Wrapper generated by AOS stdenv makeWrapper'

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
        *)
          shift
          ;;
      esac
    done

    echo "exec \"$real\" \"\$@\""
  } > "$wrapper"

  chmod +x "$wrapper"
}

# addToSearchPath <var> <dir>
# Append a directory to a colon-separated search path variable.
addToSearchPath() {
  local varName="$1"
  local dir="$2"
  if [ -d "$dir" ]; then
    eval "export $varName=\"\${$varName:+\$$varName:}$dir\""
  fi
}

# stripDirs <dir>
# Strip debugging symbols from ELF binaries and libraries.
stripDirs() {
  local dir="$1"
  echo "stripping binaries in $dir"
  find "$dir" -type f \( -name '*.so*' -o -name '*.a' -o -executable \) | while IFS= read -r f; do
    if file "$f" 2>/dev/null | grep -q "ELF"; then
      strip --strip-unneeded "$f" 2>/dev/null || true
    fi
  done
}

# fixupPhase — post-install cleanup
# Called automatically after the install phase.
_fixupPhase() {
  if [ -d "$out/bin" ]; then
    patchShebangs "$out/bin"
  fi
  if [ -d "$out/lib" ]; then
    patchShebangs "$out/lib"
  fi
  if [ -d "$out/libexec" ]; then
    patchShebangs "$out/libexec"
  fi

  # Strip unless explicitly disabled
  if [ "${dontStrip:-0}" != "1" ]; then
    if [ -d "$out/bin" ]; then stripDirs "$out/bin"; fi
    if [ -d "$out/lib" ]; then stripDirs "$out/lib"; fi
  fi

  # Remove empty directories
  find "$out" -type d -empty -delete 2>/dev/null || true

  # Remove .la files (libtool archives cause problems in Nix)
  find "$out" -name '*.la' -delete 2>/dev/null || true
}

# ---------------------------------------------------------------------------
# Phase runner
# ---------------------------------------------------------------------------
# The phase runner is invoked by the build script generated by mkDerivation.
# Each phase is a { name; script; } record, turned into sequential script
# sections by lib/derivations.nix. This setup.sh provides the helper
# functions that those phase scripts can call.
#
# The actual phase iteration happens in the builder script. This file
# is sourced at the beginning of that script.
# ---------------------------------------------------------------------------

echo "AOS stdenv setup complete (NIX_BUILD_CORES=$NIX_BUILD_CORES)"
