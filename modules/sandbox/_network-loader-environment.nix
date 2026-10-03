{lib}: let
  # These inputs can reach a privileged Network executable before its own
  # entrypoint checks run.
  denylist = [
    "BASH_ENV"
    "ENV"
    "GCONV_PATH"
    "GLIBC_TUNABLES"
    "LD_ASSUME_KERNEL"
    "LD_AUDIT"
    "LD_BIND_NOT"
    "LD_BIND_NOW"
    "LD_DEBUG"
    "LD_DEBUG_OUTPUT"
    "LD_DYNAMIC_WEAK"
    "LD_HWCAP_MASK"
    "LD_LIBRARY_PATH"
    "LD_ORIGIN_PATH"
    "LD_POINTER_GUARD"
    "LD_PREFER_MAP_32BIT_EXEC"
    "LD_PRELOAD"
    "LD_PROFILE"
    "LD_PROFILE_OUTPUT"
    "LD_SHOW_AUXV"
    "LD_TRACE_LOADED_OBJECTS"
    "LD_TRACE_PRELINKING"
    "LD_USE_LOAD_BIAS"
    "LD_VERBOSE"
    "LD_WARN"
    "LIBC_FATAL_STDERR_"
    "LOCPATH"
    "MALLOC_CHECK_"
    "MALLOC_PERTURB_"
    "MALLOC_TRACE"
    "NLSPATH"
    "NODE_OPTIONS"
    "NODE_PATH"
    "PERL5LIB"
    "PERLLIB"
    "PYTHONHOME"
    "PYTHONPATH"
    "RUBYLIB"
    "RUBYOPT"
  ];
in {
  inherit denylist;

  # Check the canonical rendered unit, including contributions from other
  # modules. External files and manager pass-through can add names beyond the
  # fixed scrub list.
  renderedUnitMatchesSourcePolicy = text:
    lib.all (name: lib.hasInfix "UnsetEnvironment=${name}\n" text) denylist
    && !lib.hasInfix "\nEnvironmentFile=" text
    && !lib.hasInfix "\nPassEnvironment=" text;
}
