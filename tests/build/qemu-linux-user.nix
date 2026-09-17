##! Checks Linux process emulation and the binfmt_misc preserved-argv contract.
{
  pkgs,
  qemu,
}: let
  cpu = pkgs.stdenv.hostPlatform.constraints.cpu;
  architecture =
    if cpu == "i686"
    then "i386"
    else cpu;
in
  pkgs.mkDerivation {
    pname = "aos-qemu-linux-user";
    version = "1";
    src = null;
    buildDeps = [qemu];
    runtimeDeps = [pkgs.gcc-libs];
    phases = [
      {
        name = "check";
        script = ''
          cat > probe.c <<'SOURCE'
          #include <string.h>

          int main(int argc, char **argv)
          {
              return argc != 2 ||
                  strcmp(argv[0], "preserved argv zero") != 0 ||
                  strcmp(argv[1], "argument with spaces") != 0;
          }
          SOURCE
          cc -O2 probe.c -o probe

          ${qemu}/bin/qemu-${architecture} -0 'preserved argv zero' \
            "$PWD/probe" 'argument with spaces'
          ${qemu}/bin/qemu-${architecture}-binfmt-P \
            "$PWD/probe" 'preserved argv zero' 'argument with spaces'
          if ${qemu}/bin/qemu-${architecture}-binfmt-P "$PWD/probe"; then
            echo 'binfmt interpreter accepted a missing original argv[0]' >&2
            exit 1
          fi

          # Guest thread exit also unwinds a host QEMU thread. Both processes
          # must resolve their own libgcc_s without environment injection.
          cat > thread-exit.c <<'SOURCE'
          #include <pthread.h>

          static void *exit_thread(void *argument)
          {
              pthread_exit(argument);
          }

          int main(void)
          {
              pthread_t thread;
              int token = 0;
              void *result = 0;

              if (pthread_create(&thread, 0, exit_thread, &token) != 0) {
                  return 1;
              }
              if (pthread_join(thread, &result) != 0) {
                  return 2;
              }
              return result != &token;
          }
          SOURCE
          cc -O2 -pthread thread-exit.c \
            -Wl,--push-state,--no-as-needed,-l:libgcc_s.so.1,--pop-state \
            -o thread-exit
          unset LD_PRELOAD LD_LIBRARY_PATH
          ${qemu}/bin/qemu-${architecture} "$PWD/thread-exit"

          mkdir -p "$out"
          echo PASS > "$out/result"
        '';
      }
    ];
  }
