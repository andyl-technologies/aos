# Checks authorization routing after applying the complete manager patch set.
{pkgs, ...}:
pkgs.systemd.overrideAttrs (old: {
  pname = "systemd-switch-root-access-check";
  outputs = ["out"];
  runtimeDeps = [];
  propagatedDeps = [];
  # This derivation exports checked source, so there are no executable bytes
  # for the production package's backend artifact finalizer to bind.
  postFinalize = "";
  phases =
    builtins.filter (phase: phase.name == "unpack") old.phases
    ++ [
      {
        name = "check-access";
        script = ''
          ${pkgs.python3}/bin/python3 - <<'PY'
          import pathlib
          import re

          source = pathlib.Path("src/core/dbus-manager.c").read_text()

          def method(name):
              start = source.index(f"static int method_{name}(")
              end = source.find("\nstatic ", start + 1)
              return source[start:end if end >= 0 else len(source)]

          # The new permission belongs to exactly one entrypoint. The three
          # destructive manager methods keep their independent reboot check.
          expected = {
              "switch_root": "aos_switch_root",
              "reboot": "reboot",
              "soft_reboot": "reboot",
              "kexec": "reboot",
          }
          for name, permission in expected.items():
              checks = re.findall(
                  r'mac_selinux_access_check\(message, "([^"]+)", reterr_error\)',
                  method(name),
              )
              assert checks == [permission], (name, checks)

          assert source.count('"aos_switch_root"') == 1
          assert "if (!in_initrd())" in method("switch_root")
          print("SwitchRoot-only SELinux routing passed")

          # Compile the actual access-check function against controlled library
          # results. In particular, an allow_unknown result must not reach the
          # library's otherwise successful access check.
          access = pathlib.Path("src/core/selinux-access.c").read_text()
          start = access.index("static int check_access(")
          end = access.index("\n}\n", start) + 3
          prelude = r"""
          #include <assert.h>
          #include <errno.h>
          #include <stdbool.h>
          #include <stdarg.h>
          #include <string.h>
          typedef struct { int unused; } sd_bus_error;
          struct audit_info { const char *function, *path, *cmdline; };
          #define SD_BUS_ERROR_ACCESS_DENIED "org.freedesktop.DBus.Error.AccessDenied"
          #define streq(a, b) (strcmp((a), (b)) == 0)
          static int unknown, allowed, calls;
          static bool enforcing;
          static bool mac_selinux_enforcing(void) { return enforcing; }
          static int sym_security_deny_unknown(void) { return unknown; }
          static int sym_selinux_check_access(const char *s, const char *t,
                          const char *c, const char *p, void *a) {
                  calls++;
                  errno = EACCES;
                  return allowed ? 0 : -1;
          }
          static int sd_bus_error_set(sd_bus_error *e, const char *n, const char *m) {
                  return -EACCES;
          }
          static int sd_bus_error_setf(sd_bus_error *e, const char *n, const char *f, ...) {
                  return -EACCES;
          }
          static int errno_or_else(int e) { return -(errno ? errno : e); }
          static const char *empty_to_na(const char *s) { return s ? s : "n/a"; }
          static int log_selinux_enforcing_errno(int r, const char *f, ...) {
                  return enforcing ? r : 0;
          }
          """
          cases = r"""
          int main(void) {
                  struct audit_info audit = { .function = "test" };
                  sd_bus_error error = {};
                  for (int mode = 0; mode < 2; mode++) {
                          enforcing = mode;
                          for (int behavior = -1; behavior <= 2; behavior++) {
                                  unknown = behavior;
                                  allowed = 1;
                                  calls = 0;
                                  int r = check_access("s", "t", "system", "aos_switch_root", &audit, &error);
                                  assert((r >= 0) == (behavior == 1));
                                  assert(calls == (behavior == 1));
                          }
                          unknown = 1;
                          allowed = 0;
                          calls = 0;
                          assert((check_access("s", "t", "system", "aos_switch_root", &audit, &error) < 0) == enforcing);
                          assert(calls == 1);
                          /* Existing permissions retain their ordinary checks. */
                          unknown = 0;
                          allowed = 1;
                          calls = 0;
                          assert(check_access("s", "t", "system", "reboot", &audit, &error) == 0);
                          assert(calls == 1);
                  }
                  return 0;
          }
          """
          pathlib.Path("switch-root-access.c").write_text(prelude + access[start:end] + cases)
          PY

          $CC -std=gnu11 -Wall -Wextra -Werror -Wno-unused-parameter \
            switch-root-access.c -o switch-root-access
          ./switch-root-access

          mkdir -p "$out"
          cp src/core/dbus-manager.c "$out/dbus-manager.c"
          cp src/core/selinux-access.c "$out/selinux-access.c"
          touch "$out/passed"
        '';
      }
    ];
})
