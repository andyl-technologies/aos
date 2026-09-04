##! fuse3 — Low-level Filesystem in Userspace library
##!
##! Upstream does not split its low- and high-level APIs into separate shared
##! objects, so this package ships the complete dynamically linked libfuse3
##! library and public headers. AOS consumers use only the low-level custom-FD
##! session API; privileged mount operations and policy remain in the mount
##! broker. The DSO retains upstream mount-helper and mtab fallback strings,
##! but they are inert in that architecture: this output contains no helper,
##! utility, init script, udev rule, or mtab integration.
{
  mkDerivation,
  fetchurl,
  meson,
  ninja,
  pkg-config,
}: let
  version = "3.18.2";
  source = fetchurl {
    urls = [
      "https://github.com/libfuse/libfuse/releases/download/fuse-${version}/fuse-${version}.tar.gz"
    ];
    hash = "sha256-8B3oVxfiCt9fmK/zJKzYXdc9YaXKODTVc9zwvW5Uopg=";
  };
in
  mkDerivation {
    pname = "fuse3";
    inherit version;

    src = source;

    buildDeps = [
      meson
      ninja
      pkg-config
    ];
    runtimeDeps = [];
    propagatedDeps = [];

    # Build-system paths must not survive in the library, headers, or
    # pkg-config metadata and accidentally enlarge consumers' closures.
    outputChecks = {
      out = {
        disallowedReferences = [
          meson
          ninja
          pkg-config
        ];
      };
    };

    phases = [
      {
        name = "unpack";
        script = ''
          tar xf $src
          cd fuse-${version}
        '';
      }
      {
        name = "configure";
        script = ''
          meson setup build \
            $mesonFlags \
            --prefix=$out \
            --libdir=lib \
            --includedir=include \
            --buildtype=release \
            -Ddefault_library=shared \
            -Dutils=false \
            -Dexamples=false \
            -Dtests=false \
            -Duseroot=false \
            -Ddisable-mtab=true \
            -Denable-usdt=false \
            -Denable-io-uring=false \
            -Dinitscriptdir= \
            -Dudevrulesdir=
        '';
      }
      {
        name = "build";
        script = ''
          PYTHONPATH=${meson}/lib/python3/site-packages \
            ninja -C build -j$NIX_BUILD_CORES
        '';
      }
      {
        name = "install";
        script = ''
          PYTHONPATH=${meson}/lib/python3/site-packages \
            ninja -C build install

          # Check the install-stage payload before the stdenv adds its target
          # metadata. The final output is checked independently below.
          actualManifest=$(
            find "$out" -type f -printf 'file %P\n'
            find "$out" -type l -printf 'symlink %P -> %l\n'
          )
          actualManifest=$(printf '%s\n' "$actualManifest" | sort)
          expectedManifest='file include/fuse3/cuse_lowlevel.h
          file include/fuse3/fuse.h
          file include/fuse3/fuse_common.h
          file include/fuse3/fuse_log.h
          file include/fuse3/fuse_lowlevel.h
          file include/fuse3/fuse_opt.h
          file include/fuse3/libfuse_config.h
          file lib/libfuse3.so.3.18.2
          file lib/pkgconfig/fuse3.pc
          symlink lib/libfuse3.so -> libfuse3.so.4
          symlink lib/libfuse3.so.4 -> libfuse3.so.3.18.2'

          if [ "$actualManifest" != "$expectedManifest" ]; then
            echo "unexpected fuse3 installation manifest:" >&2
            printf '%s\n' "$actualManifest" >&2
            exit 1
          fi
        '';
      }
    ];

    # Keep package-shape, protocol-parity, and custom-I/O behavior claims in
    # separate gates so a passing metadata probe cannot mask a protocol fault.
    checks = {
      testing,
      self,
      pkgs,
    }: {
      soname = testing.mkSONAMECheck {
        pkg = self;
        libs = ["libfuse3.so"];
      };

      symbols = testing.mkSymbolCheck {
        pkg = self;
        libName = "libfuse3.so";
        symbols = [
          "fuse_passthrough_close"
          "fuse_passthrough_open"
          "fuse_session_custom_io_317"
          "fuse_session_receive_buf"
        ];
      };

      low-level-link = testing.mkLinkCheck {
        pname = "lib-fuse3-low-level";
        library = self;
        includes = ["${self}/include/fuse3"];
        libs = ["-lfuse3"];
        testSource = ''
          #define FUSE_USE_VERSION 317
          #include <fuse_lowlevel.h>

          #pragma GCC diagnostic error "-Wincompatible-pointer-types"

          int main(void) {
            int (*volatile custom_io)(struct fuse_session *,
                                      const struct fuse_custom_io *,
                                      size_t, int) = fuse_session_custom_io_317;
            int (*volatile passthrough_open)(fuse_req_t, int) =
              fuse_passthrough_open;
            int (*volatile passthrough_close)(fuse_req_t, int) =
              fuse_passthrough_close;

            return fuse_version() == 318 && custom_io != 0 &&
              passthrough_open != 0 && passthrough_close != 0 ? 0 : 1;
          }
        '';
      };

      # libfuse carries a private copy of the Linux FUSE protocol header. It
      # is deliberately not installed, so compare that pinned source header
      # with the independently packaged AOS Linux UAPI instead of allowing a
      # consumer to depend on libfuse's private copy.
      uapi-parity = pkgs.mkDerivation {
        pname = "fuse3-linux-uapi-parity-check";
        version = "0";
        src = source;

        buildDeps = [pkgs.linux-headers];

        phases = [
          {
            name = "unpack";
            script = ''
              tar xf $src
              cd fuse-${version}
            '';
          }
          {
            name = "check";
            script = ''
              set -eu

              cat > parity.c <<'EOF'
              #include <stddef.h>
              #include <stdint.h>
              #include <stdio.h>
              #include <sys/ioctl.h>

              #if defined(USE_LINUX_UAPI)
              #include <linux/fuse.h>
              #else
              #include "fuse_kernel.h"
              #endif

              #define FIELD(type, field) \
                printf(#type "." #field "=%zu\n", offsetof(struct type, field))

              int main(void) {
                _Static_assert(FUSE_KERNEL_VERSION == 7,
                               "unexpected FUSE ABI major");
                _Static_assert(FUSE_KERNEL_MINOR_VERSION == 45,
                               "unexpected FUSE ABI minor");
                _Static_assert(
                  __builtin_types_compatible_p(
                    __typeof__(((struct fuse_open_out *)0)->backing_id),
                    int32_t),
                  "fuse_open_out.backing_id must be signed i32");
                _Static_assert(
                  __builtin_types_compatible_p(
                    __typeof__(((struct fuse_in_header *)0)->total_extlen),
                    uint16_t),
                  "fuse_in_header.total_extlen must be u16");
                _Static_assert(
                  __builtin_types_compatible_p(
                    __typeof__(((struct fuse_in_header *)0)->padding),
                    uint16_t),
                  "fuse_in_header.padding must be u16");
                _Static_assert(sizeof(struct fuse_in_header) == 40 &&
                               offsetof(struct fuse_in_header, total_extlen) == 36 &&
                               offsetof(struct fuse_in_header, padding) == 38,
                               "unexpected FUSE input header layout");
                _Static_assert(sizeof(struct fuse_out_header) == 16 &&
                               offsetof(struct fuse_out_header, len) == 0 &&
                               offsetof(struct fuse_out_header, error) == 4 &&
                               offsetof(struct fuse_out_header, unique) == 8,
                               "unexpected FUSE output header layout");

                printf("abi=%u.%u\n", FUSE_KERNEL_VERSION,
                       FUSE_KERNEL_MINOR_VERSION);
                printf("FUSE_PASSTHROUGH=%llu\n",
                       (unsigned long long)FUSE_PASSTHROUGH);
                printf("FOPEN_PASSTHROUGH=%u\n", FOPEN_PASSTHROUGH);
                printf("FUSE_DEV_IOC_BACKING_OPEN=%lu\n",
                       (unsigned long)FUSE_DEV_IOC_BACKING_OPEN);
                printf("FUSE_DEV_IOC_BACKING_CLOSE=%lu\n",
                       (unsigned long)FUSE_DEV_IOC_BACKING_CLOSE);

                printf("fuse_in_header.size=%zu\n",
                       sizeof(struct fuse_in_header));
                FIELD(fuse_in_header, len);
                FIELD(fuse_in_header, opcode);
                FIELD(fuse_in_header, unique);
                FIELD(fuse_in_header, nodeid);
                FIELD(fuse_in_header, uid);
                FIELD(fuse_in_header, gid);
                FIELD(fuse_in_header, pid);
                FIELD(fuse_in_header, total_extlen);
                FIELD(fuse_in_header, padding);

                printf("fuse_out_header.size=%zu\n",
                       sizeof(struct fuse_out_header));
                FIELD(fuse_out_header, len);
                FIELD(fuse_out_header, error);
                FIELD(fuse_out_header, unique);

                printf("fuse_init_in.size=%zu\n", sizeof(struct fuse_init_in));
                FIELD(fuse_init_in, major);
                FIELD(fuse_init_in, minor);
                FIELD(fuse_init_in, max_readahead);
                FIELD(fuse_init_in, flags);
                FIELD(fuse_init_in, flags2);
                FIELD(fuse_init_in, unused);

                printf("fuse_init_out.size=%zu\n", sizeof(struct fuse_init_out));
                FIELD(fuse_init_out, major);
                FIELD(fuse_init_out, minor);
                FIELD(fuse_init_out, max_readahead);
                FIELD(fuse_init_out, flags);
                FIELD(fuse_init_out, max_background);
                FIELD(fuse_init_out, congestion_threshold);
                FIELD(fuse_init_out, max_write);
                FIELD(fuse_init_out, time_gran);
                FIELD(fuse_init_out, max_pages);
                FIELD(fuse_init_out, map_alignment);
                FIELD(fuse_init_out, flags2);
                FIELD(fuse_init_out, max_stack_depth);
                FIELD(fuse_init_out, request_timeout);
                FIELD(fuse_init_out, unused);

                printf("fuse_open_out.size=%zu\n", sizeof(struct fuse_open_out));
                FIELD(fuse_open_out, fh);
                FIELD(fuse_open_out, open_flags);
                FIELD(fuse_open_out, backing_id);
                printf("fuse_open_out.backing_id.signed=%u\n",
                       ((struct fuse_open_out){ .backing_id = -1 }).backing_id < 0);

                printf("fuse_backing_map.size=%zu\n",
                       sizeof(struct fuse_backing_map));
                FIELD(fuse_backing_map, fd);
                FIELD(fuse_backing_map, flags);
                FIELD(fuse_backing_map, padding);
                return 0;
              }
              EOF

              gcc -std=c11 -Wall -Wextra -Werror -Iinclude \
                -o libfuse-uapi parity.c
              gcc -std=c11 -Wall -Wextra -Werror -DUSE_LINUX_UAPI \
                -o linux-uapi parity.c
              ./libfuse-uapi > libfuse-uapi.txt
              ./linux-uapi > linux-uapi.txt

              if ! cmp -s libfuse-uapi.txt linux-uapi.txt; then
                echo "libfuse and AOS Linux FUSE UAPIs differ:" >&2
                diff -u libfuse-uapi.txt linux-uapi.txt >&2 || true
                exit 1
              fi

              mkdir -p "$out"
              cp linux-uapi.txt "$out/result"
            '';
          }
        ];
      };

      custom-fd = testing.mkLinkCheck {
        pname = "lib-fuse3-custom-fd";
        library = self;
        includes = ["${self}/include/fuse3"];
        libs = ["-lfuse3"];
        testSource = ''
          #define FUSE_USE_VERSION 317
          #include <fuse_lowlevel.h>

          #include <errno.h>
          #include <fcntl.h>
          #include <poll.h>
          #include <stdint.h>
          #include <stdio.h>
          #include <string.h>
          #include <sys/socket.h>
          #include <sys/uio.h>
          #include <time.h>
          #include <unistd.h>

          enum {
            WIRE_FUSE_INIT = 26,
            WIRE_FUSE_INIT_EXT = 1U << 30,
            WIRE_FUSE_INIT_RESERVED = 1U << 31,
            WIRE_FUSE_PASSTHROUGH_FLAGS2 = 1U << (37 - 32),
          };

          struct wire_in_header {
            uint32_t len;
            uint32_t opcode;
            uint64_t unique;
            uint64_t nodeid;
            uint32_t uid;
            uint32_t gid;
            uint32_t pid;
            uint16_t total_extlen;
            uint16_t padding;
          };

          struct wire_out_header {
            uint32_t len;
            int32_t error;
            uint64_t unique;
          };

          struct wire_init_in {
            uint32_t major;
            uint32_t minor;
            uint32_t max_readahead;
            uint32_t flags;
            uint32_t flags2;
            uint32_t unused[11];
          };

          struct wire_init_out {
            uint32_t major;
            uint32_t minor;
            uint32_t max_readahead;
            uint32_t flags;
            uint16_t max_background;
            uint16_t congestion_threshold;
            uint32_t max_write;
            uint32_t time_gran;
            uint16_t max_pages;
            uint16_t map_alignment;
            uint32_t flags2;
            uint32_t max_stack_depth;
            uint16_t request_timeout;
            uint16_t unused[11];
          };

          struct init_request {
            struct wire_in_header header;
            struct wire_init_in body;
          };

          struct init_response {
            struct wire_out_header header;
            struct wire_init_out body;
          };

          struct callback_state {
            unsigned int init_calls;
            unsigned int destroy_calls;
            unsigned int read_calls;
            int negotiated_passthrough;
          };

          static ssize_t custom_read(int fd, void *buf, size_t len,
                                     void *userdata) {
            struct callback_state *state = userdata;
            if (state->read_calls++ != 0) {
              errno = ENODEV;
              return -1;
            }
            return read(fd, buf, len);
          }

          static ssize_t custom_writev(int fd, struct iovec *iov, int count,
                                       void *userdata) {
            (void)userdata;
            return writev(fd, iov, count);
          }

          static void initialize(void *userdata, struct fuse_conn_info *conn) {
            struct callback_state *state = userdata;
            state->init_calls++;
            state->negotiated_passthrough =
              conn->proto_major == 7 && conn->proto_minor == 45 &&
              (conn->capable_ext & FUSE_CAP_PASSTHROUGH) != 0 &&
              fuse_set_feature_flag(conn, FUSE_CAP_PASSTHROUGH);
            conn->max_backing_stack_depth = FUSE_BACKING_STACKED_OVER;
          }

          static void destroy(void *userdata) {
            struct callback_state *state = userdata;
            state->destroy_calls++;
          }

          static int fail(const char *message) {
            fprintf(stderr, "%s\n", message);
            return 1;
          }

          static int wait_readable(int fd) {
            struct timespec now;
            if (clock_gettime(CLOCK_MONOTONIC, &now) != 0)
              return -1;
            int64_t deadline = (int64_t)now.tv_sec * 1000 +
              now.tv_nsec / 1000000 + 2000;

            for (;;) {
              if (clock_gettime(CLOCK_MONOTONIC, &now) != 0)
                return -1;
              int64_t remaining = deadline -
                ((int64_t)now.tv_sec * 1000 + now.tv_nsec / 1000000);
              if (remaining <= 0) {
                errno = ETIMEDOUT;
                return -1;
              }

              struct pollfd descriptor = {
                .fd = fd,
                .events = POLLIN | POLLHUP,
              };
              int result = poll(&descriptor, 1, (int)remaining);
              if (result > 0)
                return (descriptor.revents & (POLLIN | POLLHUP)) != 0 ? 0 : -1;
              if (result == 0) {
                errno = ETIMEDOUT;
                return -1;
              }
              if (errno != EINTR)
                return -1;
            }
          }

          int main(void) {
            _Static_assert(sizeof(struct wire_in_header) == 40,
                           "incorrect FUSE request header layout");
            _Static_assert(sizeof(struct wire_init_in) == 64,
                           "incorrect FUSE init request layout");
            _Static_assert(sizeof(struct wire_init_out) == 64,
                           "incorrect FUSE init response layout");
            _Static_assert(sizeof(struct init_request) == 104,
                           "incorrect complete FUSE_INIT request layout");
            _Static_assert(sizeof(struct init_response) == 80,
                           "incorrect complete FUSE_INIT response layout");

            char *argv[] = { (char *)"fuse3-custom-fd", NULL };
            struct fuse_args args = FUSE_ARGS_INIT(1, argv);
            struct callback_state state = {0};
            struct fuse_lowlevel_ops operations = {
              .init = initialize,
              .destroy = destroy,
            };
            struct fuse_custom_io io = {
              .writev = custom_writev,
              .read = custom_read,
            };
            struct fuse_session *session = fuse_session_new(
              &args, &operations, sizeof(operations), &state);
            if (session == NULL)
              return fail("fuse_session_new failed");

            int rejected[2];
            if (socketpair(AF_UNIX, SOCK_SEQPACKET, 0, rejected) != 0)
              return fail("rejected socketpair failed");
            if (fuse_session_custom_io(session, NULL, sizeof(io),
                                       rejected[0]) != -EINVAL)
              return fail("null custom IO was not rejected");
            if (fcntl(rejected[0], F_GETFD) < 0)
              return fail("libfuse consumed an fd after rejecting null IO");

            struct fuse_custom_io incomplete_io = { .writev = custom_writev };
            if (fuse_session_custom_io(session, &incomplete_io,
                                       sizeof(incomplete_io), rejected[0]) != -EINVAL)
              return fail("incomplete custom IO was not rejected");
            if (fcntl(rejected[0], F_GETFD) < 0)
              return fail("libfuse consumed an fd after rejecting custom IO");
            if (fuse_session_custom_io(session, &io, sizeof(io), -1) != -EBADF)
              return fail("negative custom IO fd was not rejected");
            if (fcntl(rejected[0], F_GETFD) < 0)
              return fail("negative fd rejection mutated session ownership");
            close(rejected[0]);
            close(rejected[1]);

            int sockets[2];
            if (socketpair(AF_UNIX, SOCK_SEQPACKET, 0, sockets) != 0)
              return fail("socketpair failed");
            int session_fd = sockets[0];
            int peer_fd = sockets[1];

            if (access("${self}/bin/fusermount3", F_OK) == 0)
              return fail("mount helper unexpectedly exists");
            if (fuse_session_custom_io(session, &io, sizeof(io), session_fd) != 0)
              return fail("fuse_session_custom_io rejected a valid transport");
            if (fcntl(session_fd, F_GETFD) < 0)
              return fail("session fd was not live after ownership transfer");

            const uint64_t unique = UINT64_C(0x517a45);
            struct init_request request = {
              .header = {
                .len = sizeof(request),
                .opcode = WIRE_FUSE_INIT,
                .unique = unique,
              },
              .body = {
                .major = 7,
                .minor = 45,
                .max_readahead = 128 * 1024,
                .flags = WIRE_FUSE_INIT_EXT,
                .flags2 = WIRE_FUSE_PASSTHROUGH_FLAGS2,
              },
            };
            if ((request.body.flags & WIRE_FUSE_INIT_EXT) == 0 ||
                (request.body.flags & WIRE_FUSE_INIT_RESERVED) != 0 ||
                request.header.total_extlen != 0 || request.header.padding != 0)
              return fail("FUSE_INIT request extension fields were invalid");
            if (write(peer_fd, &request, sizeof(request)) != sizeof(request))
              return fail("failed to inject exact FUSE_INIT request");

            /* The public loop owns and releases its receive buffer. The custom
             * reader returns ENODEV after INIT so the loop terminates without
             * relying on libfuse's private allocator/free implementation. */
            if (fuse_session_loop(session) != 0)
              return fail("public session loop failed");
            if (state.read_calls != 2)
              return fail("session loop did not stop after exact FUSE_INIT");

            struct init_response response = {0};
            if (wait_readable(peer_fd) != 0)
              return fail("timed out waiting for FUSE_INIT response");
            ssize_t response_len = read(peer_fd, &response, sizeof(response));
            if (response_len != (ssize_t)sizeof(response) ||
                response.header.len != sizeof(response) ||
                response.header.error != 0 || response.header.unique != unique)
              return fail("FUSE_INIT response was not exactly 80 bytes");
            if (response.body.major != 7 || response.body.minor != 45)
              return fail("libfuse negotiated an unexpected FUSE ABI");
            if ((response.body.flags & WIRE_FUSE_INIT_EXT) == 0 ||
                (response.body.flags & WIRE_FUSE_INIT_RESERVED) != 0 ||
                (response.body.flags2 & WIRE_FUSE_PASSTHROUGH_FLAGS2) == 0 ||
                /* The wire depth includes the FUSE layer itself. */
                response.body.max_stack_depth != FUSE_BACKING_STACKED_OVER + 1 ||
                !state.negotiated_passthrough || state.init_calls != 1)
              return fail("passthrough capability negotiation failed");
            for (size_t index = 0;
                 index < sizeof(response.body.unused) /
                   sizeof(response.body.unused[0]);
                 index++)
              if (response.body.unused[index] != 0)
                return fail("FUSE_INIT response reserved field was nonzero");

            fuse_session_destroy(session);
            errno = 0;
            if (fcntl(session_fd, F_GETFD) != -1 || errno != EBADF)
              return fail("session destroy did not close the supplied fd");
            if (wait_readable(peer_fd) != 0)
              return fail("timed out waiting for peer EOF");
            char byte;
            if (read(peer_fd, &byte, 1) != 0)
              return fail("peer did not observe EOF after session destroy");
            if (state.destroy_calls != 1)
              return fail("filesystem destroy callback count was not one");

            close(peer_fd);
            fuse_opt_free_args(&args);
            return 0;
          }
        '';
      };

      abi-metadata = pkgs.mkDerivation {
        pname = "fuse3-abi-metadata-check";
        version = "0";
        src = null;

        buildDeps = [
          pkgs.elfutils
          pkgs.grep
        ];

        phases = [
          {
            name = "check";
            script = ''
              set -eu

              dynamic=dynamic.txt
              symbols=symbols.txt
              readelf --dynamic --wide ${self}/lib/libfuse3.so > "$dynamic"
              readelf --dyn-syms --wide ${self}/lib/libfuse3.so > "$symbols"

              sonameCount=$(grep -c '(SONAME)' "$dynamic")
              test "$sonameCount" -eq 1
              grep -F -q 'Library soname: [libfuse3.so.4]' "$dynamic"

              grep -F -q 'fuse_passthrough_open@@FUSE_3.17' "$symbols"
              grep -F -q 'fuse_passthrough_close@@FUSE_3.17' "$symbols"
              grep -F -q 'fuse_session_custom_io_317@@FUSE_3.17' "$symbols"

              mkdir -p "$out"
              printf '%s\n' 'soname=libfuse3.so.4' > "$out/result"
              printf '%s\n' 'custom-fd-symbol-version=FUSE_3.17' >> "$out/result"
            '';
          }
        ];
      };

      closure = pkgs.mkDerivation {
        pname = "fuse3-runtime-closure-check";
        version = "0";
        src = null;

        outputChecks = {};
        exportReferencesGraph.runtime = [self];
        buildDeps = [pkgs.jq];
        dontStrip = true;
        dontNukeRefs = true;

        phases = [
          {
            name = "check";
            script = ''
              set -eu

              size=$(jq '[.runtime[].narSize] | add // 0' "$NIX_ATTRS_JSON_FILE")
              maxBytes=$((32 * 1024 * 1024))
              if [ "$size" -gt "$maxBytes" ]; then
                echo "fuse3 runtime closure is $size bytes (max: $maxBytes)" >&2
                exit 1
              fi

              for buildTool in ${meson} ${ninja} ${pkg-config}; do
                if jq -e --arg path "$buildTool" '.runtime | any(.path == $path)' \
                  "$NIX_ATTRS_JSON_FILE" >/dev/null; then
                  echo "fuse3 runtime closure retains build tool: $buildTool" >&2
                  exit 1
                fi
              done

              if ! jq -e \
                --arg self ${self} \
                --arg glibc ${pkgs.glibc} \
                '([.runtime[].path] | sort) == ([$self, $glibc] | sort)' \
                "$NIX_ATTRS_JSON_FILE" >/dev/null; then
                echo "fuse3 runtime closure differs from the self+glibc allowlist:" >&2
                jq -r '.runtime[].path' "$NIX_ATTRS_JSON_FILE" >&2
                exit 1
              fi

              if ! find ${self} -mindepth 1 \
                ! -type d ! -type f ! -type l -print0 -quit \
                > special-files; then
                echo "failed to scan fuse3 final output for special files" >&2
                exit 1
              fi
              if [ -s special-files ]; then
                echo "fuse3 final output contains a special file" >&2
                exit 1
              fi

              if ! find ${self} -mindepth 1 -type d \
                -printf 'directory %P\0' > manifest-directories; then
                echo "failed to scan fuse3 final-output directories" >&2
                exit 1
              fi
              if ! find ${self} -type f \
                -printf 'file %P\0' > manifest-files; then
                echo "failed to scan fuse3 final-output files" >&2
                exit 1
              fi
              if ! find ${self} -type l \
                -printf 'symlink %P -> %l\0' > manifest-symlinks; then
                echo "failed to scan fuse3 final-output symlinks" >&2
                exit 1
              fi
              sort -z manifest-directories manifest-files manifest-symlinks \
                > manifest-actual

              printf '%s\0' \
                'directory include' \
                'directory include/fuse3' \
                'directory lib' \
                'directory lib/pkgconfig' \
                'directory nix-support' \
                'file include/fuse3/cuse_lowlevel.h' \
                'file include/fuse3/fuse.h' \
                'file include/fuse3/fuse_common.h' \
                'file include/fuse3/fuse_log.h' \
                'file include/fuse3/fuse_lowlevel.h' \
                'file include/fuse3/fuse_opt.h' \
                'file include/fuse3/libfuse_config.h' \
                'file lib/libfuse3.so.3.18.2' \
                'file lib/pkgconfig/fuse3.pc' \
                'file nix-support/aos-target-platform' \
                'symlink lib/libfuse3.so -> libfuse3.so.4' \
                'symlink lib/libfuse3.so.4 -> libfuse3.so.3.18.2' \
                > manifest-expected-unsorted
              sort -z manifest-expected-unsorted > manifest-expected

              if ! cmp -s manifest-actual manifest-expected; then
                echo "unexpected fuse3 final-output manifest" >&2
                exit 1
              fi

              mkdir -p "$out"
              printf 'closure-bytes=%s\n' "$size" > "$out/result"
            '';
          }
        ];
      };
    };

    meta = {
      description = "Low-level Filesystem in Userspace library";
      homepage = "https://github.com/libfuse/libfuse";
      # The release LICENSE assigns include/, lib/, and meson.build to
      # version 2.1 of the LGPL. No GPL-only utility sources are installed.
      license = "LGPL-2.1-only";
    };
  }
