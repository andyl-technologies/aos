##! Exercises a fifth H-through-P library slice through deterministic public APIs.
{testing}: let
  mkLibraryProbe = {
    package,
    primaryInput,
    primaryOperation,
    primaryExpected,
    primarySource,
    primaryFiles ? {},
    badInput,
    badOperation,
    badExpected,
    badSource,
    badFiles ? {},
    libraries,
  }:
    testing.mkQualificationPackageProbe {
      name = package;
      spec = {
        schema_version = "aos.release.package-probe/v1";
        inherit package;
        primary = {
          input = primaryInput;
          operation = primaryOperation;
          expected = primaryExpected;
          files = primaryFiles // {"primary.c" = primarySource;};
          steps = [
            {
              argv = ["@cc@" "primary.c" "-I@out@/include" "-L@out@/lib" "-Wl,-rpath,@out@/lib"] ++ libraries ++ ["-o" "primary-check"];
              exit_code = 0;
              stdout.exact = "";
            }
            {
              argv = ["@work@/primary/primary-check"];
              exit_code = 0;
              stdout.exact = "${package} primary passed\n";
              stderr.exact = "";
            }
          ];
          artifacts = [];
        };
        bad_input = {
          input = badInput;
          operation = badOperation;
          expected = badExpected;
          files = badFiles // {"bad-input.c" = badSource;};
          steps = [
            {
              argv = ["@cc@" "bad-input.c" "-I@out@/include" "-L@out@/lib" "-Wl,-rpath,@out@/lib"] ++ libraries ++ ["-o" "bad-input-check"];
              exit_code = 0;
              stdout.exact = "";
            }
            {
              argv = ["@work@/bad-input/bad-input-check"];
              exit_code = 7;
              stdout.exact = "";
              stderr.exact = "${package} rejected invalid input\n";
              observes_rejection = true;
            }
          ];
          artifacts = [];
        };
      };
    };

  program = package: body: ''
    #include <stdio.h>
    static int pass(void) { return puts("${package} primary passed") == EOF; }
    static int reject(void) {
        fputs("${package} rejected invalid input\n", stderr);
        return 7;
    }
    ${body}
  '';
in {
  kmod = mkLibraryProbe {
    package = "kmod";
    primaryInput = "The syntactically valid kernel module name loop.";
    primaryOperation = "Construct and inspect a module object through libkmod.";
    primaryExpected = "Libkmod returns an object retaining the exact module name.";
    primarySource = program "kmod" ''
      #include <string.h>
      #include <libkmod.h>
      int main(void) {
          struct kmod_ctx *context = kmod_new(NULL, NULL);
          struct kmod_module *module = NULL;
          if (context == NULL) return 2;
          int status = kmod_module_new_from_name(context, "loop", &module);
          int valid = status == 0 && module != NULL
              && strcmp(kmod_module_get_name(module), "loop") == 0;
          if (module != NULL) kmod_module_unref(module);
          kmod_unref(context);
          return valid ? pass() : 3;
      }
    '';
    badInput = "A kernel module path that does not exist.";
    badOperation = "Construct a module from the missing path through libkmod.";
    badExpected = "Libkmod returns ENOENT and no module object.";
    badSource = program "kmod" ''
      #include <errno.h>
      #include <libkmod.h>
      int main(void) {
          struct kmod_ctx *context = kmod_new(NULL, NULL);
          struct kmod_module *module = NULL;
          if (context == NULL) return 2;
          int status = kmod_module_new_from_path(context, "missing-qualification.ko", &module);
          if (module != NULL) kmod_module_unref(module);
          kmod_unref(context);
          return status == -ENOENT && module == NULL ? reject() : 3;
      }
    '';
    libraries = ["-lkmod"];
  };

  libisofs = mkLibraryProbe {
    package = "libisofs";
    primaryInput = "An in-memory ISO image named qualification.";
    primaryOperation = "Initialize libisofs and create the image through iso_image_new.";
    primaryExpected = "Libisofs returns an image with the requested volume identifier.";
    primarySource = program "libisofs" ''
      #include <sys/types.h>
      #include <stdint.h>
      #include <string.h>
      #include <libisofs/libisofs.h>
      int main(void) {
          IsoImage *image = NULL;
          if (iso_init() <= 0) return 2;
          int status = iso_image_new("qualification", &image);
          int valid = status > 0 && image != NULL
              && strcmp(iso_image_get_volume_id(image), "qualification") == 0;
          if (image != NULL) iso_image_unref(image);
          iso_finish();
          return valid ? pass() : 3;
      }
    '';
    badInput = "A directory node name containing a slash.";
    badOperation = "Add the invalid child name through iso_tree_add_new_dir.";
    badExpected = "Libisofs returns a negative name-validation error and no node.";
    badSource = program "libisofs" ''
      #include <sys/types.h>
      #include <stdint.h>
      #include <libisofs/libisofs.h>
      int main(void) {
          IsoImage *image = NULL;
          IsoDir *directory = NULL;
          if (iso_init() <= 0 || iso_image_new("qualification", &image) <= 0) return 2;
          int status = iso_tree_add_new_dir(iso_image_get_root(image), "bad/name", &directory);
          iso_image_unref(image);
          iso_finish();
          return status < 0 && directory == NULL ? reject() : 3;
      }
    '';
    libraries = ["-lisofs"];
  };

  libmaxminddb = mkLibraryProbe {
    package = "libmaxminddb";
    primaryInput = "The library's compiled version and invalid-metadata status.";
    primaryOperation = "Query the version and translate the status through libmaxminddb.";
    primaryExpected = "The public API returns version 1.13.3 and the documented diagnostic.";
    primarySource = program "libmaxminddb" ''
      #include <string.h>
      #include <maxminddb.h>
      int main(void) {
          int valid = strcmp(MMDB_lib_version(), "1.13.3") == 0
              && strcmp(MMDB_strerror(MMDB_INVALID_METADATA_ERROR),
                        "The MaxMind DB file contains invalid metadata") == 0;
          return valid ? pass() : 2;
      }
    '';
    badInput = "A short text file that is not a MaxMind database.";
    badOperation = "Open the malformed database through MMDB_open.";
    badExpected = "Libmaxminddb returns MMDB_INVALID_METADATA_ERROR.";
    badFiles."invalid.mmdb" = "not a MaxMind database\n";
    badSource = program "libmaxminddb" ''
      #include <maxminddb.h>
      int main(void) {
          MMDB_s database = {0};
          int status = MMDB_open("invalid.mmdb", MMDB_MODE_MMAP, &database);
          if (status == MMDB_SUCCESS) {
              MMDB_close(&database);
              return 2;
          }
          return status == MMDB_INVALID_METADATA_ERROR ? reject() : 3;
      }
    '';
    libraries = ["-lmaxminddb"];
  };

  libnetfilter_cthelper = mkLibraryProbe {
    package = "libnetfilter_cthelper";
    primaryInput = "A connection-tracking helper named qualification on queue 42.";
    primaryOperation = "Set and retrieve the helper attributes through the object API.";
    primaryExpected = "The helper preserves the exact name and queue number.";
    primarySource = program "libnetfilter_cthelper" ''
      #include <stdint.h>
      #include <string.h>
      #include <libnetfilter_cthelper/libnetfilter_cthelper.h>
      int main(void) {
          struct nfct_helper *helper = nfct_helper_alloc();
          if (helper == NULL) return 2;
          nfct_helper_attr_set_str(helper, NFCTH_ATTR_NAME, "qualification");
          nfct_helper_attr_set_u16(helper, NFCTH_ATTR_QUEUE_NUM, 42);
          int valid = strcmp(nfct_helper_attr_get_str(helper, NFCTH_ATTR_NAME), "qualification") == 0
              && nfct_helper_attr_get_u16(helper, NFCTH_ATTR_QUEUE_NUM) == 42;
          nfct_helper_free(helper);
          return valid ? pass() : 3;
      }
    '';
    badInput = "A netlink header with no connection-tracking helper payload.";
    badOperation = "Parse the empty payload through nfct_helper_nlmsg_parse_payload.";
    badExpected = "The helper parser returns a negative malformed-message status.";
    badSource = program "libnetfilter_cthelper" ''
      #include <stdint.h>
      #include <linux/netlink.h>
      #include <libnetfilter_cthelper/libnetfilter_cthelper.h>
      int main(void) {
          struct nfct_helper *helper = nfct_helper_alloc();
          struct nlmsghdr header = {.nlmsg_len = sizeof(header)};
          if (helper == NULL) return 2;
          int status = nfct_helper_nlmsg_parse_payload(&header, helper);
          nfct_helper_free(helper);
          return status < 0 ? reject() : 3;
      }
    '';
    libraries = ["-lnetfilter_cthelper"];
  };

  libnetfilter_queue = mkLibraryProbe {
    package = "libnetfilter_queue";
    primaryInput = "A minimal IPv4 packet buffer whose second byte is replaced with Z.";
    primaryOperation = "Allocate and modify the packet through pktb_mangle.";
    primaryExpected = "The packet buffer records the replacement and its mangled state.";
    primarySource = program "libnetfilter_queue" ''
      #include <stdbool.h>
      #include <stdint.h>
      #include <sys/socket.h>
      #include <libnetfilter_queue/pktbuff.h>
      int main(void) {
          unsigned char packet[20] = {0x45};
          struct pkt_buff *buffer = pktb_alloc(AF_INET, packet, sizeof(packet), 8);
          if (buffer == NULL) return 2;
          int status = pktb_mangle(buffer, 0, 1, 1, "Z", 1);
          int valid = status == 1 && pktb_data(buffer)[1] == 'Z' && pktb_mangled(buffer);
          pktb_free(buffer);
          return valid ? pass() : 3;
      }
    '';
    badInput = "A packet replacement larger than the buffer's available tail room.";
    badOperation = "Apply the oversized replacement through pktb_mangle.";
    badExpected = "The packet buffer rejects the replacement with status 0.";
    badSource = program "libnetfilter_queue" ''
      #include <stdbool.h>
      #include <stdint.h>
      #include <sys/socket.h>
      #include <libnetfilter_queue/pktbuff.h>
      int main(void) {
          unsigned char packet[20] = {0x45};
          char replacement[100] = {0};
          struct pkt_buff *buffer = pktb_alloc(AF_INET, packet, sizeof(packet), 8);
          if (buffer == NULL) return 2;
          int status = pktb_mangle(buffer, 0, 1, 1, replacement, sizeof(replacement));
          pktb_free(buffer);
          return status == 0 ? reject() : 3;
      }
    '';
    libraries = ["-lnetfilter_queue"];
  };

  libnfnetlink = mkLibraryProbe {
    package = "libnfnetlink";
    primaryInput = "A netlink message buffer with room for one 32-bit attribute.";
    primaryOperation = "Append attribute type 1 with value 42 through nfnl_addattr32.";
    primaryExpected = "Libnfnetlink appends the aligned attribute and increases the message length.";
    primarySource = program "libnfnetlink" ''
      #include <string.h>
      #include <linux/netlink.h>
      #include <libnfnetlink/libnfnetlink.h>
      int main(void) {
          char storage[64] = {0};
          struct nlmsghdr *header = (struct nlmsghdr *)storage;
          header->nlmsg_len = NLMSG_LENGTH(0);
          int status = nfnl_addattr32(header, sizeof(storage), 1, 42);
          return status == 0 && header->nlmsg_len == 24 ? pass() : 2;
      }
    '';
    badInput = "A netlink buffer with no room beyond its initial header.";
    badOperation = "Append a 32-bit attribute through nfnl_addattr32.";
    badExpected = "Libnfnetlink rejects the attribute with status -1 and preserves the header length.";
    badSource = program "libnfnetlink" ''
      #include <string.h>
      #include <linux/netlink.h>
      #include <libnfnetlink/libnfnetlink.h>
      int main(void) {
          char storage[16] = {0};
          struct nlmsghdr *header = (struct nlmsghdr *)storage;
          header->nlmsg_len = NLMSG_LENGTH(0);
          int status = nfnl_addattr32(header, sizeof(storage), 1, 42);
          return status == -1 && header->nlmsg_len == 16 ? reject() : 2;
      }
    '';
    libraries = ["-lnfnetlink"];
  };

  libnftnl = mkLibraryProbe {
    package = "libnftnl";
    primaryInput = "An nftables table named qualification in the IPv4 family.";
    primaryOperation = "Set and retrieve table attributes through libnftnl.";
    primaryExpected = "The table object preserves its family and name attributes.";
    primarySource = program "libnftnl" ''
      #include <string.h>
      #include <libnftnl/table.h>
      int main(void) {
          struct nftnl_table *table = nftnl_table_alloc();
          if (table == NULL) return 2;
          nftnl_table_set_u32(table, NFTNL_TABLE_FAMILY, 2);
          int status = nftnl_table_set_str(table, NFTNL_TABLE_NAME, "qualification");
          int valid = status == 0 && nftnl_table_get_u32(table, NFTNL_TABLE_FAMILY) == 2
              && strcmp(nftnl_table_get_str(table, NFTNL_TABLE_NAME), "qualification") == 0;
          nftnl_table_free(table);
          return valid ? pass() : 3;
      }
    '';
    badInput = "Text that is not an nftables JSON document.";
    badOperation = "Parse the malformed text through nftnl_table_parse.";
    badExpected = "Libnftnl returns a negative parse status.";
    badSource = program "libnftnl" ''
      #include <libnftnl/table.h>
      int main(void) {
          struct nftnl_table *table = nftnl_table_alloc();
          struct nftnl_parse_err *error = nftnl_parse_err_alloc();
          if (table == NULL || error == NULL) return 2;
          int status = nftnl_table_parse(table, NFTNL_PARSE_JSON, "not JSON", error);
          nftnl_parse_err_free(error);
          nftnl_table_free(table);
          return status < 0 ? reject() : 3;
      }
    '';
    libraries = ["-lnftnl"];
  };

  libpciaccess = mkLibraryProbe {
    package = "libpciaccess";
    primaryInput = "The PCI devices exposed by the qualification kernel through sysfs.";
    primaryOperation = "Initialize and clean up libpciaccess's system backend.";
    primaryExpected = "Libpciaccess discovers the platform without an initialization error.";
    primarySource = program "libpciaccess" ''
      #include <pciaccess.h>
      int main(void) {
          int status = pci_system_init();
          if (status != 0) return 2;
          pci_system_cleanup();
          return pass();
      }
    '';
    badInput = "The impossible PCI address ffff:ff:1f.7.";
    badOperation = "Look up the absent slot through pci_device_find_by_slot.";
    badExpected = "Libpciaccess reports that no device occupies the address by returning null.";
    badSource = program "libpciaccess" ''
      #include <pciaccess.h>
      int main(void) {
          if (pci_system_init() != 0) return 2;
          struct pci_device *device = pci_device_find_by_slot(0xffff, 0xff, 0x1f, 7);
          pci_system_cleanup();
          return device == NULL ? reject() : 3;
      }
    '';
    libraries = ["-lpciaccess"];
  };

  libqcow = mkLibraryProbe {
    package = "libqcow";
    primaryInput = "A request for a new libqcow file handle.";
    primaryOperation = "Initialize and free the handle through the public API.";
    primaryExpected = "Libqcow reports its package version and returns a usable handle.";
    primarySource = program "libqcow" ''
      #include <string.h>
      #include <libqcow.h>
      int main(void) {
          libqcow_file_t *file = NULL;
          libqcow_error_t *error = NULL;
          int status = libqcow_file_initialize(&file, &error);
          int valid = status == 1 && file != NULL && error == NULL
              && strcmp(libqcow_get_version(), "20240308") == 0;
          libqcow_file_free(&file, NULL);
          libqcow_error_free(&error);
          return valid ? pass() : 2;
      }
    '';
    badInput = "Codepage number 999, which libqcow does not support.";
    badOperation = "Set the invalid codepage through libqcow_set_codepage.";
    badExpected = "Libqcow returns -1 and supplies a structured error.";
    badSource = program "libqcow" ''
      #include <libqcow.h>
      int main(void) {
          libqcow_error_t *error = NULL;
          int status = libqcow_set_codepage(999, &error);
          int rejected = status == -1 && error != NULL;
          libqcow_error_free(&error);
          return rejected ? reject() : 2;
      }
    '';
    libraries = ["-lqcow"];
  };

  libslirp = mkLibraryProbe {
    package = "libslirp";
    primaryInput = "The linked libslirp implementation version.";
    primaryOperation = "Query its version string and state format version.";
    primaryExpected = "The runtime version matches the public header and exposes a positive state version.";
    primarySource = program "libslirp" ''
      #include <string.h>
      #include <slirp/libslirp.h>
      int main(void) {
          int valid = strcmp(slirp_version_string(), SLIRP_VERSION_STRING) == 0
              && slirp_state_version() > 0;
          return valid ? pass() : 2;
      }
    '';
    badInput = "A Slirp configuration version above the supported maximum.";
    badOperation = "Construct a Slirp instance through slirp_new while suppressing its expected assertion log.";
    badExpected = "Libslirp rejects the configuration by returning null.";
    badSource = program "libslirp" ''
      #include <fcntl.h>
      #include <unistd.h>
      #include <slirp/libslirp.h>
      int main(void) {
          int saved_stderr = dup(STDERR_FILENO);
          int null_output = open("/dev/null", O_WRONLY);
          if (saved_stderr < 0 || null_output < 0) return 2;
          if (dup2(null_output, STDERR_FILENO) < 0) return 3;
          SlirpConfig config = {.version = SLIRP_CONFIG_VERSION_MAX + 1};
          SlirpCb callbacks = {0};
          Slirp *slirp = slirp_new(&config, &callbacks, NULL);
          fflush(stderr);
          if (dup2(saved_stderr, STDERR_FILENO) < 0) return 4;
          close(null_output);
          close(saved_stderr);
          if (slirp != NULL) {
              slirp_cleanup(slirp);
              return 5;
          }
          return reject();
      }
    '';
    libraries = ["-lslirp"];
  };

  libtpms = mkLibraryProbe {
    package = "libtpms";
    primaryInput = "A request to select the TPM 2 implementation.";
    primaryOperation = "Query libtpms's version and select TPM 2 through TPMLIB_ChooseTPMVersion.";
    primaryExpected = "Libtpms exposes a nonzero version and accepts TPM 2.";
    primarySource = program "libtpms" ''
      #include <libtpms/tpm_library.h>
      int main(void) {
          return TPMLIB_GetVersion() > 0
              && TPMLIB_ChooseTPMVersion(TPMLIB_TPM_VERSION_2) == 0 ? pass() : 2;
      }
    '';
    badInput = "A TPM implementation selector outside the public enum.";
    badOperation = "Select the invalid implementation through TPMLIB_ChooseTPMVersion.";
    badExpected = "Libtpms returns a nonzero parameter error.";
    badSource = program "libtpms" ''
      #include <libtpms/tpm_library.h>
      int main(void) {
          TPM_RESULT status = TPMLIB_ChooseTPMVersion((TPMLIB_TPMVersion)99);
          return status != 0 ? reject() : 2;
      }
    '';
    libraries = ["-ltpms"];
  };

  nghttp3 = mkLibraryProbe {
    package = "nghttp3";
    primaryInput = "A runtime version query with no minimum version.";
    primaryOperation = "Query nghttp3_version and compare it with the public header constants.";
    primaryExpected = "The linked library reports the compiled nghttp3 version.";
    primarySource = program "nghttp3" ''
      #include <string.h>
      #include <nghttp3/nghttp3.h>
      int main(void) {
          const nghttp3_info *info = nghttp3_version(0);
          int valid = info != NULL && info->version_num == NGHTTP3_VERSION_NUM
              && strcmp(info->version_str, NGHTTP3_VERSION) == 0;
          return valid ? pass() : 2;
      }
    '';
    badInput = "A minimum nghttp3 version greater than any 24-bit release.";
    badOperation = "Query nghttp3_version with the unsupported minimum.";
    badExpected = "Nghttp3 rejects the requirement by returning null.";
    badSource = program "nghttp3" ''
      #include <nghttp3/nghttp3.h>
      int main(void) {
          return nghttp3_version(0xffffff) == NULL ? reject() : 2;
      }
    '';
    libraries = ["-lnghttp3"];
  };

  ngtcp2 = mkLibraryProbe {
    package = "ngtcp2";
    primaryInput = "A runtime version query with no minimum version.";
    primaryOperation = "Query ngtcp2_version and compare it with the public header constants.";
    primaryExpected = "The linked library reports the compiled ngtcp2 version.";
    primarySource = program "ngtcp2" ''
      #include <string.h>
      #include <ngtcp2/ngtcp2.h>
      int main(void) {
          const ngtcp2_info *info = ngtcp2_version(0);
          int valid = info != NULL && info->version_num == NGTCP2_VERSION_NUM
              && strcmp(info->version_str, NGTCP2_VERSION) == 0;
          return valid ? pass() : 2;
      }
    '';
    badInput = "A minimum ngtcp2 version greater than any 24-bit release.";
    badOperation = "Query ngtcp2_version with the unsupported minimum.";
    badExpected = "Ngtcp2 rejects the requirement by returning null.";
    badSource = program "ngtcp2" ''
      #include <ngtcp2/ngtcp2.h>
      int main(void) {
          return ngtcp2_version(0xffffff) == NULL ? reject() : 2;
      }
    '';
    libraries = ["-lngtcp2"];
  };
}
