##! Exercises additional Q-through-Z packet and filesystem formats offline.
{testing}: {
  tcpdump = testing.mkQualificationPackageProbe {
    name = "tcpdump";
    spec = {
      schema_version = "aos.release.package-probe/v1";
      package = "tcpdump";
      primary = {
        input = "A classic PCAP containing one Ethernet, IPv4, and UDP packet.";
        operation = "Filter the capture for its UDP destination port and write a second capture.";
        expected = "Tcpdump selects the packet and preserves its captured bytes.";
        files = {
          "create.py" = ''
            import socket
            import struct

            ethernet = bytes.fromhex("00112233445566778899aabb0800")
            ipv4 = struct.pack(
                "!BBHHHBBH4s4s",
                0x45, 0, 28, 0, 0, 64, 17, 0,
                socket.inet_aton("192.0.2.1"),
                socket.inet_aton("198.51.100.2"),
            )
            udp = struct.pack("!HHHH", 1234, 4321, 8, 0)
            packet = ethernet + ipv4 + udp
            header = struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
            record = struct.pack("<IIII", 0, 0, len(packet), len(packet))
            open("packet.pcap", "wb").write(header + record + packet)
            open("packet.bin", "wb").write(packet)
          '';
          "verify.py" = ''
            capture = open("selected.pcap", "rb").read()
            packet = open("packet.bin", "rb").read()
            assert len(capture) == 24 + 16 + len(packet)
            assert capture.endswith(packet)
            print("tcpdump filter passed")
          '';
        };
        steps = [
          {
            argv = ["@python@" "create.py"];
            exit_code = 0;
            stdout.exact = "";
            stderr.exact = "";
          }
          {
            argv = ["@out@/bin/tcpdump" "-n" "-r" "packet.pcap" "-w" "selected.pcap" "udp" "port" "4321"];
            exit_code = 0;
          }
          {
            argv = ["@python@" "verify.py"];
            exit_code = 0;
            stdout.exact = "tcpdump filter passed\n";
            stderr.exact = "";
          }
        ];
        artifacts = [];
      };
      bad_input = {
        input = "A valid empty PCAP and a filter expression ending in an operator.";
        operation = "Compile the malformed packet filter.";
        expected = "Tcpdump rejects the filter expression before processing packets.";
        files = {
          "create.py" = ''
            import struct

            header = struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
            open("empty.pcap", "wb").write(header)
          '';
        };
        steps = [
          {
            argv = ["@python@" "create.py"];
            exit_code = 0;
            stdout.exact = "";
            stderr.exact = "";
          }
          {
            argv = ["@out@/bin/tcpdump" "-n" "-r" "empty.pcap" "udp" "and"];
            exit_code = 1;
            stdout.exact = "";
            observes_rejection = true;
          }
        ];
        artifacts = [];
      };
    };
  };

  xfsprogs = testing.mkQualificationPackageProbe {
    name = "xfsprogs";
    spec = {
      schema_version = "aos.release.package-probe/v1";
      package = "xfsprogs";
      primary = {
        input = "A sparse 320 MiB regular file.";
        operation = "Create an XFS filesystem in the file and read its superblock magic through xfs_db.";
        expected = "Mkfs creates the image and xfs_db reports the canonical XFS magic value.";
        files."create.py" = ''
          with open("image.xfs", "wb") as image:
              image.truncate(320 * 1024 * 1024)
        '';
        steps = [
          {
            argv = ["@python@" "create.py"];
            exit_code = 0;
            stdout.exact = "";
            stderr.exact = "";
          }
          {
            argv = ["@out@/sbin/mkfs.xfs" "-f" "-q" "image.xfs"];
            exit_code = 0;
            stdout.exact = "";
            stderr.exact = "";
          }
          {
            argv = ["@out@/sbin/xfs_db" "-r" "-c" "sb 0" "-c" "p magicnum" "image.xfs"];
            exit_code = 0;
            stdout.exact = "magicnum = 0x58465342\n";
            stderr.exact = "";
          }
        ];
        artifacts = [];
      };
      bad_input = {
        input = "A sparse one-MiB file below XFS's minimum filesystem size.";
        operation = "Attempt to create an XFS filesystem in the undersized image.";
        expected = "Mkfs rejects the image size with a failure status.";
        files."create.py" = ''
          with open("tiny.xfs", "wb") as image:
              image.truncate(1024 * 1024)
        '';
        steps = [
          {
            argv = ["@python@" "create.py"];
            exit_code = 0;
            stdout.exact = "";
            stderr.exact = "";
          }
          {
            argv = ["@out@/sbin/mkfs.xfs" "-f" "-q" "tiny.xfs"];
            exit_code = 1;
            stdout.exact = "";
            observes_rejection = true;
          }
        ];
        artifacts = [];
      };
    };
  };
}
