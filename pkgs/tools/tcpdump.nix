##! tcpdump — Network packet analyzer
{
  lib,
  mkDerivation,
  fetchurl,
  gnumake,
  libpcap,
}: let
  version = "4.99.6";
in
  mkDerivation {
    platformSupport = {
      build = [{abi = ["gnu"]; os = ["linux"];}];
      host = [{abi = ["gnu"]; cpu = ["x86_64" "aarch64"]; os = ["linux"];} {abi = ["darwin"]; cpu = ["x86_64" "aarch64"]; os = ["darwin"];}];
      target = [];
      role = "public-package";
    };
    pname = "tcpdump";
    qualification.packageProbe = lib.qualification.commandProbe {
      "primary" = {
        "artifacts" = [];
        "expected" = "Tcpdump selects the packet and preserves its captured bytes.";
        "files" = {
          "create.py" = "import socket\nimport struct\n\nethernet = bytes.fromhex(\"00112233445566778899aabb0800\")\nipv4 = struct.pack(\n    \"!BBHHHBBH4s4s\",\n    0x45, 0, 28, 0, 0, 64, 17, 0,\n    socket.inet_aton(\"192.0.2.1\"),\n    socket.inet_aton(\"198.51.100.2\"),\n)\nudp = struct.pack(\"!HHHH\", 1234, 4321, 8, 0)\npacket = ethernet + ipv4 + udp\nheader = struct.pack(\"<IHHIIII\", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)\nrecord = struct.pack(\"<IIII\", 0, 0, len(packet), len(packet))\nopen(\"packet.pcap\", \"wb\").write(header + record + packet)\nopen(\"packet.bin\", \"wb\").write(packet)\n";
          "verify.py" = "capture = open(\"selected.pcap\", \"rb\").read()\npacket = open(\"packet.bin\", \"rb\").read()\nassert len(capture) == 24 + 16 + len(packet)\nassert capture.endswith(packet)\nprint(\"tcpdump filter passed\")\n";
        };
        "input" = "A classic PCAP containing one Ethernet, IPv4, and UDP packet.";
        "operation" = "Filter the capture for its UDP destination port and write a second capture.";
        "steps" = [
          {
            "argv" = [
              "@python@"
              "create.py"
            ];
            "exit_code" = 0;
            "stderr" = {
              "exact" = "";
            };
            "stdout" = {
              "exact" = "";
            };
          }
          {
            "argv" = [
              "@out@/bin/tcpdump"
              "-n"
              "-r"
              "packet.pcap"
              "-w"
              "selected.pcap"
              "udp"
              "port"
              "4321"
            ];
            "exit_code" = 0;
          }
          {
            "argv" = [
              "@python@"
              "verify.py"
            ];
            "exit_code" = 0;
            "stderr" = {
              "exact" = "";
            };
            "stdout" = {
              "exact" = "tcpdump filter passed\n";
            };
          }
        ];
      };
      "badInput" = {
        "artifacts" = [];
        "expected" = "Tcpdump rejects the filter expression before processing packets.";
        "files" = {
          "create.py" = "import struct\n\nheader = struct.pack(\"<IHHIIII\", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)\nopen(\"empty.pcap\", \"wb\").write(header)\n";
        };
        "input" = "A valid empty PCAP and a filter expression ending in an operator.";
        "operation" = "Compile the malformed packet filter.";
        "steps" = [
          {
            "argv" = [
              "@python@"
              "create.py"
            ];
            "exit_code" = 0;
            "stderr" = {
              "exact" = "";
            };
            "stdout" = {
              "exact" = "";
            };
          }
          {
            "argv" = [
              "@out@/bin/tcpdump"
              "-n"
              "-r"
              "empty.pcap"
              "udp"
              "and"
            ];
            "exit_code" = 1;
            "observes_rejection" = true;
            "stdout" = {
              "exact" = "";
            };
          }
        ];
      };
    };

    inherit version;

    src = fetchurl {
      urls = [
        "https://www.tcpdump.org/release/tcpdump-${version}.tar.gz"
      ];
      hash = "sha256-WDmSGg9n19j6PazZzUHkTInMuGfoptshbWJijH/RSwk=";
    };

    buildDeps = [
      gnumake
    ];
    runtimeDeps = [libpcap];

    phases = [
      {
        name = "unpack";
        script = ''
          tar xf $src
          cd tcpdump-${version}
        '';
      }
      {
        name = "configure";
        script = ''
          ./configure \
            $configureFlags \
            --prefix=$out
        '';
      }
      {
        name = "build";
        script = ''
          make -j$NIX_BUILD_CORES
        '';
      }
      {
        name = "install";
        script = ''
          make install
        '';
      }
    ];

    meta = {
      description = "tcpdump — network packet analyzer";
      homepage = "https://www.tcpdump.org";
      license = "BSD-3-Clause";
    };
  }
