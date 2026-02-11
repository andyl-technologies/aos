;;; ANDYL OS -- Networking Packages
;;; Copyright (C) 2024 ANDYL OS Contributors
;;;
;;; This module defines the core networking packages for ANDYL OS:
;;;
;;;   andyl-iproute2    -- Network configuration utilities (ip, ss, tc, bridge)
;;;   andyl-iptables    -- Legacy firewall rules management
;;;   andyl-nftables    -- Modern firewall framework (nft)
;;;   andyl-libnftnl    -- Netfilter netlink library (nftables dependency)
;;;   andyl-libmnl      -- Minimalistic netlink library (nftables dependency)
;;;   andyl-curl            -- HTTP/HTTPS client and library
;;;   andyl-openssh         -- Secure shell client and server
;;;   andyl-chrony          -- NTP time synchronization
;;;   andyl-ca-certificates -- Mozilla CA certificate bundle
;;;
;;; ANDYL OS uses systemd-networkd for primary network management
;;; (see RFC-0001 section 6).  The packages in this module provide
;;; supplementary networking tools for firewall management, diagnostics,
;;; remote access, and time synchronization.
;;;
;;; Note: systemd-resolved handles DNS and systemd-timesyncd provides
;;; basic NTP.  chrony is included for deployments requiring high-accuracy
;;; time synchronization (e.g., database clusters, financial systems).
;;;
;;; Package dependency graph:
;;;
;;;   andyl-iproute2
;;;     +-- andyl-glibc
;;;     +-- andyl-linux-headers
;;;
;;;   andyl-libmnl
;;;     +-- andyl-glibc
;;;
;;;   andyl-libnftnl
;;;     +-- andyl-libmnl
;;;
;;;   andyl-iptables
;;;     +-- andyl-glibc
;;;     +-- andyl-linux-headers
;;;     +-- andyl-libnftnl    (for iptables-nft translation layer)
;;;     +-- andyl-libmnl
;;;
;;;   andyl-nftables
;;;     +-- andyl-libnftnl
;;;     +-- andyl-libmnl
;;;     +-- andyl-glibc
;;;     +-- andyl-linux-headers
;;;
;;;   andyl-curl
;;;     +-- andyl-openssl
;;;     +-- andyl-zlib
;;;
;;;   andyl-openssh
;;;     +-- andyl-openssl
;;;     +-- andyl-zlib
;;;
;;;   andyl-chrony
;;;     +-- andyl-glibc
;;;     +-- andyl-linux-headers
;;;
;;;   andyl-ca-certificates
;;;     (trivial-build-system, extracts Mozilla CA bundle from curl source)

(define-module (andyl packages networking)
  #:use-module (guix packages)
  #:use-module (guix download)
  #:use-module (guix build-system gnu)
  #:use-module (guix build-system trivial)
  #:use-module (guix utils)
  #:use-module ((guix licenses) #:prefix license:)
  #:use-module (andyl packages gcc)
  #:use-module (andyl packages glibc)
  #:use-module (andyl packages linux)
  #:use-module (andyl packages base)
  #:use-module (andyl packages compression)
  #:use-module (andyl packages tls)
  #:use-module (andyl config))


;;; =========================================================================
;;; iproute2 -- network configuration utilities
;;; =========================================================================
;;;
;;; iproute2 provides the modern Linux network configuration tools:
;;;   ip       -- Configure interfaces, routes, tunnels, VRFs
;;;   ss       -- Socket statistics (replacement for netstat)
;;;   tc       -- Traffic control (QoS, rate limiting)
;;;   bridge   -- Bridge management
;;;   nstat    -- Network statistics
;;;   rtacct   -- Route accounting
;;;
;;; While systemd-networkd handles declarative network configuration,
;;; iproute2 is essential for runtime diagnostics, debugging, and
;;; advanced network management.

(define-public andyl-iproute2
  (package
    (name "andyl-iproute2")
    (version (config-version "networking" "iproute2"))
    (source (origin
              (method url-fetch)
              (uri (string-append
                    "https://cdn.kernel.org/pub/linux/utils/net/iproute2/"
                    "iproute2-" version ".tar.xz"))
              (sha256
               ;; TODO: guix download https://cdn.kernel.org/pub/linux/utils/net/iproute2/iproute2-6.11.0.tar.xz
               (base32 "0000000000000000000000000000000000000000000000000000"))))
    (build-system gnu-build-system)
    (native-inputs
     (list andyl-gcc
           andyl-pkg-config
           andyl-bison))
    (inputs
     (list andyl-glibc
           andyl-linux-headers))
    (arguments
     (list
      ;; iproute2 uses a custom configure script (not autoconf)
      #:phases
      #~(modify-phases %standard-phases
          (replace 'configure
            (lambda* (#:key outputs #:allow-other-keys)
              (let ((out (assoc-ref outputs "out")))
                (invoke "./configure")
                ;; Set install prefix via environment
                (setenv "PREFIX" out)
                (setenv "SBINDIR" (string-append out "/sbin"))
                (setenv "CONFDIR" (string-append out "/etc/iproute2"))
                (setenv "DOCDIR" (string-append out "/share/doc/iproute2"))
                (setenv "MANDIR" (string-append out "/share/man"))))))
      #:make-flags
      #~(list (string-append "PREFIX=" (assoc-ref %outputs "out"))
              (string-append "SBINDIR=" (assoc-ref %outputs "out") "/sbin")
              (string-append "CONFDIR=" (assoc-ref %outputs "out") "/etc/iproute2")
              (string-append "DOCDIR=" (assoc-ref %outputs "out") "/share/doc/iproute2")
              (string-append "MANDIR=" (assoc-ref %outputs "out") "/share/man"))
      #:tests? #f))
    (home-page "https://wiki.linuxfoundation.org/networking/iproute2")
    (synopsis "Linux network configuration utilities for ANDYL OS")
    (description
     "iproute2 provides the modern Linux network configuration and
diagnostic tools: ip (interfaces, routes, tunnels), ss (socket statistics),
tc (traffic control), and bridge (bridge management).  Used alongside
systemd-networkd for runtime network diagnostics and advanced
configuration.")
    (license license:gpl2)))


;;; =========================================================================
;;; libmnl -- minimalistic netlink library
;;; =========================================================================
;;;
;;; libmnl is a minimalistic user-space library for interacting with
;;; the Linux kernel Netlink interface.  It is a dependency of libnftnl
;;; and nftables.

(define-public andyl-libmnl
  (package
    (name "andyl-libmnl")
    (version (config-version "networking" "libmnl"))
    (source (origin
              (method url-fetch)
              (uri (string-append
                    "https://www.netfilter.org/projects/libmnl/files/"
                    "libmnl-" version ".tar.bz2"))
              (sha256
               ;; TODO: guix download https://www.netfilter.org/projects/libmnl/files/libmnl-1.0.5.tar.bz2
               (base32 "0000000000000000000000000000000000000000000000000000"))))
    (build-system gnu-build-system)
    (native-inputs (list andyl-gcc andyl-pkg-config))
    (inputs (list andyl-glibc))
    (arguments
     (list
      #:configure-flags
      #~(list "--disable-static")
      #:tests? #f))
    (home-page "https://www.netfilter.org/projects/libmnl/")
    (synopsis "Minimalistic Netlink library for ANDYL OS")
    (description
     "libmnl is a minimalistic user-space library for interacting with
the Linux kernel Netlink socket interface.  It provides helpers for
Netlink message construction, parsing, and socket handling.  Required
by libnftnl and nftables.")
    (license license:lgpl2.1+)))


;;; =========================================================================
;;; libnftnl -- Netfilter netlink library
;;; =========================================================================
;;;
;;; libnftnl provides a low-level API for interacting with the nf_tables
;;; kernel subsystem via Netlink.  It is the primary dependency of the
;;; nft command-line tool.

(define-public andyl-libnftnl
  (package
    (name "andyl-libnftnl")
    (version (config-version "networking" "libnftnl"))
    (source (origin
              (method url-fetch)
              (uri (string-append
                    "https://www.netfilter.org/projects/libnftnl/files/"
                    "libnftnl-" version ".tar.xz"))
              (sha256
               ;; TODO: guix download https://www.netfilter.org/projects/libnftnl/files/libnftnl-1.2.8.tar.xz
               (base32 "0000000000000000000000000000000000000000000000000000"))))
    (build-system gnu-build-system)
    (native-inputs (list andyl-gcc andyl-pkg-config))
    (inputs (list andyl-glibc andyl-libmnl))
    (arguments
     (list
      #:configure-flags
      #~(list "--disable-static")
      #:tests? #f))
    (home-page "https://www.netfilter.org/projects/libnftnl/")
    (synopsis "Netfilter nf_tables netlink library for ANDYL OS")
    (description
     "libnftnl provides a low-level C API for interacting with the
Linux kernel nf_tables subsystem via Netlink.  It handles Netlink
message construction and parsing for nf_tables rules, chains, tables,
and sets.  Required by the nft command-line tool.")
    (license license:gpl2+)))


;;; =========================================================================
;;; iptables -- legacy firewall rules management
;;; =========================================================================
;;;
;;; iptables provides the legacy Linux firewall rule management tools.
;;; While nftables is the modern replacement, iptables remains essential
;;; because:
;;;   - Kubernetes (kube-proxy) uses iptables rules by default
;;;   - Many container networking plugins (Calico, Flannel) use iptables
;;;   - The iptables-nft translation layer maps iptables rules to nftables
;;;
;;; This build includes iptables-nft, which translates iptables commands
;;; to nftables kernel API calls, providing compatibility with software
;;; that expects the iptables CLI while using the modern nftables backend.

(define-public andyl-iptables
  (package
    (name "andyl-iptables")
    (version (config-version "networking" "iptables"))
    (source (origin
              (method url-fetch)
              (uri (string-append
                    "https://www.netfilter.org/projects/iptables/files/"
                    "iptables-" version ".tar.xz"))
              (sha256
               ;; TODO: guix download https://www.netfilter.org/projects/iptables/files/iptables-1.8.10.tar.xz
               (base32 "0000000000000000000000000000000000000000000000000000"))))
    (build-system gnu-build-system)
    (native-inputs (list andyl-gcc andyl-pkg-config))
    (inputs
     (list andyl-glibc
           andyl-linux-headers
           andyl-libnftnl         ; for iptables-nft backend
           andyl-libmnl))         ; netlink communication
    (arguments
     (list
      #:configure-flags
      #~(list "--disable-static"
              ;; Enable iptables-nft (translates iptables to nftables)
              "--enable-nftables"
              ;; Enable connection tracking helpers
              "--enable-connlabel"
              ;; Install to output prefix
              (string-append "--with-xtlibdir="
                             (assoc-ref %outputs "out")
                             "/lib/xtables"))
      #:tests? #f))
    (home-page "https://www.netfilter.org/projects/iptables/")
    (synopsis "Linux firewall administration tools for ANDYL OS")
    (description
     "iptables provides commands for managing Linux kernel packet filtering
rules: iptables (IPv4), ip6tables (IPv6), arptables, and ebtables.
This build includes the iptables-nft backend which translates iptables
commands to the modern nftables kernel API.  Required by Kubernetes
kube-proxy and many container networking plugins.")
    (license license:gpl2)))


;;; =========================================================================
;;; nftables -- modern firewall framework
;;; =========================================================================
;;;
;;; nftables is the modern replacement for iptables, providing a unified
;;; framework for packet filtering, NAT, and traffic classification.
;;;
;;; Key advantages over iptables:
;;;   - Single tool for IPv4, IPv6, ARP, and bridge filtering
;;;   - More expressive rule syntax with sets, maps, and concatenations
;;;   - Atomic rule replacement (no packet loss during ruleset changes)
;;;   - Better performance through optimized bytecode
;;;
;;; nftables is the recommended firewall tool for new ANDYL OS
;;; configurations.  iptables is retained for Kubernetes compatibility.

(define-public andyl-nftables
  (package
    (name "andyl-nftables")
    (version (config-version "networking" "nftables"))
    (source (origin
              (method url-fetch)
              (uri (string-append
                    "https://www.netfilter.org/projects/nftables/files/"
                    "nftables-" version ".tar.xz"))
              (sha256
               ;; TODO: guix download https://www.netfilter.org/projects/nftables/files/nftables-1.1.0.tar.xz
               (base32 "0000000000000000000000000000000000000000000000000000"))))
    (build-system gnu-build-system)
    (native-inputs (list andyl-gcc andyl-pkg-config andyl-bison))
    (inputs
     (list andyl-glibc
           andyl-linux-headers
           andyl-libnftnl
           andyl-libmnl))
    (arguments
     (list
      #:configure-flags
      #~(list "--disable-static"
              ;; Disable man page generation (requires asciidoc)
              "--disable-man-doc"
              ;; Enable JSON output support
              "--with-json"
              ;; Install systemd unit for nftables.service
              (string-append "--with-systemd-unitdir="
                             (assoc-ref %outputs "out")
                             "/lib/systemd/system"))
      #:tests? #f))
    (home-page "https://www.netfilter.org/projects/nftables/")
    (synopsis "Modern firewall framework for ANDYL OS")
    (description
     "nftables is the modern Linux firewall framework replacing iptables.
It provides the nft command for managing packet filtering, NAT, and
traffic classification rules.  Features include atomic rule replacement,
sets and maps, concatenated matches, and a unified tool for IPv4, IPv6,
ARP, and bridge filtering.")
    (license license:gpl2)))


;;; =========================================================================
;;; curl -- HTTP/HTTPS client and library
;;; =========================================================================
;;;
;;; curl provides both a command-line tool and a library (libcurl) for
;;; transferring data using HTTP, HTTPS, FTP, and many other protocols.
;;;
;;; In ANDYL OS, curl is used for:
;;;   - Downloading artifacts from the binary cache
;;;   - Health check endpoints
;;;   - Cloud metadata service queries (169.254.169.254)
;;;   - General HTTP/HTTPS communication from scripts

(define-public andyl-curl
  (package
    (name "andyl-curl")
    (version (config-version "networking" "curl"))
    (source (origin
              (method url-fetch)
              (uri (string-append
                    "https://curl.se/download/curl-" version ".tar.xz"))
              (sha256
               ;; TODO: guix download https://curl.se/download/curl-8.10.1.tar.xz
               (base32 "0000000000000000000000000000000000000000000000000000"))))
    (build-system gnu-build-system)
    (native-inputs
     (list andyl-gcc
           andyl-pkg-config
           andyl-perl))           ; for test scripts (disabled but configure checks)
    (inputs
     (list andyl-glibc
           andyl-openssl           ; TLS backend
           andyl-zlib))            ; HTTP compression
    (arguments
     (list
      #:configure-flags
      #~(list "--disable-static"
              ;; Use OpenSSL as the TLS backend
              (string-append "--with-openssl="
                             (assoc-ref %build-inputs "andyl-openssl"))
              ;; Use our zlib
              (string-append "--with-zlib="
                             (assoc-ref %build-inputs "andyl-zlib"))
              ;; Enable HTTP/2 support (built-in)
              "--with-nghttp2"
              ;; Disable protocols not needed on servers
              "--disable-ldap"
              "--disable-ldaps"
              "--disable-rtsp"
              "--disable-dict"
              "--disable-telnet"
              "--disable-pop3"
              "--disable-imap"
              "--disable-smb"
              "--disable-smtp"
              "--disable-gopher"
              "--disable-mqtt"
              ;; CA bundle path
              "--with-ca-bundle=/etc/ssl/certs/ca-certificates.crt")
      #:tests? #f))
    (home-page "https://curl.se/")
    (synopsis "HTTP/HTTPS client and library for ANDYL OS")
    (description
     "curl provides a command-line tool and the libcurl library for
transferring data using HTTP, HTTPS, FTP, and other protocols.  Built
with OpenSSL for TLS and zlib for HTTP compression.  Used by the ANDYL
OS update agent, health checks, and cloud metadata queries.")
    (license license:x11)))


;;; =========================================================================
;;; OpenSSH -- secure shell client and server
;;; =========================================================================
;;;
;;; OpenSSH provides encrypted remote login, file transfer, and tunneling.
;;; It is the primary remote access mechanism for ANDYL OS servers.
;;;
;;; The server (sshd) runs as a systemd service and is the main
;;; administrative access path to deployed machines.
;;;
;;; Security configuration:
;;;   - Uses our hardened OpenSSL build (TLS 1.2+, no weak ciphers)
;;;   - Privilege separation enabled
;;;   - PAM support disabled (ANDYL OS uses SSH keys, not passwords)

(define-public andyl-openssh
  (package
    (name "andyl-openssh")
    (version (config-version "networking" "openssh"))
    (source (origin
              (method url-fetch)
              (uri (string-append
                    "https://ftp.openbsd.org/pub/OpenBSD/OpenSSH/portable/"
                    "openssh-" version ".tar.gz"))
              (sha256
               ;; TODO: guix download https://ftp.openbsd.org/pub/OpenBSD/OpenSSH/portable/openssh-9.9p1.tar.gz
               (base32 "0000000000000000000000000000000000000000000000000000"))))
    (build-system gnu-build-system)
    (native-inputs
     (list andyl-gcc
           andyl-pkg-config))
    (inputs
     (list andyl-glibc
           andyl-openssl            ; TLS/crypto
           andyl-zlib))             ; compression
    (arguments
     (list
      #:configure-flags
      #~(list ;; Use our OpenSSL
              (string-append "--with-ssl-dir="
                             (assoc-ref %build-inputs "andyl-openssl"))
              ;; Privilege separation user and path
              "--with-privsep-user=sshd"
              "--with-privsep-path=/var/empty"
              ;; PID file location
              "--with-pid-dir=/run"
              ;; Default path for users
              (string-append "--with-default-path="
                             (assoc-ref %outputs "out") "/bin"
                             ":/usr/bin:/bin")
              ;; Disable PAM (use SSH keys, not passwords)
              "--without-pam"
              ;; Disable Kerberos (not needed for server environments)
              "--without-kerberos5"
              ;; Enable sandbox (seccomp on Linux)
              "--with-sandbox=seccomp_filter"
              ;; Strip installed binaries
              "--with-strip=strip")

      #:phases
      #~(modify-phases %standard-phases
          ;; OpenSSH tries to create /var/empty during install;
          ;; redirect to our output
          (add-before 'install 'fix-install-paths
            (lambda* (#:key outputs #:allow-other-keys)
              (let ((out (assoc-ref outputs "out")))
                (mkdir-p (string-append out "/var/empty"))))))

      #:tests? #f))
    (home-page "https://www.openssh.com/")
    (synopsis "Secure shell client and server for ANDYL OS")
    (description
     "OpenSSH provides encrypted remote login (ssh), file transfer (scp,
sftp), and tunneling for ANDYL OS.  The server (sshd) is the primary
remote administration tool for deployed machines.  Built with OpenSSL
for cryptography, seccomp sandbox for privilege separation, and
configured for key-based authentication (PAM disabled).")
    (license (license:non-copyleft
              "https://www.openbsd.org/policy.html"
              "ISC-style license"))))


;;; =========================================================================
;;; Chrony -- NTP time synchronization
;;; =========================================================================
;;;
;;; Chrony is a versatile NTP implementation that is more accurate and
;;; reliable than systemd-timesyncd, particularly in environments with:
;;;   - Intermittent network connectivity
;;;   - Virtual machines with unstable clocks
;;;   - Requirements for sub-millisecond accuracy
;;;
;;; systemd-timesyncd provides basic SNTP for simple deployments.
;;; Chrony is included for production deployments requiring high-accuracy
;;; time synchronization (database clusters, distributed systems,
;;; financial applications).
;;;
;;; Chrony can operate as both an NTP client and server, and supports
;;; hardware timestamping for nanosecond-level accuracy on supported NICs.

(define-public andyl-chrony
  (package
    (name "andyl-chrony")
    (version (config-version "networking" "chrony"))
    (source (origin
              (method url-fetch)
              (uri (string-append
                    "https://chrony-project.org/releases/chrony-"
                    version ".tar.gz"))
              (sha256
               ;; TODO: guix download https://chrony-project.org/releases/chrony-4.6.1.tar.gz
               (base32 "0000000000000000000000000000000000000000000000000000"))))
    (build-system gnu-build-system)
    (native-inputs
     (list andyl-gcc
           andyl-pkg-config))
    (inputs
     (list andyl-glibc
           andyl-linux-headers))
    (arguments
     (list
      #:phases
      #~(modify-phases %standard-phases
          ;; Chrony uses its own configure script (not autoconf).
          ;; It accepts --prefix but not all autoconf flags.
          (replace 'configure
            (lambda* (#:key outputs #:allow-other-keys)
              (let ((out (assoc-ref outputs "out")))
                (invoke "./configure"
                        (string-append "--prefix=" out)
                        (string-append "--sysconfdir=" out "/etc")
                        ;; Enable seccomp sandbox
                        "--enable-scfilter"
                        ;; Enable hardware timestamping support
                        "--enable-ntp-signd"
                        ;; Chrony user for privilege dropping
                        "--with-user=chrony")))))
      #:tests? #f))
    (home-page "https://chrony-project.org/")
    (synopsis "NTP time synchronization for ANDYL OS")
    (description
     "Chrony is a versatile NTP implementation providing high-accuracy
time synchronization.  It supports hardware timestamping, seccomp
sandboxing, and operates as both NTP client and server.  Used in
ANDYL OS production deployments requiring sub-millisecond time accuracy
(database clusters, distributed systems).  For basic time sync,
systemd-timesyncd is sufficient.")
    (license license:gpl2)))


;;; =========================================================================
;;; CA Certificates -- Mozilla trusted root certificate bundle
;;; =========================================================================
;;;
;;; The CA certificate bundle provides the set of trusted root Certificate
;;; Authority (CA) certificates used for TLS verification.  Without this,
;;; curl, OpenSSH, and any TLS client cannot verify server certificates.
;;;
;;; This package extracts the Mozilla CA bundle from the curl project's
;;; maintained cacert.pem and installs it to /etc/ssl/certs/ where
;;; OpenSSL and other TLS libraries expect to find it.
;;;
;;; The bundle is updated periodically from:
;;;   https://curl.se/docs/caextract.html
;;;
;;; This is referenced in the base image package list
;;; (phase-4-base-image.md section 4.2).

(define-public andyl-ca-certificates
  (package
    (name "andyl-ca-certificates")
    (version (config-version "networking" "ca-certificates"))
    (source (origin
              (method url-fetch)
              (uri (string-append
                    "https://curl.se/ca/cacert-" version ".pem"))
              (sha256
               ;; TODO: guix download https://curl.se/ca/cacert-2024-07-02.pem
               (base32 "0000000000000000000000000000000000000000000000000000"))))
    (build-system trivial-build-system)
    (arguments
     (list
      #:modules '((guix build utils))
      #:builder
      #~(begin
          (use-modules (guix build utils))
          (let* ((source  (assoc-ref %build-inputs "source"))
                 (out     (assoc-ref %outputs "out"))
                 (certdir (string-append out "/etc/ssl/certs"))
                 (docdir  (string-append out "/share/doc/"
                                         #$(package-name this-package))))

            ;; Install the CA bundle
            (mkdir-p certdir)
            (copy-file source
                       (string-append certdir "/ca-certificates.crt"))

            ;; Create a symlink at the alternate path that some programs expect
            (symlink "ca-certificates.crt"
                     (string-append certdir "/ca-bundle.crt"))

            ;; Also install to the OpenSSL default location
            (let ((ssldir (string-append out "/etc/ssl")))
              (symlink "certs/ca-certificates.crt"
                       (string-append ssldir "/cert.pem")))

            ;; Install documentation
            (mkdir-p docdir)
            (call-with-output-file (string-append docdir "/README")
              (lambda (port)
                (display
                 "Mozilla CA Certificate Bundle\n\nExtracted from: https://curl.se/docs/caextract.html\nVersion: "
                 port)
                (display #$(package-version this-package) port)
                (newline port)
                (display "License: MPL-2.0\n" port)))))))

    (home-page "https://curl.se/docs/caextract.html")
    (synopsis "Mozilla CA certificate bundle for ANDYL OS")
    (description
     "The Mozilla CA certificate bundle provides trusted root Certificate
Authority (CA) certificates for TLS/SSL verification.  Installed to
/etc/ssl/certs/ca-certificates.crt where OpenSSL, curl, and other TLS
clients expect to find it.  Extracted from the Mozilla NSS project
and maintained by the curl project.")
    (license license:mpl2.0)))
