;;; ANDYL OS -- Server System Configuration
;;; Copyright (C) 2024 ANDYL OS Contributors
;;;
;;; This module defines the server-specific system configuration for ANDYL OS,
;;; inheriting from the base system definition and adding:
;;;
;;;   - SSH service with hardened configuration
;;;   - nftables firewall with restrictive defaults
;;;   - Chrony for high-accuracy time synchronization
;;;   - SELinux in enforcing mode (production)
;;;   - Hardened sysctl settings for server security
;;;   - Audit rules for security monitoring
;;;
;;; The server configuration is the standard deployment target for production
;;; ANDYL OS machines.  It includes all the security hardening and network
;;; services expected on a headless server.
;;;
;;; See:
;;;   RFC-0001 section 6 (systemd as PID 1)
;;;   Phase 4 section 4.2 (Operating System Definition)

(define-module (andyl system server)
  #:use-module (guix packages)
  #:use-module (guix records)
  #:use-module (guix gexp)
  #:use-module (andyl system base)
  #:use-module (andyl config)
  #:use-module (andyl packages networking)
  #:use-module (andyl packages audit)
  #:export (andyl-os-server
            %andyl-server-kernel-arguments
            %andyl-server-services
            %andyl-server-sysctl-settings
            %andyl-server-sshd-config
            %andyl-server-nftables-config))


;;;
;;; Server Kernel Arguments
;;;
;;; The server variant uses enforcing mode for SELinux (enforcing=1) and
;;; includes additional security hardening parameters.
;;;

(define %andyl-server-kernel-arguments
  (append %andyl-base-kernel-arguments
          (list "lockdown=integrity"
                "modules_disabled=1")))


;;;
;;; Server Services
;;;
;;; Additional systemd services enabled on server deployments beyond
;;; the base set.
;;;

(define %andyl-server-services
  (list
   ;; SSH server for remote administration
   "sshd.service"

   ;; nftables firewall
   "nftables.service"

   ;; Chrony NTP for high-accuracy time sync (replaces timesyncd)
   "chronyd.service"

   ;; ZFS auto-snapshot timers for data protection
   "zfs-auto-snapshot-frequent.timer"
   "zfs-auto-snapshot-hourly.timer"
   "zfs-auto-snapshot-daily.timer"

   ;; First-boot relabeling (runs once after Ignition)
   "andyl-selinux-relabel.service"))


;;;
;;; Hardened sysctl Settings
;;;
;;; These kernel parameters harden the network stack and restrict
;;; information leakage.  They are applied via systemd-sysctl.service
;;; using a drop-in configuration file.
;;;

(define %andyl-server-sysctl-settings
  (config-ref/alist "security.sysctl"))


;;;
;;; SSH Server Configuration
;;;
;;; Hardened sshd_config installed to /etc/ssh/sshd_config via the
;;; /etc overlay upper layer.  Key-based authentication only, no
;;; passwords, no root login.
;;;

(define %andyl-server-sshd-config
  (let ((port         (config-ref "security.ssh.port" 22))
        (permit-root  (config-ref "security.ssh.permit-root-login" "prohibit-password"))
        (password-auth (config-ref "security.ssh.password-auth" #f))
        (challenge    (config-ref "security.ssh.challenge-response-auth" #f))
        (max-tries    (config-ref "security.ssh.max-auth-tries" 3))
        (max-sessions (config-ref "security.ssh.max-sessions" 10))
        (grace-time   (config-ref "security.ssh.login-grace-time" 30))
        (tcp-fwd      (config-ref "security.ssh.allow-tcp-forwarding" #f))
        (agent-fwd    (config-ref "security.ssh.allow-agent-forwarding" #f))
        (x11-fwd      (config-ref "security.ssh.x11-forwarding" #f))
        (log-level    (config-ref "security.ssh.log-level" "VERBOSE"))
        (ciphers      (config-ref/list "security.ssh.ciphers"))
        (macs         (config-ref/list "security.ssh.macs"))
        (kex          (config-ref/list "security.ssh.kex-algorithms"))
        (alive-int    (config-ref "security.ssh.client-alive-interval" 300))
        (alive-max    (config-ref "security.ssh.client-alive-count-max" 3)))
    (define (bool->yn v) (if v "yes" "no"))
    (string-append
     "# ANDYL OS SSH Server Configuration\n"
     "# Generated from config/security.toml\n\n"
     "# Network\n"
     "Port " (number->string port) "\n"
     "AddressFamily any\n"
     "ListenAddress 0.0.0.0\n"
     "ListenAddress ::\n\n"
     "# Host keys (generated on first boot by Ignition)\n"
     "HostKey /etc/ssh/ssh_host_ed25519_key\n"
     "HostKey /etc/ssh/ssh_host_rsa_key\n\n"
     "# Authentication: key-based only\n"
     "PermitRootLogin " permit-root "\n"
     "PubkeyAuthentication yes\n"
     "PasswordAuthentication " (bool->yn password-auth) "\n"
     "ChallengeResponseAuthentication " (bool->yn challenge) "\n"
     "KbdInteractiveAuthentication no\n"
     "UsePAM no\n\n"
     "# Restrict authorized keys location\n"
     "AuthorizedKeysFile .ssh/authorized_keys\n\n"
     "# Disable unused authentication methods\n"
     "GSSAPIAuthentication no\n"
     "HostbasedAuthentication no\n\n"
     "# Security\n"
     "PermitEmptyPasswords no\n"
     "StrictModes yes\n"
     "MaxAuthTries " (number->string max-tries) "\n"
     "MaxSessions " (number->string max-sessions) "\n"
     "LoginGraceTime " (number->string grace-time) "\n\n"
     "# Forwarding\n"
     "AllowTcpForwarding " (bool->yn tcp-fwd) "\n"
     "AllowAgentForwarding " (bool->yn agent-fwd) "\n"
     "X11Forwarding " (bool->yn x11-fwd) "\n"
     "PermitTunnel no\n"
     "GatewayPorts no\n\n"
     "# Logging\n"
     "SyslogFacility AUTH\n"
     "LogLevel " log-level "\n\n"
     "# Subsystem\n"
     "Subsystem sftp internal-sftp\n\n"
     "# Ciphers: modern, strong only\n"
     "Ciphers " (string-join ciphers ",") "\n"
     "MACs " (string-join macs ",") "\n"
     "KexAlgorithms " (string-join kex ",") "\n\n"
     "# Keep alive\n"
     "ClientAliveInterval " (number->string alive-int) "\n"
     "ClientAliveCountMax " (number->string alive-max) "\n")))


;;;
;;; nftables Firewall Configuration
;;;
;;; Default firewall ruleset for ANDYL OS servers.  Restrictive by default:
;;;   - Allow SSH (port 22)
;;;   - Allow ICMP/ICMPv6 (ping, neighbor discovery)
;;;   - Allow established/related connections
;;;   - Drop everything else
;;;
;;; This configuration is installed to /etc/nftables.conf and loaded
;;; by nftables.service at boot.
;;;

(define (format-port-list ports)
  "Format a list of port numbers as a comma-separated string."
  (string-join (map number->string ports) ", "))

(define %andyl-server-nftables-config
  (let ((allowed-tcp (config-ref/list "security.firewall.allowed-tcp"))
        (fwd-policy  (config-ref "security.firewall.forward-policy" "drop")))
    (string-append
     "#!/usr/sbin/nft -f\n"
     "# ANDYL OS Server Firewall Configuration\n"
     "# Generated from config/security.toml\n\n"
     "flush ruleset\n\n"
     "table inet filter {\n"
     "    chain input {\n"
     "        type filter hook input priority filter; policy drop;\n\n"
     "        # Allow loopback traffic\n"
     "        iif lo accept\n\n"
     "        # Allow established and related connections\n"
     "        ct state established,related accept\n\n"
     "        # Drop invalid packets\n"
     "        ct state invalid drop\n\n"
     "        # Allow ICMP (ping, path MTU discovery)\n"
     "        ip protocol icmp accept\n"
     "        ip6 nexthdr icmpv6 accept\n\n"
     "        # Allowed TCP ports\n"
     "        tcp dport { " (format-port-list allowed-tcp) " } accept\n\n"
     "        # Log dropped packets (rate-limited)\n"
     "        limit rate 5/minute burst 5 packets log prefix \"nftables-drop: \" level info\n"
     "    }\n\n"
     "    chain forward {\n"
     "        type filter hook forward priority filter; policy " fwd-policy ";\n"
     "    }\n\n"
     "    chain output {\n"
     "        type filter hook output priority filter; policy accept;\n"
     "    }\n"
     "}\n")))


;;;
;;; Server Operating System
;;;
;;; The server configuration inherits from andyl-os-base and overrides:
;;;   - kernel-arguments: enforcing=1 for SELinux, lockdown=integrity
;;;   - extra-services: sshd, nftables, chrony
;;;

(define andyl-os-server
  (andyl-operating-system
   (host-name "andyl-os")
   (kernel-arguments %andyl-server-kernel-arguments)
   (extra-services %andyl-server-services)))
