;;; ANDYL OS -- SELinux Packages
;;; Copyright (C) 2024 ANDYL OS Contributors
;;;
;;; This module defines the SELinux userspace stack for ANDYL OS.
;;; SELinux is the definitive mandatory access control system for
;;; ANDYL OS, providing label-based type enforcement, RBAC, and
;;; audit integration.
;;;
;;; The SELinux userspace stack consists of:
;;;   libsepol            -- SELinux binary policy manipulation library
;;;   libselinux           -- SELinux shared library (userspace API)
;;;   libsemanage          -- SELinux policy management library
;;;   policycoreutils      -- Core utilities (sestatus, restorecon, etc.)
;;;   selinux-policy-targeted -- Upstream reference targeted policy
;;;   container-selinux    -- Container runtime policy module
;;;   setools              -- Policy analysis tools (sesearch, seinfo)
;;;
;;; All userspace packages are sourced from the SELinux Project on
;;; GitHub (version 3.7).
;;;
;;; Custom ANDYL OS policy is defined separately in:
;;;   (andyl packages selinux-policy)
;;;
;;; See also:
;;;   RFC-0003 section 3.7 (Security Modules -- SELinux kernel config)
;;;   Phase 3 section 3.12 (SELinux Policy Development and Userspace)

(define-module (andyl packages selinux)
  #:use-module (guix packages)
  #:use-module (guix download)
  #:use-module (guix build-system gnu)
  #:use-module (guix utils)
  #:use-module ((guix licenses) #:prefix license:)
  #:use-module (andyl packages gcc)
  #:use-module (andyl packages glibc)
  #:use-module (andyl config))


;;; =========================================================================
;;; SELinux version used across all userspace packages
;;; =========================================================================

(define %selinux-version (config-version "security" "selinux-userspace"))

;;; Helper to construct the GitHub release tarball URI for SELinux
;;; components.  Each component (libsepol, libselinux, etc.) is released
;;; as a separate tarball from the SELinuxProject/selinux repository.
(define (selinux-uri component version)
  (string-append
   "https://github.com/SELinuxProject/selinux/releases/download/"
   version "/" component "-" version ".tar.gz"))


;;; =========================================================================
;;; libsepol -- SELinux binary policy manipulation library
;;; =========================================================================
;;;
;;; libsepol provides an API for manipulating SELinux binary policies.
;;; It is the lowest-level library in the SELinux stack and has no
;;; dependencies on other SELinux libraries.  It is used by checkpolicy
;;; (the policy compiler), libsemanage, and other policy tools.

(define-public andyl-libsepol
  (package
    (name "andyl-libsepol")
    (version %selinux-version)
    (source (origin
              (method url-fetch)
              (uri (selinux-uri "libsepol" version))
              (sha256
               ;; TODO: Compute actual hash:
               ;;   guix download https://github.com/SELinuxProject/selinux/releases/download/3.7/libsepol-3.7.tar.gz
               (base32 "0000000000000000000000000000000000000000000000000000"))))
    (build-system gnu-build-system)
    (native-inputs (list andyl-gcc))
    (inputs (list andyl-glibc))
    (arguments
     (list
      #:phases
      #~(modify-phases %standard-phases
          ;; libsepol uses a simple Makefile, not autotools
          (delete 'configure)
          (replace 'build
            (lambda _
              (invoke "make" "CC=gcc"
                      "-j" (number->string (parallel-job-count)))))
          (replace 'install
            (lambda* (#:key outputs #:allow-other-keys)
              (let ((out (assoc-ref outputs "out")))
                (invoke "make" "install"
                        (string-append "PREFIX=" out)
                        (string-append "SHLIBDIR=" out "/lib"))))))
      #:tests? #f))
    (home-page "https://github.com/SELinuxProject/selinux")
    (synopsis "SELinux binary policy manipulation library")
    (description
     "libsepol provides an API for manipulating SELinux binary policies.
It is the foundational library in the SELinux userspace stack, used by
the policy compiler and management tools.")
    (license license:lgpl2.1+)))


;;; =========================================================================
;;; libselinux -- SELinux shared library (userspace API)
;;; =========================================================================
;;;
;;; libselinux provides the primary API for SELinux-aware applications.
;;; It wraps the /sys/fs/selinux interface and provides functions for
;;; getting/setting security contexts, checking access, and querying
;;; policy state.  This library is used by coreutils, systemd, container
;;; runtimes, and other SELinux-aware software.

(define-public andyl-libselinux
  (package
    (name "andyl-libselinux")
    (version %selinux-version)
    (source (origin
              (method url-fetch)
              (uri (selinux-uri "libselinux" version))
              (sha256
               ;; TODO: Compute actual hash:
               ;;   guix download https://github.com/SELinuxProject/selinux/releases/download/3.7/libselinux-3.7.tar.gz
               (base32 "0000000000000000000000000000000000000000000000000000"))))
    (build-system gnu-build-system)
    (native-inputs (list andyl-gcc))
    (inputs (list andyl-glibc andyl-libsepol))
    (arguments
     (list
      #:phases
      #~(modify-phases %standard-phases
          ;; libselinux uses a simple Makefile, not autotools
          (delete 'configure)
          (replace 'build
            (lambda* (#:key inputs #:allow-other-keys)
              (let ((sepol (assoc-ref inputs "andyl-libsepol")))
                (invoke "make" "CC=gcc"
                        (string-append "CFLAGS=-I" sepol "/include")
                        (string-append "LDFLAGS=-L" sepol "/lib")
                        "-j" (number->string (parallel-job-count))))))
          (replace 'install
            (lambda* (#:key outputs #:allow-other-keys)
              (let ((out (assoc-ref outputs "out")))
                (invoke "make" "install"
                        (string-append "PREFIX=" out)
                        (string-append "SHLIBDIR=" out "/lib"))))))
      #:tests? #f))
    (home-page "https://github.com/SELinuxProject/selinux")
    (synopsis "SELinux shared library for userspace applications")
    (description
     "libselinux provides the primary API for SELinux-aware applications.
It wraps the kernel's /sys/fs/selinux interface and provides functions
for getting/setting security contexts, checking access permissions,
and querying policy state.  Used by coreutils, systemd, container
runtimes, and other security-aware software.")
    (license license:public-domain)))


;;; =========================================================================
;;; libsemanage -- SELinux policy management library
;;; =========================================================================
;;;
;;; libsemanage provides an API for managing SELinux policies at a high
;;; level.  It handles the compilation of policy modules, management of
;;; file contexts, and coordination between the policy store on disk and
;;; the loaded policy in the kernel.  It is used by semanage, semodule,
;;; and other policy management tools.

(define-public andyl-libsemanage
  (package
    (name "andyl-libsemanage")
    (version %selinux-version)
    (source (origin
              (method url-fetch)
              (uri (selinux-uri "libsemanage" version))
              (sha256
               ;; TODO: Compute actual hash:
               ;;   guix download https://github.com/SELinuxProject/selinux/releases/download/3.7/libsemanage-3.7.tar.gz
               (base32 "0000000000000000000000000000000000000000000000000000"))))
    (build-system gnu-build-system)
    (native-inputs (list andyl-gcc))
    (inputs (list andyl-glibc andyl-libsepol andyl-libselinux))
    (arguments
     (list
      #:phases
      #~(modify-phases %standard-phases
          ;; libsemanage uses a simple Makefile, not autotools
          (delete 'configure)
          (replace 'build
            (lambda* (#:key inputs #:allow-other-keys)
              (let ((sepol (assoc-ref inputs "andyl-libsepol"))
                    (selinux (assoc-ref inputs "andyl-libselinux")))
                (invoke "make" "CC=gcc"
                        (string-append "CFLAGS=-I" sepol "/include"
                                       " -I" selinux "/include")
                        (string-append "LDFLAGS=-L" sepol "/lib"
                                       " -L" selinux "/lib")
                        "-j" (number->string (parallel-job-count))))))
          (replace 'install
            (lambda* (#:key outputs #:allow-other-keys)
              (let ((out (assoc-ref outputs "out")))
                (invoke "make" "install"
                        (string-append "PREFIX=" out)
                        (string-append "SHLIBDIR=" out "/lib"))))))
      #:tests? #f))
    (home-page "https://github.com/SELinuxProject/selinux")
    (synopsis "SELinux policy management library")
    (description
     "libsemanage provides a high-level API for managing SELinux policies.
It handles compilation of policy modules, management of file contexts,
and coordination between the on-disk policy store and the kernel's
loaded policy.  Used by semanage, semodule, and other policy management
tools.")
    (license license:lgpl2.1+)))


;;; =========================================================================
;;; policycoreutils -- SELinux policy core utilities
;;; =========================================================================
;;;
;;; policycoreutils provides the essential command-line tools for
;;; administering SELinux:
;;;   sestatus    -- display SELinux status
;;;   semanage    -- manage SELinux policy components (booleans, ports, etc.)
;;;   seinfo      -- query SELinux policy information
;;;   restorecon  -- restore file security contexts
;;;   semodule    -- manage SELinux policy modules
;;;   fixfiles    -- fix file SELinux security contexts
;;;   audit2allow -- generate policy from audit denial logs

(define-public andyl-policycoreutils
  (package
    (name "andyl-policycoreutils")
    (version %selinux-version)
    (source (origin
              (method url-fetch)
              (uri (selinux-uri "policycoreutils" version))
              (sha256
               ;; TODO: Compute actual hash:
               ;;   guix download https://github.com/SELinuxProject/selinux/releases/download/3.7/policycoreutils-3.7.tar.gz
               (base32 "0000000000000000000000000000000000000000000000000000"))))
    (build-system gnu-build-system)
    (native-inputs (list andyl-gcc))
    (inputs (list andyl-glibc andyl-libsepol andyl-libselinux andyl-libsemanage))
    (arguments
     (list
      #:phases
      #~(modify-phases %standard-phases
          ;; policycoreutils uses a simple Makefile, not autotools
          (delete 'configure)
          (replace 'build
            (lambda* (#:key inputs #:allow-other-keys)
              (let ((sepol (assoc-ref inputs "andyl-libsepol"))
                    (selinux (assoc-ref inputs "andyl-libselinux"))
                    (semanage (assoc-ref inputs "andyl-libsemanage")))
                (invoke "make" "CC=gcc"
                        (string-append "CFLAGS=-I" sepol "/include"
                                       " -I" selinux "/include"
                                       " -I" semanage "/include")
                        (string-append "LDFLAGS=-L" sepol "/lib"
                                       " -L" selinux "/lib"
                                       " -L" semanage "/lib")
                        "-j" (number->string (parallel-job-count))))))
          (replace 'install
            (lambda* (#:key outputs #:allow-other-keys)
              (let ((out (assoc-ref outputs "out")))
                (invoke "make" "install"
                        (string-append "PREFIX=" out)
                        (string-append "SBINDIR=" out "/sbin"))))))
      #:tests? #f))
    (home-page "https://github.com/SELinuxProject/selinux")
    (synopsis "SELinux policy core utilities")
    (description
     "policycoreutils provides essential command-line tools for managing
SELinux on a running system: sestatus (display status), semanage (manage
policy components), restorecon (restore file contexts), semodule (manage
policy modules), audit2allow (generate policy from audit logs), fixfiles
(batch relabeling), and seinfo (query policy).")
    (license license:gpl2+)))


;;; =========================================================================
;;; andyl-selinux-policy-targeted -- upstream reference targeted policy
;;; =========================================================================
;;;
;;; The upstream SELinux reference policy provides the base set of type
;;; definitions, roles, and access rules that all SELinux systems build
;;; upon.  The "targeted" variant confines specific daemons and services
;;; while leaving general user sessions in an unconfined domain.
;;;
;;; This is the Fedora/RHEL-derived reference targeted policy that
;;; provides domains for systemd, sshd, networking daemons, and other
;;; common services.  ANDYL OS-specific policy modules (defined in
;;; andyl-selinux-policy) layer on top of this base.

(define-public andyl-selinux-policy-targeted
  (package
    (name "andyl-selinux-policy-targeted")
    (version (config-version "security" "refpolicy"))
    (source (origin
              (method url-fetch)
              (uri (string-append
                    "https://github.com/SELinuxProject/refpolicy/releases/download/RELEASE_"
                    "2_20240916"
                    "/refpolicy-" version ".tar.bz2"))
              (sha256
               ;; TODO: Compute actual hash:
               ;;   guix download https://github.com/SELinuxProject/refpolicy/releases/download/RELEASE_2_20240916/refpolicy-2.20240916.tar.bz2
               (base32 "0000000000000000000000000000000000000000000000000000"))))
    (build-system gnu-build-system)
    (native-inputs (list andyl-gcc andyl-libsepol andyl-libselinux
                         andyl-libsemanage andyl-policycoreutils))
    (inputs (list andyl-glibc))
    (arguments
     (list
      #:phases
      #~(modify-phases %standard-phases
          ;; The reference policy uses its own Makefile with make conf
          (replace 'configure
            (lambda* (#:key inputs outputs #:allow-other-keys)
              (let ((out (assoc-ref outputs "out"))
                    (sepol (assoc-ref inputs "andyl-libsepol")))
                ;; Configure for targeted policy type
                (substitute* "build.conf"
                  (("^TYPE = .*") "TYPE = standard\n")
                  (("^NAME = .*") "NAME = targeted\n")
                  (("^DISTRO = .*") "DISTRO = redhat\n")
                  (("^SYSTEMD = .*") "SYSTEMD = y\n"))
                ;; Set install prefix
                (substitute* "Makefile"
                  (("/usr") out)))))
          (replace 'build
            (lambda* (#:key inputs #:allow-other-keys)
              (let ((sepol (assoc-ref inputs "andyl-libsepol")))
                (invoke "make"
                        (string-append "CFLAGS=-I" sepol "/include")
                        (string-append "LDFLAGS=-L" sepol "/lib")
                        "-j" (number->string (parallel-job-count))))))
          (replace 'install
            (lambda* (#:key outputs #:allow-other-keys)
              (let ((out (assoc-ref outputs "out")))
                (invoke "make" "install"
                        (string-append "DESTDIR=" out))
                ;; Install SELinux config file
                (mkdir-p (string-append out "/etc/selinux"))
                (call-with-output-file
                    (string-append out "/etc/selinux/config")
                  (lambda (port)
                    (display "# ANDYL OS SELinux Configuration\n" port)
                    (display "# See RFC-0003 section 3.7 for rationale\n" port)
                    (display "SELINUX=enforcing\n" port)
                    (display "SELINUXTYPE=targeted\n" port)))))))
      #:tests? #f))
    (home-page "https://github.com/SELinuxProject/refpolicy")
    (synopsis "SELinux reference targeted policy")
    (description
     "The SELinux reference policy (targeted variant) provides the base set
of type definitions, roles, and mandatory access control rules.  The
targeted policy confines specific daemons and services while leaving
general user sessions in an unconfined domain.  This is the foundation
upon which ANDYL OS-specific policy modules are layered.")
    (license license:gpl2+)))


;;; =========================================================================
;;; andyl-container-selinux -- Container SELinux policy module
;;; =========================================================================
;;;
;;; This package provides the upstream container-selinux policy module
;;; for container runtimes (Podman, containerd, CRI-O).  It defines
;;; standard container SELinux types and access rules used by Kubernetes
;;; and container runtimes:
;;;   container_t           -- domain for container processes
;;;   container_file_t      -- type for container image layers
;;;   container_runtime_t   -- domain for the container runtime daemon
;;;   container_var_lib_t   -- type for container storage
;;;
;;; This is the upstream module from github.com/containers/container-selinux,
;;; compatible with Kubernetes Pod SecurityContext seLinuxOptions.

(define-public andyl-container-selinux
  (package
    (name "andyl-container-selinux")
    (version (config-version "security" "container-selinux"))
    (source (origin
              (method url-fetch)
              (uri (string-append
                    "https://github.com/containers/container-selinux/archive/v"
                    version ".tar.gz"))
              (sha256
               ;; TODO: Compute actual hash:
               ;;   guix download https://github.com/containers/container-selinux/archive/v2.232.1.tar.gz
               (base32 "0000000000000000000000000000000000000000000000000000"))))
    (build-system gnu-build-system)
    (native-inputs (list andyl-gcc andyl-libsepol andyl-libselinux
                         andyl-policycoreutils))
    (inputs (list andyl-glibc andyl-selinux-policy-targeted))
    (arguments
     (list
      #:phases
      #~(modify-phases %standard-phases
          (delete 'configure)
          (replace 'build
            (lambda* (#:key inputs #:allow-other-keys)
              (let ((sepol (assoc-ref inputs "andyl-libsepol")))
                (invoke "make"
                        (string-append "CFLAGS=-I" sepol "/include")
                        (string-append "LDFLAGS=-L" sepol "/lib")))))
          (replace 'install
            (lambda* (#:key outputs #:allow-other-keys)
              (let* ((out (assoc-ref outputs "out"))
                     (policy-dir (string-append out "/etc/selinux/targeted")))
                (invoke "make" "install"
                        (string-append "DESTDIR=" out))))))
      #:tests? #f))
    (home-page "https://github.com/containers/container-selinux")
    (synopsis "Container SELinux policy module")
    (description
     "The container-selinux policy module provides SELinux type definitions
and access rules for container runtimes (Podman, containerd, CRI-O).
Defines container_t, container_file_t, container_runtime_t, and
container_var_lib_t types.  Compatible with Kubernetes Pod SecurityContext
seLinuxOptions and the standard container runtime SELinux integration
used by RHEL, Fedora, and CentOS.")
    (license license:gpl2+)))


;;; =========================================================================
;;; andyl-setools -- SELinux policy analysis tools
;;; =========================================================================
;;;
;;; SETools provides tools for analyzing and querying SELinux policies:
;;;   sesearch   -- search policy rules (allow, type_transition, etc.)
;;;   seinfo     -- query policy components (types, roles, booleans)
;;;   sediff     -- compare two SELinux policies
;;;   seinfoflow -- information flow analysis
;;;   sesearch   -- search and display policy rules
;;;
;;; These tools are essential for policy development, debugging AVC
;;; denials, and verifying that policy meets security requirements.

(define-public andyl-setools
  (package
    (name "andyl-setools")
    (version (config-version "security" "setools"))
    (source (origin
              (method url-fetch)
              (uri (string-append
                    "https://github.com/SELinuxProject/setools/releases/download/"
                    version "/setools-" version ".tar.bz2"))
              (sha256
               ;; TODO: Compute actual hash:
               ;;   guix download https://github.com/SELinuxProject/setools/releases/download/4.5.1/setools-4.5.1.tar.bz2
               (base32 "0000000000000000000000000000000000000000000000000000"))))
    (build-system gnu-build-system)
    (native-inputs (list andyl-gcc))
    (inputs (list andyl-glibc andyl-libsepol andyl-libselinux andyl-libsemanage))
    (arguments
     (list
      #:phases
      #~(modify-phases %standard-phases
          (replace 'build
            (lambda* (#:key inputs #:allow-other-keys)
              (let ((sepol (assoc-ref inputs "andyl-libsepol"))
                    (selinux (assoc-ref inputs "andyl-libselinux"))
                    (semanage (assoc-ref inputs "andyl-libsemanage")))
                (invoke "make" "CC=gcc"
                        (string-append "CFLAGS=-I" sepol "/include"
                                       " -I" selinux "/include"
                                       " -I" semanage "/include")
                        (string-append "LDFLAGS=-L" sepol "/lib"
                                       " -L" selinux "/lib"
                                       " -L" semanage "/lib")
                        "-j" (number->string (parallel-job-count))))))
          (replace 'install
            (lambda* (#:key outputs #:allow-other-keys)
              (let ((out (assoc-ref outputs "out")))
                (invoke "make" "install"
                        (string-append "PREFIX=" out))))))
      #:tests? #f))
    (home-page "https://github.com/SELinuxProject/setools")
    (synopsis "SELinux policy analysis tools")
    (description
     "SETools provides command-line tools for analyzing and querying SELinux
policies: sesearch (search policy rules), seinfo (query policy components
like types, roles, and booleans), sediff (compare policies), and
seinfoflow (information flow analysis).  Essential for policy development,
debugging AVC denials, and verifying security requirements.")
    (license license:gpl2+)))
