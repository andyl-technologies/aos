;;; ANDYL OS -- Package Tests
(define-module (andyl tests packages)
  #:use-module (srfi srfi-64)
  #:use-module (guix packages)
  #:use-module (andyl config)
  #:use-module (andyl packages gcc)
  #:use-module (andyl packages glibc)
  #:use-module (andyl packages linux)
  #:use-module (andyl packages base)
  #:use-module (andyl packages kernel)
  #:use-module (andyl packages systemd)
  #:use-module (andyl packages containerd)
  #:use-module (andyl packages kubernetes))

(test-begin "packages")

;; Verify packages are loadable and have correct structure
(test-assert "andyl-gcc is a package"
  (package? andyl-gcc))

(test-assert "andyl-glibc is a package"
  (package? andyl-glibc))

(test-assert "andyl-linux-headers is a package"
  (package? andyl-linux-headers))

(test-assert "andyl-kernel is a package"
  (package? andyl-kernel))

;; Verify versions come from config
(test-equal "GCC version matches config"
  (config-version "toolchain" "gcc")
  (package-version andyl-gcc))

(test-equal "glibc version matches config"
  (config-version "toolchain" "glibc")
  (package-version andyl-glibc))

(test-equal "kernel version matches config"
  (config-version "kernel" "linux")
  (package-version andyl-kernel))

;; Verify base packages exist
(test-assert "andyl-coreutils is a package"
  (package? andyl-coreutils))

(test-assert "andyl-bash is a package"
  (package? andyl-bash))

;; K8s packages
(test-assert "andyl-containerd is a package"
  (package? andyl-containerd))

(test-assert "andyl-kubelet is a package"
  (package? andyl-kubelet))

(test-end "packages")
