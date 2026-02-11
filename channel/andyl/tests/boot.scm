;;; ANDYL OS -- Boot Configuration Tests
(define-module (andyl tests boot)
  #:use-module (srfi srfi-64)
  #:use-module (andyl config))

(test-begin "boot")

;; Kernel args
(test-assert "boot kernel-args base is a list"
  (list? (config-ref/list "boot.kernel-args.base")))

;; Partition sizes
(test-assert "root partition size is a number"
  (number? (config-ref "boot.partitions.root-mib")))

(test-assert "ESP partition size is a number"
  (number? (config-ref "boot.partitions.esp-mib")))

;; Filesystem labels
(test-assert "root label is a string"
  (string? (config-ref "boot.filesystem.root-label")))

(test-end "boot")
