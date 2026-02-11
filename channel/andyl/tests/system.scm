;;; ANDYL OS -- System Definition Tests
(define-module (andyl tests system)
  #:use-module (srfi srfi-64)
  #:use-module (andyl system base)
  #:use-module (andyl config))

(test-begin "system")

;; System record exists
(test-assert "andyl-os-base is defined"
  (andyl-operating-system? andyl-os-base))

;; Kernel arguments include expected entries
(test-assert "base kernel arguments is a list"
  (list? %andyl-base-kernel-arguments))

(test-assert "kernel args include root="
  (any (lambda (arg) (string-prefix? "root=" arg))
       %andyl-base-kernel-arguments))

;; File systems defined
(test-assert "base file systems is a list"
  (list? %andyl-base-file-systems))

(test-end "system")
