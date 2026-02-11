;;; ANDYL OS -- Security Tests
(define-module (andyl tests security)
  #:use-module (srfi srfi-64)
  #:use-module (andyl config))

(test-begin "security")

;; SELinux config accessible
(test-assert "SELinux enforcing is boolean"
  (boolean? (config-ref "security.selinux.enforcing")))

;; SSH config accessible
(test-assert "SSH port is a number"
  (number? (config-ref "security.ssh.port")))

;; Sysctl values accessible
(test-assert "sysctl alist is available"
  (list? (config-ref/alist "security.sysctl")))

(test-end "security")
