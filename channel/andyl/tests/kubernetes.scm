;;; ANDYL OS -- Kubernetes Configuration Tests
(define-module (andyl tests kubernetes)
  #:use-module (srfi srfi-64)
  #:use-module (andyl config))

(test-begin "kubernetes")

;; K8s versions
(test-assert "kubelet version is a string"
  (string? (config-version "kubernetes" "kubelet")))

(test-assert "containerd version is a string"
  (string? (config-version "kubernetes" "containerd")))

;; Firewall config
(test-assert "worker TCP ports is a list"
  (list? (config-ref/list "kubernetes.firewall.worker-tcp")))

;; Modules
(test-assert "kernel modules to load is a list"
  (list? (config-ref/list "kubernetes.modules.load")))

(test-end "kubernetes")
