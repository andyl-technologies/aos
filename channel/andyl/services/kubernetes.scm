;;; ANDYL OS -- Kubernetes Service Definitions (Re-export Module)
;;; Copyright (C) 2024 ANDYL OS Contributors
;;;
;;; This module re-exports Kubernetes service definitions from the
;;; split service modules for backward compatibility:
;;;
;;;   (andyl services containerd) -- containerd systemd service and config
;;;   (andyl services kubelet)    -- kubelet systemd service and sysctl
;;;
;;; New code should import the specific modules directly.
;;;
;;; See:
;;;   RFC-0007 sections 2, 4 (CRI Setup, Kubelet on Immutable OS)
;;;   Phase 7 sections 7.6, 7.7 (containerd and kubelet Configuration)

(define-module (andyl services kubernetes)
  #:use-module (andyl services containerd)
  #:use-module (andyl services kubelet)
  #:re-export (%andyl-containerd-service-unit
               %andyl-containerd-config-toml
               %andyl-containerd-tmpfiles
               %andyl-containerd-modules-load
               andyl-containerd-units
               %andyl-kubelet-service-unit
               %andyl-k8s-sysctl-settings
               %andyl-kubelet-tmpfiles
               andyl-kubelet-units))


;;;
;;; Combined unit files
;;;
;;; Returns all Kubernetes-related units from both containerd and kubelet
;;; service modules.
;;;

(define-public (andyl-kubernetes-units)
  "Return an alist of (filename . content) pairs for all systemd unit
files, sysctl, tmpfiles.d, and modules-load.d configuration for
Kubernetes on ANDYL OS."
  (append (andyl-containerd-units)
          (andyl-kubelet-units)))
