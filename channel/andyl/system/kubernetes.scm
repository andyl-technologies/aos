;;; ANDYL OS -- Kubernetes System Definitions (Re-export Module)
;;; Copyright (C) 2024 ANDYL OS Contributors
;;;
;;; This module re-exports Kubernetes system definitions from the
;;; split system modules for backward compatibility:
;;;
;;;   (andyl system k8s-worker)        -- Kubernetes worker node
;;;   (andyl system k8s-control-plane) -- Kubernetes control plane node
;;;
;;; New code should import the specific modules directly.
;;;
;;; See:
;;;   RFC-0007 (Kubernetes Production Support)
;;;   Phase 7 sections 7.9, 7.10 (Worker and Control Plane Image Variants)

(define-module (andyl system kubernetes)
  #:use-module (andyl system k8s-worker)
  #:use-module (andyl system k8s-control-plane)
  #:re-export (andyl-os-k8s-worker
               andyl-os-k8s-control-plane
               %andyl-k8s-worker-packages
               %andyl-k8s-worker-services
               %andyl-k8s-worker-file-systems
               %andyl-k8s-worker-nftables-config
               %andyl-k8s-control-plane-packages
               %andyl-k8s-control-plane-nftables-config))
