# Kubernetes Pods Remote Attestation

## Overview

This project implements a **Remote Attestation** architecture integrated within **Kubernetes-orchestrated** clusters.
It relies on **hardware-based integrity verification** and **trust validation** of **pods** running in the cluster by leveraging **TPM-protected** measurements and authenticated attestation proofs.

The goal is to ensure that workloads are executed on trusted worker nodes and that containerized applications maintain a verifiable chain of integrity throughout their lifecycle.

## Reference

```bibtex
@article{k8s_pod_attestation,
  author       = {Francesco Zaritto and
                  Enrico Bravi and
                  Silvia Sisinni and
                  Antonio Lioy},
  title        = {Extending Kubernetes for Pods Integrity Verification},
  journal      = {Journal of Network and Systems Management},
  volume       = {34},
  number       = {1},
  pages        = {14},
  year         = {2026},
  url          = {https://doi.org/10.1007/s10922-025-09988-z},
  doi          = {10.1007/S10922-025-09988-Z}
}
```

## Design

![architecture-overview](./images/pod-attestation-interactions.png)

