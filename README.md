# Kubernets Pods Remote Attestation

## Overview

This project implements a **Remote Attestation** architecture integrated within **Kubernetes-orchestrated** clusters.
It relies on **hardware-based integrity verification** and **trust validation** of **pods** running in the cluster by leveraging **TPM-protected** measurements and authenticated attestation proofs.

The goal is to ensure that workloads are executed on trusted worker nodes and that containerized applications maintain a verifiable chain of integrity throughout their lifecycle.

## Reference

Zaritto, F., Bravi, E., Sisinni, S. *et al.* (2026). **Extending Kubernetes for Pods Integrity Verification.** *Journal of Network and Systems Management*, 34, 14. [https://doi.org/10.1007/s10922-025-09988-z](https://doi.org/10.1007/s10922-025-09988-z)

## Design

![architecture-overview](./images/pod-attestation-interactions.png)

