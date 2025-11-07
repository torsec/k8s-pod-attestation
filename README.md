# Kubernets Pods Remote Attestation

## Overview

This project implements a **Remote Attestation** architecture integrated within **Kubernetes-orchestrated** clusters.
It relies on **hardware-based integrity verification** and **trust validation** of **pods** running in the cluster by leveraging **TPM-protected** measurements and authenticated attestation proofs.

The goal is to ensure that workloads are executed on trusted worker nodes and that containerized applications maintain a verifiable chain of integrity throughout their lifecycle.

## Reference

[**"Hardware-Based Remote Attestation for Kubernetes Workloads"** — Springer Journal of Network and Systems Management (2025)](https://link.springer.com/article/10.1007/s10922-025-09988-z)

## Design


![architecture-overview](./images/pod-attestation-interactions.png)

