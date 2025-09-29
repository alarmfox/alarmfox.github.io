+++
title = "Writing a RISCV Hypervisor"
date = "2025-09-12T22:18:53+02:00"
#dateFormat = "2006-01-02" # This value can be configured for per-post date formatting
author = "alarmfox"
authorTwitter = "" #do not include @
cover = ""
tags = ["riscv", "virtualization", "hypervisor"]
keywords = ["riscv", "virtualization", "hypervisor", "rust"]
description = ""
showFullContent = false
readingTime = true
hideComments = false
draft = true
+++

# Introduction
Currently, my reasearch focus is on RISC-V and the CoVE [1] specification. Shortly, the CoVE specification
talks virtualization-based Confidential Computing and specifies what services the firmware 
(the TSM-driver, TSM stands for TEE Security Manager) should offer to upper level software (ie. an OS
or an hypervisor). The TSM-driver orchestrates different TSMs which are some software that mix up
hypervisor and security functionalities.


## Confidential Computing in RISC-V
There is not a clear definition of confidential computing. My favourite one is "the set of methodologies
and techniques which implement a Trusted Execution Environment (TEE)".

There are different ways to create a virtual machine in CoVE:
- use a multi-step approach (this is my target): create the object TVM, configure the pages, *load* the
guest code (and other stuff in guest memory), create a virtual CPU, boot the VM
- migrate an existing VM (not my target)

The main idea behind all these virtualization-based Confidential Computing solutions (like ARM CCA, TDX)
is to partition the system in separated spaces (someone leverages crypto-accelerators) and to rely on low-level 
software that assures this model. Moreover, some assurance must be given on the authenticity on the whole platform
(this is out-of-scope for this post).

CoVE does something similar. It allows two different models (one more static relying on Physical Memory Protection or PMP)
the other more dynamic (based on another hardware component called Memory Tracking Table or MTT) partitiong 
the platform.

CoVE proposes a communication model (through context switches) between different domains using a trusted 
component (the firmware, TSM-driver) and TSM. An untrusted domain (which runs a regular OS) can 
perform a request to another domain and this is 
routed to destination thanks to the TSM-driver.

# Goal
I don't want to write a fully fledged "hypervisor" like KVM, Virtual Box and others. I want to create a
minimal reproducible program that creates a "guest" and possibly automating the process. It is clear that
_virtualization_ is something very tied to the hardware architecture.

All the reasoning below is based on the following assumptions:
- use the Privilege ISA Version v1.12
- use a single physical core (theoretically I should call this **hart**)

All my doubts are as follows:

- Understand the real role of TSM and TSM-driver: should the TSM-driver be aware of every TVM? 
Does the TSM need to be a real hypervisor?
- Implement a small **SV39** page table system: how do i define a page table entry (PTE)? 
How do i walk a Guest Virtual Address (GVA) to a Host Physical Address (HPA)?
- How do I create a vCPU (or should i say vHart) and map it to the physical core?
- How do I spawn a VM in another domain?

# References
[1] CoVE specification: https://github.com/riscv-non-isa/riscv-ap-tee
