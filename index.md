---
layout: home
title: What is Qiling Framework (in a nutshell)
---

<p align="center">
<img width="150" height="150" src="{{ site.baseurl }}/images/qiling_small.png">
</p>

---

- Qiling Framework is not only an emulataion tool. It combines binary instrumentation and binary emulation into one single framework. Its features include
    - **Redirect process execution flow on the fly**
    - **Hot-patching binary during execution**
    - **Code injection during execution**
    - **Partial binary execution, without running the entire file**
    - **Patch a "unpacked" content of a packed binary file**
- Qiling Framework emulates 
    - **Windows X86 32/64bit**
    - **Linux X86 32/64bit, ARM, AARCH64, MIPS**
    - **MacOS X86 32/64bit**
    - **FreeBSD X86 32/64bit**
- Qiling Framework able to run on top of Windows/MacOS/Linux/FreeBSD without CPU architecture limitation

---

### What is missing in reverse engineering world
The insecure Internet of Things (IoT) devices and malware attack are growing and they are affecting our day-to-day life. The security industry is struggling to safeguard and cope with such growth and attacks. Abominably, IoT firmware and malware sample analysis remain the two biggiest challanges for the security industry.

The attack surface swifts quickly as the IoT devices and malware are moving towards different platform (Operatiing System) and CPU archirecture. Reverse engineers are not only struggling to understand each operating systems and cpu architecture, but more discouragingly there is lack of tools to perform indept analysis.

Common techniques of analysis such as full emulation, usermode emulation, binary instrumentation tool, disassembler and sandboxing are ancient and obsolete. These tools are either limited in cross platform support or CPU architecture support.

---

### Why Qiling Framework
Qiling Framework is aimed to change IoT research, threat analysis and reverse engineering technique. The main objective is to build a framework and not just engineer another tool. It is designed for easy application, intended to serve future expansion and open-sourced to allow customization. Hence, sustainable future development could be benefited from the work of the community.

By design, Qiling Framework runs on different types of platforms and supports as many CPU architures as possible. As such, Python, a simple and commonly used programming language by reverse engineers, is chosen as fundamental language for Qiling Framework's development.

Qiling Framework is designed as a binary instrumentation and binary emulation framework that supports cross-platform and multi-architecture targets. It is also packed with powerful features such as code interception and arbitary code injection before or during a binary execution and hotpatching packed binary.