<h1>Threat, Research and Workaround</h1>
The insecurity of smart Internet-connected or so-called “IoT” devices has become more concerning than ever. The existence of malware exploiting vulnerable, often poorly secured and configured Internet-facing devices has been known for many years. Hardware vendors and the entire security industry are struggling to fight the adversaries while trying to build better and safer products. Unfortunately, IoT threats and malware analysis remain the two biggest challenges in the security industry.

Modern IoT threats and malware are moving towards various platforms and CPU architecture. Reverse engineers are struggling to cope and understand different operating systems and CPU architecture. Besides, lack of updated tools makes the situation worse. Current available tools are nowhere near to catch up with the speed of fast-growing security threat.

Common techniques used to perform analysis such as full system emulation, user-mode emulation, binary instrumentation, disassembler and sandboxing are just barely sufficient. These tools are either serving single type operating system or works on one CPU architecture. Also, these tools need to be used separately, streamlining information or cross referencing data is almost impossible. These are the reasons why reverse engineering is never an easy task.

* [1] Research from SonicWall has revealed that a record high of 10.52bn malware attacks occurred in 2018 indicating an escalation in the volume of cyberattacks as well as new targeted threat tactics used by cybercriminals

---
<h1>Solution</h1>
Qiling Framework is aimed to change IoT security research, malware analysis and reverse engineering landscape. The main objective is to build a cross-platform and multi-architecture framework and not just another reverse engineering tool. 

Qiling Framework is designed as a binary instrumentation and binary emulation framework that supports cross-platform and multi-architecture. It is packed with powerful features such as code interception and arbitrary code injection before or during a binary execution. It is also able to patch a packed binary during execution.

Qiling Framework is open source and it is written in Python, a simple and commonly used programming language. This will encourage continuous contributions from the security and open-source community. Hence, making the Qiling Framework a sustainable project.

---
<h1>What is Qiling Framework</h1>
Qiling Framework is not just an emulation platform or a reverse engineering tool. It combines binary instrumentation and binary emulation into one single framework. With Qiling Framework, it able to:

  - Redirect process execution flow on the fly
  - Hot-patching binary during execution
  - Code injection during execution
  - Partial binary execution, without running the entire file
  - Patch a "unpacked" content of a packed binary file

Qiling Framework is able to emulate: 
  - Windows X86 32/64bit
  - Linux X86 32/64bit, ARM, AARCH64, MIPS
  - MacOS X86 32/64bit
  - FreeBSD X86 32/64bit
  - UEFI

Qiling Framework is able to run on top of Linux/FreeBSD/MacOS/Windows(WSL) without CPU architecture limitation

---

<h1>How Qiling Framework Works</h1>
##### Demo Setup

  - *Hardware : X86 64bit*
  - *OS : Ubuntu 18.04 64bit*

##### Demo #1 Solving simple CTF challenge with Qiling Framework and IDAPro
Mini Qiling Framework tutorial : how to work with IDAPro

[![qiling DEMO 1: Catching wannacry's killer switch](https://raw.githubusercontent.com/qilingframework/qilingframework.github.io/master/images/demo1-en.jpg)](https://www.youtube.com/watch?v=SPjVAt2FkKA "Video DEMO 1")

---
##### Demo #2 Fuzzing with Qiling Unicornalf
More information on fuzzing with Qiling can be found [here](https://github.com/qilingframework/qiling/tree/dev/examples/fuzzing/README.md).

[![qiling DEMO 2: Fuzzing with Qiling Unicornalf](https://raw.githubusercontent.com/qilingframework/qilingframework.github.io/master/images/qilingfzz-s.png)](https://github.com/qilingframework/qiling/blob/dev/examples/fuzzing/qilingfzz.png "Demo #2 Fuzzing with Qiling Unicornalf")


---
##### Demo #3 Emulating ARM router firmware on Ubuntu X64 machine
Qiling Framework hot-patch and emulates ARM router's /usr/bin/httpd on a X86_64Bit Ubuntu

[![qiling DEMO 3: Fully emulating httpd from ARM router firmware with Qiling on Ubuntu X64 machine](https://raw.githubusercontent.com/qilingframework/qilingframework.github.io/master/images/demo3-en.jpg)](https://www.youtube.com/watch?v=Nxu742-SNvw "Demo #3 Emulating ARM router firmware on Ubuntu X64 machine")

```python
from qiling import *
def my_sandbox(path, rootfs):
    ql = Qiling(path, rootfs, stdin = sys.stdin, stdout = sys.stdout, stderr = sys.stderr)
    # Patch 0x00005930 from br0 to ens33
    ql.patch(0x00005930, b'ens33\x00', file_name = b'libChipApi.so')
    ql.root = False
    ql.run()


if __name__ == "__main__":
    my_sandbox(["rootfs/tendaac15/bin/httpd"], "rootfs/tendaac15")
```
---
##### Demo #4 Emulating UEFI
Qiling Framework emulates UEFI

[![qiling DEMO 4: Emulating UEFI](https://raw.githubusercontent.com/qilingframework/qilingframework.github.io/master/images/demo4-s.png)](https://raw.githubusercontent.com/qilingframework/qilingframework.github.io/master/images/demo4-en.png "Demo #4 Emulating UEFI")

```python
import sys
import pickle
sys.path.append("..")
from qiling import *
from qiling.os.uefi.const import *

def force_notify_RegisterProtocolNotify(ql, address, params):
    event_id = params['Event']
    if event_id in ql.loader.events:
        ql.loader.events[event_id]['Guid'] = params["Protocol"]
        # let's force notify
        event = ql.loader.events[event_id]
        event["Set"] = True
        ql.loader.notify_list.append((event_id, event['NotifyFunction'], event['NotifyContext']))
        ######
        return EFI_SUCCESS
    return EFI_INVALID_PARAMETER


if __name__ == "__main__":
    with open("rootfs/x8664_efi/rom2_nvar.pickel", 'rb') as f:
        env = pickle.load(f)
    ql = Qiling(["rootfs/x8664_efi/bin/TcgPlatformSetupPolicy"], "rootfs/x8664_efi", env=env)
    ql.set_api("hook_RegisterProtocolNotify", force_notify_RegisterProtocolNotify)
    ql.run()
```
