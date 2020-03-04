---
layout: page
title: How does it work
permalink: /demo/
---

##### Demo Setup
- *Hardware : X86 64bit*
- *OS : Ubuntu 18.04 64bit*

##### Demo #1 Solving simple CTF challenge with Qiling Framework and IDAPro
[![qiling DEMO 1: Catching wannacry's killer switch](https://i.ytimg.com/vi/SPjVAt2FkKA/0.jpg)](https://www.youtube.com/watch?v=SPjVAt2FkKA "Video DEMO 1")

##### Demo #2 Catching Wannacry's killer switch
Qiling Framework executes Wannacry binary, hooking address 0x40819a to catch the killerswitch url

[![qiling DEMO 2: Catching wannacry's killer switch](https://img.youtube.com/vi/gVtpcXBxwE8/0.jpg)](https://www.youtube.com/watch?v=gVtpcXBxwE8 "Video DEMO 2")

###### Sample code

```python
from qiling import *

def stopatkillerswtich(ql):
    ql.uc.emu_stop()

if __name__ == "__main__":
    ql = Qiling(["rootfs/x86_windows/bin/wannacry.bin"], "rootfs/x86_windows")
    ql.hook_address(stopatkillerswtich, 0x40819a)
    ql.run()
```

###### Execution output

```
0x1333804: __set_app_type(0x2)
0x13337ce: __p__fmode() = 0x500007ec
0x13337c3: __p__commode() = 0x500007f0
0x132f1e1: _controlfp(0x10000, 0x30000) = 0x8001f
0x132d151: _initterm(0x40b00c, 0x40b010)
0x1333bc0: __getmainargs(0xffffdf9c, 0xffffdf8c, 0xffffdf98, 0x0, 0xffffdf90) = 0
0x132d151: _initterm(0x40b000, 0x40b008)
0x1001e10: GetStartupInfo(0xffffdfa0)
0x104d9f3: GetModuleHandleA(0x00) = 400000
0x125b18e: InternetOpenA(0x0, 0x1, 0x0, 0x0, 0x0)
0x126f0f1: InternetOpenUrlA(0x0, "http://www.iuqerfsodp9ifjaposdfjhgosurijfaewrwergwea.com", "", 0x0, 0x84000000, 0x0)
```
---

##### Demo #3 Hotpatching a Windows crackme
Using Qiling Framework to dynamically patch a Windows crackme binary so that it always displays "Congratulation" dialog

[![qiling DEMO 3: hotpatching a Windows crackme](http://img.youtube.com/vi/p17ONUbCnUU/0.jpg)](https://www.youtube.com/watch?v=p17ONUbCnUU "Video DEMO 3")

###### Sample code

```python
from qiling import *

def force_call_dialog_func(ql):
    # get DialogFunc address
    lpDialogFunc = ql.unpack32(ql.mem_read(ql.sp - 0x8, 4))
    # setup stack memory for DialogFunc
    ql.stack_push(0)
    ql.stack_push(1001)
    ql.stack_push(273)
    ql.stack_push(0)
    ql.stack_push(0x0401018)
    # force EIP to DialogFunc
    ql.pc = lpDialogFunc


def my_sandbox(path, rootfs):
    ql = Qiling(path, rootfs)
    # NOP out some code
    ql.patch(0x004010B5, b'\x90\x90')
    ql.patch(0x004010CD, b'\x90\x90')
    ql.patch(0x0040110B, b'\x90\x90')
    ql.patch(0x00401112, b'\x90\x90')
    # hook at an address with a callback
    ql.hook_address(0x00401016, force_call_dialog_func)
    ql.run()


if __name__ == "__main__":
    my_sandbox(["rootfs/x86_windows/bin/Easy_CrackMe.exe"], "rootfs/x86_windows")
```

###### Execution output

```
0x10cae10: GetStartupInfo(0xffffdf40)
0x1121fa7: GetStdHandle(0xfffffff6) = 0xfffffff6
0x111fbc4: GetFileType(0xfffffff6) = 0x2
0x1121fa7: GetStdHandle(0xfffffff5) = 0xfffffff5
0x111fbc4: GetFileType(0xfffffff5) = 0x2
0x1121fa7: GetStdHandle(0xfffffff4) = 0xfffffff4
0x111fbc4: GetFileType(0xfffffff4) = 0x2
0x1121fd1: SetHandleCount(0x20) = 32
0x1121fbf: GetCommandLineA() = 0x501091b8
0x111fcd4: GetEnvironmentStringsW() = 0x501091e4
0x1117ffa: WideCharToMultiByte(0x0, 0x0, 0x501091e4, 0x1, 0x0, 0x0, 0x0, 0x0) = 2
0x1117ffa: WideCharToMultiByte(0x0, 0x0, 0x501091e4, 0x1, 0x50002098, 0x2, 0x0, 0x0) = 1
0x111fcbc: FreeEnvironmentStringsW(0x501091e4) = 1
0x1116a0b: GetACP() = 437
0x1121f8f: GetCPInfo(0x1b5, 0xffffdf44) = 1
0x1121f8f: GetCPInfo(0x1b5, 0xffffdf1c) = 1
0x111e43e: GetStringTypeW(0x1, 0x40541c, 0x1, 0xffffd9d8) = 0
0x10ffc95: GetStringTypeExA(0x0, 0x1, 0x405418, 0x1, 0xffffd9d8) = 0
0x111e39c: LCMapStringW(0x0, 0x100, 0x40541c, 0x1, 0x0, 0x0) = 0
0x1128a50: LCMapStringA(0x0, 0x100, 0x405418, 0x1, 0x0, 0x0) = 0
0x111e39c: LCMapStringW(0x0, 0x100, 0x40541c, 0x1, 0x0, 0x0) = 0
0x1128a50: LCMapStringA(0x0, 0x100, 0x405418, 0x1, 0x0, 0x0) = 0
0x111685a: GetModuleFileNameA(0x0, 0x40856c, 0x104) = 42
0x10cae10: GetStartupInfo(0xffffdfa0)
0x11169f3: GetModuleHandleA(0x00) = 400000
0x104cf42: DialogBoxParamA(0x400000, 0x65, 0x00, 0x401020, 0x00) = 0
Input DlgItemText :

        << enter any string or number here >>

0x1063d14: GetDlgItemTextA(0x00, 0x3e8, 0xffffdef4, 0x64) = 3
0x105ea11: MessageBoxA(0x00, "Congratulation !!", "EasyCrackMe", 0x40) = 2
0x1033ba3: EndDialog(0x00, 0x00) = 1
0x1124d12: ExitProcess(0x01)
```
