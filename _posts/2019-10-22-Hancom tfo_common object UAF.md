---
published: false
categories: [vulnerability,Hancom]
tags: [vulnerability,Hancom,bodystream,CVE-2019-16338]
---

### Affected Software
~~~shell
0:000> lmvm HwordAPP
Browse full module list
start    end        module name
6f250000 705da000   HwordApp   (export symbols)       C:\Program Files (x86)\Hnc\Office NEO\HOffice96\Bin\HwordApp.dll
    Loaded symbol image file: C:\Program Files (x86)\Hnc\Office NEO\HOffice96\Bin\HwordApp.dll
    Image path: C:\Program Files (x86)\Hnc\Office NEO\HOffice96\Bin\HwordApp.dll
    Image name: HwordApp.dll
    Browse all global symbols  functions  data
    Timestamp:        Tue May 21 10:48:44 2019 (5CE3670C)
    CheckSum:         0136D9FA
    ImageSize:        0138A000
    Translations:     0000.04b0 0000.04e4 0409.04b0 0409.04e4
    Information from resource tables:
~~~

### Product Background
Hancom Office is the only Office software you need to edit in a variety of formatsand translate into many languages,all from wherever you are.
It is widely used in Korean.

### Vulnerability Details
Although CVE is assigned with CVE-2019-16338 but the vendor hasn't fixed this bug till 2019-10

This vulnerability was discovered within the hwordapp.dll which is part of the Hangul Office Suite. Hangul Office is published by Hancom, Inc. and is considered one of the more popular Office suites used within South Korea. When opening a craft document, hwordapp doesn't properly process a tfo_common object which will cause a UAF problem, this problem may lead to code execution under the context of the application.

Crash Context

~~~shell
eax=f0f0f0f0 ebx=0000004b ecx=7a1ae440 edx=00780000 esi=7a1a0320 edi=7a1a0320
eip=6fe01a41 esp=006f849c ebp=006f84a4 iopl=0         nv up ei pl nz na pe nc
cs=0023  ss=002b  ds=002b  es=002b  fs=0053  gs=002b             efl=00210206
HwordApp!HwordDeletePropertyArray+0xb73da1:
6fe01a41 ff10            call    dword ptr [eax]      ds:002b:f0f0f0f0=????????
~~~

Malloc

~~~shell
bp hwordapp+0x0BBA502
~~~



Free

~~~shell
bp hwordapp+0x00304669
~~~



Reuse

~~~shell
bp hwordapp+0xBB1A41

0:000> kb
 # ChildEBP RetAddr  Args to Child              
WARNING: Stack unwind information not available. Following frames may be wrong.
00 011b8314 702c989f 061f9370 ae17e673 011b84a4 HwordApp!HwordDeletePropertyArray+0xb73da1
01 011b83e0 6fa84e01 011b8474 011b84a4 011b8444 HwordApp!HwordDeletePropertyArray+0xb7bbff
02 011b83fc 7037fb94 011b8474 011b84a4 011b8444 HwordApp!HwordDeletePropertyArray+0x337161
03 011b84fc 7035384b 011bbf24 6fa382b5 ae17da7f HwordApp!HwordDeletePropertyArray+0xc31ef4
04 011bbfec 6fd07707 ae17a5e3 20d2cff8 00000000 HwordApp!HwordDeletePropertyArray+0xc05bab
05 011bc070 6f9c696e 111d2fa8 011bc0d0 111c4fdc HwordApp!HwordDeletePropertyArray+0x5b9a67
06 011bc098 6f9c527a 31c34fe8 011bc0d0 111c4fdc HwordApp!HwordDeletePropertyArray+0x278cce
07 011bc16c 6f7677a3 00000000 72c28fd0 011bc2a0 HwordApp!HwordDeletePropertyArray+0x2775da
08 011bc4f4 00d8a08b 65436fa0 011bc6cc 00000000 HwordApp!HwordDeletePropertyArray+0x19b03
09 011bd934 00d8b9dc 65436fa0 00000000 65436fa0 Hword!CHncAppShield::operator=+0x586cb
0a 011bd984 00d895e4 65436fa0 00000000 011bdc28 Hword!CHncAppShield::operator=+0x5a01c
0b 011bdc28 00d8896a 65436fa0 00000000 00000000 Hword!CHncAppShield::operator=+0x57c24
0c 011bf2e0 00cfa917 011bf348 ee071d33 77eb8fd0 Hword!CHncAppShield::operator=+0x56faa
0d 011bf320 00e8aa17 011bf348 ee071c83 21a39f78 Hword+0xa917
0e 011bf340 00e0b7d1 77ebafd8 011bf4a0 6f8ab66c Hword!CHncAppShield::operator=+0x159057
0f 011bf34c 6f8ab66c 77eb8fe8 77ebafd8 ae179133 Hword!CHncAppShield::operator=+0xd9e11
10 011bf4a0 6f8ab52b 011bf500 ae17914f 22700c08 HwordApp!HwordDeletePropertyArray+0x15d9cc
11 011bf4dc 6f7317e4 0f76df30 011bf500 22700c08 HwordApp!HwordDeletePropertyArray+0x15d88b
12 011bf4f0 00d84593 0f76df30 011bf500 0000d11a HwordApp!HwordCreateActionImpl+0x124
13 011bf508 00d8635b 0000d11a 0000d216 000009ff Hword!CHncAppShield::operator=+0x52bd3
14 011bf51c 00d8645f 22700c08 0001d11a 71c79f9b Hword!CHncAppShield::operator=+0x5499b
15 011bf538 00d94167 00000001 0001d11a 0001d11a Hword!CHncAppShield::operator=+0x54a9f
16 011bf574 00d0d860 000b06ae 00000111 0001d11a Hword!CHncAppShield::operator=+0x627a7
17 011bf5c8 7498be5b 000b06ae 00000111 011bf994 Hword+0x1d860
~~~

object size:0xA8


#### PoC


### Timeline
2018-05-27 Discovered
