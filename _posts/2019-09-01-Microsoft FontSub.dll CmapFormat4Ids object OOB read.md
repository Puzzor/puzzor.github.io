---
published: true
categories: [vulnerability,microsoft]
tags: [vulnerability,microsoft,cve-2019-1148,fontsub]
---
## Microsoft FontSub.dll CmapFormat4Ids object OOB read

### Affected Software
~~~shell
0:000> lmvm fontsub
start    end        module name
729c0000 729d5000   FONTSUB    (pdb symbols)          C:\Users\Puzzor\Desktop\Debugging
    Loaded symbol image file: C:\Windows\system32\FONTSUB.dll
    Image path: C:\Windows\SysWOW64\FONTSUB.dll
    Image name: FONTSUB.dll
    Timestamp:        Sun Apr 14 13:39:52 2019 (5CB2C7A8)
    CheckSum:         0001CBD1
    ImageSize:        00015000
    File version:     6.1.7601.24439
    Product version:  6.1.7601.24439
    File flags:       0 (Mask 3F)
    File OS:          40004 NT Win32
    File type:        2.0 Dll
    File date:        00000000.00000000
    Translations:     0409.04b0
    Information from resource tables:
        CompanyName:      Microsoft Corporation
        ProductName:      Microsoft® Windows® Operating System
        InternalName:     fontsub
        OriginalFilename: fontsub
        ProductVersion:   6.1.7601.24439
        FileVersion:      6.1.7601.24439 (win7sp1_ldr.190413-2027)
        FileDescription:  Font Subsetting DLL
        LegalCopyright:   © Microsoft Corporation. All rights reserved.
~~~
### Product Background
The Microsoft Font Subsetting DLL (fontsub.dll) is a default Windows helper library for subsetting TTF fonts.

### Vulnerability Details
CVE-2019-1148
During our analysis, we found a OOB read problem in 
GetGlyphIdx function, the comparison at 0x100069C3 is not enough, which may cause out of bound read.

Crash context:
~~~assembly
0:000> g
(820.a38): Access violation - code c0000005 (first chance)
First chance exceptions are reported before any exception handling.
This exception may be expected and handled.
eax=0527b968 ebx=00000009 ecx=ffffff2d edx=0527d190 esi=05270030 edi=00000030
eip=729c69ca esp=002ff294 ebp=002ff2a4 iopl=0         nv up ei ng nz na pe nc
cs=0023  ss=002b  ds=002b  es=002b  fs=0053  gs=002b             efl=00010286
FONTSUB!GetGlyphIdx+0x80:
729c69ca 0fb70c4a        movzx   ecx,word ptr [edx+ecx*2] ds:002b:0527cfea=????
~~~
We can see edx points to a block of memory allocated in ReadAllocCmapFormat4Ids function, and ecx is a negative value, which we consider it should be a positive one(we will discuss this later), this negative value will cause out of bound read.
~~~shell
0:000> !heap -p -a edx
    address 0527d190 found in
    _DPH_HEAP_ROOT @ 5261000
    in busy allocation (  DPH_HEAP_BLOCK:         UserAddr         UserSize -         VirtAddr         VirtSize)
                                 5261cfc:          527d190            1fe6e -          527d000            21000
    729e8e89 verifier!AVrfDebugPageHeapAllocate+0x00000229
    77730fe6 ntdll!RtlDebugAllocateHeap+0x00000030
    776eab8e ntdll!RtlpAllocateHeap+0x000000c4
    77693461 ntdll!RtlAllocateHeap+0x0000023a
    76ac9d45 msvcrt!malloc+0x0000008d
    729c651b FONTSUB!Mem_Alloc+0x0000000e
    729c6a8d FONTSUB!ReadAllocCmapFormat4Ids+0x0000004e
    729c6d98 FONTSUB!ReadAllocCmapFormat4+0x000000ce
    729cc4a1 FONTSUB!MakeKeepGlyphList+0x000003e1
    729c27ea FONTSUB!CreateDeltaTTFEx+0x0000010f
    729c2edc FONTSUB!CreateDeltaTTF+0x000001e7
    729c1421 FONTSUB!CreateFontPackage+0x000000e1
~~~
The compare between ecx and edx is around the crash point, if ecx is greater or equal to edx, a jmp will be made, otherwise, the crash point will be executed.
When we set a breakpoint at this compare, we can observe the value of edx:
~~~shell
0:000>
eax=0072b968 ebx=00000009 ecx=ffffff2d edx=0000ff37 esi=00720030 edi=00000030
eip=726f69c3 esp=003df65c ebp=003df66c iopl=0         nv up ei ng nz na pe nc
cs=0023  ss=002b  ds=002b  es=002b  fs=0053  gs=002b             efl=00000286
FONTSUB!GetGlyphIdx+0x79:
726f69c3 3bca            cmp     ecx,edx
~~~
From above, we can see that edx is 0xff37, and we can easily calculate that edx*2 is 0x1fe6e, this value is just the size of the memory allocated in ReadAllocCmapFormat4Ids, then we infer that this compare is to make sure the read will not cause a out of bounds. But in our case, ecx is a negative, which will cause an OOB read.

HOW ECX COMES INTO NEGATIVE?

We can see ecx is set at 0x100069A3:
~~~shell
eax=0528b968 ebx=00000009 ecx=0528b968 edx=00000001 esi=05280030 edi=000006a0
eip=743969a3 esp=002ef350 ebp=002ef360 iopl=0         nv up ei pl nz na pe nc
cs=0023  ss=002b  ds=002b  es=002b  fs=0053  gs=002b             efl=00000206
FONTSUB!GetGlyphIdx+0x59:
743969a3 8bc8            mov     ecx,eax
0:000> !heap -p -a eax
    address 0528b968 found in
    _DPH_HEAP_ROOT @ 5271000
    in busy allocation (  DPH_HEAP_BLOCK:         UserAddr         UserSize -         VirtAddr         VirtSize)
                                 5271d30:          528b960              6a0 -          528b000             2000
          unknown!printable
    74068e89 verifier!AVrfDebugPageHeapAllocate+0x00000229
    77730fe6 ntdll!RtlDebugAllocateHeap+0x00000030
    776eab8e ntdll!RtlpAllocateHeap+0x000000c4
    77693461 ntdll!RtlAllocateHeap+0x0000023a
    76ac9d45 msvcrt!malloc+0x0000008d
    7439651b FONTSUB!Mem_Alloc+0x0000000e
    74396b0a FONTSUB!ReadAllocCmapFormat4Segs+0x0000002e
    74396d71 FONTSUB!ReadAllocCmapFormat4+0x000000a7
    7439c4a1 FONTSUB!MakeKeepGlyphList+0x000003e1
    743927ea FONTSUB!CreateDeltaTTFEx+0x0000010f
    74392edc FONTSUB!CreateDeltaTTF+0x000001e7
    74391421 FONTSUB!CreateFontPackage+0x000000e1
~~~

Let's set a breakpoint at 100069B8, with our PoC, edx is 0, then after add ecx,edx, ecx is still negative. But with the normal file, edx is 0xd4, then let's see why edx is not big enough to make ecx a positive value.

Edx comes from 0x10006985, then we will set a breakpoint at 0x10006985, after some analysis, we confirm that eax+6 comes from the offset of 0x25A6 in the PoC file: in our case, the value at offset 0x25A6 in the PoC is  0x0001. Let's change it to 0x4141 and run it again:
~~~shell
eax=008fb968 ebx=00000009 ecx=008fb968 edx=00040030 esi=008f0030 edi=000000d4
eip=743a6985 esp=002ef444 ebp=002ef454 iopl=0         nv up ei pl nz na po nc
cs=0023  ss=002b  ds=002b  es=002b  fs=0053  gs=002b             efl=00000202
FONTSUB!GetGlyphIdx+0x3b:
743a6985 0fb75006        movzx   edx,word ptr [eax+6]     ds:002b:008fb96e=4141
0:000> dd eax
008fb968  00300039 4141040f 003a0040 01a80000
008fb978  0041005a 0000ffc1 005b0060 01c40000
008fb988  0061007a 0000ffbb 007b007e 01ce0000
008fb998  00a0017e 00000000 01800180 01d6ff91
008fb9a8  018f018f 01dcff66 01920193 00000000
008fb9b8  01a001a1 00000000 01af01b0 03940000
008fb9c8  01c201c2 0396003e 01cd01dc 03980000
008fb9d8  01e201e3 00000000 01e601e7 03980000
~~~
EDX can be controlled here, we guess that if we can change edx to a smaller value and not equal to 0, we may cause the crash.

To verify our hypothesis, we will just modify the original normal file, we will just try to modify only 2 bytes to see if we can cause the crash: 

We just change the value at offset 0x25A4 in the normal file:  change it from 0x01A8 to 0x0001. Let's compare the results:
~~~shell
0:000> g
##########
Breakpoint at fontsub+0x6985 hits
eax=0505b960 ebx=00000001 ecx=0505b960 edx=00000022 esi=05050022 edi=000000d4
eip=73d26985 esp=002bf6a8 ebp=002bf6b8 iopl=0         nv up ei pl nz na pe nc
cs=0023  ss=002b  ds=002b  es=002b  fs=0053  gs=002b             efl=00000206
FONTSUB!GetGlyphIdx+0x3b:
73d26985 0fb75006        movzx   edx,word ptr [eax+6]     ds:002b:0505b966=01a8
~~~
~~~shell
0:000> g
##########
Breakpoint at fontsub+0x6985 hits
eax=0085b960 ebx=00000001 ecx=0085b960 edx=00000022 esi=00850022 edi=000000d4
eip=743a6985 esp=0037f084 ebp=0037f094 iopl=0         nv up ei pl nz na pe nc
cs=0023  ss=002b  ds=002b  es=002b  fs=0053  gs=002b             efl=00000206
FONTSUB!GetGlyphIdx+0x3b:
743a6985 0fb75006        movzx   edx,word ptr [eax+6]     ds:002b:0085b966=0001
~~~
For the modified normal file, when we continue to run the program, it will cause a crash too
~~~shell
0:000> g
(c40.3a4): Access violation - code c0000005 (first chance)
First chance exceptions are reported before any exception handling.
This exception may be expected and handled.
eax=0085b960 ebx=00000001 ecx=ffffff2e edx=0085d188 esi=00850022 edi=00000020
eip=743a69ca esp=0037f084 ebp=0037f094 iopl=0         nv up ei ng nz na po nc
cs=0023  ss=002b  ds=002b  es=002b  fs=0053  gs=002b             efl=00010282
FONTSUB!GetGlyphIdx+0x80:
743a69ca 0fb70c4a        movzx   ecx,word ptr [edx+ecx*2] ds:002b:0085cfe4=????
~~~
Finally we can make a conclusion that in GetGlyphIdx function, the comparison at 0x100069C3 is not enough, which may cause out of bound read.

#### PoC
[PoC Link](https://github.com/Puzzor/puzzor.github.io/raw/master/_posts/assests/CVE-2019-1148.PoC.bin)
### Timeline
2019.07.29 Found the crash and started analysis

2019.08.16 Microsoft released a patch and this bug is killed by jr00u too: [Link](https://bugs.chromium.org/p/project-zero/issues/detail?id=1864&can=1&q=finder%3Amjurczyk%20fixed%3A2019-aug-13&colspec=ID%20Status%20Restrict%20Reported%20Vendor%20Product%20Finder%20Summary)