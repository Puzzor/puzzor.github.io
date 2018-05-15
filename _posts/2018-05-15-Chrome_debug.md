---
published: true
---
## Trace javascript execution in Chrome
We can insert some Math.cos(0x0), Math.cos(0x2), etc. into the html to trace the execution of javascript in Chrome. Then, in windbg, set a breakpoint at ***chrome_child!v8::base::ieee754::cos*** to trace. ***chrome_child!v8::base::ieee754::cos*** accepts one parameter and it's a **double.**

If we call  **Math.cos(0x2)**，ESP will be like:

~~~shell
chrome_child!v8::base::ieee754::cos:
6cbc4ba0 55              push    ebp
4:048> dd esp
002deb24  5490bd7c 00000000 40000000 002deb34
002deb34  5d815a98 2e40c666 20304185 290161a9
002deb44  00000001 290161a9 290053ad 002deb7c
002deb54  2e412d78 00000004 29015e1d 00000004
002deb64  29015e1d 290161a9 0000006a 29046995
002deb74  290456a9 290053ad 002debac 2e412d78
002deb84  5d806349 20304185 290456a9 290451f1
002deb94  20304185 20304185 00000060 29046899
~~~

 ESP+8==0x40000000

If we call Math.cos(0x4)

~~~shell
chrome_child!v8::base::ieee754::cos:
6cc64ba0 55              push    ebp
4:049> dd esp
0033e814  3430bd7c 00000000 40100000 0033e824
0033e824  46e95a98 4578c666 58184185 291961a9
0033e834  00000001 291961a9 291853ad 0033e86c
0033e844  45792d78 00000008 29195e1d 00000008
0033e854  29195e1d 291961a9 0000006a 291c6995
0033e864  291c56a9 291853ad 0033e89c 45792d78
0033e874  46e86349 58184185 291c56a9 291c51f1
0033e884  58184185 58184185 00000060 291c6899
~~~

ESP+8==0x40100000

So we can use ESP+8 to distinguish each call. Below is table for different value passed to ***Math.cos***

~~~shell
Math.cos(0x2)        40000000
Math.cos(0x4)        40100000
Math.cos(0x6)        40180000
Math.cos(0x8)        40200000
Math.cos(0xA)        40240000
Math.cos(0xC)        40280000
Math.cos(0xE)        402c0000
Math.cos(0x10)       40300000
Math.cos(0x12)       40320000
Math.cos(0x14)       40340000
Math.cos(0x16)       40360000
Math.cos(0x18)       40380000
Math.cos(0x1A)       403a0000
~~~



