# Uroburos Rootkit分析


# Uroburos Rootkit Analyse



# Uroburos Rootkit中的HOOK的简单分析以及驱动的提取
**Uroburos是一个rootkit，由两个文件，一个驱动程序和一个加密的虚拟文件系统组成。它可以窃取信息（最著名的是：文件），还可以捕获网络流量。它的模块化结构使其可以轻松扩展新功能，这不仅使其非常复杂，而且具有很高的灵活性和危险性。Uroburos的驱动程序部分非常复杂，并且设计得非常离散且很难识别。**
本文章的分析基于BAE Systems的report以及spresec的博客，使用的样本为[626576e5f0f85d77c460a322a92bb267](https://www.virustotal.com/gui/file/0d1fe4ab3b074b5ef47aca88c5d1b8262a1293d51111d59c4e563980a873c5a6/detection)，使用的主要工具为volatility（rekall也可以）。
## Hook分析
### 查找函数hook
根据BAE Systems的report，该rootkit对IoCreateDevice()函数进行了hook。我们通过一个受该rootkit映像的image来对该hook进行分析。
- 使用volatility的enumfunc插件来列举出所有导出函数的内存地址：
```
$ python2 /opt/volatility-2.3.1/vol.py -f uroburos.vmem --profile=WinXPSP3x86 enumfunc -K -E | grep IoCreateDevice

Volatility Foundation Volatility Framework 2.3.1

<KERNEL>             Export     ntoskrnl.exe         340        0x000000008056aad6 IoCreateDevice
```
- 使用volshell来查看该函数是如何被hook的：
```
$ python2 /opt/volatility-2.3.1/vol.py -f uroburos_mod.vmem --profile=WinXPSP3x86 volshell
Volatility Foundation Volatility Framework 2.3.1
Current context: process System, pid=4, ppid=0 DTB=0x334000
Welcome to volshell! Current memory image is:
./uroburos_mod.vmem
To get help, type 'hh()'
>>> dis(0x000000008056aad6)
0x8056aad6 6a01                             PUSH 0x1
0x8056aad8 cdc3                             INT 0xc3
0x8056aada 90                               NOP
0x8056aadb 81ec90000000                     SUB ESP, 0x90
0x8056aae1 a140ae5480                       MOV EAX, [0x8054ae40]
0x8056aae6 8945fc                           MOV [EBP-0x4], EAX
```
从上面的结果可以看出，0x1被压入栈中，然后INT 0xc3执行一个中断。我们进一步跟进这个中断，看一下它的具体信息。

- 使用idt查看一下IDT：
```
$ python2 /opt/volatility-2.3.1/vol.py -f uroburos.mem --profile=WinXPSP3x86 idt
Volatility Foundation Volatility Framework 2.3.1
   CPU  Index   Selector Value      Module               Section     
------ ------ ---------- ---------- -------------------- ------------
[snip]      
     0     BC        0x8 0x8053d0b8 ntoskrnl.exe         .text       
     0     BD        0x8 0x8053d0c2 ntoskrnl.exe         .text       
     0     BE        0x8 0x8053d0cc ntoskrnl.exe         .text       
     0     BF        0x8 0x8053d0d6 ntoskrnl.exe         .text       
     0     C0        0x8 0x8053d0e0 ntoskrnl.exe         .text       
     0     C1        0x8 0x806d1984 hal.dll              .text       
     0     C2        0x8 0x8053d0f4 ntoskrnl.exe         .text       
     0     C3        0x8 0x896a3670 UNKNOWN                          
     0     C4        0x8 0x8053d108 ntoskrnl.exe         .text       
     0     C5        0x8 0x8053d112 ntoskrnl.exe         .text       
     0     C6        0x8 0x8053d11c ntoskrnl.exe         .text       
     0     C7        0x8 0x8053d126 ntoskrnl.exe         .text       
     0     C8        0x8 0x8053d130 ntoskrnl.exe         .text 
[snip]
```
在上面的结果中，我们可以发现，INT 0xc3处理的中断位于一个名为“UNKNOWN”的模块中。无法正确识别出来这是不是系统模块，说明确实有问题。

### 修改volatility的apihooks插件
通过前面几步操作，我们可以确认hook的地址。但是需要更多的信息，最好是能看到hook的具体操作内容和流程。因为volatility的原生apihooks.py是不支持内联中断hook的，所以需要对原生插件做一个改进。  

原生apihooks.py中有个check_inline()函数，可以看到其代码是典型的内联hook的逻辑，该内联hook在当前模块，无条件的jmps，push/ret等的外部寻找调用。不幸的是，该rootkit没有使用任何这些方法。 在修改了一些代码之后，添加了以下逻辑来处理内联中断hook：
```
elif op.flowControl == "FC_INT" and idt:
    # Clear the push value 
    if push_val:
        push_val = None
    # Check for INT, ignore INT3
    if op.mnemonic == "INT" and op.size > 1 and op.operands[0].type == 'Immediate':
        # Check interrupt handler address
        d = idt[op.operands[0].value]
        if d and outside_module(d):
            break
```
将修改后的插件合入volatility，然后重新运行：
```
$ python2 /opt/volatility-2.3.1/vol.py -f uroburos.vmem --profile=WinXPSP3x86 apihooks -P
Volatility Foundation Volatility Framework 2.3.1
************************************************************************
Hook mode: Kernelmode
Hook type: Inline/Trampoline
Victim module: ntoskrnl.exe (0x804d7000 - 0x806cf580)
Function: ntoskrnl.exe!IoCreateDevice at 0x8056aad6
Hook address: 0x896a3670
Hooking module: <unknown>

Disassembly(0):
0x8056aad6 6a01             PUSH 0x1
0x8056aad8 cdc3             INT 0xc3
0x8056aada 90               NOP
0x8056aadb 81ec90000000     SUB ESP, 0x90
0x8056aae1 a140ae5480       MOV EAX, [0x8054ae40]
0x8056aae6 8945fc           MOV [EBP-0x4], EAX
0x8056aae9 8b4508           MOV EAX, [EBP+0x8]
0x8056aaec 89               DB 0x89
0x8056aaed 45               INC EBP

Disassembly(1):
0x896a3670 90               NOP
0x896a3671 90               NOP
0x896a3672 90               NOP
0x896a3673 90               NOP
0x896a3674 90               NOP
0x896a3675 90               NOP
0x896a3676 90               NOP
0x896a3677 90               NOP
0x896a3678 90               NOP
0x896a3679 90               NOP
0x896a367a 90               NOP
0x896a367b 90               NOP
0x896a367c 90               NOP
0x896a367d 90               NOP
0x896a367e 90               NOP
0x896a367f 90               NOP
0x896a3680 6a08             PUSH 0x8
0x896a3682 6888366a89       PUSH DWORD 0x896a3688
0x896a3687 cb               RETF

************************************************************************
Hook mode: Kernelmode
Hook type: Inline/Trampoline
Victim module: ntoskrnl.exe (0x804d7000 - 0x806cf580)
Function: ntoskrnl.exe!IofCallDriver at 0x804ee120
Hook address: 0x896a3670
Hooking module: <unknown>

Disassembly(0):
0x804ee120 6a00             PUSH 0x0
0x804ee122 cdc3             INT 0xc3
0x804ee124 90               NOP
0x804ee125 90               NOP
[snip]
```

ok，这次没有问题了。

### Hook的详细分析
到现在为止，我们可以跟深入跟踪处理hook的指令进行更详细的分析了。重新使用volshell插件来看一下处理IoCreateDevice()的hook的具体函数：

```
>>> dis(0x000000008056aad6, 0xb)
0x8056aad6 6a01                             PUSH 0x1
0x8056aad8 cdc3                             INT 0xc3
0x8056aada 90                               NOP
0x8056aadb 81ec90000000                     SUB ESP, 0x90
>>> dis(0x896a3670, 0x18)
0x896a3670 90                               NOP
0x896a3671 90                               NOP
0x896a3672 90                               NOP
0x896a3673 90                               NOP
0x896a3674 90                               NOP
0x896a3675 90                               NOP
0x896a3676 90                               NOP
0x896a3677 90                               NOP
0x896a3678 90                               NOP
0x896a3679 90                               NOP
0x896a367a 90                               NOP
0x896a367b 90                               NOP
0x896a367c 90                               NOP
0x896a367d 90                               NOP
0x896a367e 90                               NOP
0x896a367f 90                               NOP
0x896a3680 6a08                             PUSH 0x8
0x896a3682 6888366a89                       PUSH DWORD 0x896a3688
0x896a3687 cb                               RETF
>>> dis(0x896a3688, 0x29)
0x896a3688 fb                               STI
0x896a3689 50                               PUSH EAX
0x896a368a 51                               PUSH ECX
0x896a368b 0fb6442414                       MOVZX EAX, BYTE [ESP+0x14]
0x896a3690 8b4c2418                         MOV ECX, [ESP+0x18]
0x896a3694 894c2414                         MOV [ESP+0x14], ECX
0x896a3698 8b0d506c6c89                     MOV ECX, [0x896c6c50]
0x896a369e 8d04c1                           LEA EAX, [ECX+EAX*8]
0x896a36a1 8b4804                           MOV ECX, [EAX+0x4]
0x896a36a4 894c2418                         MOV [ESP+0x18], ECX
0x896a36a8 59                               POP ECX
0x896a36a9 8b00                             MOV EAX, [EAX]
0x896a36ab 870424                           XCHG [ESP], EAX
0x896a36ae c20c00                           RET 0xc
>>> dd(0x896c6c50, 1)
896c6c50  89a2d800
>>> dd(0x89a2d800+1*8, 1)
89a2d808  8963a020
>>> dis(0x8963a020, 0xb)
0x8963a020 55                               PUSH EBP
0x8963a021 8bec                             MOV EBP, ESP
0x8963a023 83ec18                           SUB ESP, 0x18
0x8963a026 e875fd0100                       CALL 0x89659da0
```
现在我们找到了处理hook的详细的函数代码，我们可以将内存导出，然后使用IDA进行分析。

## 导出驱动
### 追踪内存中的驱动
我们直接使用volatility的modlist插件，并没有发现任何有价值的消息。之前为rootkit驱动程序确定的内存空间中似乎没有模块。我们注意到驱动程序似乎占用了很大的内存空间，我们可以从目前为止确定的最低地址开始向后搜索内存。寻找PE头，以0x8963a020为起点，向后看0x6000字节。
```
>>> db(0x8963a020-0x6000, 0x6000)
0x89634020  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00   ................
0x89634030  00 00 00 00 00 00 00 00 00 00 00 00 d0 00 00 00   ................
0x89634040  0e 1f ba 0e 00 b4 09 cd 21 b8 01 4c cd 21 54 68   ........!..L.!Th
0x89634050  69 73 20 70 72 6f 67 72 61 6d 20 63 61 6e 6e 6f   is.program.canno
0x89634060  74 20 62 65 20 72 75 6e 20 69 6e 20 44 4f 53 20   t.be.run.in.DOS.
0x89634070  6d 6f 64 65 2e 0d 0d 0a 24 00 00 00 00 00 00 00   mode....$.......
0x89634080  b2 4e 55 e7 f6 2f 3b b4 f6 2f 3b b4 f6 2f 3b b4   .NU../;../;../;.
0x89634090  f6 2f 3a b4 26 2f 3b b4 af 0c 28 b4 ff 2f 3b b4   ./:.&/;...(../;.
0x896340a0  d1 e9 46 b4 f4 2f 3b b4 d1 e9 4a b4 74 2f 3b b4   ..F../;...J.t/;.
0x896340b0  d1 e9 41 b4 f7 2f 3b b4 d1 e9 43 b4 f7 2f 3b b4   ..A../;...C../;.
0x896340c0  52 69 63 68 f6 2f 3b b4 00 00 00 00 00 00 00 00   Rich./;.........
0x896340d0  00 00 00 00 4c 01 05 00 e7 eb 14 51 00 00 00 00   ....L......Q....
0x896340e0  00 00 00 00 e0 00 02 21 0b 01 08 00 00 00 07 00   .......!........
0x896340f0  00 72 02 00 00 00 00 00 40 d1 00 00 00 10 00 00   .r......@.......
[snip]
```

在上面的结果中，我们看到了DOS头，然后往前看一点，去寻找“MZ”：
```
>>> db(0x89634000, 0x100)
0x89634000  00 00 00 00 03 00 00 00 04 00 00 00 ff ff 00 00   ................
0x89634010  b8 00 00 00 00 00 00 00 40 00 00 00 00 00 00 00   ........@.......
0x89634020  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00   ................
0x89634030  00 00 00 00 00 00 00 00 00 00 00 00 d0 00 00 00   ................
0x89634040  0e 1f ba 0e 00 b4 09 cd 21 b8 01 4c cd 21 54 68   ........!..L.!Th
0x89634050  69 73 20 70 72 6f 67 72 61 6d 20 63 61 6e 6e 6f   is.program.canno
0x89634060  74 20 62 65 20 72 75 6e 20 69 6e 20 44 4f 53 20   t.be.run.in.DOS.
0x89634070  6d 6f 64 65 2e 0d 0d 0a 24 00 00 00 00 00 00 00   mode....$.......
0x89634080  b2 4e 55 e7 f6 2f 3b b4 f6 2f 3b b4 f6 2f 3b b4   .NU../;../;../;.
0x89634090  f6 2f 3a b4 26 2f 3b b4 af 0c 28 b4 ff 2f 3b b4   ./:.&/;...(../;.
0x896340a0  d1 e9 46 b4 f4 2f 3b b4 d1 e9 4a b4 74 2f 3b b4   ..F../;...J.t/;.
0x896340b0  d1 e9 41 b4 f7 2f 3b b4 d1 e9 43 b4 f7 2f 3b b4   ..A../;...C../;.
0x896340c0  52 69 63 68 f6 2f 3b b4 00 00 00 00 00 00 00 00   Rich./;.........
0x896340d0  00 00 00 00 4c 01 05 00 e7 eb 14 51 00 00 00 00   ....L......Q....
0x896340e0  00 00 00 00 e0 00 02 21 0b 01 08 00 00 00 07 00   .......!........
0x896340f0  00 72 02 00 00 00 00 00 40 d1 00 00 00 10 00 00   .r......@.......
```
奇怪的是“MZ”和“PE”的魔术字都没有找到，这意味moddump插件可能存在问题，需要进行修改。

### 修补内存
volatility有个patcher插件可以处理这种情况。我们首先要写一个xml文件来修补PE头：

![](/img/素材/patchdriver_xml.png)

这将在每个页面边界的起始位置搜索我们在内存中找到的驱动程序的开始字节，并为结构正确的PE头插入魔术字。

```
$ python2 /opt/volatility-2.3.1/vol.py -f uroburos_mod.vmem --profile=WinXPSP3x86 patcher -w -x patchdriver.xml
Volatility Foundation Volatility Framework 2.3.1
Write support requested.  Please type "Yes, I want to enable write support" below precisely (case-sensitive):
Yes, I want to enable write support
Calibrating for speed: Reading patch locations per page
Patching Fix Driver MZ Header at page 9634000

```

看起来没有问题，我们检查一下：
```
>>> db(0x89634000, 0x100)
0x89634000  4d 5a 90 00 03 00 00 00 04 00 00 00 ff ff 00 00   MZ..............
0x89634010  b8 00 00 00 00 00 00 00 40 00 00 00 00 00 00 00   ........@.......
0x89634020  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00   ................
0x89634030  00 00 00 00 00 00 00 00 00 00 00 00 d0 00 00 00   ................
0x89634040  0e 1f ba 0e 00 b4 09 cd 21 b8 01 4c cd 21 54 68   ........!..L.!Th
0x89634050  69 73 20 70 72 6f 67 72 61 6d 20 63 61 6e 6e 6f   is.program.canno
0x89634060  74 20 62 65 20 72 75 6e 20 69 6e 20 44 4f 53 20   t.be.run.in.DOS.
0x89634070  6d 6f 64 65 2e 0d 0d 0a 24 00 00 00 00 00 00 00   mode....$.......
0x89634080  b2 4e 55 e7 f6 2f 3b b4 f6 2f 3b b4 f6 2f 3b b4   .NU../;../;../;.
0x89634090  f6 2f 3a b4 26 2f 3b b4 af 0c 28 b4 ff 2f 3b b4   ./:.&/;...(../;.
0x896340a0  d1 e9 46 b4 f4 2f 3b b4 d1 e9 4a b4 74 2f 3b b4   ..F../;...J.t/;.
0x896340b0  d1 e9 41 b4 f7 2f 3b b4 d1 e9 43 b4 f7 2f 3b b4   ..A../;...C../;.
0x896340c0  52 69 63 68 f6 2f 3b b4 00 00 00 00 00 00 00 00   Rich./;.........
0x896340d0  50 45 00 00 4c 01 05 00 e7 eb 14 51 00 00 00 00   PE..L......Q....
0x896340e0  00 00 00 00 e0 00 02 21 0b 01 08 00 00 00 07 00   .......!........
0x896340f0  00 72 02 00 00 00 00 00 40 d1 00 00 00 10 00 00   .r......@.......
```

OK,这次就没有问题了。
### 转储驱动程序
现在PE结构已经修复了，我们可以从内存中将驱动程序转储出来：

```
$ python2 /opt/volatility-2.3.1/vol.py -f uroburos_mod.vmem --profile=WinXPSP3x86 moddump -b 0x89634000 -D .
Volatility Foundation Volatility Framework 2.3.1
Module Base Module Name          Result
----------- -------------------- ------
0x089634000 UNKNOWN              OK: driver.89634000.sys
```

这里需要注意的是，我们使用moddump插件进行内存转储时，并没有修复ImageBase，所以需要我们进行手动修复。这里可以使用pefile库：
```
>>> import pefile
>>> pe = pefile.PE('driver.89634000.sys')
>>> hex(pe.OPTIONAL_HEADER.ImageBase)
'0x10000'
>>> pe.OPTIONAL_HEADER.ImageBase = 0x89634000
>>> pe.write(filename='driver.89634000_mod.sys')
```

OK，到此为止，转储出来的驱动程序应该就没有问题了，使用IDA打开看一下：
![](/img/素材/ida_image.png)
没有问题，现在就可以使用IDA进行深入的静态分析了。

