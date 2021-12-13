# Linux-0.11-03


本文是Linux 0.11系列学习记录的正式的第三篇。

<!--more-->

## 06 先解决段寄存器的历史包袱问题

书接上回，上回书咱们说到，操作系统又折腾了一下内存，之后的很长一段时间内存布局就不会变了，终于稳定下来了，目前它长这个样子。

![图片](https://mmbiz.qpic.cn/mmbiz_png/GLeh42uInXRvb1zDVW17W3KsMIzHI1lAibZHfocia9RakibZxN77SqCbWSia85E1ibL0q932Wq1riaNpF1ESUwXBp9gA/640?wx_fmt=png&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1)

`0` 地址开始处存放着操作系统的全部代码，也就是 `system` 模块，`0x90000` 位置处往后的几十个字节存放着一些设备的信息，方便以后使用。

|内存地址| 长度(字节)|名称|
|-- |--|--|
0x90000|2|光标位置
0x90002|2|扩展内存数
0x90004|2|显示页面
0x90006|1|显示模式
0x90007|1|字符列数
0x90008|2|未知
0x9000A|1|显示内存
0x9000B|1|显示状态
0x9000C|2|显卡特性参数
0x9000E|1|屏幕行数
0x9000F|1|屏幕列数
0x90080|16|硬盘1参数表
0x90090|16|硬盘2参数表
0x901FC|2|根设备号

这里的内存布局十分清晰，主要是方便后续操作系统的大显身手。接下来就要模式的转换，需要从现在的 16 位的实模式转变为之后 32 位的保护模式。

从业务来讲，这本应是比较复杂的一部分内容，难度较高，但从代码量看，却是少得可怜。

从 16 位的实模式到 32 位保护模式的转换是 x86 的历史包袱问题，现在的 CPU 几乎都是支持 32 位模式甚至 64 位模式了，很少有还仅仅停留在 16 位的实模式下的 CPU。所以我们要为了这个历史包袱，写一段模式转换的代码，如果 Intel CPU 被重新设计而不用考虑兼容性，那么今天的代码将会减少很多甚至不复存在。

这里仍然是 `setup.s` 文件中的代码:

```assembly
lidt  idt_48      ; load idt with 0,0
lgdt  gdt_48      ; load gdt with whatever appropriate

idt_48:
    .word   0     ; idt limit=0
    .word   0,0   ; idt base=0L
```

要理解这两条指令，就涉及到实模式和保护模式的第一个区别。我们现在还处于实模式下，这个模式的 CPU 计算物理地址的方式还记得么？不记得的话看一下 **第一回 最开始的两行代码**。

就是`段基址左移四位，再加上偏移地址`。比如：

![图片](https://mmbiz.qpic.cn/mmbiz_png/GLeh42uInXRvb1zDVW17W3KsMIzHI1lASoeJCvybCI2kRtJicsOpamRsZibS53DhuiaAoicKShDhasnzJ3ufk5EbDA/640?wx_fmt=png&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1)

当 CPU 切换到保护模式后，同样的代码，内存地址的计算方式发生了改变。刚刚 `ds` 寄存器里存储的值，在实模式下叫做`段基址`，在保护模式下叫`段选择子`。段选择子里存储着`段描述符的索引`。

![tupian](https://mmbiz.qpic.cn/mmbiz_png/GLeh42uInXRvb1zDVW17W3KsMIzHI1lA0WFW4KHnBCicAqahTyX9efUR013ZB8YiczmfzERiciaZsyQToWkyrpnYhw/640?wx_fmt=png&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1)

通过段描述符索引，可以从全局描述符表 `gdt` 中找到一个段描述符，段描述符里存储着段基址。

![pic](https://mmbiz.qpic.cn/mmbiz_png/GLeh42uInXRvb1zDVW17W3KsMIzHI1lAcUiccry1x6LKEnpbyOKWCnRicF49deDIUlJd1ECxrPqI9FTr1Yp3mLqQ/640?wx_fmt=png&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1)

段基址取出来，再和偏移地址相加，就得到了物理地址，整个过程如下。

![pic](https://mmbiz.qpic.cn/mmbiz_png/GLeh42uInXRvb1zDVW17W3KsMIzHI1lATicvoUOED4kVopkpEzoqTGbaJuMJibyC2poicIbIXHc1WLRpM0YLy69CA/640?wx_fmt=png&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1)

总结一下就是，**段寄存器（比如 ds、ss、cs）里存储的是段选择子，段选择子去全局描述符表中寻找段描述符，从中取出段基址**。

好了，全局描述符表（gdt）长什么样？它在哪？怎么让 CPU 知道它在哪？

先说说它在哪？在内存中呗，那么怎么告诉 CPU 全局描述符表（gdt）在内存中的什么位置呢？答案是**由操作系统把这个位置信息存储在一个叫 `gdtr` 的寄存器中**。

![pic](https://mmbiz.qpic.cn/mmbiz_png/GLeh42uInXRvb1zDVW17W3KsMIzHI1lAhFaTO3kIK1QZ89q0mpwibj8Fn4hwMbWf3ZmWWIXNbyHwT9PsBzUeUDg/640?wx_fmt=png&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1)

怎么存呢？就是刚刚那条指令。

```assembly
lgdt    gdt_48
```

其中 `lgdt` 就表示把后面的值（gdt_48）放在 gdtr 寄存器中，gdt_48 标签，我们看看它长什么样。

```assembly
gdt_48:
    .word   0x800       ; gdt limit=2048, 256 GDT entries
    .word   512+gdt,0x9 ; gdt base = 0X9xxxx
```

可以看到这个标签位置处表示一个 48 位的数据，其中高 32 位存储着的正是全局描述符表 `gdt` 的内存地址 `0x90200 + gdt`。
`gdt` 是个标签，表示在本文件内的偏移量，而本文件是 `setup.s`，编译后是放在 `0x90200` 这个内存地址的，所以要加上 0x90200 这个值。

![pic](https://mmbiz.qpic.cn/mmbiz_png/GLeh42uInXRvb1zDVW17W3KsMIzHI1lAbXUxkk0sGMcgzuRmr3NkFcj7D6DLogQzAktbP1Iic6ZdfGuvElv6oww/640?wx_fmt=png&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1)

那 `gdt` 这个标签处，就是全局描述符表在内存中的真正数据了。

```assembly

gdt:
    .word   0,0,0,0     ; dummy

    .word   0x07FF      ; 8Mb - limit=2047 (2048*4096=8Mb)
    .word   0x0000      ; base address=0
    .word   0x9A00      ; code read/exec
    .word   0x00C0      ; granularity=4096, 386

    .word   0x07FF      ; 8Mb - limit=2047 (2048*4096=8Mb)
    .word   0x0000      ; base address=0
    .word   0x9200      ; data read/write
    .word   0x00C0      ; granularity=4096, 386
```

根据刚刚的段描述符格式。

![pic](https://mmbiz.qpic.cn/mmbiz_png/GLeh42uInXRvb1zDVW17W3KsMIzHI1lAcUiccry1x6LKEnpbyOKWCnRicF49deDIUlJd1ECxrPqI9FTr1Yp3mLqQ/640?wx_fmt=png&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1)

可以看出目前全局描述符表有三个段描述符，第一个为空，第二个是代码段描述符（`type=code`），第三个是数据段描述符（`type=data`），第二个和第三个段描述符的段基址都是 0，也就是之后在逻辑地址转换物理地址的时候，通过段选择子查找到无论是代码段还是数据段，取出的段基址都是 0，那么物理地址将直接等于程序员给出的逻辑地址（准确说是逻辑地址中的偏移地址）。

![pic](https://mmbiz.qpic.cn/mmbiz_png/GLeh42uInXRvb1zDVW17W3KsMIzHI1lAdBQRzAH7Tib7zRUrTCVFZKiaTS5wSSN3AKcHOLwsvwu16wE7uEAibvGGg/640?wx_fmt=png&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1)

具体段描述符的细节还有很多，就不展开了，比如这里的高 22 位就表示它是代码段还是数据段。

![pic](https://mmbiz.qpic.cn/mmbiz_png/GLeh42uInXRvb1zDVW17W3KsMIzHI1lAcUiccry1x6LKEnpbyOKWCnRicF49deDIUlJd1ECxrPqI9FTr1Yp3mLqQ/640?wx_fmt=png&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1)

接下来我们看看目前的内存布局，还是别管比例。

![pic](https://mmbiz.qpic.cn/mmbiz_png/GLeh42uInXRvb1zDVW17W3KsMIzHI1lAhKOS9ibE4WvwQ00f94aHMhhGRnwHVPXXVwbbUFMTyq6melME7MzAl3A/640?wx_fmt=png&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1)

这里我把 `idtr` 寄存器也画出来了，这个是`中断描述符表`，其原理和全局描述符表一样。全局描述符表是让段选择子去里面寻找段描述符用的，而中断描述符表是用来在发生中断时，CPU 拿着中断号去中断描述符表中寻找中断处理程序的地址，找到后就跳到相应的中断程序中去执行，具体我们后面遇到了再说。

好了，今天我们就讲，操作系统设置了个全局描述符表 gdt，为后面切换到保护模式后，能去那里寻找到段描述符，然后拼凑成最终的物理地址，就这个作用。当然，还有很多段描述符，作用不仅仅是转换成最终的物理地址，不过这是后话了。

这仅仅是进入保护模式前准备工作的其中一个，后面的路还长着呢。欲知后事如何，且听下回分解。

------- 本回扩展资料 -------

保护模式下逻辑地址到线性地址（不开启分页时就是物理地址）的转化，看 Intel 手册：
**Volume 3 Chapter 3.4 Logical And Linear Addresses**

![pic](https://mmbiz.qpic.cn/mmbiz_png/GLeh42uInXRvb1zDVW17W3KsMIzHI1lAvMK8vVYCu3h4CAk6mJicvQRf4TabRqsvUu0bvuBr0Cmibks1CPbf8Stw/640?wx_fmt=png&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1)

段描述符结构和详细说明，看 Intel 手册：
Volume 3 Chapter 3.4.5 Segment Descriptors

![pic](https://mmbiz.qpic.cn/mmbiz_png/GLeh42uInXRvb1zDVW17W3KsMIzHI1lAzOrxAjrXp5ZrLaO6gZm82zia7yh8ChQxQ4pGKkUPe0pJeNMMOXB23Cg/640?wx_fmt=png&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1)

比如文中说的数据段与代码段的划分，其实还有更细分的权限控制。

![pic](https://mmbiz.qpic.cn/mmbiz_png/GLeh42uInXRvb1zDVW17W3KsMIzHI1lAwEgHSYuDoN3qsbRdA12KLfDLgtoGyDich1ticibHOhsFloqRkibyrE4Vog/640?wx_fmt=png&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1)

## 原文地址

[你管这破玩意叫操作系统源码 | 第六回 先解决段寄存器的历史包袱问题](https://mp.weixin.qq.com/s/p1a6QxYZyMpJF__uBSE1Kg)

