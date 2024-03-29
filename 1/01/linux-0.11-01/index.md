# 

# Linux-0.11-01


本文是Linux 0.11系列学习记录的正式的第一篇。

<!--more-->

## 前言

从这一篇开始，您就将跟着我一起进入这操作系统的梦幻之旅！

别担心，每一章的内容会非常的少，而且你也不要抱着很大的负担去学习，只需要像读小说一样，跟着我一章一章读下去就好。

## 01 最开始的两行代码

当按下开机键的那一刻，在主板上提前写死的固件程序 **BIOS** 会将硬盘中**启动区的 512 字节**的数据，原封不动复制到**内存中的 0x7c00** 这个位置，并跳转到那个位置进行执行。

![image-20211129201140709](https://cdn.jsdelivr.net/gh/AlexsanderShaw/BlogImages@main/img/202111292011746.png)

启动区的定义非常简单，只要硬盘中的 0 盘 0 道 1 扇区的 512 个字节的最后两个字节分别是 **0x55** 和 **0xaa**，那么 BIOS 就会认为它是个启动区。

所以对于我们理解操作系统而言，此时的 BIOS 仅仅就是个代码搬运工，把 512 字节的二进制数据从硬盘搬运到了内存中而已。**所以作为操作系统的开发人员，仅仅需要把操作系统最开始的那段代码，编译并存储在硬盘的 0 盘 0 道 1 扇区即可**。之后 BIOS 会帮我们把它放到内存里，并且跳过去执行。

而 Linux-0.11 的最开始的代码，就是这个用汇编语言写的 **bootsect.s**，位于 **boot** 文件夹下。

![image-20211129201125519](https://cdn.jsdelivr.net/gh/AlexsanderShaw/BlogImages@main/img/202111292011546.png)

 通过编译，这个 `bootsect.s` 会被编译成二进制文件，存放在启动区的第一扇区。

![image-20211129201112697](https://cdn.jsdelivr.net/gh/AlexsanderShaw/BlogImages@main/img/202111292011736.png)

 随后就会如刚刚所说，由 BIOS 搬运到内存的 0x7c00 这个位置，而 CPU 也会从这个位置开始，不断往后一条一条语句无脑地执行下去。

 那我们的梦幻之旅，就从这个文件的第一行代码开始啦！

```assembly
mov ax,0x07c0
mov ds,ax
```

好吧，先连续看两行。

这段代码是用汇编语言写的，含义是把 `0x07c0` 这个值复制到 **ax 寄存器**里，再将 `ax` 寄存器里的值复制到 **ds 寄存器**。那其实这一番折腾的结果就是，让 ds 这个寄存器里的值变成了 0x07c0。

![image-20211129201058974](https://cdn.jsdelivr.net/gh/AlexsanderShaw/BlogImages@main/img/202111292010011.png)

 ds 是一个 16 位的段寄存器，具体表示数据段寄存器，在内存寻址时充当段基址的作用。啥意思呢？就是当我们之后用汇编语言写一个内存地址时，实际上仅仅是写了偏移地址，比如：

```assembly
mov ax, [0x0001]
```

实际上相当于

```assembly
mov ax, [ds:0x0001]
```

ds 是默认加上的，表示在 ds 这个段基址处，往后再偏移 0x0001 单位，将这个位置的内存数据，复制到 ax 寄存器中。

 形象地比喻一下就是，你和朋友商量去哪玩比较好，你说天安门、南锣鼓巷、颐和园等等，实际上都是**偏移地址**，省略了北京市这个**基址**。

 当然你完全可以说北京天安门、北京南锣鼓巷这样，每次都加上北京这个前缀。不过如果你事先和朋友说好，以下我说的地方都是北京市里的哈，之后你就不用每次都带着北京市这个词了，是不是很方便？

 那 ds 这个数据段寄存器的作用就是如此，方便了描述一个内存地址时，可以省略一个基址，没什么神奇之处。

```text
ds : 0x0001

北京市 : 南锣鼓巷
```

 再看，这个 ds 被赋值为了 0x07c0，由于 x86 为了让自己在 16 位这个实模式下能访问到 20 位的地址线这个历史因素（不了解这个的就先别纠结为啥了），所以段基址要先左移四位。**那 0x07c0 左移四位就是 0x7c00**，那这就刚好和这段代码被 BIOS 加载到的内存地址 0x7c00 一样了。

 也就是说，之后再写的代码，里面访问的数据的内存地址，都先默认加上 0x7c00，再去内存中寻址。

 为啥统一加上 0x7c00 这个数呢？这很好解释，BIOS 规定死了把操作系统代码加载到内存 0x7c00，那么里面的各种数据自然就全都被偏移了这么多，所以把数据段寄存器 ds 设置为这个值，方便了以后通过这种基址的方式访问内存里的数据。

![image-20211129201045645](https://cdn.jsdelivr.net/gh/AlexsanderShaw/BlogImages@main/img/202111292010677.png)

OK，赶紧消化掉前面的知识，那本篇就到此为止，只讲了两行代码，知识量很少，我没骗你吧。

 希望你能做到，对 BIOS 将操作系统代码加载到内存 0x7c00，以及我们通过 mov 指令将默认的数据段寄存器 ds 寄存器的值改为 0x07c0 方便以后的基址寻址方式，这两件事在心里认可，并且没有疑惑，这才方便后面继续进行。

 后面的世界越来越精彩，欲知后事如何，且听下回分解。

**------- 本回扩展资料 -------**

有关寄存器的详细信息，可以参考 Intel 手册：

Volume 1 Chapter 3.2 OVERVIEW OF THE BASIC EXECUTION ENVIRONMEN

有关计算机启动部分的原理如果还不清楚，可以看我之前的一篇文章了解一下：

[计算机的启动过程](http://mp.weixin.qq.com/s?__biz=Mzk0MjE3NDE0Ng==&mid=2247483867&idx=1&sn=76ece31324d32922a7cb9db129decd3f&chksm=c2c67b76f5b1f260bb459e12c029f8e6a7a813055811ab8ed794a3f36d0d7d50e66df27f4f0a&scene=21#wechat_redirect)

如果想了解计算机启动时详细的初始化过程，还是得参考 Intel 手册：

Volume 3A Chapter 9 PROCESSOR MANAGEMENT AND INITIALIZATION

## 02 自己给自己挪个地儿

书接上回，上回书咱们说到，CPU 执行操作系统的最开始的两行代码。

```assembly
mov ax,0x07c0
mov ds,ax
```

将数据段寄存器 ds 的值变成了 **0x07c0**，方便了之后访问内存时利用这个**段基址**进行寻址。


接下来我们带着这两行代码，继续往下看几行。

```assembly
mov ax,0x07c0
mov ds,ax
mov ax,0x9000
mov es,ax
mov cx,#256
sub si,si
sub di,di
rep movw
```

此时 ds 寄存器的值已经是 0x07c0 了，然后又通过同样的方式将 **es** 寄存器的值变成 **0x9000**，接着又把 **cx** 寄存器的值变成 **256**（代码里确实是用十进制表示的，与其他地方有些不一致，不过无所谓）。

再往下看有两个 **sub** 指令，这个 sub 指令很简单，比如

```assembly
sub a,b
```

就表示

```
a = a - b
```

那么代码中的

```assembly
sub si,si
```

就表示

```
si = si - si
```

所以如果 sub 后面的两个寄存器一模一样，就相当于把这个寄存器里的值**清零**，这是一个基本玩法。

那就非常简单了，经过这些指令后，以下几个寄存器分别被附上了指定的值，我们梳理一下。

**ds = 0x07c0**

**es = 0x9000**

**cx = 256**

**si = 0**

**di = 0**

还记得上一讲画的 CPU 寄存器的总图么？此时就是这样了

![图片](https://cdn.jsdelivr.net/gh/AlexsanderShaw/BlogImages@main/img/202111292021173)
 
干嘛要给这些毫不相干的寄存器附上值呢？其实就是为下一条指令服务的，就是

```assembly
rep movw
```

其中 **rep** 表示重复执行后面的指令。

而后面的指令 **movw** 表示复制一个**字**（word 16位），那其实就是**不断重复地复制一个字**。

那下面自然就有三连问：

**重复执行多少次呢**是 cx 寄存器中的值，也就是 256 次。

**从哪复制到哪呢**是从 ds:si 处复制到 es:di 处。

**一次复制多少呢**刚刚说过了，复制一个字，16 位，也就是两个字节。

上面是直译，那把这段话翻译成更人话的方式讲出来就是，**将内存地址 0x7c00 处开始往后的 512 字节的数据，原封不动复制到 0x90000 处**。



就是下图的第二步。

 

![图片](https://mmbiz.qpic.cn/mmbiz_png/GLeh42uInXQTPFYPO4Z8pgsvib6LNWbmwxAlvjw73zzibib75w72ficTQDfK0BzRrnpF9BOzSWX9lELFo8icOzjrJjQ/640?wx_fmt=png&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1)

 

没错，就是这么折腾了一下。现在，操作系统最开头的代码，已经被挪到了 **0x90000** 这个位置了。

 

再往后是一个**跳转**指令。

```
jmpi go,0x9000
go: 
  mov ax,cs
  mov ds,ax
```

仔细想想或许你能猜到它想干嘛。

 

**jmpi** 是一个**段间跳转指令**，表示跳转到 **0x9000:go** 处执行。



还记得上一讲说的 **段基址 : 偏移地址** 这种格式的内存地址要如何计算吧？段基址仍然要先左移四位，因此结论就是跳转到 **0x90000 + go** 这个内存地址处执行。忘记的赶紧回去看看，这才过了一回哦，要稳扎稳打。

 

再说 go，go 就是一个**标签**，最终编译成机器码的时候会被翻译成一个值，这个值就是 go 这个标签在文件内的偏移地址。



这个偏移地址再加上 0x90000，就刚好是 go 标签后面那段代码 **mov ax,cs** 此时所在的内存地址了。

 

![图片](https://mmbiz.qpic.cn/mmbiz_png/GLeh42uInXQTPFYPO4Z8pgsvib6LNWbmweb6k9bphaOxpbqX5IDeJjC94RmUENlPKFvUECHFaPty7JWMBee9EFw/640?wx_fmt=png&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1)



那假如 **mov ax,cx** 这行代码位于最终编译好后的二进制文件的 **0x08** 处，那 go 就等于 0x08，而最终 CPU 跳转到的地址就是 **0x90008** 处。

 

所以到此为止，前两回的内容，其实就是一段 **512** 字节的代码和数据，从硬盘的启动区先是被移动到了内存 **0x7c00** 处，然后又立刻被移动到 **0x90000** 处，并且跳转到此处往后再稍稍偏移 **go** 这个标签所代表的偏移地址处，也就是 **mov ax,cs** 这行指令的位置。

 

仍然是保持每回的简洁，本文就讲到这里，希望大家还跟得上，接下来的下一回，我们就把目光定位到 go 标签处往后的代码，看看他又要折腾些什么吧。



后面的世界越来越精彩，欲知后事如何，且听下回分解。





**------- 本回扩展与延伸 -------**





有关**寄存器**的详细信息，可以参考 Intel 手册：

Volume 1 Chapter 3.2 OVERVIEW OF THE BASIC EXECUTION ENVIRONMEN



如果想了解**汇编指令**的信息，可以参考 Intel 手册：

Volume 2 Chapter 3 ~ Chapter 5

比如本文出现的 sub 指令，你完全没必要去百度它的用法，直接看手册。



![图片](https://cdn.jsdelivr.net/gh/AlexsanderShaw/BlogImages@main/img/202111292021278)



Intel 手册对于理解底层知识非常直接有效，但却没有很好的中文翻译版本，因此让许多人望而生畏，只能去看一些错误百出的中文二手资料和博客。因此我也发起了一个 **Intel 手册翻译计划**，就在阅读原文的 GitHub 里，感兴趣的同胞们可以参与进来，我们共同完成一份伟大的事。



![图片](https://mmbiz.qpic.cn/mmbiz_png/GLeh42uInXQTPFYPO4Z8pgsvib6LNWbmw3AHbicy2aJYccZxmKQdHXhia9RiaBbZmlGnGRjq3T1y9gDmJv1eDuXcMA/640?wx_fmt=png&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1)



希望你跟完整个系列，收获的不仅仅是 Linux 0.11 源码的了解，更是自己探索问题和寻找答案的一个科学思考方式。



所以每次**本回扩展与延伸**这里，希望你也能每天进步一点点，实践起来，再不济，也能多学几个英语单词不是？

## 原文地址

[你管这破玩意叫操作系统源码 | 第一回 最开始的两行代码](https://mp.weixin.qq.com/s/LIsqRX51W7d_yw-HN-s2DA)

[你管这破玩意叫操作系统源码 | 第二回 自己给自己挪个地儿](https://mp.weixin.qq.com/s/U-txDYt0YqLh5EeFOcB4NQ)

