# Linux操作系统的大千世界——启动过程


## 前言

x86架构的操作系统有两种运行模式：实模式和保护模式。实模式只能寻址1M空间，每个段最大为64K。保护模式扩展了可寻址空间，对于32位系统可以寻址4G。

从实模式到保护模式，有一个启动过程，本文就简单记录下该过程。

## 一、BIOS阶段

计算机通电后，主板会上电。此时，没有操作系统，内存也是空的，CPU并不知道应该执行哪里的指令。因此，这里需要有个中间“介质”暂时来保存一些“计划”，统领后续的操作执行，这个“介质”就是主板上的**ROM(Read Only Memory, 只读存储器)**。

ROM是只读的，上面固化了一些初始化程序，即**BIOS(Basic Input and Output System，基本输入输出系统)**。

在系统启动的前面阶段，处于实模式状态，此时的内存地址空间只有1M，因此需要谨慎考虑，充分利用。

![img](https://cdn.jsdelivr.net/gh/AlexsanderShaw/BlogImages@main/img/vuln/shebei5f364ef5c9d1a3b1d9bb7153bd166bfc.jpeg)

在x86系统中，将1M空间最上面的0xf0000到0xffffff总计64K的空间映射给了ROM，也就是说，到这部分地址访问的时候，就会访问ROM。

在计算机刚通电时，首先要做一些重置工作，将CS设置为0xffff，将IP设置为0x0000，所以第一指令指向CS << 4 + IP = 0xffff0，刚好在ROM的地址空间范围。在这里，有一个JMP指令会跳转到ROM中做初始化工作的代码，于是BIOS就开始进行初始化工作。

首先，BIOS进行硬件自检，确保硬件运作良好无问题；然后，开始建立一个中断向量表和中断服务程序，此时与键盘鼠标等的硬件通信都需要通过中断来进行。此外，还要在内存空间映射显存的空间，以实现在显示器上显示一些字符。

## 二、bootloader阶段

BIOS在完成自己的工作后，接下来应该做什么呢？--去找操作系统。

操作系统一般安装在硬盘上，在BIOS的洁面上，会看到启动盘的选项。启动盘一般位于磁盘的第一个扇区，占512字节，以0xAA55结束。那么这512字节的代码是谁放在这里的呢？在 Linux 里面有一个工具，叫 **Grub2**，全称 Grand Unified Bootloader Version 2，主要负责系统启动。可以通过 `grub2-mkconfig -o /boot/grub2/grub.cfg` 来配置系统启动的选项，可以看到里面有类似这样的配置：

```c
menuentry 'CentOS Linux (3.10.0-862.el7.x86_64) 7 (Core)' --class centos --class gnu-linux --class gnu --class os --unrestricted $menuentry_id_option 'gnulinux-3.10.0-862.el7.x86_64-advanced-b1aceb95-6b9e-464a-a589-bed66220ebee' {
  load_video
  set gfxpayload=keep
  insmod gzio
  insmod part_msdos
  insmod ext2
  set root='hd0,msdos1'
  if [ x$feature_platform_search_hint = xy ]; then
    search --no-floppy --fs-uuid --set=root --hint='hd0,msdos1'  b1aceb95-6b9e-464a-a589-bed66220ebee
  else
    search --no-floppy --fs-uuid --set=root b1aceb95-6b9e-464a-a589-bed66220ebee
  fi
  linux16 /boot/vmlinuz-3.10.0-862.el7.x86_64 root=UUID=b1aceb95-6b9e-464a-a589-bed66220ebee ro console=tty0 console=ttyS0,115200 crashkernel=auto net.ifnames=0 biosdevname=0 rhgb quiet 
  initrd16 /boot/initramfs-3.10.0-862.el7.x86_64.img
}
```

文件中的选项会在系统启动的时候，成为一个列表，我们可以选择从哪个系统启动。

grub2 第一个要安装的是 **boot.img**。它由 boot.S 编译而成，总计 512 字节，正式安装到启动盘的第一个扇区，该扇区通常称为 **MBR（Master Boot Record，主引导记录 / 扇区）**。

BIOS 完成任务后，会将 boot.img 从硬盘加载到内存中的 0x7C00 来运行。由于 512 个字节实在有限，boot.img 做不了太多的事情。它能做的最重要的一个事情就是加载 grub2 的另一个镜像 **core.img**。core.img 由 **lzma_decompress.img、diskboot.img、kernel.img** 和一系列的模块组成，功能丰富，可以做很多事情。

![img](https://static001.geekbang.org/resource/image/2b/6a/2b8573bbbf31fc0cb0420e32d07b196a.jpeg)

boot.img 先加载的是 core.img 的第一个扇区。如果从硬盘启动的话，这个扇区里面是 **diskboot.img**，对应的代码是 diskboot.S。boot.img 将控制权交给 diskboot.img 后，diskboot.img 的任务就是将 core.img 的其他部分加载进来，先是解压缩程序 lzma_decompress.img，再往下是 kernel.img，最后是各个模块 module 对应的映像。这里需要注意，kernel.img 不是 Linux 的内核，而是 grub 的内核。

lzma_decompress.img 对应的代码是 startup_raw.S，本来 kernel.img 是压缩过的，现在执行的时候，需要解压缩。在这之前的程序都非常非常小，完全可以在实模式下运行，但是随着加载的东西越来越大，实模式这 1M 的地址空间已经不能满足要求，所以在真正的解压缩之前，lzma_decompress.img 调用 **real_to_prot**，切换到保护模式，这样就能在更大的寻址空间里面，加载更多的东西。

## 三、从实模式切换到保护模式

切换到保护模式要干很多工作，大部分工作都与内存的访问方式有关。

第一项是**启用分段**，就是在内存里面建立**段描述符表**，将寄存器里面的段寄存器变成段选择子，指向某个段描述符，这样就能实现不同进程的切换了。

第二项是**启动分页**。能够管理的内存变大了，就需要将内存分成相等大小的块。保护模式还需要做的一项重要工作是打开 **Gate A20**，也就是第 21 根地址线的控制线。在实模式 8086 下面，一共就 20 个地址线，可访问 1M 的地址空间。如果超过了这个限度怎么办呢？当然是绕回来了。在保护模式下，第 21 根要起作用了，于是我们就需要打开 Gate A20。切换保护模式的函数 DATA32 call real_to_prot 会打开 Gate A20，也就是第 21 根地址线的控制线。

（这里对 Gate A20 做个简单介绍：因为8086只有20根地址线，即A0-A19。而段寄存器却只有16位，导致无法直接寻址20位的内存空间，因此intel使用了 CS<<4: offset（16位)作为拼凑为20位的地址，而FFFF左移4位后与FFFF相加的值为10FFEF，结果为21位，最高位1被丢弃，从而100000-10FFEF回卷为00000-0FFEF。因此00000-0FFEF对应有**两个**逻辑地址，很多8086的程序员利用这个回卷特点进行编程。但是到80286时，地址线变为了24根，而CS中存放的也不再是段基地址，而是段选择子，通过段选择子拿到的段基地址可以很方便的扩充到24位，因此就可以访问整个16M地址空间了，但是为了不得罪老用户，intel必须兼容8086，因此就加了个A20与门，当处于实模式时，关闭A20开关，即与门输出为0，这就等价于8086丢弃最高20位的1了，从而地址仍然会进行回卷，这样旧的软件就可以继续跑了。同时，当我们在保护模式下运行基于80286的新程序时，就开启A20开关，即A20与门的输出与地址线A20保持一致，从而可以直接访问更宽的地址。）

接下来，对压缩过的 kernel.img 进行解压缩，然后跳转到 kernel.img 开始运行。kernel.img 对应的代码是 startup.S 以及一堆 c 文件，在 startup.S 中会调用 `grub_main`，这是 grub kernel 的主函数。在这个函数里面，`grub_load_config()` 开始解析，上面写的那个 grub.conf 文件里的配置信息。如果是正常启动，grub_main 最后会调用 `grub_command_execute (“normal”, 0, 0)`，最终会调用 `grub_normal_execute()` 函数。在这个函数里面，`grub_show_menu()`会显示出让你选择的那个操作系统的列表。一旦选定了某个操作系统，就要开始调用 `grub_menu_execute_entry()` ，开始解析并执行选择的那一项。

例如里面的 linux16 命令，表示装载指定的内核文件，并传递内核启动参数。于是 `grub_cmd_linux()` 函数会被调用，它会首先读取 Linux 内核镜像头部的一些数据结构，放到内存中的数据结构来，进行检查。如果检查通过，则会读取整个 Linux 内核镜像到内存。如果配置文件里面还有 `initrd` 命令，用于为即将启动的内核传递 `init ramdisk` 路径。于是 `grub_cmd_initrd()` 函数会被调用，将 `initramfs` 加载到内存中来。当这些事情做完之后，`grub_command_execute (“boot”, 0, 0)` 才开始真正地启动内核。

上述过程可以总结如下：

![无标题-2021-07-20-0942](https://cdn.jsdelivr.net/gh/AlexsanderShaw/BlogImages@main/img/vuln/shebei无标题-2021-07-20-0942.png)

## 参考文献

这里给出我之前总结过的一篇详细的Linux开机启动过程：[Linux开机启动过程详解](https://www.v4ler1an.com/2020/10/boot/)

专栏 —— 《趣谈Linux操作系统》


