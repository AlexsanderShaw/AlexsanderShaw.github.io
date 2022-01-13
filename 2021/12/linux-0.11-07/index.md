# Linux-0.11-07


Peach Fuzzer Professional本文是Linux 0.11系列学习记录的正式的第七篇。

从本篇开始，在每篇文章中会加入自己的理解和补充，各位可按需查看。

<!--more-->



## 10  进入 main.c

在前面我们已经设置了idt、gdt、页表等，并且开启了保护模式，接下来就准备进入 `main.c` 。

我们前面有提到，在下面的代码处准备跳转到 `main.c`：

```assembly
after_page_tables:
    push 0
    push 0
    push 0
    push L6
    push _main
    jmp setup_paging
...
setup_paging:
    ...
    ret
```

在经过连续的 5 个 `push` 操作之后，内存栈变成如下形式：

![image-20220110195323919](https://cdn.jsdelivr.net/gh/AlexsanderShaw/BlogImages@main/img/202201101953947.png)

然后，`setup_paging` 最后一个指令是 **ret**，也就是我们上一回讲的设置分页的代码的最后一个指令，形象地说它叫**返回指令**，但 CPU 可没有那么聪明，它并不知道该返回到哪里执行，只是很机械地**把栈顶的元素值当做返回地址**，跳转去那里执行。

再具体说是，把 `esp` 寄存器（栈顶地址）所指向的内存处的值，赋值给 eip 寄存器，而 `cs:eip` 就是 CPU 要执行的下一条指令的地址。而此时栈顶刚好是 `main.c` 里写的 main 函数的内存地址，是我们刚刚特意压入栈的，所以 CPU 就理所应当跳过来了。

当然 Intel CPU 是设计了 `call` 和` ret` 这一配对儿的指令，意为调用函数和返回，具体可以看后面本回扩展资料里的内容。

至于其他压入栈的 L6 是用作当 main 函数返回时的跳转地址，但由于在操作系统层面的设计上，main 是绝对不会返回的，所以也就没用了。而其他的三个压栈的 0，本意是作为 main 函数的参数，但实际上似乎也没有用到，所以也不必关心。

总之，经过这一个小小的骚操作，程序终于跳转到 `main.c` 这个由 c 语言写就的主函数 main 里了。

```c
void main(void)		/* 这里确实是void，并没错。 */
{			/* 在startup 程序(head.s)中就是这样假设的。 */
/*
 * 此时中断仍被禁止着，做完必要的设置后就将其开启。
 */
	// 下面这段代码用于保存：
	// 根设备号 -> ROOT_DEV； 高速缓存末端地址 -> buffer_memory_end；
	// 机器内存数 -> memory_end；主内存开始地址 -> main_memory_start；
 	ROOT_DEV = ORIG_ROOT_DEV;
 	drive_info = DRIVE_INFO;
	memory_end = (1<<20) + (EXT_MEM_K<<10);// 内存大小=1Mb 字节+扩展内存(k)*1024 字节。
	memory_end &= 0xfffff000;			// 忽略不到4Kb（1 页）的内存数。
	if (memory_end > 16*1024*1024)		// 如果内存超过16Mb，则按16Mb 计。
		memory_end = 16*1024*1024;
	if (memory_end > 12*1024*1024)		// 如果内存>12Mb，则设置缓冲区末端=4Mb
		buffer_memory_end = 4*1024*1024;
	else if (memory_end > 6*1024*1024)	// 否则如果内存>6Mb，则设置缓冲区末端=2Mb
		buffer_memory_end = 2*1024*1024;
	else
		buffer_memory_end = 1*1024*1024;// 否则则设置缓冲区末端=1Mb
	main_memory_start = buffer_memory_end;// 主内存起始位置=缓冲区末端；
#ifdef RAMDISK	// 如果定义了虚拟盘，则主内存将减少。
	main_memory_start += rd_init(main_memory_start, RAMDISK*1024);
#endif
// 以下是内核进行所有方面的初始化工作。阅读时最好跟着调用的程序深入进去看，实在看
// 不下去了，就先放一放，看下一个初始化调用-- 这是经验之谈:)
	mem_init(main_memory_start,memory_end);
	trap_init();	// 陷阱门（硬件中断向量）初始化。（kernel/traps.c）
	blk_dev_init();	// 块设备初始化。（kernel/blk_dev/ll_rw_blk.c）
	chr_dev_init();	// 字符设备初始化。（kernel/chr_dev/tty_io.c）空，为以后扩展做准备。
	tty_init();		// tty 初始化。（kernel/chr_dev/tty_io.c）
	time_init();	// 设置开机启动时间 -> startup_time。
	sched_init();	// 调度程序初始化(加载了任务0 的tr, ldtr) （kernel/sched.c）
	buffer_init(buffer_memory_end);// 缓冲管理初始化，建内存链表等。（fs/buffer.c）
	hd_init();		// 硬盘初始化。（kernel/blk_dev/hd.c）
	floppy_init();	// 软驱初始化。（kernel/blk_dev/floppy.c）
	sti();			// 所有初始化工作都做完了，开启中断。

// 下面过程通过在堆栈中设置的参数，利用中断返回指令切换到任务0。
	move_to_user_mode();	// 移到用户模式。（include/asm/system.h）
	if (!fork()) {		/* we count on this going ok */
		init();
	}
/*
 * 注意!! 对于任何其它的任务，'pause()'将意味着我们必须等待收到一个信号才会返
 * 回就绪运行态，但任务0（task0）是唯一的意外情况（参见'schedule()'），因为任
 * 务0 在任何空闲时间里都会被激活（当没有其它任务在运行时），
 * 因此对于任务0'pause()'仅意味着我们返回来查看是否有其它任务可以运行，如果没
 * 有的话我们就回到这里，一直循环执行'pause()'。
 */
	for(;;) pause();
} // end main
```

整个OS会最终停留在最后一行的死循环中，永不返回，直到关机。

至此，进入 `main` 函数的准备工作已经全部完成了，前面我们做的所有工作如下：

![image-20220110200152063](https://cdn.jsdelivr.net/gh/AlexsanderShaw/BlogImages@main/img/202201102001095.png)

此时的内存布局如下：

![image-20220110200218189](https://cdn.jsdelivr.net/gh/AlexsanderShaw/BlogImages@main/img/202201102002227.png)

然后进入到 `main` 函数中继续执行。

## 第一部分总结

截止到这一篇位置，第一部分已经全部完成，在进入 `main.c` 之前的所有工作都已经完成，接下来的运行就开始运行 `main` 函数了。

由于这一部分大部分都是在和 Intel CPU 打交道，所以参考资料大部分是 Intel 手册：

![image-20220110200612851](https://cdn.jsdelivr.net/gh/AlexsanderShaw/BlogImages@main/img/202201102006889.png)

