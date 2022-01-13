# Linux-0.11-08


Peach Fuzzer Professional本文是Linux 0.11系列学习记录的正式的第八篇。

从本篇开始，正式进入第二部分，从 main 函数开始。

<!--more-->

## 11. main.c 的初步理解

在经过前面 10 回的操作后，进去 main 函数之前的工作都已完成，接下来就是操作系统的全部代码骨架的地方 —— main 函数。

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

其中的代码部分也就 20 几行，接下来我们拆分来看整个的 `main` 函数。

### 1. 第一部分，参数的取值和计算

```c
// 下面这段代码用于保存：
	// 根设备号 -> ROOT_DEV； 高速缓存末端地址 -> buffer_memory_end；
	// 机器内存数 -> memory_end；主内存开始地址 -> main_memory_start；
 	ROOT_DEV = ORIG_ROOT_DEV;
 	drive_info = DRIVE_INFO;     // 之前在汇编语言中获取的各个设备的参数信息
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
```

设备参数信息来自 `setup.s` 汇编程序调用 BIOS 中断获取的各个设备的信息，并保存在约定好的内存地址 `0x90000` 处，如下表所示：

![image-20220113111731825](https://cdn.jsdelivr.net/gh/AlexsanderShaw/BlogImages@main/img/202201131117592.png)

上面的内存变量则指明了主内存的开始地址、系统所拥有的内存容量和作为高速缓冲区内存的末端地址。而且如果还定义了虚拟盘（RAM DISK），主内存还会适当减少。

### 2. 第二部分，各种初始化 init 操作

内核进行所有方面的硬件初始化工作，包括陷阱门、块设备、字符设备和 tty，还包括人工设置第一个任务（task 0）。所有的初始化工作完成后，程序就设置中断允许标志以开启中断，并切换到任务 0 中进行。在阅读这些初始化子程序时，最好跟着被调用的程序深入进去看，实在看不下去了，就先放放，然后看下一个，在有些理解之后再继续研究没有看懂的地方。

```c
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

```

### 3. 第三部分，切换到用户态

在完成各种初始化后，切换到用户态模式，并在新的进程中做最终的初始化 —— init。

```c
// 下面过程通过在堆栈中设置的参数，利用中断返回指令切换到任务0。
	move_to_user_mode();	// 移到用户模式。（include/asm/system.h）
	if (!fork()) {		/* we count on this going ok */
		init();
	}
```

`init()` 函数会创建一个进程，设置终端的标准 IO，然后再创建出一个执行 shell 程序的进程来接收用户的命令，此时就会出现如下画面：

![image-20220113112752230](https://cdn.jsdelivr.net/gh/AlexsanderShaw/BlogImages@main/img/202201131127277.png)

在整个内核完成初始化后，内核将执行权切换到了用户模式，也即 CPU 从 0 特权级切换到了第 3 特权级。此时 `main.c` 的主程序就工作在任务 0 中，然后系统第一次调用进程创建函数 `fork()`，创建出一个用于运行 `init()` 的子进程。系统的整个初始化过程如下图所示：

![image-20220113113655747](https://cdn.jsdelivr.net/gh/AlexsanderShaw/BlogImages@main/img/202201131136781.png)

### 4. 第四部分，设置无限循环

```c
/*
 * 注意!! 对于任何其它的任务，'pause()'将意味着我们必须等待收到一个信号才会返
 * 回就绪运行态，但任务0（task0）是唯一的意外情况（参见'schedule()'），因为任
 * 务0 在任何空闲时间里都会被激活（当没有其它任务在运行时），
 * 因此对于任务0'pause()'仅意味着我们返回来查看是否有其它任务可以运行，如果没
 * 有的话我们就回到这里，一直循环执行'pause()'。
 */
	for(;;) pause();
```

### 5. 阶段总结

到此为止，我们对 `main.c` 的整体就有了全面的认识，对于其中的细节我们会在接下来的过程中详细分析。

截止到目前为止的内存布局如下：

![image-20220113113901050](https://cdn.jsdelivr.net/gh/AlexsanderShaw/BlogImages@main/img/202201131139101.png)

在接下来的操作中，操作系统会在上面的内存布局中建立各种数据结构及其调用。

我们目前已完成的工作如下：

![image-20220113114006517](https://cdn.jsdelivr.net/gh/AlexsanderShaw/BlogImages@main/img/202201131140576.png)

前面所有工作的重心就是三张表的设置：全局描述符表、中断描述符表、页表。同时还设置了各种段寄存器，栈顶指针。并且，还为后续的程序提供了设备信息，保存在 0x90000 处往后的几个位置上。

### 6. 参考链接

1. [第十一回 整个操作系统就 20 几行代码](https://mp.weixin.qq.com/s/kYBrMgHt7C9EmAcwJIPIxg)
2. 《Linux 内核完全剖析》第7章
