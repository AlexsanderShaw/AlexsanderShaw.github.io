# Linux ptrace 详解


# Linux ptrace 详解

**备注：文章中使用的Linux内核源码版本为Linux 5.9，使用的Linux版本为Linux ubuntu 5.4.0-65-generic**

## 一、简述

ptrace系统调用提供了一个进程(`tracer`)可以控制另一个进程(`tracee`)运行的方法，并且`tracer`可以监控和修改`tracee`的内存和寄存器，主要用作实现断点调试和系统调用跟踪。

`tracee`首先要被attach到`tracer`上，这里的attach以线程为对象，在多线程场景（这里的多线程场景指的使用`clone CLONE_THREAD` flag创建的线程组）下，每个线程可以分别被attach到`tracer`上。ptrace的命令总是以下面的调用格式发送到指定的`tracee`上：

```c
ptrace(PTRACE_foom, pid, ...)   // pid为linux中对应的线程ID
```

一个进程可以通过调用`fork()`函数来初始化一个跟踪，并让生成的子进程执行`PTRACE_TRACEME`，然后执行`execve`(一般情况下)来启动跟踪。进程也可以使用`PTRACE_ATTACH`或`PTRACE_SEIZE`进行跟踪。

当处于被跟踪状态时，`tracee`每收到一个信号就会stop，即使是某些时候信号是被忽略的。`tracer`将在下一次调用`waitpid`或与`wait`相关的系统调用之一）时收到通知。该调用会返回一个状态值，包含`tracee`停止的原因。`tracee`发生stop时，`tracer`可以使用各种ptrace的`request`来检查和修改`tracee`。然后，`tracer`使`tracee`继续运行，选择性地忽略所传递的信号（甚至传递一个与原来不同的信号）。

当`tracer`结束跟踪后，发送`PTRACE_DETACH`信号释放`tracee`，`tracee`可以在常规状态下继续运行。

## 二、函数原型及初步使用

### 1. 函数原型

ptrace的原型如下：

```C
long ptrace(enum __ptrace_request request, pid_t pid, void *addr, void *data);
```

其中`request`参数表明执行的行为（后续将重点介绍）， `pid`参数标识目标进程，`addr`参数表明执行`peek`和`poke`操作的地址，`data`参数则对于`poke`操作，指明存放数据的地址，对于`peek`操作，指明获取数据的地址。

返回值，成功执行时，`PTRACE_PEEK`请求返回所请求的数据，其他情况时返回0，失败则返回-1。`errno`被设置为

### 2. 函数定义

ptrace的内核实现在kernel/ptrace.c文件中，内核接口是SYSCALL_DEFINE4(ptrace, long, request, long, pid, unsigned long, addr, unsigned long, data)，从中可以看到整个代码逻辑比较简单，其中对PTRACE_TRACEME和PTRACE_ATTACH 是做特殊处理的。其他的是与架构相关的。

```c
SYSCALL_DEFINE4(ptrace, long, request, long, pid, unsigned long, addr,unsigned long, data)
{
    struct task_struct *child;
    long ret;

    if (request == PTRACE_TRACEME) {
        ret = ptrace_traceme();
        if (!ret)
            arch_ptrace_attach(current);
        goto out;
    }

    child = find_get_task_by_vpid(pid);
    if (!child) {
        ret = -ESRCH;
        goto out;
    }

    if (request == PTRACE_ATTACH || request == PTRACE_SEIZE) {
        ret = ptrace_attach(child, request, addr, data);
        /*
        * Some architectures need to do book-keeping after
        * a ptrace attach.
        */
        if (!ret)
            arch_ptrace_attach(child);
        goto out_put_task_struct;
    }

    ret = ptrace_check_attach(child, request == PTRACE_KILL ||
                request == PTRACE_INTERRUPT);
    if (ret < 0)
        goto out_put_task_struct;

    ret = arch_ptrace(child, request, addr, data);
    if (ret || request != PTRACE_DETACH)
        ptrace_unfreeze_traced(child);

out_put_task_struct:
    put_task_struct(child);
out:
    return ret;
}
```
系统调用都改为了`SYSCALL_DEFINE`的方式。如何获得上面的定义的呢？这里需要穿插一下`SYSCALL_DEFINE`的定义(syscall.h):
```c
#define SYSCALL_DEFINE1(name, ...) SYSCALL_DEFINEx(1, _##name, __VA_ARGS__)
#define SYSCALL_DEFINE2(name, ...) SYSCALL_DEFINEx(2, _##name, __VA_ARGS__)
#define SYSCALL_DEFINE3(name, ...) SYSCALL_DEFINEx(3, _##name, __VA_ARGS__)
#define SYSCALL_DEFINE4(name, ...) SYSCALL_DEFINEx(4, _##name, __VA_ARGS__)
#define SYSCALL_DEFINE5(name, ...) SYSCALL_DEFINEx(5, _##name, __VA_ARGS__)
#define SYSCALL_DEFINE6(name, ...) SYSCALL_DEFINEx(6, _##name, __VA_ARGS__)
```
宏定义进行展开：

```c
#define SYSCALL_DEFINEx(x, sname, ...)				\
	SYSCALL_METADATA(sname, x, __VA_ARGS__)			\
	__SYSCALL_DEFINEx(x, sname, __VA_ARGS__)

/*
 * The asmlinkage stub is aliased to a function named __se_sys_*() which
 * sign-extends 32-bit ints to longs whenever needed. The actual work is
 * done within __do_sys_*().
 */
#ifndef __SYSCALL_DEFINEx
#define __SYSCALL_DEFINEx(x, name, ...)					\
	__diag_push();							\
	__diag_ignore(GCC, 8, "-Wattribute-alias",			\
		      "Type aliasing is used to sanitize syscall arguments");\
	asmlinkage long sys##name(__MAP(x,__SC_DECL,__VA_ARGS__))	\
		__attribute__((alias(__stringify(__se_sys##name))));	\
	ALLOW_ERROR_INJECTION(sys##name, ERRNO);			\
	static inline long __do_sys##name(__MAP(x,__SC_DECL,__VA_ARGS__));\
	asmlinkage long __se_sys##name(__MAP(x,__SC_LONG,__VA_ARGS__));	\
	asmlinkage long __se_sys##name(__MAP(x,__SC_LONG,__VA_ARGS__))	\
	{								\
		long ret = __do_sys##name(__MAP(x,__SC_CAST,__VA_ARGS__));\
		__MAP(x,__SC_TEST,__VA_ARGS__);				\
		__PROTECT(x, ret,__MAP(x,__SC_ARGS,__VA_ARGS__));	\
		return ret;						\
	}								\
	__diag_pop();							\
	static inline long __do_sys##name(__MAP(x,__SC_DECL,__VA_ARGS__))
#endif /* __SYSCALL_DEFINEx */

```
`__SYSCALL_DEFINEx`中的`x`表示系统调用的参数个数，且`sys_ptrace`的宏定义如下：
```c
/* kernel/ptrace.c */
asmlinkage long sys_ptrace(long request, long pid, unsigned long addr,
			   unsigned long data);
```
所以对应的`__SYSCALL_DEFINEx`应该是`SYSCALL_DEFINE4`，这与上面的定义`SYSCALL_DEFINE4(ptrace, long, request, long, pid, unsigned long, addr, unsigned long, data)`一致。

仔细观察上面的代码可以发现，函数定义其实在最后一行，结尾没有分号，然后再加上花括号即形成完整的函数定义。前面的几句代码并不是函数的实现（详细的分析可以跟踪源码，出于篇幅原因此处不放出每个宏定义的跟踪）。

定义的转换过程：

```c
SYSCALL_DEFINE4(ptrace, long, request, long, pid, unsigned long, addr, unsigned long, data) 
--> SYSCALL_DEFINEx(4, _ptrace, __VA_ARGS__)  
	-->  __SYSCALL_DEFINEx(4, __ptrace, __VA_ARGS__)
      #define __SYSCALL_DEFINEx(x, name, ...) \
        asmlinkage long sys##name(__MAP(x,__SC_DECL,__VA_ARGS__)) \
      --> asmlinkage long sys_ptrace(__MAP(4,__SC_DECL,__VA_ARGS__))
```

而对`__MAP`宏和`__SC_DECL`宏的定义如下：

```c
/*
 * __MAP - apply a macro to syscall arguments
 * __MAP(n, m, t1, a1, t2, a2, ..., tn, an) will expand to
 *    m(t1, a1), m(t2, a2), ..., m(tn, an)
 * The first argument must be equal to the amount of type/name
 * pairs given.  Note that this list of pairs (i.e. the arguments
 * of __MAP starting at the third one) is in the same format as
 * for SYSCALL_DEFINE<n>/COMPAT_SYSCALL_DEFINE<n>
 */
#define __MAP0(m,...)
#define __MAP1(m,t,a,...) m(t,a)
#define __MAP2(m,t,a,...) m(t,a), __MAP1(m,__VA_ARGS__)
#define __MAP3(m,t,a,...) m(t,a), __MAP2(m,__VA_ARGS__)
#define __MAP4(m,t,a,...) m(t,a), __MAP3(m,__VA_ARGS__)
#define __MAP5(m,t,a,...) m(t,a), __MAP4(m,__VA_ARGS__)
#define __MAP6(m,t,a,...) m(t,a), __MAP5(m,__VA_ARGS__)
#define __MAP(n,...) __MAP##n(__VA_ARGS__)

#define __SC_DECL(t, a)	t a
```

按照如上定义继续进行展开

```c
__MAP(4,__SC_DECL, long request, long pid, unsigned long addr,
			   unsigned long data)
-->  __MAP4(__SC_DECL, long, request, long, pid, unsigned long, addr,
			   unsigned long, data)
-->  __SC_DECL(long, request), __MAP3(__SC_DECL, __VA_ARGS__)
  __MAP3(__SC_DECL, long, pid, unsigned long, addr, unsigned long, data)
  --> __SC_DECL(long, pid), __MAP2(__SC_DECL, unsigned long, addr, unsigned long, data)		
  		-->__SC_DECL(unsigned long, addr), __MAP1(__SC_DECL, __VA_ARGS__)
  			unsigned long addr, __SC_DECL(unsigned long, data)
  			--> unsigned long data
  long pid, __SC_DECL(unsigned long, addr), __MAP1(__SC_DECL, __VA_ARGS__)
  --> long pid, unsigned long addr, unsigned long data 
-->  long request, __SC_DECL(long, pid), __MAP2(__SC_DECL, __VA_ARGS__)
-->  long request, long pid, unsigned long addr, unsigned long data
  
```

最后调用`asmlinkage long sys_ptrace(long request, long pid, unsigned long addr, unsigned long data);`。

为什么要将系统调用定义成宏？主要是因为2个内核漏洞CVE-2009-0029，CVE-2010-3301，Linux 2.6.28及以前版本的内核中，将系统调用中32位参数传入64位的寄存器时无法作符号扩展，可能导致系统崩溃或提权漏洞。

内核开发者通过将系统调用的所有输入参数都先转化成long类型（64位），再强制转化到相应的类型来规避这个漏洞。

```c
asmlinkage long __se_sys##name(__MAP(x,__SC_LONG,__VA_ARGS__)) \
{ \
        long ret = __do_sys##name(__MAP(x,__SC_CAST,__VA_ARGS__));\
        __MAP(x,__SC_TEST,__VA_ARGS__); \
        __PROTECT(x, ret,__MAP(x,__SC_ARGS,__VA_ARGS__)); \
        return ret; \
} \

define __TYPE_AS(t, v) __same_type((__force t)0, v) /*判断t和v是否是同一个类型*/

define __TYPE_IS_L(t) (__TYPE_AS(t, 0L)) /*判断t是否是long 类型,是返回1*/

define __TYPE_IS_UL(t) (__TYPE_AS(t, 0UL)) /*判断t是否是unsigned long 类型,是返回1*/

define __TYPE_IS_LL(t) (__TYPE_AS(t, 0LL) || __TYPE_AS(t, 0ULL)) /*是long类型就返回1*/

define __SC_LONG(t, a) __typeof(__builtin_choose_expr(__TYPE_IS_LL(t), 0LL, 0L)) a /*将参数转换成long类型*/

define __SC_CAST(t, a) (__force t) a /*转成成原来的类型*/

define __force __attribute__((force)) /*表示所定义的变量类型可以做强制类型转换*/
```

### 2. 初步使用

#### 1. 最简单的ls跟踪

首先通过一个简单的例子来熟悉一下`ptrace`的使用：

```c
#include <stdio.h>
#include <unistd.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/reg.h>
#include <sys/types.h>
 
 
int main(int argc, char *argv[]){

	pid_t child;
	long orig_rax;

	child = fork();

	if(child == 0){
		ptrace(PTRACE_TRACEME, 0, NULL, NULL);  // Tell kernel, trace me
			execl("/bin/ls", "ls", NULL);
	}else{   
		/*Receive certification after child process stopped*/
		wait(NULL);

		/*Read child process's rax*/
		orig_rax = ptrace(PTRACE_PEEKUSER, child, 8*ORIG_RAX, NULL);
		printf("[+] The child made a system call %ld.\n", orig_rax);
        
		/*Continue*/
		ptrace(PTRACE_CONT, child, NULL, NULL);
        }
		
    return 0;
}   
```

运行结果如下：

![ptrace_demo](https://cdn.jsdelivr.net/gh/AlexsanderShaw/BlogImages@main/img/vuln/shebeiptrace_demo.png)

打印出系统调用号，并等待用户输入。查看`/usr/include/x86_64-linux-gnu/asm/unistd_64.h`文件（64位系统）查看59对应的系统调用：

![system_call_execve](https://cdn.jsdelivr.net/gh/AlexsanderShaw/BlogImages@main/img/vuln/shebeisystem_call_execve.png)

59号恰好为`execve`函数调用。对上面的过程进行简单总结：

1. 父进程通过调用`fork()`来创建子进程，在子进程中，执行`execl()`之前，先运行`ptrace()`，`request`参数设置为`PTRACE_TRACEME`来告诉kernel当前进程正在被trace。当有信号量传递到该进程，进程会stop，提醒父进程在`wait()`调用处继续执行。然后调用`execl()`，执行成功后，新程序运行前，`SIGTRAP`信号量被发送到该进程，子进程停止，父进程在`wait()`调用处收到通知，获取子进程的控制权，查看子进程内存和寄存器相关信息。

2. 当发生系统调用时，kernel保存了`rax`寄存器的原始内容，其中存放的是系统调用号，我们可以使用`request`参数为`PTRACE_PEEKUSER`的`ptrace`来从子进程的`USER`段读取出该值。

3. 系统调用检查结束后，子进程通过调用`request`参数为`PTRACE_CONT`的`ptrace`函数继续执行。

#### 2. 系统调用查看参数

```c
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <sys/user.h>
#include <sys/reg.h>
#include <stdio.h>
#include <sys/syscall.h>


int main(int argc, char *argv[]){
    pid_t child;
    long orig_rax, rax;
    long params[3];
    int status;
    int insyscall = 0;

    child = fork();
    if(child == 0){
        ptrace(PTRACE_TRACEME, 0, NULL, NULL);
        execl("/bin/ls", "ls", NULL);
    }else{
        while(1){
            wait(&status);
            if(WIFEXITED(status))
                break;
			orig_rax = ptrace(PTRACE_PEEKUSER, child, 8 * ORIG_RAX, NULL);
			if(orig_rax == SYS_write){
				if(insyscall == 0){
					insyscall = 1;
					params[0] = ptrace(PTRACE_PEEKUSER, child, 8 * RBX, NULL);
					params[1] = ptrace(PTRACE_PEEKUSER, child, 8 * RCX, NULL);
					params[2] = ptrace(PTRACE_PEEKUSER, child, 8 * RDX, NULL);
					printf("Write called with %ld, %ld, %ld\n", params[0], params[1], params[2]);
				}else{
					rax = ptrace(PTRACE_PEEKUSER, child, 8 * RAX, NULL);
					printf("Write returned with %ld\n", rax);
					insyscall = 0;
				}
			}
			ptrace(PTRACE_SYSCALL, child, NULL, NULL);
		}
	}
	return 0;
}
```

执行结果：

![system_call_ls](https://cdn.jsdelivr.net/gh/AlexsanderShaw/BlogImages@main/img/vuln/shebeisystem_call_ls.png)

在上面的程序中，跟踪的是`wirte`的系统调用，`ls`命令总计进行了三次`write`的调用。`request`参数为`PTEACE_SYSCALL`时的`ptrace`使kernel在进行系统调用进入或退出时stop子进程，这等价于执行`PTRACE_CONT`并在下一次系统调用进入或退出时stop。

`wait`系统调用中的`status`变量用于检查子进程是否已退出，这是用来检查子进程是否被ptrace停掉或是否退出的典型方法。而宏`WIFEXITED`则表示了子进程是否正常结束（例如通过调用`exit`或者从`main`返回等），正常结束时返回`true`。

#### 3. 系统调用参数-改进版

前面有介绍`PTRACE_GETREGS`参数，使用它来获取寄存器的值相比前面一种方法要简单很多：

```c
#include <stdio.h>
#include <sys/reg.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <sys/ptrace.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <unistd.h>

int main(int argc, char *argv[]){

    pid_t child;
    long orig_rax, rax;
    long params[3];
    int status;
    int insyscall = 0;
    struct user_regs_struct regs;

    child = fork();
    if(child == 0){
        ptrace(PTRACE_TRACEME, child, 8 * ORIG_RAX, NULL);
        execl("/bin/ls", "ls", NULL);
    }
    else{
        while(1){
            wait(&status);
            if(WIFEXITED(status))
                break;
            orig_rax = ptrace(PTRACE_PEEKUSER, child, 8*ORIG_RAX, NULL);
            if(orig_rax == SYS_write){
                if(insyscall == 0){
                    insyscall == 1;
                    ptrace(PTRACE_GETREGS, child, NULL, &regs);
                    printf("Write called with %lld,  %lld,  %lld\n", regs.rbx, regs.rcx, regs.rdx);
                }else{
                    rax = ptrace(PTRACE_PEEKUSER, child, 8*rax, NULL);
                    printf("Write returned with %ld\n", rax);
                    insyscall = 0;
                }
            }
            ptrace(PTRACE_SYSCALL, child, NULL, NULL);
        }
    }
    return 0;
}
```

执行结果：

![system_call_getregs](https://cdn.jsdelivr.net/gh/AlexsanderShaw/BlogImages@main/img/vuln/shebeisystem_call_getregs.png)

整体输出与前面的代码无所差别，但在代码开发上使用了`PTRACE_GETREGS`来获取子进程的寄存器的值，简洁了很多。

## 三、sys_ptrace函数源码分析

### 1. Linux-2.6版本的源码分析

#### 1. 源码分析

首先看一下linux-2.6.0的`sys_ptrace`的处理流程（以`/arch/i386/kernel/ptrace.c`为例）：

```c
/* 
 * Note that this implementation of ptrace behaves differently from vanilla
 * ptrace.  Contrary to what the man page says, in the PTRACE_PEEKTEXT,
 * PTRACE_PEEKDATA, and PTRACE_PEEKUSER requests the data variable is not
 * ignored.  Instead, the data variable is expected to point at a location
 * (in user space) where the result of the ptrace call is written (instead of
 * being returned).
 */
asmlinkage int sys_ptrace(long request, long pid, long addr, long data)
{
	struct task_struct *child;
	struct user * dummy = NULL;
	int i, ret;

	lock_kernel();
	ret = -EPERM;
	if (request == PTRACE_TRACEME) {  // 请求为PTRACE_TRACEME
		/* 检查是否做好被跟踪的准备 */
		if (current->ptrace & PT_PTRACED)
			goto out;
		ret = security_ptrace(current->parent, current);
		if (ret)
			goto out;
    /* 检查通过，在process flags中设置ptrace位*/
		current->ptrace |= PT_PTRACED;
		ret = 0;
		goto out;
	}
  
  /* 非PTRACE_TRACEME的请求*/
	ret = -ESRCH;   // 首先设置返回值为ESRCH，表明没有该进程，宏定义在errno-base.h头文件中
	read_lock(&tasklist_lock);
	child = find_task_by_pid(pid);		// 查找task结构
	if (child)
		get_task_struct(child);
	read_unlock(&tasklist_lock);
	if (!child)     // 没有找到task结构，指明所给pid错误
		goto out;

	ret = -EPERM;   // 返回操作未授权
	if (pid == 1)		// init进程不允许被调试
		goto out_tsk;
	
  /* 请求为 PTRACE_ATTACH 时*/
	if (request == PTRACE_ATTACH) {
		ret = ptrace_attach(child); // 进行attach
		goto out_tsk;
	}
	
  /* 检查进程是否被跟踪，没有的话不能执行其他功能；
   * 当不是PTRACE_KILL时，要求进程状态为TASK_STOPPED；
   * 被跟踪进程必须为当前进程的子进程
   * 在之前是直接在该代码处实现以上逻辑，现在重新将以上功能封装成了ptrace_check_attach函数
   */
	ret = ptrace_check_attach(child, request == PTRACE_KILL);  
	if (ret < 0)
		goto out_tsk;
  
  /* 以下就为根据不同的request参数进行对应的处理了，用一个switch来总括，流程比较简单。*/
	switch (request) {
    /* when I and D space are separate, these will need to be fixed. 这算预告吗？23333*/
    case PTRACE_PEEKTEXT: /* read word at location addr. */ 
    case PTRACE_PEEKDATA: {
      unsigned long tmp;
      int copied;

      copied = access_process_vm(child, addr, &tmp, sizeof(tmp), 0);
      ret = -EIO;  // 返回I/O错误
      if (copied != sizeof(tmp))
        break;
      ret = put_user(tmp,(unsigned long *) data);
      break;
    }

    /* read the word at location addr in the USER area. */
    case PTRACE_PEEKUSR: {
      unsigned long tmp;

      ret = -EIO;
      if ((addr & 3) || addr < 0 || 
          addr > sizeof(struct user) - 3)
        break;

      tmp = 0;  /* Default return condition */
      if(addr < FRAME_SIZE*sizeof(long))
        tmp = getreg(child, addr);
      if(addr >= (long) &dummy->u_debugreg[0] &&
         addr <= (long) &dummy->u_debugreg[7]){
        addr -= (long) &dummy->u_debugreg[0];
        addr = addr >> 2;
        tmp = child->thread.debugreg[addr];
      }
      ret = put_user(tmp,(unsigned long *) data);
      break;
    }

    /* when I and D space are separate, this will have to be fixed. */
    case PTRACE_POKETEXT: /* write the word at location addr. */
    case PTRACE_POKEDATA:
      ret = 0;
      if (access_process_vm(child, addr, &data, sizeof(data), 1) == sizeof(data))
        break;
      ret = -EIO;
      break;

    case PTRACE_POKEUSR: /* write the word at location addr in the USER area */
      ret = -EIO;
      if ((addr & 3) || addr < 0 || 
          addr > sizeof(struct user) - 3)
        break;

      if (addr < FRAME_SIZE*sizeof(long)) {
        ret = putreg(child, addr, data);
        break;
      }
      /* We need to be very careful here.  We implicitly
         want to modify a portion of the task_struct, and we
         have to be selective about what portions we allow someone
         to modify. */

        ret = -EIO;
        if(addr >= (long) &dummy->u_debugreg[0] &&
           addr <= (long) &dummy->u_debugreg[7]){

          if(addr == (long) &dummy->u_debugreg[4]) break;
          if(addr == (long) &dummy->u_debugreg[5]) break;
          if(addr < (long) &dummy->u_debugreg[4] &&
             ((unsigned long) data) >= TASK_SIZE-3) break;

          if(addr == (long) &dummy->u_debugreg[7]) {
            data &= ~DR_CONTROL_RESERVED;
            for(i=0; i<4; i++)
              if ((0x5f54 >> ((data >> (16 + 4*i)) & 0xf)) & 1)
                goto out_tsk;
          }

          addr -= (long) &dummy->u_debugreg;
          addr = addr >> 2;
          child->thread.debugreg[addr] = data;
          ret = 0;
        }
        break;

    case PTRACE_SYSCALL: /* continue and stop at next (return from) syscall */
    case PTRACE_CONT: { /* restart after signal. */
      long tmp;

      ret = -EIO;
      if ((unsigned long) data > _NSIG)
        break;
      if (request == PTRACE_SYSCALL) {
        set_tsk_thread_flag(child, TIF_SYSCALL_TRACE);
      }
      else {
        clear_tsk_thread_flag(child, TIF_SYSCALL_TRACE);
      }
      child->exit_code = data;
    /* make sure the single step bit is not set. */
      tmp = get_stack_long(child, EFL_OFFSET) & ~TRAP_FLAG;
      put_stack_long(child, EFL_OFFSET,tmp);
      wake_up_process(child);
      ret = 0;
      break;
    }

  /*
   * make the child exit.  Best I can do is send it a sigkill. 
   * perhaps it should be put in the status that it wants to 
   * exit.
   */
    case PTRACE_KILL: {
      long tmp;

      ret = 0;
      if (child->state == TASK_ZOMBIE)	/* already dead */
        break;
      child->exit_code = SIGKILL;
      /* make sure the single step bit is not set. */
      tmp = get_stack_long(child, EFL_OFFSET) & ~TRAP_FLAG;
      put_stack_long(child, EFL_OFFSET, tmp);
      wake_up_process(child);
      break;
    }

    case PTRACE_SINGLESTEP: {  /* set the trap flag. */
      long tmp;

      ret = -EIO;
      if ((unsigned long) data > _NSIG)
        break;
      clear_tsk_thread_flag(child, TIF_SYSCALL_TRACE);
      if ((child->ptrace & PT_DTRACE) == 0) {
        /* Spurious delayed TF traps may occur */
        child->ptrace |= PT_DTRACE;
      }
      tmp = get_stack_long(child, EFL_OFFSET) | TRAP_FLAG;
      put_stack_long(child, EFL_OFFSET, tmp);
      child->exit_code = data;
      /* give it a chance to run. */
      wake_up_process(child);
      ret = 0;
      break;
    }

    case PTRACE_DETACH:
      /* detach a process that was attached. */
      ret = ptrace_detach(child, data);
      break;

    case PTRACE_GETREGS: { /* Get all gp regs from the child. */
        if (!access_ok(VERIFY_WRITE, (unsigned *)data, FRAME_SIZE*sizeof(long))) {
        ret = -EIO;
        break;
      }
      for ( i = 0; i < FRAME_SIZE*sizeof(long); i += sizeof(long) ) {
        __put_user(getreg(child, i),(unsigned long *) data);
        data += sizeof(long);
      }
      ret = 0;
      break;
    }

    case PTRACE_SETREGS: { /* Set all gp regs in the child. */
      unsigned long tmp;
        if (!access_ok(VERIFY_READ, (unsigned *)data, FRAME_SIZE*sizeof(long))) {
        ret = -EIO;
        break;
      }
      for ( i = 0; i < FRAME_SIZE*sizeof(long); i += sizeof(long) ) {
        __get_user(tmp, (unsigned long *) data);
        putreg(child, i, tmp);
        data += sizeof(long);
      }
      ret = 0;
      break;
    }

    case PTRACE_GETFPREGS: { /* Get the child FPU state. */
      if (!access_ok(VERIFY_WRITE, (unsigned *)data,
               sizeof(struct user_i387_struct))) {
        ret = -EIO;
        break;
      }
      ret = 0;
      if (!child->used_math)
        init_fpu(child);
      get_fpregs((struct user_i387_struct __user *)data, child);
      break;
    }

    case PTRACE_SETFPREGS: { /* Set the child FPU state. */
      if (!access_ok(VERIFY_READ, (unsigned *)data,
               sizeof(struct user_i387_struct))) {
        ret = -EIO;
        break;
      }
      child->used_math = 1;
      set_fpregs(child, (struct user_i387_struct __user *)data);
      ret = 0;
      break;
    }

    case PTRACE_GETFPXREGS: { /* Get the child extended FPU state. */
      if (!access_ok(VERIFY_WRITE, (unsigned *)data,
               sizeof(struct user_fxsr_struct))) {
        ret = -EIO;
        break;
      }
      if (!child->used_math)
        init_fpu(child);
      ret = get_fpxregs((struct user_fxsr_struct __user *)data, child);
      break;
    }

    case PTRACE_SETFPXREGS: { /* Set the child extended FPU state. */
      if (!access_ok(VERIFY_READ, (unsigned *)data,
               sizeof(struct user_fxsr_struct))) {
        ret = -EIO;
        break;
      }
      child->used_math = 1;
      ret = set_fpxregs(child, (struct user_fxsr_struct __user *)data);
      break;
    }

    case PTRACE_GET_THREAD_AREA:
      ret = ptrace_get_thread_area(child,
                 addr, (struct user_desc __user *) data);
      break;

    case PTRACE_SET_THREAD_AREA:
      ret = ptrace_set_thread_area(child,
                 addr, (struct user_desc __user *) data);
      break;

    default:
      ret = ptrace_request(child, request, addr, data);
      break;
    }
out_tsk:
	put_task_struct(child);
out:
	unlock_kernel();
	return ret;
}
```

整体来看较为简单，经过简单的验证后根据不同的`request`参数进入不同的处理流程。

#### 2. 流程梳理

根据源码分析结果，梳理函数的整体处理流程如下（为保证图片清晰，将图片进行了切割）：

![image-20210205100242848](/Users/yaoyao/Desktop/image-20210205100242848.png)

![image-20210205100304868](/Users/yaoyao/Desktop/image-20210205100304868.png)

上述流程图基本描述清晰了Linux-2.6版本下的`sys_ptrace`函数的执行流程。其中可以看参数为到`PTRACE_TRACEME, PTRACE_ATTACH`时进行了特殊处理，其他情况下，流程基本相同，根据不同的`request`的值调用对应的handler函数即可。

#### 3. 其他

在Linux-2.6版本中，针对不同platform设计了不同的函数实现，总体流程上没有改变，只是根据不同的platform特点在某些位置坐了不同的处理方式。各platform对应的函数实现文件如下：

![image-20210205101058491](https://cdn.jsdelivr.net/gh/AlexsanderShaw/BlogImages@main/img/vuln/shebeiimage-20210205101058491.png)

在`kernel/ptrace.c`中实现对公共函数的实现，此处不做过多介绍，感兴趣的师傅可自行研究：

```c
/*
 * linux/kernel/ptrace.c
 *
 * (C) Copyright 1999 Linus Torvalds
 *
 * Common interfaces for "ptrace()" which we do not want
 * to continually duplicate across every architecture.
 */

... ...
  
/*
 * ptrace a task: make the debugger its new parent and
 * move it to the ptrace list.
 *
 * Must be called with the tasklist lock write-held.
 */
void __ptrace_link(task_t *child, task_t *new_parent)
{
	... ...
}
 
/*
 * unptrace a task: move it back to its original parent and
 * remove it from the ptrace list.
 *
 * Must be called with the tasklist lock write-held.
 */
void __ptrace_unlink(task_t *child)
{
	... ...
}

/*
 * Check that we have indeed attached to the thing..
 */
int ptrace_check_attach(struct task_struct *child, int kill)
{
	if (!(child->ptrace & PT_PTRACED))
		return -ESRCH;

	if (child->parent != current)
		return -ESRCH;

	if (!kill) {
		if (child->state != TASK_STOPPED)
			return -ESRCH;
		wait_task_inactive(child);
	}

	/* All systems go.. */
	return 0;
}

int ptrace_attach(struct task_struct *task)
{
	... ...
}

int ptrace_detach(struct task_struct *child, unsigned int data)
{
	... ...
}

/*
 * Access another process' address space.
 * Source/target buffer must be kernel space, 
 * Do not walk the page table directly, use get_user_pages
 */

int access_process_vm(struct task_struct *tsk, unsigned long addr, void *buf, int len, int write)
{
	... ...
}

int ptrace_readdata(struct task_struct *tsk, unsigned long src, char __user *dst, int len)
{
	... ...
}

int ptrace_writedata(struct task_struct *tsk, char __user *src, unsigned long dst, int len)
{
	... ...
}

static int ptrace_setoptions(struct task_struct *child, long data)
{
	... ...
}

static int ptrace_getsiginfo(struct task_struct *child, siginfo_t __user * data)
{
	... ...
}

static int ptrace_setsiginfo(struct task_struct *child, siginfo_t __user * data)
{
	... ...
}

int ptrace_request(struct task_struct *child, long request,
		   long addr, long data)
{
	int ret = -EIO;

	switch (request) {
#ifdef PTRACE_OLDSETOPTIONS
	case PTRACE_OLDSETOPTIONS:
#endif
	case PTRACE_SETOPTIONS:
		ret = ptrace_setoptions(child, data);
		break;
	case PTRACE_GETEVENTMSG:
		ret = put_user(child->ptrace_message, (unsigned long __user *) data);
		break;
	case PTRACE_GETSIGINFO:
		ret = ptrace_getsiginfo(child, (siginfo_t __user *) data);
		break;
	case PTRACE_SETSIGINFO:
		ret = ptrace_setsiginfo(child, (siginfo_t __user *) data);
		break;
	default:
		break;
	}

	return ret;
}

void ptrace_notify(int exit_code)
{
	BUG_ON (!(current->ptrace & PT_PTRACED));

	/* Let the debugger run.  */
	current->exit_code = exit_code;
	set_current_state(TASK_STOPPED);
	notify_parent(current, SIGCHLD);
	schedule();

	/*
	 * Signals sent while we were stopped might set TIF_SIGPENDING.
	 */

	spin_lock_irq(&current->sighand->siglock);
	recalc_sigpending();
	spin_unlock_irq(&current->sighand->siglock);
}

EXPORT_SYMBOL(ptrace_notify);

```

### 2. Linux-5.9版本的源码分析

#### 1. 源码分析

Linux-5.9版本的源码分析：

```c
SYSCALL_DEFINE4(ptrace, long, request, long, pid, unsigned long, addr,
		unsigned long, data)
{
	struct task_struct *child;
	long ret;

	if (request == PTRACE_TRACEME) { // 请求是否为PTRACE_TRACEME
		ret = ptrace_traceme();
		if (!ret)						
			arch_ptrace_attach(current);
		goto out;
	}

	child = find_get_task_by_vpid(pid); // 通过pid请求task结构
	if (!child) {  // 请求失败，返回ESRCH
		ret = -ESRCH;
		goto out;
	}

	if (request == PTRACE_ATTACH || request == PTRACE_SEIZE) {
		ret = ptrace_attach(child, request, addr, data);
		/*
		 * Some architectures need to do book-keeping after
		 * a ptrace attach.
		 */
		if (!ret)
			arch_ptrace_attach(child);
		goto out_put_task_struct;
	}

	ret = ptrace_check_attach(child, request == PTRACE_KILL ||
				  request == PTRACE_INTERRUPT);
	if (ret < 0)
		goto out_put_task_struct;

  /* 根据不同的架构进行不同的处理 */
	ret = arch_ptrace(child, request, addr, data);
	if (ret || request != PTRACE_DETACH)
		ptrace_unfreeze_traced(child);

 out_put_task_struct:
	put_task_struct(child);
 out:
	return ret;
}
```

#### 2. 流程梳理

梳理上述源码，可以得到函数流程图如下：

![image-20210205114716666](https://cdn.jsdelivr.net/gh/AlexsanderShaw/BlogImages@main/img/vuln/shebeiimage-20210205114716666.png)

#### 3. 其他

Linux-5.9中使用了宏的方式，在进行函数调用时先进行函数替换解析出完整的函数体再进行具体执行（详细替换可参考系列（一）中的函数定义部分内容）。而且与Linux-2.6不同的是，`kernel/ptrace.c`负责总体调度，使用`arch_ptrace`进行不同架构的处理的选择：

![image-20210205110727411](https://cdn.jsdelivr.net/gh/AlexsanderShaw/BlogImages@main/img/vuln/shebeiimage-20210205110727411.png)

Linux-5.9版本的这种改动相比Linux-2.6的设计，更为清晰也更为安全（个人十分喜欢这种设计，由衷佩服这些优秀的开发者）。

## 四、Request参数详解

### 1. 参数简述

`ptrace`总计有4个参数，其中比较重要的是第一个参数--`request`，该参数决定了具体执行的系统调用功能。可取值如下（部分）：

| Request                          | Description                                                  |
| -------------------------------- | ------------------------------------------------------------ |
| PTRACE_TRACEME                   | 进程被其父进程跟踪，其父进程应该希望跟踪子进程。该值仅被tracee使用，其余的request值仅被tracer使用 |
| PTRACE_PEEKTEXT, PTRACE_PEEKDATA | 从tracee的addr指定的内存地址中读取一个字节作为ptrace()调用的结果 |
| PTRACE_PEEKUSER                  | 从tracee的USER区域中便宜为addr处读取一个字节，该值保存了进程的寄存器和其他信息 |
| PTRACE_POKETEXT, PTRACE_POKEDATA | 向tracee的addr内存地址处复制一个字节数据                     |
| PTRACE_POKEUSER                  | 向tracee的USER区域中偏移为addr地址处复制一个字节数据         |
| PTRACE_GETREGS                   | 复制tracee的通用寄存器到tracer的data处                       |
| PTRACE_GETFPREGS                 | 复制tracee的浮点寄存器到tracer的data处                       |
| PTRACE_GETREGSET                 | 读取tracee的寄存器                                           |
| PTRACE_SETREGS                   | 设置tracee的通用寄存器                                       |
| PTRACE_SETFPREGS                 | 设置tracee的浮点寄存器                                       |
| PTRACE_CONT                      | 重新运行stopped状态的tracee进程                              |
| PTRACE_SYSCALL                   | 重新运行stopped状态的tracee进程，但是使tracee在系统调用的下一个entry或从系统调用退出或在执行一条指令后stop |
| PTRACE_SINGLESTEP                | 设置单步执行标志                                             |
| PTRACE_ATTACH                    | 跟踪指定pid的进程                                            |
| PTRACE_DETACH                    | 结束跟踪                                                     |

备注：上述参数中，`PTRACE_GETREGS, PTRACE_SETREGS, PTRACE_GETFPREGS, PTRACE_SETFPREGS`参数为Interl386特有。

各参数所代表的值由`/usr/include/sys/ptrace.h`文件指定：

![20210201202646](https://cdn.jsdelivr.net/gh/AlexsanderShaw/BlogImages@main/img/vuln/shebei20210201202646.png)

### 2. 重要参数详解

下面将对`request`中几个常见、重要的参数进行详细解析：

##### 1. PTRACE_TRACEME

1. 描述
   本进程被其父进程跟踪，如果子进程没有被其父进程跟踪，不能使用该选项。`PTRACE_TRACEME` 只被`tracee`使用。
   
2. 定义

   ```c
    /**
     * ptrace_traceme  --  helper for PTRACE_TRACEME
    *
    * Performs checks and sets PT_PTRACED.
    * Should be used by all ptrace implementations for PTRACE_TRACEME.
    */
    static int ptrace_traceme(void)
    {
        int ret = -EPERM;

        write_lock_irq(&tasklist_lock);   // 首先让writer拿到读写lock，并且会disable local irp

        /* Are we already being traced? */

        // 是否已经处于ptrace中
        if (!current->ptrace) {
            ret = security_ptrace_traceme(current->parent);
            /*
            * Check PF_EXITING to ensure ->real_parent has not passed
            * exit_ptrace(). Otherwise we don't report the error but
            * pretend ->real_parent untraces us right after return.
            */
            if (!ret && !(current->real_parent->flags & PF_EXITING)) {
                // 检查通过，将子进程链接到父进程的ptrace链表中
                current->ptrace = PT_PTRACED;
                ptrace_link(current, current->real_parent);
            }
        }

        write_unlock_irq(&tasklist_lock);

        return ret;
    }
   ```
   
3. 分析

   通过分析源码我们可以明确看到，`PTRACE_TRACEME`并没有真正使子进程停止。它内部完成的操作只有对父进程是否能对子进程进行trace的合法性检查，然后将子进程链接到父进程的饿ptrace链表中。真正导致子进程停止的是`exec`系统调用。

   在系统调用成功后，kernel会判断该进程是否被ptrace跟踪。如果处于跟踪状态，kernel将会向该进程发送`SIGTRAP`信号，正是该信号导致了当前进程的停止。

   ```c
   /**
    * ptrace_event - possibly stop for a ptrace event notification
    * @event:	%PTRACE_EVENT_* value to report
    * @message:	value for %PTRACE_GETEVENTMSG to return
    *
    * Check whether @event is enabled and, if so, report @event and @message
    * to the ptrace parent.
    *
    * Called without locks.
    */
   static inline void ptrace_event(int event, unsigned long message)
   {
   	if (unlikely(ptrace_event_enabled(current, event))) {
   		current->ptrace_message = message;
   		ptrace_notify((event << 8) | SIGTRAP);
   	} else if (event == PTRACE_EVENT_EXEC) {
   		/* legacy EXEC report via SIGTRAP */
   		if ((current->ptrace & (PT_PTRACED|PT_SEIZED)) == PT_PTRACED)
   			send_sig(SIGTRAP, current, 0);
   	}
   }
   ```

   在`exec.c`中对该函数的调用如下：

   ```c
   static int exec_binprm(struct linux_binprm *bprm)
   {
   	pid_t old_pid, old_vpid;
   	int ret, depth;
   
   	/* Need to fetch pid before load_binary changes it */
   	old_pid = current->pid;
   	rcu_read_lock();
   	old_vpid = task_pid_nr_ns(current, task_active_pid_ns(current->parent));
   	rcu_read_unlock();
   	.......
   	audit_bprm(bprm);
   	trace_sched_process_exec(current, old_pid, bprm);
     
     // 调用ptrace_event,传入的event为PTRACE_EVENT_EXEC
     // 直接走发送SIGTRAP的逻辑
   	ptrace_event(PTRACE_EVENT_EXEC, old_vpid);  
     
   	proc_exec_connector(current);
   	return 0;
   }
   ```

   `SIGTRAP`信号的值为5，专门为调试设计。当kernel发生`int 3`时，触发回掉函数`do_trap()`，其代码如下：

   ```c
   asmlinkage void do_trap(struct pt_regs *regs, unsigned long address)
   {
   	force_sig_fault(SIGTRAP, TRAP_TRACE, (void __user *)address);
   
   	regs->pc += 4;
   }
   
   
   int force_sig_fault(int sig, int code, void __user *addr
   	___ARCH_SI_TRAPNO(int trapno)
   	___ARCH_SI_IA64(int imm, unsigned int flags, unsigned long isr))
   {
   	return force_sig_fault_to_task(sig, code, addr
   				       ___ARCH_SI_TRAPNO(trapno)
   				       ___ARCH_SI_IA64(imm, flags, isr), current);
   }
   ```

   父进程唤醒`wait`对子进程进行监控，`wait`有3种退出情况（子进程正常退出、收到信号退出、收到信号暂停），对于`PTRACE_TRACEME`来说，对应的是第三种情况--收到信号后暂停。

   `PTRACE_TRACEME`只是表明了子进程可以被trace，如果进程调用了`PTRACE_TRACEME`，那么该进程处理信号的方式会发生改变。例如一个进程正在运行，此时输入`ctrl+c(SIGINT)`,则进程会直接退出；如果进程中有`ptrace  (PTRACE_TRACEME,0，NULL,NULL)`，当输入`CTRL+C`时，该进程将会处于stopped的状态。

   在`sys_ptrace`函数中，该部分的处理流程如下：

   ![image-20210205142516160](https://cdn.jsdelivr.net/gh/AlexsanderShaw/BlogImages@main/img/vuln/shebeiimage-20210205142516160.png)

   在5.9版中，单独写成了`ptrace_traceme()`函数，而在2.6版本中，直接在`sys_ptrace`的逻辑中进行实现：

   ![image-20210205142732193](https://cdn.jsdelivr.net/gh/AlexsanderShaw/BlogImages@main/img/vuln/shebeiimage-20210205142732193.png)

   虽然2个版本的核心功能相同，但是5.9版本的处理逻辑和情况考量相比2.6版本上升了很大高度。

##### 2. PTRACE_ATTACH

1. 描述

   attach到pid指定的进程，使其成为调用进程的`tracee`。`tracer`会向`tracee`发送一个`SIGSTOP`信号，但不一定已通过此调用完成而停止；`tracer`使用`waitpid()`等待`tracee`停止。

2. 定义

   ```c
   static int ptrace_attach(struct task_struct *task, long request,
   			 unsigned long addr,
   			 unsigned long flags)
   {
   	bool seize = (request == PTRACE_SEIZE);
   	int retval;
   
   	retval = -EIO;  /* I/O error*/
   
   	/*
   	* 判断request是PTRACE_SEIZE还是PTRACE_ATTACH。
   	* 如果request为PTRACE_SEIZE，则进行必要的参数检查，错误时退出。
   	*/
   	if (seize) {
   		if (addr != 0)
   			goto out;
   		if (flags & ~(unsigned long)PTRACE_O_MASK)
   			goto out;
   		flags = PT_PTRACED | PT_SEIZED | (flags << PT_OPT_FLAG_SHIFT);
   	} else {
   		flags = PT_PTRACED;
   	}
   
   	audit_ptrace(task);
   
   	/* 
   	* 判断task进程是否为kernel thread（PF_KTHREAD），
   	* 调用same_thread_group(task, current)，判断task是否和current进程在同一个线程组，查看current进程是否有权限trace task进程。
   	* 如果不符合要求，则直接退出。
   	*/
   	retval = -EPERM;  /* Operation not permitted, retval = -1 */
   	if (unlikely(task->flags & PF_KTHREAD))
   		goto out;
   	if (same_thread_group(task, current))
   		goto out;
   
   	/*
   	 * Protect exec's credential calculations against our interference;
   	 * SUID, SGID and LSM creds get determined differently
   	 * under ptrace.
   	 */
   	retval = -ERESTARTNOINTR;
   	if (mutex_lock_interruptible(&task->signal->cred_guard_mutex))
   		goto out;
   
   	task_lock(task);
   	retval = __ptrace_may_access(task, PTRACE_MODE_ATTACH_REALCREDS);
   	task_unlock(task);
   	if (retval)
   		goto unlock_creds;
   
   	write_lock_irq(&tasklist_lock);
   	retval = -EPERM;
   	if (unlikely(task->exit_state))
   		goto unlock_tasklist;
   	if (task->ptrace)
   		goto unlock_tasklist;
   
   	/*
   	 * 设置子进程task->ptrace = PT_TRACED，被跟踪状态
   	 */
   	if (seize)
   		flags |= PT_SEIZED;
   	task->ptrace = flags;
   
   	/*
   	 * 调用__ptrace_link(task, current)，将task->ptrace_entry链接到current->ptraced链表中。
   	 */
   	ptrace_link(task, current);
   
   	/* SEIZE doesn't trap tracee on attach */
   	/*
   	 * 如果是PTRACE_ATTACH请求（PTRACE_SEIZE请求不会停止被跟踪进程），
   	 * 则调用send_sig_info(SIGSTOP,SEND_SIG_PRIV, task);
   	 * 发送SIGSTOP信号，中止task运行，设置task->state为TASK_STOPPED
   	 */
   	if (!seize)
   		send_sig_info(SIGSTOP, SEND_SIG_PRIV, task);
   
   	spin_lock(&task->sighand->siglock);
   
   	/*
   	 * If the task is already STOPPED, set JOBCTL_TRAP_STOP and
   	 * TRAPPING, and kick it so that it transits to TRACED.  TRAPPING
   	 * will be cleared if the child completes the transition or any
   	 * event which clears the group stop states happens.  We'll wait
   	 * for the transition to complete before returning from this
   	 * function.
   	 *
   	 * This hides STOPPED -> RUNNING -> TRACED transition from the
   	 * attaching thread but a different thread in the same group can
   	 * still observe the transient RUNNING state.  IOW, if another
   	 * thread's WNOHANG wait(2) on the stopped tracee races against
   	 * ATTACH, the wait(2) may fail due to the transient RUNNING.
   	 *
   	 * The following task_is_stopped() test is safe as both transitions
   	 * in and out of STOPPED are protected by siglock.
   	 * 
   	 * 
   	 *
   	 * 等待task->jobctl的JOBCTL_TRAPPING_BIT位被清零，
   	 * 阻塞时进程状态被设置为TASK_UNINTERRUPTIBLE，引发进程调度
   	 */
   
   	if (task_is_stopped(task) &&
   	    task_set_jobctl_pending(task, JOBCTL_TRAP_STOP | JOBCTL_TRAPPING))
   		signal_wake_up_state(task, __TASK_STOPPED);
   
   	spin_unlock(&task->sighand->siglock);
   
   	retval = 0;
   unlock_tasklist:
   	write_unlock_irq(&tasklist_lock);
   unlock_creds:
   	mutex_unlock(&task->signal->cred_guard_mutex);
   out:
   	if (!retval) {
   		/*
   		 * We do not bother to change retval or clear JOBCTL_TRAPPING
   		 * if wait_on_bit() was interrupted by SIGKILL. The tracer will
   		 * not return to user-mode, it will exit and clear this bit in
   		 * __ptrace_unlink() if it wasn't already cleared by the tracee;
   		 * and until then nobody can ptrace this task.
   		 */
   		wait_on_bit(&task->jobctl, JOBCTL_TRAPPING_BIT, TASK_KILLABLE);
   		proc_ptrace_connector(task, PTRACE_ATTACH);
   	}
   
   	return retval;
   }
   ```

3. 分析

    代码上可以看出，`PTRACE_ATTACH`处理的方式与`PTRACE_TRACEME`处理的方式不同。`PTRACE_ATTACH`会使父进程直接向子进程发送`SIGSTOP`信号，如果子进程停止，那么父进程的`wait`操作被唤醒，从而成功attach。一个进程不能attach多次。

    在2.6版本中的实现如下(`kernel/ptrace.c`)：

    ```c
    int ptrace_attach(struct task_struct *task)
    {
    	int retval;
    	task_lock(task);
    	retval = -EPERM;
    	if (task->pid <= 1)		// 不能调试init
    		goto bad;
    	if (task == current)  // 不能调试自身
    		goto bad;
    	if (!task->mm)
    		goto bad;
      /* 鉴权 */
    	if(((current->uid != task->euid) ||
    	    (current->uid != task->suid) ||
    	    (current->uid != task->uid) ||
     	    (current->gid != task->egid) ||
     	    (current->gid != task->sgid) ||
     	    (current->gid != task->gid)) && !capable(CAP_SYS_PTRACE))
    		goto bad;
    	rmb();
    	if (!task->mm->dumpable && !capable(CAP_SYS_PTRACE))
    		goto bad;
    	
    	if (task->ptrace & PT_PTRACED)   // 一个进程不能被attach多次
    		goto bad;
    	retval = security_ptrace(current, task);
    	if (retval)
    		goto bad;
    
    	/* Go */
    	task->ptrace |= PT_PTRACED;
    	if (capable(CAP_SYS_PTRACE))
    		task->ptrace |= PT_PTRACE_CAP;
    	task_unlock(task);
    
    	write_lock_irq(&tasklist_lock);
    	__ptrace_link(task, current);      // 调用__ptrace_link(task, current)，将task->ptrace_entry链接到current->ptraced链表中
    	write_unlock_irq(&tasklist_lock);
    
    	force_sig_specific(SIGSTOP, task);  // 发送SIGSTOP，终止运行
    	return 0;
    
    bad:
    	task_unlock(task);
    	return retval;
    }
    ```

##### 3. PTRACE_PEEKTEXT，PTRACE_PEEKDATA

1. 描述

   在Linux（i386）中，用户代码段和用户数据段是重合的所以PTRACE_PEEKTEXT，PTRACE_PEEKDATA的处理是相同的。在其它CPU或操作系统上有可能是分开的，那要分开处理。读写用户段数据通过`read_long()`和`write_long()`两个辅助函数完成。

2. 定义

3. 分析

##### 4. PTRACE_PEEKUSR

1. 描述
2. 定义
3. 分析

##### 5. PTRACE_POKEUSR

1. 描述
2. 定义
3. 分析

##### 6. PTRACE_SYSCALL，PTRACE_CONT

1. 描述
2. 定义
3. 分析

##### 7. PTRACE_KILL

1. 描述
2. 定义
3. 分析

##### 8. PTRACE_DETACH

1. 描述
2. 定义
3. 分析


