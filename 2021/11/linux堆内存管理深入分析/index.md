# Linux堆内存管理深入分析


# Linux堆内存管理深入分析

## 1. 堆概述

### 1. 概念

程序运行过程中，堆可以提供动态分配的内存，允许程序申请大小未知的内存。堆其实就是程序虚拟地址空间的一块连续的线性区域，增长方向为由低到高。一般称管理堆的那部分程序为堆管理器。

堆管理器处于用户程序与内核中间，提供主要以下功能：

1. 响应用户的申请内存请求，向OS申请内存，然后将其返回给用户程序。同时，为了保持内存管理的高效性，内核一般会预先分配很大的一块连续的内存，然后让堆管理器通过某种算法来管理这块内存。只有当出现了堆空间不足的情况，堆管理器才会再次与OS交互，申请新的内存。
2. 管理用户所释放的内存。一般来说，用户释放的内存并不是直接返还给OS，而是由堆管理器进行管理。这些释放的内存在堆管理器的管理下，可以来响应用户新申请的内存的请求。

目前Linux发行版中使用的堆分配器是glibc中的堆分配器：ptmalloc2，其主要通过 `malloc/free` 函数来分配和释放内存块。

注：Linux 内存管理的一个基本思想：只有在真正访问一个地址的时候，OS才会建立虚拟页面与物理页面的映射关系。基于这个思想，OS虽然已经给程序分配了很大的一块内存，但是这块内存其实只是虚拟内存。只有当用户使用到响应的内存时，OS才会真正分配物理页面给用户使用。

### 2. 堆的基本操作

1. 堆分配：`malloc`

   在 glibc 的 [malloc.c](https://github.com/iromise/glibc/blob/master/malloc/malloc.c#L448) 中，其说明如下：

   ```c
   /*
     malloc(size_t n)
     Returns a pointer to a newly allocated chunk of at least n bytes, or null
     if no space is available. Additionally, on failure, errno is set to ENOMEM 
     on ANSI C systems.
     
     If n is zero, malloc returns a minumum-sized chunk. (The minimum
     size is 16 bytes on most 32bit systems, and 24 or 32 bytes on 64bit
     systems.)  On most systems, size_t is an unsigned type, so calls
     with negative arguments are interpreted as requests for huge amounts
     of space, which will often fail. The maximum supported value of n
     differs across systems, but is in all cases less than the maximum
     representable value of a size_t.
   */
   ```

   `malloc` 函数返回的是对应大小字节的内存块的指针。

   - 当n = 0时，返回当前系统允许的堆的最小内存块
   - 当n为负数时，由于在大多数系统上，**size_t 是无符号数（这一点非常重要）**，所以程序会申请很大的内存空间，但通常来说都会失败，因为系统没有那么多的内存可以分配。

2. 堆释放：`free`

   在 glibc 的 [malloc.c](https://github.com/iromise/glibc/blob/master/malloc/malloc.c#L448) 中，其说明如下：

   ```c
   /*
         free(void* p)
         Releases the chunk of memory pointed to by p, that had been previously
         allocated using malloc or a related routine such as realloc.
         It has no effect if p is null. It can have arbitrary (i.e., bad!)
         effects if p has already been freed.
         
         Unless disabled (using mallopt), freeing very large spaces will
         when possible, automatically trigger operations that give
         back unused memory to the system, thus reducing program footprint.
       */
   ```

   `free` 函数会释放由指针 p 所指向的内存块。该内存块可能是 `malloc` f分配的，也可能是类似函数 `realloc` 等分配的。

   - **当 p 为空指针时，函数不执行任何操作。**
   - 当 p 已经被释放后，再次释放会出现意料之外的效果，这其实就是 `Double Free(双重释放)`。
   - 除了被禁用 (mallopt) 的情况下，当释放很大的内存空间时，程序会将这些内存空间还给OS，以便于减小程序所使用的内存空间。

3. 内存分配涉及到的系统调用

   无论是 `malloc` 还是 `free`，在动态申请和释放内存时，并不是真正与系统交互的函数。这些函数背后的系统调用主要是 [(s)brk](https://man7.org/linux/man-pages/man2/sbrk.2.html) 函数以及 [mmap, munmap](https://man7.org/linux/man-pages/man2/mmap.2.html) 函数。

   **堆内存块申请**

   ![img](https://cdn.jsdelivr.net/gh/AlexsanderShaw/BlogImages@main/img/vuln/shebei20210809170445.png)

   #### 

   对于堆内存的分配操作，OS提供了 brk 函数，glibc 提供了 sbrk 函数，我们可以通过增加 [brk](https://en.wikipedia.org/wiki/Sbrk) 的大小来向OS申请内存。

   初始时，堆的起始地址 [start_brk](http://elixir.free-electrons.com/linux/v3.8/source/include/linux/mm_types.h#L365) 以及堆的当前末尾 [brk](http://elixir.free-electrons.com/linux/v3.8/source/include/linux/mm_types.h#L365) 指向同一地址。根据是否开启 ASLR，两者的具体位置会有所不同

   - 不开启 ASLR 保护时，start_brk 以及 brk 会指向 data/bss 段的结尾。
   - 开启 ASLR 保护时，start_brk 以及 brk 也会指向同一位置，只是这个位置是在 data/bss 段结尾后的随机偏移处。

   具体效果如下图（这个图片与网上流传的基本一致，这里是因为要画一张大图，所以自己单独画了下）所示：

   ![img](https://cdn.jsdelivr.net/gh/AlexsanderShaw/BlogImages@main/img/vuln/shebei20210809173409.png)

   代码例子：

   ```c
   /* sbrk and brk example */
   #include <stdio.h>
   #include <unistd.h>
   #include <sys/types.h>
   
   int main()
   {
           void *curr_brk, *tmp_brk = NULL;
   
           printf("Welcome to sbrk example:%d\n", getpid());
   
           /* sbrk(0) gives current program break location */
           tmp_brk = curr_brk = sbrk(0);
           printf("Program Break Location1:%p\n", curr_brk);
           getchar(); // 使用getchar来暂停运行，方便观察
   
           /* brk(addr) increments/decrements program break location */
           brk(curr_brk+4096);
   
           curr_brk = sbrk(0);
           printf("Program break Location2:%p\n", curr_brk);
           getchar();
   
           brk(tmp_brk);
   
           curr_brk = sbrk(0);
           printf("Program Break Location3:%p\n", curr_brk);
           getchar();
   
           return 0;
   }
   ```

   1. 在第一次调用brk之前

      输出如下：

      

   2. 

4. 





