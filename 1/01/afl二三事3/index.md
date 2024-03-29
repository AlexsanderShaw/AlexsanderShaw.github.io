# 

# AFL二三事 -- 2


本文是AFL系列第二篇，主要介绍AFL的一些基本原理。

<!--more-->

## 一、代码覆盖率

### 1. 计算方法

代码覆盖率的计量单位，通常有3种：

>函数（Fuction-Level）
>
>基本块（BasicBlock-Level）
>
>边界（Edge-Level）

* （1）函数（Fuction-Level）

  这个很容易理解，就是代码执行时调用到哪些函数，但是函数里面的具体代码行却不作统计，相对比较粗糙但高效的统计方式。

  所以，通常的统计方式是用基本块，简称BB。

* （2）基本块（BasicBlock-Level）

  基本块，直接看下图就很容易理解了。

![image-20210819105527622](https://cdn.jsdelivr.net/gh/AlexsanderShaw/BlogImages@main/img/vuln/shebei20210819105527.png)

 IDA中每一块代码就代表着一个基本块，就是以指令跳转为作划分界限的。

* （3）边界（Edge-Level）

  edge本身就涵盖了基本块部分，唯一的差别是edge多记录了一些执行边界的信息。比如示例代码：

 ![image-20210825094512035](https://cdn.jsdelivr.net/gh/AlexsanderShaw/BlogImages@main/img/vuln/shebei20210825094512.png)

  在IDA中可以看到A、B、C这3个基本块，但当a为假时，程序就会从A执行到C。

  ![image-20210825094442736](https://cdn.jsdelivr.net/gh/AlexsanderShaw/BlogImages@main/img/vuln/shebei20210825094442.png)

  前面基本块的方式就无法确切地知道是否曾从A执行到C，尤其是该段代码被多次执行的情况，就更无法知道，这时edge覆盖方式就出现了。

  edge会在A跟C之间建立虚拟块D，通过判断D是否执行过，来确认是否曾从A执行到C，这种方式也会比较消耗性能。

  ![image-20210825094456219](https://cdn.jsdelivr.net/gh/AlexsanderShaw/BlogImages@main/img/vuln/shebei20210825094456.png)

*以上内容摘自泉哥博客，原文链接`https://riusksk.me/2018/07/29/honggfuzz%E6%BC%8F%E6%B4%9E%E6%8C%96%E6%8E%98%E6%8A%80%E6%9C%AF1/`*

AFL采用的是第三种方式。

### 2. AFL中两种代码覆盖率计算方式

AFL支持两种代码覆盖率计算方式，有源码的情况下，在源代码编译时进行插桩，无源码的情况下，使用QEMU进行二进制插桩。下一章节会分别详细讲解这两种情况使用的插桩技术。

## 二、插桩

### 1. 有源码

我们以如下代码为例进行说明，文件名为 `socket.c`

```c
#include<stdio.h>
#include<stdlib.h>
#include<string.h>
#include<unistd.h>
#include<sys/socket.h>
#include<netinet/in.h>

#define SERV_PORT 8000
#define SIZE 100
#define MAXLINE 64

int command(char* buf)
{
    char recv[32];
    memset(recv, 32, 0);
    strcpy(recv, buf + 8);
    return 0;
}

int main()
{
    struct sockaddr_in servaddr,cliaddr;
    socklen_t cliaddr_len;
    int listenfd,connfd;
    char buf[MAXLINE];
    int i,n,flag = 0;
	
    listenfd = socket(AF_INET,SOCK_STREAM,0);
    bzero(&servaddr,sizeof(servaddr));
    servaddr.sin_family = AF_INET;
    servaddr.sin_addr.s_addr = htonl(INADDR_ANY);
    servaddr.sin_port = htons(SERV_PORT);
    bind(listenfd,(struct sockaddr *)&servaddr,sizeof(servaddr));
    listen(listenfd,20);
    printf("Accepting connections..\n");
    
    cliaddr_len = sizeof(cliaddr);
    connfd = accept(listenfd,(struct sockaddr *)&cliaddr,&cliaddr_len);
    char send_msg[MAXLINE*2] = "hello, send by send() :\n";
    send(connfd, send_msg, strlen(send_msg), 0);
    n = read(connfd,buf,MAXLINE);
    if(n!=0){
        if(!strncmp(buf, "test ", 5))
            sprintf(send_msg, "test: %s\n", buf + 5);
        else if(!strncmp(buf, "help", 4))
            sprintf(send_msg, "help:\n\ttest\n\tcommand\n\texit\n");
        else if(!strncmp(buf, "command ", 8)){
            command(buf);
            sprintf(send_msg, "it's a command\n");
        }
        else if(!strncmp(buf, "exit", 4))
            send(connfd, "bye~\n", 4, 0);
        else
            sprintf(send_msg, "unknown command!\n");
        send(connfd, send_msg, strlen(send_msg), 0);
    }
    else
        printf("Client say close the connection..\n");
    close(connfd);
}
```

可以进行源码插桩的指令有 `afl-gcc`、`afl-g++`、`afl-clang`、`afl-clang++` ( `afl-clang-fast` 和 `afl-clang-fast++` 暂不讨论)，通过查看这些文件的具体属性，可以发现后三者都是 `afl-gcc` 的软链接，其实都是同一个二进制文件：

![image-20210819105959293](https://cdn.jsdelivr.net/gh/AlexsanderShaw/BlogImages@main/img/vuln/shebei20210819105959.png)

通过分析 `afl-gcc.c` 中的代码可以发现， `afl-gcc` 就是在原有的编译指令上增加一些编译选项然后调用对应的系统调用指令：

为了方便查看每次源码编译时的编译选项，可以对 `afl-gcc.c` 进行修改，在 `main()` 函数中调用 `execvp()` 之前添加如下代码，打印出实际执行的编译指令：

```c
//print command
for(int i = 0; i < cc_par_cnt; i++){
    printf("%s ", cc_params[i]);
}
printf("\n");
```

其中数组 `cc_params` 存放着编译指令和选项，整数 `cc_par_cnt` 存放数组有效值，修改完成后对AFL重新进行编译即可。

（`afl-clang-fast` 和 `afl-clang-fast++` 对应的源码文件为 `llvm_mode/afl-clang-fast.c` ，修改方法相同）

使用 `afl-gcc` 对上面代码进行编译

```shell
afl-gcc -o socket_afl socket.c
```

![image-20210819163111374](https://cdn.jsdelivr.net/gh/AlexsanderShaw/BlogImages@main/img/vuln/shebei20210819163111.png)

可以看到实际执行的编译指令为 `gcc -o socket socket.c -B /usr/local/lib/afl -g -O3 -funroll-loops -D__AFL_COMPILER=1 -DFUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION=1` ，其中 `-B <directory>` 选项用于将<directory>添加到编译器的搜索路径，`-g` 选项生成调试信息，`-O3` 优化生成代码，`-funroll-loops` 选项展开循环的迭代次数可以在编译时或进入循环时确定，剩余两个为AFL使用的选项。（gcc的选项可以参考此链接 `https://gcc.gnu.org/onlinedocs/gcc-4.4.2/gcc/Optimize-Options.html`）

如果了解编译过程，那么就知道把源代码编译成二进制，主要是经过”源代码”->”汇编代码”->”二进制”这样的过程。而将汇编代码编译成为二进制的工具，即为汇编器assembler。Linux系统下的常用汇编器是as。不过，编译完成AFL后，在其目录下也会存在一个as文件，并作为符号链接指向afl-as。所以，如果通过-B选项为gcc设置了搜索路径，那么afl-as便会作为汇编器，执行实际的汇编操作。

所以，AFL的代码插桩，就是在将源文件编译为汇编代码后，通过 `afl-as` 完成。

**afl-as**

下面通过对比 `gcc` 和 `afl-gcc` 的编译结果进行大致分析。

将 `afl-gcc` 中添加的 `-B`、`-D__AFL_COMPILER=1`、`DFUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION=1` 三个选项去掉，调用 `gcc`

```shell
gcc -o socket socket.c -g -O3 -funroll-loops
```

这样就生成了 `socket_afl` 和 `socket` 两个文件。

使用 `bindiff` 对这两个文件中的 `main` 函数进行对比

![image-20210819164111883](https://cdn.jsdelivr.net/gh/AlexsanderShaw/BlogImages@main/img/vuln/shebei20210819164111.png)

上图中右下角部分看起来结构不一样，不过这里是 `bindiff` 识别bug，多出了一个代码块并且少了一条线，我们可以分别使用 `ida` 打开这两个文件，查看 `main` 函数的结构图

![image-20210819164420030](https://cdn.jsdelivr.net/gh/AlexsanderShaw/BlogImages@main/img/vuln/shebei20210819164420.png)

这里对 `bindiff` 误报结果的详细分析就不多说了，这个不是本次的重点。

可以看到 `afl` 进行源代码插桩时不会改变代码的逻辑结构，也不会增加或减少代码块。

对比看下每个代码块中代码的区别

![image-20210819164616722](https://cdn.jsdelivr.net/gh/AlexsanderShaw/BlogImages@main/img/vuln/shebei20210819164616.png)

可以看出，基本每个代码块都被添加了一段相似的汇编代码

在 `ida` 中将这部分代码拷贝出来，如下：

	lea     rsp, [rsp-98h]
	mov     [rsp+1D0h+var_1D0], rdx
	mov     [rsp+1D0h+var_1C8], rcx
	mov     [rsp+1D0h+var_1C0], n
	mov     rcx, 650Eh
	call    __afl_maybe_log
	mov     n, [rsp+1D0h+var_1C0]
	mov     rcx, [rsp+1D0h+var_1C8]
	mov     rdx, [rsp+1D0h+var_1D0]
	lea     rsp, [rsp+98h]

对比可以发现，不同的代码块只有 `mov     rcx, 650Eh` 这条汇编代码向 `rcx` 存放的值不同，这个就是随机生成的标识代码块的id，当运行到这部分汇编时 `afl` 就知道是哪个代码块被执行了。

上述 `ida` 中的汇编代码原型可以在 `afl-as.h` 中找到（以64位代码为例）：

![image-20210819165131286](https://cdn.jsdelivr.net/gh/AlexsanderShaw/BlogImages@main/img/vuln/shebei20210819165131.png)

上述代码执行的主要功能包括：

- 保存 `rdx`、 `rcx` 、`rax` 寄存器
- 将 `rcx` 的值设置为 `fprintf()` 函数将要打印的变量内容
- 调用 `__afl_maybe_log` 函数
- 恢复寄存器

在以上的功能中， `__afl_maybe_log` 是插桩代码所执行的实际内容，后续将详细展开。

可以在 `afl-as.c` 中查看到该汇编的调用，通过 `fprintf()` 函数的调用，将格式化字符串添加到汇编文件的相应位置。

![image-20210819170330292](https://cdn.jsdelivr.net/gh/AlexsanderShaw/BlogImages@main/img/vuln/shebei20210825094725.png)

这里分析下 `R(MAP_SIZE)` ，它就是上面汇编代码中将 `rcx` 设置的值。根据定义， `MAP_SIZE` 为64K，而对于 `R(x)` 函数定义如下：

![image-20210819170411739](https://cdn.jsdelivr.net/gh/AlexsanderShaw/BlogImages@main/img/vuln/shebei20210819170411.png)

其中 `R(MAP_SIZE)` 相当于 `random() % (1 << MAP_SIZE_POW2)` ，也就是生成随机数，所以标识代码块的id是随机生成的（两次编译生成的代码段id不同）。

上述过程总结起来就是**在处理到某个分支需要插入桩代码时， `afl-as` 会随机生成一个随机数，作为运行时保存在 `rcx` 中的值。而这个随机数，便是用于标识这个代码块的id。**

（**备注：因为代码块ID随机的问题，会导致一定的性能问题。在AFL++中开发了一种新的afl-clang-lto编译模式，对该问题进行了一定程度上的优化，后续在分析AFL++时会再深入谈该问题**）

### 2. 无源码

无源码情况下，AFL使用QEMU进行二进制插桩，具体插桩原理待补充。

## 三、变异策略

AFL维护了一个队列(queue)，每次从这个队列中取出一个文件，对其进行大量变异，并检查运行后是否会引起目标崩溃、发现新路径等结果。变异的主要类型如下：

>bitflip，按位翻转，1变为0，0变为1<br>
>arithmetic，整数加/减算术运算<br>
>interest，把一些特殊内容替换到原文件中<br>
>dictionary，把自动生成或用户提供的token替换/插入到原文件中<br>
>havoc，中文意思是“大破坏”，此阶段会对原文件进行大量变异<br>
>splice，中文意思是“拼接”，此阶段会将两个文件拼接起来得到一个新的文件

其中，前四项 bitflip, arithmetic, interest, dictionary 是非 dumb mode（-d）和主 fuzzer（-M）会进行的操作，由于其变异方式没有随机性，所以也称为 deterministic fuzzing ；havoc 和 splice 则存在随机性，是所有状况的 fuzzer（是否 dumb mode、主从 fuzzer）都会执行的变异。

以下将对这些变异类型进行具体介绍。

###（1） bitflip

拿到一个原始文件，首先进行的就是bitflip，而且还会根据翻转量/步长进行多种不同的翻转，按照顺序依次为：

>bitflip 1/1， 每次翻转1个bit，按照每1个bit的步长从头开始<br>
>bitflip 2/1， 每次翻转相邻的2个bit，按照每1个bit的步长从头开始<br>
>bitflip 4/1， 每次翻转相邻的4个bit，按照每1个bit的步长从头开始<br>
>bitflip 8/8， 每次翻转相邻的8个bit，按照每8个bit的步长从头开始，即依次对每个byte做翻转<br>
>bitflip 16/8，每次翻转相邻的16个bit，按照每8个bit的步长从头开始，即依次对每个word做翻转<br>
>bitflip 32/8，每次翻转相邻的32个bit，按照每8个bit的步长从头开始，即依次对每个dword做翻转<br>

在上述过程中，AFL巧妙地嵌入了一些对文件格式的启发式判断，以图尽可能多得获取文件信息。

**自动检测token**

在进行 bitflip 1/1变异时，对于每个 byte 的最低位( least significant bit )翻转还进行了额外的处理：如果连续多个 bytes 的最低位被翻转后，程序的执行路径都未变化，而且与原始执行路径不一致，那么就把这一段连续的 bytes 判断是一条token。

例如，PNG文件中用IHDR作为起始块的标识，那么就会存在类似于以下的内容：

```
	........IHDR........
```
当翻转到字符I的最高位时，因为IHDR被破坏，此时程序的执行路径肯定与处理正常文件的路径是不同的；随后，在翻转接下来3个字符的最高位时，IHDR标识同样被破坏，程序应该会采取同样的执行路径。由此，AFL就判断得到一个可能的token：IHDR，并将其记录下来为后面的变异提供备选。

AFL采取的这种方式是非常巧妙的：就本质而言，这实际上是对每个byte进行修改并检查执行路径；但集成到bitflip后，就不需要再浪费额外的执行资源了。此外，为了控制这样自动生成的token的大小和数量，AFL还在config.h中通过宏定义了限制：

```c
	/* Length limits for auto-detected dictionary tokens: */
	
	#define MIN_AUTO_EXTRA 3 #define MAX_AUTO_EXTRA 32 
	/* Maximum number of auto-extracted dictionary tokens to actually use in fuzzing (first value), and to keep in memory as candidates. The latter should be much higher than the former. */
	
	#define USE_AUTO_EXTRAS 10 
	#define MAX_AUTO_EXTRAS (USE_AUTO_EXTRAS * 10)
```

对于一些文件来说，我们已知其格式中出现的token长度不会超过4，那么我们就可以修改 `MAX_AUTO_EXTRA` 为4并重新编译AFL，以排除一些明显不会是token的情况。遗憾的是，这些设置是通过宏定义来实现，所以不能做到运行时指定，每次修改后必须重新编译AFL。

**生成effector map**

在进行bitflip 8/8变异时，AFL还生成了一个非常重要的信息：effector map。这个effector map几乎贯穿了整个deterministic fuzzing的始终。

具体地，在对每个byte进行翻转时，如果其造成执行路径与原始路径不一致，就将该byte在effector map中标记为1，即“有效”的，否则标记为0，即“无效”的。

这样做的逻辑是：如果一个byte完全翻转，都无法带来执行路径的变化，那么这个byte很有可能是属于”data”，而非”metadata”（例如size, flag等），对整个fuzzing的意义不大。所以，在随后的一些变异中，会参考effector map，跳过那些“无效”的byte，从而节省了执行资源。

由此，通过极小的开销（没有增加额外的执行次数），AFL又一次对文件格式进行了启发式的判断。看到这里，不得不叹服于AFL实现上的精妙。

不过，在某些情况下并不会检测有效字符。第一种情况就是dumb mode或者从fuzzer，此时文件所有的字符都有可能被变异。第二、第三种情况与文件本身有关：

```c
	/* Minimum input file length at which the effector logic kicks in: */
	
	#define EFF_MIN_LEN 128 
	/* Maximum effector density past which everything is just fuzzed unconditionally (%): */
	
	#define EFF_MAX_PERC 90
```

即默认情况下，如果文件小于128 bytes，那么所有字符都是“有效”的；同样地，如果AFL发现一个文件有超过90%的bytes都是“有效”的，那么也不差那10%了，大笔一挥，干脆把所有字符都划归为“有效”。

***

###（2） arithmetic

在bitflip变异全部进行完成后，便进入下一个阶段：arithmetic。与bitflip类似的是，arithmetic根据目标大小的不同，也分为了多个子阶段：

>arith 8/8，每次对8个bit进行加减运算，按照每8个bit的步长从头开始，即对文件的每个byte进行整数加减变异<br>
>arith 16/8，每次对16个bit进行加减运算，按照每8个bit的步长从头开始，即对文件的每个word进行整数加减变异<br>
>arith 32/8，每次对32个bit进行加减运算，按照每8个bit的步长从头开始，即对文件的每个dword进行整数加减变异<br>

加减变异的上限，在config.h中的宏ARITH_MAX定义，默认为35。所以，对目标整数会进行+1, +2, …, +35, -1, -2, …, -35的变异。特别地，由于整数存在大端序和小端序两种表示方式，AFL会贴心地对这两种整数表示方式都进行变异。

此外，AFL还会智能地跳过某些arithmetic变异。第一种情况就是前面提到的effector map：如果一个整数的所有bytes都被判断为“无效”，那么就跳过对整数的变异。第二种情况是之前bitflip已经生成过的变异：如果加/减某个数后，其效果与之前的某种bitflip相同，那么这次变异肯定在上一个阶段已经执行过了，此次便不会再执行。

***

###（3） interest

下一个阶段是interest，具体可分为：

>interest 8/8，每次对8个bit进替换，按照每8个bit的步长从头开始，即对文件的每个byte进行替换<br>
>interest 16/8，每次对16个bit进替换，按照每8个bit的步长从头开始，即对文件的每个word进行替换<br>
>interest 32/8，每次对32个bit进替换，按照每8个bit的步长从头开始，即对文件的每个dword进行替换<br>

而用于替换的”interesting values”，是AFL预设的一些比较特殊的数：

```c
static s8  interesting_8[]  = { INTERESTING_8 };
static s16 interesting_16[] = { INTERESTING_8, INTERESTING_16 };
static s32 interesting_32[] = { INTERESTING_8, INTERESTING_16, INTERESTING_32 };
```

这些数的定义在config.h文件中：

```c
	/* List of interesting values to use in fuzzing. */
	
	#define INTERESTING_8 \ -128, /* Overflow signed 8-bit when decremented */ \ -1, /* */ \ 0, /* */ \ 1, /* */ \ 16, /* One-off with common buffer size */ \ 32, /* One-off with common buffer size */ \ 64, /* One-off with common buffer size */ \ 100, /* One-off with common buffer size */ \ 127 /* Overflow signed 8-bit when incremented */ 
	#define INTERESTING_16 \ -32768, /* Overflow signed 16-bit when decremented */ \ -129, /* Overflow signed 8-bit */ \ 128, /* Overflow signed 8-bit */ \ 255, /* Overflow unsig 8-bit when incremented */ \ 256, /* Overflow unsig 8-bit */ \ 512, /* One-off with common buffer size */ \ 1000, /* One-off with common buffer size */ \ 1024, /* One-off with common buffer size */ \ 4096, /* One-off with common buffer size */ \ 32767 /* Overflow signed 16-bit when incremented */ 
	#define INTERESTING_32 \ -2147483648LL, /* Overflow signed 32-bit when decremented */ \ -100663046, /* Large negative number (endian-agnostic) */ \ -32769, /* Overflow signed 16-bit */ \ 32768, /* Overflow signed 16-bit */ \ 65535, /* Overflow unsig 16-bit when incremented */ \ 65536, /* Overflow unsig 16 bit */ \ 100663045, /* Large positive number (endian-agnostic) */ \ 2147483647 /* Overflow signed 32-bit when incremented */
```

可以看到，用于替换的基本都是可能会造成溢出的数。

与之前类似，effector map仍然会用于判断是否需要变异；此外，如果某个interesting value，是可以通过bitflip或者arithmetic变异达到，那么这样的重复性变异也是会跳过的。

***

###（4） dictionary

进入到这个阶段，就接近deterministic fuzzing的尾声了。具体有以下子阶段：

>user extras (over)，从头开始，将用户提供的tokens依次替换到原文件中<br>
>user extras (insert)，从头开始，将用户提供的tokens依次插入到原文件中<br>
>auto extras (over)，从头开始，将自动检测的tokens依次替换到原文件中<br>

其中，用户提供的tokens，是在词典文件中设置并通过-x选项指定的，如果没有则跳过相应的子阶段。

**user extras (over)**

对于用户提供的tokens，AFL先按照长度从小到大进行排序。这样做的好处是，只要按照顺序使用排序后的tokens，那么后面的token不会比之前的短，从而每次覆盖替换后不需要再恢复到原状。

随后，AFL会检查tokens的数量，如果数量大于预设的MAX_DET_EXTRAS（默认值为200），那么对每个token会根据概率来决定是否进行替换：

```c
for (j = 0; j < extras_cnt; j++) {

    /* Skip extras probabilistically if extras_cnt > MAX_DET_EXTRAS. Also skip them if there's no room to insert the payload, if the token is redundant, or if its entire span has no bytes set in the effector map. */

    if ((extras_cnt > MAX_DET_EXTRAS && UR(extras_cnt) >= MAX_DET_EXTRAS) ||
        extras[j].len > len - i ||
        !memcmp(extras[j].data, out_buf + i, extras[j].len) ||
        !memchr(eff_map + EFF_APOS(i), 1, EFF_SPAN_ALEN(i, extras[j].len))) {

    stage_max--;
    continue;

    }
```

这里的UR(extras_cnt)是运行时生成的一个0到extras_cnt之间的随机数。所以，如果用户词典中一共有400个tokens，那么每个token就有200/400=50%的概率执行替换变异。我们可以修改MAX_DET_EXTRAS的大小来调整这一概率。

由上述代码也可以看到，effector map在这里同样被使用了：如果要替换的目标bytes全部是“无效”的，那么就跳过这一段，对下一段目标执行替换。

**user extras (insert)**

这一子阶段是对用户提供的tokens执行插入变异。不过与上一个子阶段不同的是，此时并没有对tokens数量的限制，所以全部tokens都会从原文件的第1个byte开始，依次向后插入；此外，由于原文件并未发生替换，所以effector map不会被使用。

这一子阶段最特别的地方，就是变异不能简单地恢复。之前每次变异完，在变异位置处简单取逆即可，例如bitflip后，再进行一次同样的bitflip就恢复为原文件。正因为如此，之前的变异总体运算量并不大。

但是，对于插入这种变异方式，恢复起来则复杂的多，所以AFL采取的方式是：将原文件分割为插入前和插入后的部分，再加上插入的内容，将这3部分依次复制到目标缓冲区中（当然这里还有一些小的优化，具体可阅读代码）。而对每个token的每处插入，都需要进行上述过程。所以，如果用户提供了大量tokens，或者原文件很大，那么这一阶段的运算量就会非常的多。直观表现上，就是AFL的执行状态栏中，”user extras (insert)”的总执行量很大，执行时间很长。如果出现了这种情况，那么就可以考虑适当删减一些tokens。

**auto extras (over)**

这一项与”user extras (over)”很类似，区别在于，这里的tokens是最开始bitflip阶段自动生成的。另外，自动生成的tokens总量会由USE_AUTO_EXTRAS限制（默认为10）。

***

###（5） havoc

对于非dumb mode的主fuzzer来说，完成了上述deterministic fuzzing后，便进入了充满随机性的这一阶段；对于dumb mode或者从fuzzer来说，则是直接从这一阶段开始。

havoc，顾名思义，是充满了各种随机生成的变异，是对原文件的“大破坏”。具体来说，havoc包含了对原文件的多轮变异，每一轮都是将多种方式组合（stacked）而成：

>随机选取某个bit进行翻转<br>
>随机选取某个byte，将其设置为随机的interesting value<br>
>随机选取某个word，并随机选取大、小端序，将其设置为随机的interesting value<br>
>随机选取某个dword，并随机选取大、小端序，将其设置为随机的interesting value<br>
>随机选取某个byte，对其减去一个随机数<br>
>随机选取某个byte，对其加上一个随机数<br>
>随机选取某个word，并随机选取大、小端序，对其减去一个随机数<br>
>随机选取某个word，并随机选取大、小端序，对其加上一个随机数<br>
>随机选取某个dword，并随机选取大、小端序，对其减去一个随机数<br>
>随机选取某个dword，并随机选取大、小端序，对其加上一个随机数<br>
>随机选取某个byte，将其设置为随机数<br>
>随机删除一段bytes<br>
>随机选取一个位置，插入一段随机长度的内容，其中75%的概率是插入原文中随机位置的内容，25%的概率是插入一段随机选取的数<br>
>随机选取一个位置，替换为一段随机长度的内容，其中75%的概率是替换成原文中随机位置的内容，25%的概率是替换成一段随机选取的数<br>
>随机选取一个位置，用随机选取的token（用户提供的或自动生成的）替换<br>
>随机选取一个位置，用随机选取的token（用户提供的或自动生成的）插入<br>

怎么样，看完上面这么多的“随机”，有没有觉得晕？还没完，AFL会生成一个随机数，作为变异组合的数量，并根据这个数量，每次从上面那些方式中随机选取一个（可以参考高中数学的有放回摸球），依次作用到文件上。如此这般丧心病狂的变异，原文件就大概率面目全非了，而这么多的随机性，也就成了fuzzing过程中的不可控因素，即所谓的“看天吃饭”了。

***

###（6） splice

历经了如此多的考验，文件的变异也进入到了最后的阶段：splice。如其意思所说，splice是将两个seed文件拼接得到新的文件，并对这个新文件继续执行havoc变异。

具体地，AFL在seed文件队列中随机选取一个，与当前的seed文件做对比。如果两者差别不大，就再重新随机选一个；如果两者相差比较明显，那么就随机选取一个位置，将两者都分割为头部和尾部。最后，将当前文件的头部与随机文件的尾部拼接起来，就得到了新的文件。在这里，AFL还会过滤掉拼接文件未发生变化的情况。

***

###（7）cycle

于是乎，一个seed文件，在上述的全部变异都执行完成后，就…抱歉，还没结束。

上面的变异完成后，AFL会对文件队列的下一个进行变异处理。当队列中的全部文件都变异测试后，就完成了一个”cycle”，这个就是AFL状态栏右上角的”cycles done”。而正如cycle的意思所说，整个队列又会从第一个文件开始，再次进行变异，不过与第一次变异不同的是，这一次就不需要再进行deterministic fuzzing了。

当然，如果用户不停止AFL，那么seed文件将会一遍遍的变异下去。

变异的具体源代码可自行查看afl项目文件 `afl-fuzz.c` 中的 `fuzz_one()` 函数。

### 效果分析 ###

参考 `https://lcamtuf.blogspot.com/2014/11/pulling-jpegs-out-of-thin-air.html` 中的测试方法，同样以 `djpeg` 为目标，最初的样本集只有一个文本 `test`，采用二进制插桩的方式进行fuzz，1个主节点以及3个从节点同时进行，测试最终是否能fuzz出一个合法的图片文件。

![image-20210825094925024](https://cdn.jsdelivr.net/gh/AlexsanderShaw/BlogImages@main/img/vuln/shebei20210825094925.png)

![image-20210825094908754](https://cdn.jsdelivr.net/gh/AlexsanderShaw/BlogImages@main/img/vuln/shebei20210825094908.png)

![image-20210825094941149](https://cdn.jsdelivr.net/gh/AlexsanderShaw/BlogImages@main/img/vuln/shebei20210825094941.png)

fuzz后的样本集合如下：

![image-20210825094955862](https://cdn.jsdelivr.net/gh/AlexsanderShaw/BlogImages@main/img/vuln/shebei20210825094955.png)

使用 `afl-showmap` 对所有样本进行分析，编写脚本如下：

```shell
#!/bin/bash

path=$1
dpath=$2
rm -rf $2/*
for file in $(ls $1)
do
    echo -e '\n'$file
    afl-showmap -o $2/$file -Q -- /usr/bin/djpeg $1/$file
    echo -e '-------------------------------------\n'
done
```

第一个参数为样本集合目录，第二个参数为输出目录，假设脚本名为 `djpeg.sh` ，样本目录为 `in` ，输出目录为 `map` 

	./djpeg.sh in map

脚本的执行结果可在 `分析/djpeg_sh脚本输出结果.txt` 中查看，以下只展示部分：

```shell
id:000000,orig:1
afl-showmap 2.56b by <lcamtuf@google.com>
[*] Executing '/usr/bin/djpeg'...

-- Program output begins --
Not a JPEG file: starts with 0x74 0x65
-- Program output ends --
[+] Captured 50 tuples in 'map/id:000000,orig:1'.
-------------------------------------
```

```shell
id:000001,src:000000,op:havoc,rep:64,+cov
afl-showmap 2.56b by <lcamtuf@google.com>
[*] Executing '/usr/bin/djpeg'...
		
-- Program output begins --
Corrupt JPEG data: 2 extraneous bytes before marker 0xfe
JPEG datastream contains no image
-- Program output ends --
[+] Captured 68 tuples in 'map/id:000001,src:000000,op:havoc,rep:64,+cov'.
-------------------------------------
```

```shell
id:000005,src:000000+000001,op:splice,rep:64
afl-showmap 2.56b by <lcamtuf@google.com>
[*] Executing '/usr/bin/djpeg'...

-- Program output begins --
Corrupt JPEG data: 6 extraneous bytes before marker 0xfe
JPEG datastream contains no image
-- Program output ends --
[+] Captured 68 tuples in 'map/id:000005,src:000000+000001,op:splice,rep:64'.
-------------------------------------
```

```shell
id:000021,src:000011,op:flip32,pos:2,+cov
afl-showmap 2.56b by <lcamtuf@google.com>
[*] Executing '/usr/bin/djpeg'...

-- Program output begins --
Premature end of JPEG file
JPEG datastream contains no image
-- Program output ends --
[+] Captured 59 tuples in 'map/id:000021,src:000011,op:flip32,pos:2,+cov'.
-------------------------------------
```

```shell
id:000026,src:000021,op:havoc,rep:2
afl-showmap 2.56b by <lcamtuf@google.com>
[*] Executing '/usr/bin/djpeg'...

-- Program output begins --
Premature end of JPEG file
JPEG datastream contains no image
-- Program output ends --
[+] Captured 60 tuples in 'map/id:000026,src:000021,op:havoc,rep:2'.
-------------------------------------
```

可以看到上面样本id为21和26的输出结果相同，但是执行路径不同，可以使用 `diff` 指令进行路径对比：

```shell
diff -Nu map/id\:000021\,src\:000011\,op\:flip32\,pos\:2\,+cov map/id\:000026\,src\:000021\,op\:havoc\,rep\:2
```

结果如下：

```shell
--- map/id:000021,src:000011,op:flip32,pos:2,+cov       2019-12-03 06:38:42.236000000 +0000
+++ map/id:000026,src:000021,op:havoc,rep:2     2019-12-03 06:38:42.388000000 +0000
@@ -1,20 +1,21 @@
    003224:1
    004793:1
    005209:1
-005993:1
+005993:2
    006601:1
    007073:1
    008498:1
    008874:1
-010130:1
+010130:2
    010146:1
    010282:1
-013459:1
+013459:2
+014971:1
    017564:1
    018892:1
    019132:1
    019148:1
-019172:1
+019172:2
    019188:1
    019236:1
    019804:1
@@ -33,18 +34,18 @@
    032872:1
    033112:1
    037297:1
-037433:1
+037433:2
    037817:1
    039585:1
-039641:2
-043450:1
+039641:4
+043450:2
    043562:1
    044194:1
    044818:1
    045483:1
    046955:1
    047603:1
-048251:1
+048251:2
    051300:1
    052444:1
    053124:1
```

从最初的只有文本内容“test”的样本，afl确实已经发现了很多其它路径，但是在我的测试结果中还是没有fuzz出正常的图片文件，从输出结果上看样本id为21和26算是比较接近，没有报明显错误。

```shell
Premature end of JPEG file
JPEG datastream contains no image
```

### 参考链接 ###

1. https://github.com/google/AFL
2. https://www.secpulse.com/archives/71903.html
3. https://www.freebuf.com/articles/system/191536.html
4. http://zeroyu.xyz/2019/05/15/how-to-use-afl-fuzz
5. https://lcamtuf.blogspot.com/2014/11/pulling-jpegs-out-of-thin-air.html
6. https://paper.seebug.org/841/
7. https://paper.seebug.org/496/#part-2afl
8. https://rk700.github.io/2017/12/28/afl-internals/
9. https://rk700.github.io/2018/01/04/afl-mutations/
10. https://rk700.github.io/2018/02/02/afl-enhancement/


