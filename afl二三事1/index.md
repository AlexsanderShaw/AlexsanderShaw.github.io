# AFL二三事 -- 1


本文是AFL系列第一篇，主要介绍AFL的基本使用。

<!--more-->

## 一、简介



AFL（American Fuzzy Lop）是由安全研究员Michal Zalewski（@lcamtuf）开发的一款基于覆盖引导（Coverage-guided）的模糊测试工具，它通过记录输入样本的代码覆盖率，从而调整输入样本以提高覆盖率，增加发现漏洞的概率。

## 二、工作流程

对于有源码的情况下，AFL的工作流程大致如下：

> 1. 源码编译时进行插桩；
>
> 2. 选择输入文件，构建语料库，加入输入队列；
>
> 3. 对队列中的文件按照一定的策略进行“变异”；
>
> 4. 如果经过变异的文件更新了代码覆盖路径，则保留文件并添加到队列中；
>
> 5. 循环执行上述过程，记录触发crash的文件。
>

![20210817145304](https://cdn.jsdelivr.net/gh/AlexsanderShaw/BlogImages@main/img/vuln/shebei20210817145433.png)

## 三、使用

### 1. 基本使用

AFL安装完成后，生成的可执行程序及其作用整体概括如下：

![AFL Execution File](https://cdn.jsdelivr.net/gh/AlexsanderShaw/BlogImages@main/img/vuln/shebei20210819101659.png)
下面对每个可执行文件做详细的使用描述：

#### 1. 编译指令

`afl-gcc`、`afl-g++`、`afl-clang`、`afl-clang++`、`afl-clang-fast`、`afl-clang-fast++`这些afl的编译指令，支持使用`gcc`、`g++`、`clang`、`clang++`的任何选项，因为这些指令的本质还是调用当前系统的对应编译指令，比如使用`afl-gcc`进行源码插桩编译：

```shell
# 指令格式： afl-gcc [参数] 源文件 
afl-gcc test.c -o test
```

***

#### 2. afl-cmin, afl-tmin

`afl-cmin`和`afl-tmin`都是用于简化样本的，可以简单的理解为前者裁剪样本集合，将执行路径相同的样本剔除掉只保留一个，后者是对单个样本的裁剪，例如，`in_afl`目录下存放样本，使用`afl-cmin`对样本集合进行裁剪，将新的集合输出到`in_afl_min`中，然后使用`afl-tmin`对`in_afl_min`中名为`1.jpeg`的文件进行裁剪，输出到`1_new.jpeg`文件中，fuzz的目标程序为`/usr/bin/djpeg`，该程序使用方法为`/usr/bin/djpeg [参数] 要解析的图片文件`：

```shell
# 指令格式： afl-cmin -i 样本目录 -o 输出目录 [-Q] -- 要fuzz的可执行程序 [程序参数]
# 指令格式： afl-tmin -i 样本文件 -o 输出文件 [-Q] -- 要fuzz的可执行程序 [程序参数]
# 其中 '要fuzz的可执行程序' 必须是带有路径的，不能直接使用，比如 'djpeg 1.jpeg' 可以执行成功，但是fuzz时必须将 'djpeg' 的路径一并带上才可以，即 '/usr/bin/djpeg'
# 默认情况下afl-cmin和afl-tmin会把样本以标准输出的方式喂给要fuzz的程序，如果fuzz程序是从参数指定的文件中读取数据进行处理的，则需要使用 '@@' 来代替输入的文件路径，比如原本执行的指令为 'djpeg in_afl_min/1.jpeg' ，fuzz时指令应为 '/usr/bin/djpeg @@'
# 在安装了qemu-mode时，可以支持 '-Q' 选项，如果目标可执行程序
# 当然这两个指令还有一些其它参数，这里就不介绍使用了，以上为常见用法

afl-cmin -i in_afl -o in_afl_min -Q -- /usr/bin/djpeg @@
afl-tmin -i in_afl_min/1.jpeg -o in_afl_min/1_new.jpeg -Q -- /usr/bin/djpeg @@
```

***

#### 3. afl-analyze

`afl-analyze`用于分析样本，比如分析一个样本`1.jpeg`，被fuzz程序为`/usr/bin/djpeg`，该程序使用方法为`/usr/bin/djpeg [参数] 要解析的图片文件`

```shell
# 指令格式： afl-analyze -i 样本文件 [-Q] -- 要fuzz的可执行程序 [程序参数]
# 其中 '要fuzz的可执行程序' 必须是带有路径的，不能直接使用，比如 'djpeg 1.jpeg' 可以执行成功，但是fuzz时必须将 'djpeg' 的路径一并带上才可以，即 '/usr/bin/djpeg'
# 默认情况下afl-cmin和afl-tmin会把样本以标准输出的方式喂给要fuzz的程序，如果fuzz程序是从参数指定的文件中读取数据进行处理的，则需要使用 '@@' 来代替输入的文件路径，比如原本执行的指令为 'djpeg in_afl_min/1.jpeg' ，fuzz时指令应为 '/usr/bin/djpeg @@'
# 在安装了qemu-mode时，可以支持 '-Q' 选项，如果目标可执行程序

afl-analyze -i in_afl_min/1.jpeg -Q -- /usr/bin/djpeg @@
```

#### 4. afl-showmap

`afl-showmap`用于分析样本的执行路径，比如分析一个样本`1.jpeg`，被fuzz程序为`/usr/bin/djpeg`，该程序使用方法为`/usr/bin/djpeg [参数] 要解析的图片文件`

```shell
# 指令格式（从标准输入中读取）： afl-showmap -o 存放结果的文件 -- 要fuzz的可执行程序 [程序参数] < 样本文件路径
# 指令格式（从参数指定文件中读取输入）： afl-showmap -o 存放结果的文件 -- 要fuzz的可执行程序 [程序参数]
# 其中 '要fuzz的可执行程序' 必须是带有路径的，不能直接使用，比如 'djpeg 1.jpeg' 可以执行成功，但是fuzz时必须将 'djpeg' 的路径一并带上才可以，即 '/usr/bin/djpeg'
# 在安装了qemu-mode时，可以支持 '-Q' 选项，如果目标可执行程序

# 因为/usr/bin/djpeg指令即可用参数指定文件，也可以直接标准输入，所以以下两种方式均可
afl-showmap -o map -Q -- /usr/bin/djpeg in_afl_min/1.jpeg
afl-showmap -o map -Q -- /usr/bin/djpeg < in_afl_min/1.jpeg

# 查看结果
cat map
```

***

#### 5. afl-fuzz

`afl-fuzz`是真正进行fuzz的程序，通过`afl-fuzz help`可以查看支持的所有选项（其它命令也可以），选项如下

```shell
afl-fuzz 2.56b by <lcamtuf@google.com>

afl-fuzz [ options ] -- /path/to/fuzzed_app [ ... ]

Required parameters（必须参数）:

  -i dir        - input directory with test cases - 存放样本的目录
  -o dir        - output directory for fuzzer findings - fuzz输出的数据存放目录

Execution control settings（扩展控制设置）:

  -f file       - location read by the fuzzed program (stdin) - 指定编译文件的文件扩展名
  -t msec       - timeout for each run (auto-scaled, 50-1000 ms) - 指定程序超时时间
  -m megs       - memory limit for child process (50 MB) - 限制子进程使用的内存
  -Q            - use binary-only instrumentation (QEMU mode)  - 使用qemu-mode进行二进制插桩
	
Fuzzing behavior settings（设置编译操作）:

  -d            - quick & dirty mode (skips deterministic steps) - 不进行确定性变异，只进行随机性变异
  -n            - fuzz without instrumentation (dumb mode) - 不进行随机性编译，只进行确定性变异
  -x dir        - optional fuzzer dictionary (see README) - dictionary使用的用户指定token存放的目录

Other stuff（其他选项）:

  -T text       - text banner to show on the screen - 在屏幕上显示的banner信息
  -M / -S id    - distributed mode (see parallel_fuzzing.txt) - 并行fuzz， —M为主节点，-S为子节点
  -C            - crash exploration mode (the peruvian rabbit thing) - 分析崩溃模式

For additional tips, please consult /usr/local/share/doc/afl/README.


# 和`afl-cmin`、`afl-tmin`相同，默认向标准输入fuzz数据，如果被fuzz指令是从参数指定文件中读取数据，则使用`@@`替换文件参数
# 官方详细说明可以在项目根目录的'README.md'文件中查看
```

对已经进行过源码插桩的程序，基本指令为：

```shell
afl-fuzz -i in_dir -o out_dir -- /path/to/fuzzed_app [ ... ]
```

对没有进行过源代码插桩的程序，基本指令为：

```shell
afl-fuzz -i in_dir -o out_dir -Q -- /path/to/fuzzed_app [ ... ]
```

`afl-fuzz`的运行特点是，不管系统真实为多少核，只使用其中一个，所以只运行一个fuzz进程会发现CPU使用率不高。不过`afl-fuzz`提供了并行fuzz的选项，并行运行时基本指令为：

```shell
afl-fuzz -i in_dir -o out_dir [-Q] -M mast_name -- /path/to/fuzzed_app [ ... ]
afl-fuzz -i in_dir -o out_dir [-Q] -S slave_name1 -- /path/to/fuzzed_app [ ... ]
afl-fuzz -i in_dir -o out_dir [-Q] -S slave_name2 -- /path/to/fuzzed_app [ ... ]
...
# 主节点和所有从节点的 in_dir 和 out_dir 必须相同
```

### 2. 基本使用样例

（注：测试过程中因为我安装了多个版本的afl和afl++，所以有些地方使用的是绝对路径，在只有单版本单环境变量的情况下，可以使用相对路径）

以djpeg程序为例进行，该程序可通过`apt-get install libjpeg-progs`进行安装，安装后直接就是二进制程序，所以使用的指令都带有`-Q`选项，如果要fuzz的程序编译时使用的是`afl-gcc`、`afl-g++`、`afl-clang`、`afl-clang++`、`afl-clang-fast`、`afl-clang-fast++`这些指令，fuzz的大致流程类似，只需要将命令中的`-Q`选项去掉即可。

通过 `whereis djpeg` 指令查看 `djpeg` 的绝对路径，一般情况下路径为 `/usr/bin/djpeg`

	whereis djpeg

创建两个目录 `in_dir` 和 `out_dir` ，分别用于存放我们输入的样本和afl的fuzz结果

	mkdir in_dir
	mkdir out_dir

向 `in_dir` 中放入样本，这些样本可以自行收集，不过样本文件需要尽量小，否则变异阶段会花费较多时间，降低效率，这里我输入两个样本 `1` 和 `2` ，内容分别为 `hello` 和 `test`，在准备一个很小的图片文件（可通过绘图工具截下一小块，以jpeg形式保存即可），命名为`3`放入样本目录中

	echo 'hello' > in_dir/1
	echo 'test' > in_dir/2

使用 `afl-cmin` 对输入样本集合进行裁剪，先创建一个输出目录 `in_dir_min` ，然后执行裁剪指令

	mkdir in_dir_min
	afl-cmin -i in_dir -o in_dir_min -Q -- /usr/bin/djpeg @@

![image-20210818111000536](https://cdn.jsdelivr.net/gh/AlexsanderShaw/BlogImages@main/img/vuln/shebei20210818111000.png)

裁剪过后目录中只保留了`2` 和 `3`.

使用 `afl-tmin` 对裁剪后集合中所有的样本进行大小裁剪（该步骤产生的裁剪后样本不一定要使用，需要通过 `afl-analyze` 指令进行裁剪前后对比分析，自行判断使用哪一个，裁剪前后两个样本一定只保留一个放入最终样本集中）

	afl-tmin -i in_dir_min/2 -o in_dir_min/2_min -Q -- /usr/bin/djpeg @@
	afl-tmin -i in_dir_min/3 -o in_dir_min/3_min -Q -- /usr/bin/djpeg @@

![image-20210818112844384](https://cdn.jsdelivr.net/gh/AlexsanderShaw/BlogImages@main/img/vuln/shebei20210818112844.png)

![image-20210818112913923](https://cdn.jsdelivr.net/gh/AlexsanderShaw/BlogImages@main/img/vuln/shebei20210818112914.png)

裁剪后得到的内容如下：

![image-20210818112941674](https://cdn.jsdelivr.net/gh/AlexsanderShaw/BlogImages@main/img/vuln/shebei20210819101630.png)

使用 `afl-analyze` 分别对裁剪前后的样本进行分析，先对比分析 `3` 和 `3_min`

	afl-analyze -i in_dir_min/3 -Q -- /usr/bin/djpeg @@
	afl-analyze -i in_dir_min/3_min -Q -- /usr/bin/djpeg @@

首先是对`3`的分析：

![image-20210818113304114](https://cdn.jsdelivr.net/gh/AlexsanderShaw/BlogImages@main/img/vuln/shebei20210818113304.png)

![image-20210818113418232](https://cdn.jsdelivr.net/gh/AlexsanderShaw/BlogImages@main/img/vuln/shebei20210818113418.png)

然后是对`3_min`的分析：

![image-20210818113608997](https://cdn.jsdelivr.net/gh/AlexsanderShaw/BlogImages@main/img/vuln/shebei20210818113609.png)

`afl-tmin` 裁剪时遵循的是执行路径不变原则，但是也有可能破坏原文件中对某些标志数据，就如同上图 `3` 和 `3_min` 分析的结果，afl在识别文件结构时， `3` 和 `3_min` 是不同的，这个不同会导致后续fuzz时变异阶段的不同，所以我认为在这种情况下 `3_min` 不能完全取代 `3` 。

再对比下 `2` 和 `2_min`

	afl-analyze -i in_dir_min/2 -Q -- /usr/bin/djpeg @@
	afl-analyze -i in_dir_min/2_min -Q -- /usr/bin/djpeg @@

![image-20210818113757336](https://cdn.jsdelivr.net/gh/AlexsanderShaw/BlogImages@main/img/vuln/shebei20210818113757.png)

同理，对比这两个样本，进行取舍。

最终，选取 `2` 和 `3` 作为最终样本集，即未进行 `afl-tmin` 裁剪的样本，放入新建的 `in` 目录中

```shell
	mkdir in
	cp in_dir_min/2 in
	cp in_dir_min/3 in
```

使用 `afl-fuzz` 进行fuzz，这里采用并行fuzz模式，指令如下

```shell
afl-fuzz -i in -o out_dir -Q -M djpeg_master -- /usr/bin/djpeg @@
# 另一个终端
afl-fuzz -i in -o out_dir -Q -S djpeg_slaver_1 -- /usr/bin/djpeg @@
```

![image-20210818120328932](https://cdn.jsdelivr.net/gh/AlexsanderShaw/BlogImages@main/img/vuln/shebei20210819101525.png)

至此，最基本的使用 `afl` 就差不多了，后续就是等待出现崩溃，分析崩溃了。

### 3. 运行状态说明

上面已经给出了AFL的运行时的状态图，官方对该界面的说明在 `https://github.com/google/AFL/blob/master/docs/status_screen.txt` ，或者在项目 `docs/status_screen.txt` 中查看。

下面对界面中各个部分做简单说明：

>**Process timing**：Fuzzer运行时长、以及距离最近发现的路径、崩溃和挂起经过了多长时间；
>
>**Overall results**：Fuzzer当前状态的概述；
>
>**Cycle progress**：我们输入队列的距离；
>
>**Map coverage**：目标二进制文件中的插桩代码所观察到覆盖范围的细节；
>
>**Stage progress**：Fuzzer现在正在执行的文件变异策略、执行次数和执行速度；
>
>**Findings in depth**：有关我们找到的执行路径，异常和挂起数量的信息；
>
>**Fuzzing strategy yields**：关于突变策略产生的最新行为和结果的详细信息；
>
>**Path geometry**：有关Fuzzer找到的执行路径的信息；
>
>**CPU004**：CPU利用率。

**fuzz结果查看**

单进程下fuzz结果的输出目录包含以下几个：

>`crashes`：存放去重后触发crash的数据
>
>`fuzz_bitmap`：记录代码覆盖率
>
>`fuzzer_stats`：fuzz状态
>
>`hangs`：存放去重后触发挂起的数据
>
>`plot_data`：绘图数据
>
>`queue`：有效的样本集合



`queque` 目录下存放着有效的样本集合，我们可以从目录中文件的文件名得知样本是如何产生的，比如下图中

![image-20210818143959022](https://cdn.jsdelivr.net/gh/AlexsanderShaw/BlogImages@main/img/vuln/shebei20210818143959.png)

文件名中包含一些说明性字段：

>id：样本id
>
>orig：来自用户指定的样本集合，内容和对应的源样本一样
>
>src：从哪些样本id变异而来
>
>op：从变异的哪个阶段产生的

这样就可以得知有效样本的来源。

`crashes` 目录下存放着去重后触发崩溃的输入，我们可以从目录中文件的文件名得知数据是如何产生的，比如下图中

![image-20210818144017237](https://cdn.jsdelivr.net/gh/AlexsanderShaw/BlogImages@main/img/vuln/shebei20210818144017.png)

字段含义和 `queque` 目录中文件名基本一致。

###  4. 进阶使用

#### 1. 使用AFL对端口程序进行fuzz

截止到目前为止，绝大多数的程序都是将‘标准输入’、‘参数指定文件中的数据’以及‘端口接收的数据’作为输入。前两者 `afl` 都可以很好的处理，但是不支持将变异数据输入到端口中，为了对这类程序进行fuzz，这里介绍一种不管有无源码都可以进行fuzz的方法。

这里使用[preeny](https://github.com/zardus/preeny)项目来进行测试，其中包含一些重写的系统库，在这里的测试中主要会使用重写的网络程序库，以实现从socket读取输入转为从标准输入读取输入。安装过程十分简单，进入项目主目录后，执行make进行变异，查看 `x86_64-linux-gnu` 下是否生成 `.so` 库文件即可。

这个库利用 `LD_PRELOAD` 机制，重写了很多库函数，其中 `desock.c` 这个文件负责重写 `socket` 相关的函数，其实现的功能就是当应用从  `socket` 获取输入时，改为从 `stdin` 获取输入。

首先准备一个socket程序，这里使用如下代码为例，文件名为 `socket.c`

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

使用 `gcc` 进行编译

```shell
gcc -o socket socket.c
```

运行 `socket` 可以监听 `8000` 端口进行socket通信

通过设置 `LD_PRELOAD` 使程序加载 `preeny` 项目中编译出来的 `desock.so` 库（一般在 `preeny` 项目下的 `x86_64-linux-gnu` 目录中）来改变socket通信，具体指令如下（我的 `desock.so` 路径为 `/root/Tools/preeny/x86_64-linux-gnu/desock.so`）

```shell
# 指令格式： LD_PRELOAD="preeny编译出的desock.so的路径" socket程序 [参数]
LD_PRELOAD="/home/v4ler1an/Desktop/Fuzz/training/preeny/x86_64-linux-gnu/desock.so" ./socket
```

最终实现的结果如下：

![image-20210818163243901](https://cdn.jsdelivr.net/gh/AlexsanderShaw/BlogImages@main/img/vuln/shebei20210818163244.png)

从上面的结果可以看到 `send` 函数成功将消息发往了 `stdout`，`recv` 函数也成功从 `stdin` 中接收了消息。

这样就将 `socket` 输入转变为了标准输入，进而可以使用afl进行fuzz了。过程如下：

```shell
# 创建样本及输出目录
mkdir in
mkdir out

# 创建样本
echo 'test 123' > in/test
echo 'xxx' > in/xxx
echo 'help' > in/help
echo 'exit' > in/exit

# 对样本进行裁剪
mkdir in_min
LD_PRELOAD="/home/v4ler1an/Desktop/Fuzz/training/preeny/x86_64-linux-gnu/desock.so" afl-cmin -i in -o in_min -Q -- ./socket

# 开始fuzz
LD_PRELOAD="/home/v4ler1an/Desktop/Fuzz/training/preeny/x86_64-linux-gnu/desock.so" afl-fuzz -i in_min/ -o out/ -Q -- ./socket
```

成功执行后如下：

![image-20210818164012432](https://cdn.jsdelivr.net/gh/AlexsanderShaw/BlogImages@main/img/vuln/shebei20210818164012.png)

从上面的结果可以看出这种方式存在的问题：

1. fuzz效率很低
2. 如果socket程序是循环接收数据的，因为fuzz只能对程序进行一次输入，所以被fuzz程序在处理完这个输入后会一直保持等待，最终导致超时，而afl对超时的处理可以简单理解为忽略，所以针对这种socket程序是无法进行fuzz的，实战中绝大多数都是循环接收数据的程序，所以这种方案实际的可行性有待考虑。

***

#### 2. 使用llvm模式进行fuzz

因为使用这个模式需要修改源代码，所以只有对有源码的程序进行fuzz时才能使用。

*可在项目 llvm_mode 目录下的 README.llvm 文件中查看官方文档*

将上面的代码改成循环读取的形式，新代码如下：

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
    while(1){
        cliaddr_len = sizeof(cliaddr);
        connfd = accept(listenfd,(struct sockaddr *)&cliaddr,&cliaddr_len);
        char send_msg[MAXLINE*2] = "hello, send by send() :\n";
        send(connfd, send_msg, strlen(send_msg), 0);
        n = read(connfd,buf,MAXLINE);
        while(1){
            if(n!=0){
                if(!strncmp(buf, "test ", 5))
                    sprintf(send_msg, "test: %s\n", buf + 5);
                else if(!strncmp(buf, "help", 4))
                    sprintf(send_msg, "help:\n\ttest\n\tcommand\n\texit\n");
                else if(!strncmp(buf, "command ", 8)){
                    command(buf);
                    sprintf(send_msg, "it's a command\n");
                }
                else if(!strncmp(buf, "exit", 4)){
                    send(connfd, "bye~\n", 4, 0);
                    break;
                }
                else
                    sprintf(send_msg, "unknown command!\n");
                send(connfd, send_msg, strlen(send_msg), 0);
            }
            else{
                printf("Client say close the connection..\n");
                break;
            }
            n = read(connfd,buf,MAXLINE);
        }
        close(connfd);
    }
}
```

重复上面的编译操作，然后继续使用上面的方法进行fuzz，会发现最终无法成功。

再次对源代码进行修改，修改内容如下：

```c
--- socket.c    2019-12-02 02:10:54.532000000 +0000
+++ source/socket_fuzz1.c       2019-12-02 02:10:17.668000000 +0000
@@ -61,8 +61,14 @@
					printf("Client say close the connection..\n");
					break;
				}
+            // for afl fuzz
+            break;
+
				n = read(connfd,buf,MAXLINE);
			}
			close(connfd);
+        // for afl fuzz
+        break;
+
		}
	}
```

将上面内容到补丁文件中，假设命名为 `fuzz1.patch` ，然后执行如下命令直接修改：

```shell
	patch socket.c -i fuzz1.patch
```

因为已经有源码了，可以使用 `afl` 的编译器进行源码插桩，执行如下指令进行fuzz

```shell
# 使用 afl-gcc 进行源码编译
afl-gcc -o socket socket.c

# 创建样本
mkdir in
echo 'test 123' > in/test
echo 'xxx' > in/xxx
echo 'help' > in/help
echo 'exit' > in/exit

# 对样本进行裁剪
mkdir in_min
LD_PRELOAD="/root/Tools/preeny/x86_64-linux-gnu/desock.so" afl-cmin -i in -o in_min -- ./socket

# 开始fuzz
mkdir out
LD_PRELOAD="/root/Tools/preeny/x86_64-linux-gnu/desock.so" afl-fuzz -i in_min/ -o out/ -- ./socket
```

![image-20210818170109437](https://cdn.jsdelivr.net/gh/AlexsanderShaw/BlogImages@main/img/vuln/shebei20210818170109.png)

以上还是借助 `preeny` 进行fuzz，我们可以对源码进行进一步修改，使用 `llvm_mode` 提高fuzz效率

`llvm_mode` 主要涉及两种结构，分别如下：

```c
// 1、延迟初始化
#ifdef __AFL_HAVE_MANUAL_CONTROL
  	__AFL_INIT();
#endif

// 2、persistent mode（持久化模式）
while (__AFL_LOOP(1000)) {
	/* Read input data. */
	/* Call library code to be fuzzed. */
	/* Reset state. */
}

/* Exit normally */
```

详细说明可参考官方文档 `https://github.com/google/AFL/tree/master/llvm_mode` 或项目的 `llvm_mode/README.llvm` 文件，参考使用方式如下

对原始的循环接收 `socket.c` 源码进行修改，补丁如下：

```shell
--- socket.c    2019-12-02 09:27:40.288000000 +0000
+++ source/socket_fuzz2.c       2019-12-02 09:17:03.452000000 +0000
@@ -35,34 +35,39 @@
		printf("Accepting connections..\n");
		while(1){
			cliaddr_len = sizeof(cliaddr);
-        connfd = accept(listenfd,(struct sockaddr *)&cliaddr,&cliaddr_len);
+        //connfd = accept(listenfd,(struct sockaddr *)&cliaddr,&cliaddr_len);
			char send_msg[MAXLINE*2] = "hello, send by send() :\n";
-        send(connfd, send_msg, strlen(send_msg), 0);
-        n = read(connfd,buf,MAXLINE);
-        while(1){
-            if(n!=0){
-                if(!strncmp(buf, "test ", 5))
-                    sprintf(send_msg, "test: %s\n", buf + 5);
-                else if(!strncmp(buf, "help", 4))
-                    sprintf(send_msg, "help:\n\ttest\n\tcommand\n\texit\n");
-                else if(!strncmp(buf, "command ", 8)){
-                    command(buf);
-                    sprintf(send_msg, "it's a command\n");
+        //send(connfd, send_msg, strlen(send_msg), 0);
+        //n = read(connfd,buf,MAXLINE);
+        while (__AFL_LOOP(1000)) {
+            n = read(0,buf,MAXLINE);
+            while(1){
+                if(n!=0){
+                    if(!strncmp(buf, "test ", 5))
+                        sprintf(send_msg, "test: %s\n", buf + 5);
+                    else if(!strncmp(buf, "help", 4))
+                        sprintf(send_msg, "help:\n\ttest\n\tcommand\n\texit\n");
+                    else if(!strncmp(buf, "command ", 8)){
+                        command(buf);
+                        sprintf(send_msg, "it's a command\n");
+                    }
+                    else if(!strncmp(buf, "exit", 4)){
+                        //send(connfd, "bye~\n", 4, 0);
+                        break;
+                    }
+                    else
+                        sprintf(send_msg, "unknown command!\n");
+                    //send(connfd, send_msg, strlen(send_msg), 0);
					}
-                else if(!strncmp(buf, "exit", 4)){
-                    send(connfd, "bye~\n", 4, 0);
+                else{
+                    printf("Client say close the connection..\n");
						break;
					}
-                else
-                    sprintf(send_msg, "unknown command!\n");
-                send(connfd, send_msg, strlen(send_msg), 0);
-            }
-            else{
-                printf("Client say close the connection..\n");
					break;
+                //n = read(connfd,buf,MAXLINE);
				}
-            n = read(connfd,buf,MAXLINE);
			}
-        close(connfd);
+        //close(connfd);
+        break;
		}
	}
```

将上面的补丁信息保存到补丁文件中，假设文件名为 `fuzz2.patch` ，执行如下命令修改代码：

```shell
patch socket.c -i fuzz2.patch
```

使用 `afl-clang-fast` 进行编译（如果是C++程序，则使用 `afl-clang-fast++` 进行编译），执行如下指令进行fuzz

```shell
# 使用 afl-clang-fast 进行源码编译
afl-clang-fast -o socket socket.c

# 创建样本
mkdir in
echo 'test 123' > in/test
echo 'xxx' > in/xxx
echo 'help' > in/help
echo 'exit' > in/exit

# 对样本进行裁剪
mkdir in_min
afl-cmin -i in -o in_min -- ./socket

# 开始fuzz
mkdir out
afl-fuzz -i in_min/ -o out/ -- ./socket
```

以这种模式的fuzz，可以看到fuzz效率被大大提高。

****

#### 3. 使用 `-x` 选项进行fuzz

`afl-fuzz` 中用户可以通过指定 `-x` 选项指定fuzz中 `dictionary` 和 `havoc` 阶段（下面 `变异方法` 部分会详细说明）的 `token` 库，当对fuzz对象有一定了解的情况下可以指定 `token` 来提高 `afl` 发现新路径的概率，官方文档 `https://github.com/google/AFL/tree/master/dictionaries` 或者项目的 `dictionaries/README.dictionaries` 文件，具体使用如下

这里使用2中 `llvm_mode` 的源代码，减少样本集合，并创建token目录，添加一些其它token，具体指令如下

```shell
# 使用 afl-clang-fast 进行源码编译
afl-clang-fast -o socket socket.c

# 创建样本
mkdir in
echo 'xxx' > in/xxx
echo 'help' > in/help
echo 'test 123' > in/test

# 对样本进行裁剪
mkdir in_min
afl-cmin -i in -o in_min -- ./socket

# 创建token集合
mkdir extras
echo 'keyword_exit="exit"' > extras/socket.dict
echo 'keyword_command="command"' >> extras/socket.dict
echo -e '\nsplit_blank=" "' >> extras/socket.dict

# 开始fuzz
mkdir out
afl-fuzz -i in_min/ -o out/ -x extras/socket.dict -- ./socket
```

![image-20210819100716385](https://cdn.jsdelivr.net/gh/AlexsanderShaw/BlogImages@main/img/vuln/shebei20210819100716.png)

查看fuzz输出的 `queque` 目录

![image-20210819100803006](https://cdn.jsdelivr.net/gh/AlexsanderShaw/BlogImages@main/img/vuln/shebei20210819100803.png)

分别查看样本3和4的内容

![image-20210819100920018](https://cdn.jsdelivr.net/gh/AlexsanderShaw/BlogImages@main/img/vuln/shebei20210819100920.png)

通过指定token，成功得到了两个新的有效样本。

## 四、总结

以上为AFL的基本知识和基本使用方法，仍然属于比较基层的内容，后续将进行源码分析和更多的实例训练的相关内容。
