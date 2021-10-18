# 有毒的学Pin记录 -- 1


本文是Pin系列学习记录的第一篇，主要是官方文档的相关内容的整理总结。

<!--more-->

# Pin

version: 3.20

## 1. Introduction

Pin 是一个动态二进制插桩工具，支持 Linux\*， macOS\* 和 Windows\* 操作系统以及可执行程序。Pin可以通过pintools在程序运行期间动态地向可执行文件的任意位置插入任意代码（C/C++），也可以attach到一个正在运行的进程。

Pin 提供了丰富的 API，可以抽象出底层指令集特性，并允许将进程的寄存器数据等的上下文信息作为参数传递给注入的代码。Pin会自动存储和重置被注入代码覆盖的寄存器，以恢复程序的继续运行。对符号和调试信息也可以设置访问权限。

Pin内置了大量的样例插桩工具的源码，包括基本块分析其、缓存模拟器、指令跟踪生成器等，根据自己的实际需求进行自定义开发也十分方便。

## 2. Instrument with Pin

### 1. Pin

对 Pin 的一个最合适的理解是可以将 Pin 当作一个 JIT 编译器，只是它的输入不是字节码，而是可执行文件。Pin 会拦截可执行文件的第一条指令，然后对从该指令开始的后续的指令序列重新“compile”新的代码，然后控制权限转移到新生成的代码。生成的代码与原始代码几乎一致，但是 Pin 会保证在分支退出代码序列时重新获得控制权限。重新获得控制权后，Pin 会基于分支生成更多的代码，然后继续运行。Pin 将所有生成的代码都保存在内存中，这样可以实现代码重用。

在这种 JIT 模式下，执行的是生成的代码，原始代码仅作为参考。当生成代码时，Pin 会给到用户注入自己想执行的代码（插桩）的机会。

Pin 对所有实际执行的代码进行插桩，不管代码具体处于哪个 section 。虽然对于一些条件分支会存在异常，但是如果指令没有被执行过，就一定不会被插桩。

### 2. Pintools

在概念上，插桩主要包含两部分内容：

- 插桩机制（instrumentation code）

  在什么位置插入什么样的代码

- 分析代码（analysis code）

  在插桩点执行的代码

这两部分内容都通过 Pintool 这个可执行文件来实现。Pintool 可以看作是 Pin 中可以实现修改代码生成过程的插件。

Pintool 会向 Pin 注册插桩回调例程，每当需要生成新代码时， Pin 会调用这些回调例程。回调例程承担了检测插桩内容的作用，它会检查要生成的代码，检查其静态属性，并决定是否以及在何处注入对分析函数的调用。

分析功能收集有关应用程序的数据。Pin 确保根据需要保存和恢复整数和浮点寄存器状态，并允许将参数传递给函数。

Pintool 还可以为诸如线程创建或 fork 之类的事件注册通知回调例程，这些回调通常用于收集数据或工具初始化和清理。

因为 Pintool 采用的是类似插件的工作机制，所以必须运行在和 Pin 及插桩的可执行文件相同的地址空间内，所以 Pintool 可以访问可执行文件的全部数据，还会与可执行文件共享 fd 和其他进程信息。

在 Pintool 的开发过程中，分析代码的调优比插桩代码更重要，因为插桩代码只执行一次，但是分析代码会调用很多次。

### 3. Instrumentation Granularity

#### 1. trace instrumentation

在一个代码序列第一次执行前进行插桩，这种粒度的插桩称为“trace instrumentation”。在这种模式下，Pintool 一次“trace”执行一次检查和插桩，“trace”是指从一个 branch 开始，以一个无条件跳转 branch 结束，包含 call 和 return。

Pin 会保证每个 trace 只有一个顶部入口，但是可能包含多个出口。如果一个分支连接到了一个 trace 的中间位置，Pin 会生成一个以该分支作为开始的新的 trace 。Pin 将 trace 切分成了基本块，每个基本块称为“BBL”，每个 BBL 是一个单一入口、单一出口的指令序列。如果有分支连接到了 BBL 的中间位置，会定义一个新的 BBL 。通常以 BBL 为单位插入分析调用，而不是对每个指令都插入，这样可以降低分析调用的性能消耗。trace instrumentation 通过 `TRACE_AddInstrumentFunction` API 调用。

因为 Pin 是在程序执行时动态发现程序的执行流，所以 BBL 的概念与传统的基本块的概念有所不同，说明如下：

```c
swtich(i){
  case 4: total++;
  case 3: total++;
  case 2: total++;
  case 1: total++;
  case 0: 
  default: break;
}
```

在 IA-32 架构下，会生成如下类似的指令：

```assembly
.L7:
        addl    $1, -4(%ebp)
.L6:
        addl    $1, -4(%ebp)
.L5:
        addl    $1, -4(%ebp)
.L4:
        addl    $1, -4(%ebp)
```

传统基本块的计算方式是会把每个 addl 指令作为一个单独的指令基本块，但是对于 Pin 来说，随着执行不同的 switch cases，Pin 会在 .L7 作为入口（从 .L7 依次向下执行）的时候生成包含所有4个指令的 BBL，在 .L6 输入的时候生成包含3个指令的 BBL，依此类推。所以，在 Pin 的统计方式里，如果代码分支走到了 .L7 ，只会计算一个 Pin BBL，但是4个传统概念上的基本块都被执行了。

Pin 在遇到一些特殊指令的时候会直接作为 trace 的结束位置，生成一个 BBL， 比如 cpuid, popf 以及 REP 为前缀的指令。REP 为前缀的指令都被当作隐式循环处理，在处理完第一次的迭代后，后面的每次迭代都作为一个单独的 BBL ，因此这种情况下，会看到比传统基本块统计方式统计出更多的 BBL。

#### 2. instruction instrumentation

Pintool 会在可执行文件的每条指令都进行插桩，这种模式使得开发者不必过多关注 trace 内部的迭代循环指令，因为如上面所说，包含循环的 trace 内部的特定的 BBL 和指令可能产生多次。instruction instrumentation 通过 `INS_AddInstrumentFunction` API 进行调用。

#### 3. image instrumentation

通过“caching”插桩请求实现，会有额外的内存空间要求，属于一种“提前插桩”。image instrumentation 模式下，Pintool 在 `IMG:Image Object`第一次加载时，对整个 imgaes 进行检查和插桩， Pintool 可以遍历 image 的 sections：`SEC:Section Object`， 可以是 section 中的 routine：`RTN:Routine`，还可以是一个 routine 中的 instructions：INS。插入位置可以是例程或指令的前面或后面，都可以实现，使用的 API 为 `IMG_AddInstrumentFunction` 。

image instrumentation 需要有调试信息来确定 routine 的边界，所以在调用 `PIN_Init` 之前，需要先初始化符号信息 `PIN_InitSysmbols`。

#### 4. routine instrumentation

通过“caching”插桩请求实现，会有额外的内存空间要求，属于一种“提前插桩”。routine instrumentation 模式下，Pintool 在 image 首次加载时就对整个 routine 进行检查和插桩，对 routine 中的每条指令都可以插桩，但是没有充分的信息可以将指令划分为 BBL。插入位置可以是执行例程或指令的前后。这种模式其实更大程度上属于 image instrumentation 的替代方法，使用的 API 为 `RTN_AddInstrumentFunction`。

需要注意的是，在 image 和 routine instrumentation 模式下，插桩时并不确定 routine 是否会被执行，但是通过识别 routine 的开始指令，可以遍历出执行过的 routine 的指令。

### 4. Symbols

Pin 通过symbol object 来访问函数名， 但是 symbol 对象只能提供程序中的函数符号相关的信息，对于数据符号之类的信息必须通过其他工具获取。

Windows下，可以通过 `dbghelp.dll` 文件获取，但是可能出现死锁问题；Linux下可以通过 `libelf.so` 或 `libdwarf.so` 文件获取符号信息。

## 3. Examples

本章主要是通过运行一些 Pin 内置的样例 Pintool，来实际感受一下 Pin 的插桩过程。实践出真知。

### 1. Building the example tools

ia32 架构的样例：

```shell
$ cd source/tools/ManualExamples
$ make all TARGET=ia32
```

ia64 架构的样例：

```shell
$ cd source/tools/ManualExamples
$ make all TARGET=intel64
```

编译并运行某个样例：

```shell
$ cd source/tools/ManualExamples
$ make inscount0.test TARGET=intel64
```

编译某个样例但不运行：

```shell
$ cd source/tools/ManualExamples
$ make obj-intel64/inscount0.so TARGET=intel64
# $ make obj-ia32/inscount0.so TARGET=ia32
```

### 2. Simple Instruction Count （指令插桩）

功能：统计执行过的指令的总数。

运行和查看输出：

```shell
$ ../../../pin -t obj-intel64/inscount0.so -o inscount.out -- /bin/ls
Makefile          atrace.o     imageload.out  itrace      proccount
Makefile.example  imageload    inscount0      itrace.o    proccount.o
atrace            imageload.o  inscount0.o    itrace.out
$ cat inscount.out
Count 422838

# 输出文件存在默认名称，可以使用-o参数指定输出文件名。
```

原理：在每个指令前插入对 `docount` 的调用，并将结果保存在 `inscount.out` 文件中。

源码 `source/tools/ManualExamples/inscount0.cpp`：

```cpp
#include <iostream>
#include <fstream>
#include "pin.H"

using std::cerr;
using std::endl;
using std::ios;
using std::ofstream;
using std::string;
ofstream OutFile;
// The running count of instructions is kept here
// make it static to help the compiler optimize docount
static UINT64 icount = 0;

// 这里就是我们调用的桩代码
VOID docount() { icount++; }

// Pin calls this function every time a new instruction is encountered
// 遇到一条新指令，调用一次该函数
VOID Instruction(INS ins, VOID* v)
{
    // Insert a call to docount before every instruction, no arguments are passed
    // 指定调用的桩代码函数，执行插入操作，没有对桩代码函数进行传参
    INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)docount, IARG_END);
}

// 处理输出文件，默认文件名为“inscount.out”
KNOB< string > KnobOutputFile(KNOB_MODE_WRITEONCE, "pintool", "o", "inscount.out", "specify output file name");

// This function is called when the application exits
VOID Fini(INT32 code, VOID* v)
{
    // Write to a file since cout and cerr maybe closed by the application
    // 将输出保存到文件
    OutFile.setf(ios::showbase);
    OutFile << "Count " << icount << endl;
    OutFile.close();
}

/* ===================================================================== */
/* Print Help Message                                                 */
/* ===================================================================== */
INT32 Usage()
{
    cerr << "This tool counts the number of dynamic instructions executed" << endl;
    cerr << endl << KNOB_BASE::StringKnobSummary() << endl;
    return -1;
}
/* ===================================================================== */
/* Main                                                                  */
/* ===================================================================== */
/*   argc, argv are the entire command line: pin -t <toolname> -- ...    */
/* ===================================================================== */
int main(int argc, char* argv[])
{
    // Initialize pin 初始化
    if (PIN_Init(argc, argv)) return Usage();
    OutFile.open(KnobOutputFile.Value().c_str());
  
    // Register Instruction to be called to instrument instructions
    // 注册插桩函数
    INS_AddInstrumentFunction(Instruction, 0);
  
    // Register Fini to be called when the application exits
    // 注册程序退出时的处理函数
    PIN_AddFiniFunction(Fini, 0);
  
    // Start the program, never returns
    // 开始执行
    PIN_StartProgram();
    return 0;
}
```

### 3. Instruction Address Trace（指令插桩）

功能：打印执行的指令的地址

运行和查看输出：

```shell
$ ../../../pin -t obj-intel64/itrace.so -- /bin/ls
Makefile          atrace.o     imageload.out  itrace      proccount
Makefile.example  imageload    inscount0      itrace.o    proccount.o
atrace            imageload.o  inscount0.o    itrace.out
$ head itrace.out
0x40001e90
0x40001e91
0x40001ee4
0x40001ee5
0x40001ee7
0x40001ee8
0x40001ee9
0x40001eea
0x40001ef0
0x40001ee0
$
```

原理：在调用分析程序时，Pin 允许传递指令指针、寄存器当前值、内存操作的有效地址、常量等数据给分析程序。完整的可传递的参数的类型如下：[IARG_TYPE](https://software.intel.com/sites/landingpage/pintool/docs/98437/Pin/html/group__INST__ARGS.html#ga089c27ca15e9ff139dd3a3f8a6f8451d)。将指令计数程序中的参数更改为 `INS_InsertCall` 来传递即将执行的指令的地址，将 `docount` 更改为 `printip` 来打印指令的地址，最后将输出写入到文件 `itrace.out` 中。

源码``source/tools/ManualExamples/itrace.cpp`:

```cpp
#include <stdio.h>
#include "pin.H"
FILE* trace;
// 在每条指令执行前都会被调用，打印出当前指令的地址
VOID printip(VOID* ip) { fprintf(trace, "%p\n", ip); }
// 遇到一条新指令调用一次
VOID Instruction(INS ins, VOID* v)
{
    // 在每条指令前插入对 printip 函数的调用，并传递 ip 参数
    INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)printip, IARG_INST_PTR, IARG_END);
}
// 结束函数
VOID Fini(INT32 code, VOID* v)
{
    fprintf(trace, "#eof\n");
    fclose(trace);
}
/* ===================================================================== */
/* Print Help Message                                                    */
/* ===================================================================== */
INT32 Usage()
{
    PIN_ERROR("This Pintool prints the IPs of every instruction executed\n" + KNOB_BASE::StringKnobSummary() + "\n");
    return -1;
}
/* ===================================================================== */
/* Main                                                                  */
/* ===================================================================== */
int main(int argc, char* argv[])
{
    trace = fopen("itrace.out", "w");
    // 初始化
    if (PIN_Init(argc, argv)) return Usage();
    // 桩指令注册
    INS_AddInstrumentFunction(Instruction, 0);
    // 结束逻辑注册
    PIN_AddFiniFunction(Fini, 0);
    // 开始执行，不返回
    PIN_StartProgram();
    return 0;
}
```

### 4. Memory Reference Trace （指令插桩）

功能：内存引用追踪（只对读写内存的指令插桩）

运行和查看输出：

```shell
$ ../../../pin -t obj-intel64/pinatrace.so -- /bin/ls
Makefile          atrace.o    imageload.o    inscount0.o  itrace.out
Makefile.example  atrace.out  imageload.out  itrace       proccount
atrace            imageload   inscount0      itrace.o     proccount.o
$ head pinatrace.out
0x40001ee0: R 0xbfffe798
0x40001efd: W 0xbfffe7d4
0x40001f09: W 0xbfffe7d8
0x40001f20: W 0xbfffe864
0x40001f20: W 0xbfffe868
0x40001f20: W 0xbfffe86c
0x40001f20: W 0xbfffe870
0x40001f20: W 0xbfffe874
0x40001f20: W 0xbfffe878
0x40001f20: W 0xbfffe87c
$
```

原理：Pin 中包含可以对指令进行分类和检查功能的 API，通过调用该 API 可以实现对某一类功能的函数的追踪。

源码`source/tools/ManualExamples/itrace.cpp`：

```cpp
/*
 *  This file contains an ISA-portable PIN tool for tracing memory accesses.
 */
#include <stdio.h>
#include "pin.H"
FILE* trace;
// 打印地址读的指令的地址
VOID RecordMemRead(VOID* ip, VOID* addr) { fprintf(trace, "%p: R %p\n", ip, addr); }
// 打印地址写的指令的地址
VOID RecordMemWrite(VOID* ip, VOID* addr) { fprintf(trace, "%p: W %p\n", ip, addr); }
// 使用谓词函数调用来检测内存访问
// 每个读和写的指令都会调用
VOID Instruction(INS ins, VOID* v)
{
    // 获取指令中的内存操作数计数
    UINT32 memOperands = INS_MemoryOperandCount(ins);
    
    // 遍历指令中的每个内存操作数
    for (UINT32 memOp = 0; memOp < memOperands; memOp++)
    {		
      	// 如果是内存读
        if (INS_MemoryOperandIsRead(ins, memOp))
        {
            INS_InsertPredicatedCall(ins, IPOINT_BEFORE, (AFUNPTR)RecordMemRead, IARG_INST_PTR, IARG_MEMORYOP_EA, memOp,
                                     IARG_END);
        }

        // 在某些架构下，内存操作数可以同时用作读和写，例如 IA-32 的 %eax，这种情况下只记录一次
        // 如果是写
        if (INS_MemoryOperandIsWritten(ins, memOp))
        {
            INS_InsertPredicatedCall(ins, IPOINT_BEFORE, (AFUNPTR)RecordMemWrite, IARG_INST_PTR, IARG_MEMORYOP_EA, memOp,
                                     IARG_END);
        }
    }
}
VOID Fini(INT32 code, VOID* v)
{
    fprintf(trace, "#eof\n");
    fclose(trace);
}
/* ===================================================================== */
/* Print Help Message                                                    */
/* ===================================================================== */
INT32 Usage()
{
    PIN_ERROR("This Pintool prints a trace of memory addresses\n" + KNOB_BASE::StringKnobSummary() + "\n");
    return -1;
}
/* ===================================================================== */
/* Main                                                                  */
/* ===================================================================== */
int main(int argc, char* argv[])
{
    if (PIN_Init(argc, argv)) return Usage();
    trace = fopen("pinatrace.out", "w");
    // 注册桩函数
    INS_AddInstrumentFunction(Instruction, 0);
    // 注册结束函数
    PIN_AddFiniFunction(Fini, 0);
    // 开始，不返回
    PIN_StartProgram();
    return 0;
}
```

### 5. Detecting the loading and Unloading of Images（image插桩）

功能：在 image 加载和卸载时打印信息到 trace 文件中。

执行和查看输出:

```shell
$ ../../../pin -t obj-intel64/imageload.so -- /bin/ls
Makefile          atrace.o    imageload.o    inscount0.o  proccount
Makefile.example  atrace.out  imageload.out  itrace       proccount.o
atrace            imageload   inscount0      itrace.o     trace.out
$ cat imageload.out
Loading /bin/ls
Loading /lib/ld-linux.so.2
Loading /lib/libtermcap.so.2
Loading /lib/i686/libc.so.6
Unloading /bin/ls
Unloading /lib/ld-linux.so.2
Unloading /lib/libtermcap.so.2
Unloading /lib/i686/libc.so.6
$
```

原理：本质上没有对 image 文件进行插桩。

源码 `source/tools/ManualExamples/imageload.cpp`：

```cpp
//
// This tool prints a trace of image load and unload events
//
#include "pin.H"
#include <iostream>
#include <fstream>
#include <stdlib.h>
using std::endl;
using std::ofstream;
using std::string;
KNOB< string > KnobOutputFile(KNOB_MODE_WRITEONCE, "pintool", "o", "imageload.out", "specify file name");
ofstream TraceFile;

// Pin 在 image 加载时调用该函数，在该例中没有进行插桩
VOID ImageLoad(IMG img, VOID* v) { TraceFile << "Loading " << IMG_Name(img) << ", Image id = " << IMG_Id(img) << endl; }
// Pin 在 image 卸载时调用该函数，对于将要卸载的image无法进行插桩
VOID ImageUnload(IMG img, VOID* v) { TraceFile << "Unloading " << IMG_Name(img) << endl; }
// This function is called when the application exits
// It closes the output file.
VOID Fini(INT32 code, VOID* v)
{
    if (TraceFile.is_open())
    {
        TraceFile.close();
    }
}
/* ===================================================================== */
/* Print Help Message                                                    */
/* ===================================================================== */
INT32 Usage()
{
    PIN_ERROR("This tool prints a log of image load and unload events\n" + KNOB_BASE::StringKnobSummary() + "\n");
    return -1;
}
/* ===================================================================== */
/* Main                                                                  */
/* ===================================================================== */
int main(int argc, char* argv[])
{
    // 符号初始化
    PIN_InitSymbols();
    // pin 初始化
    if (PIN_Init(argc, argv)) return Usage();
    TraceFile.open(KnobOutputFile.Value().c_str());
    // 注册加载桩函数
    IMG_AddInstrumentFunction(ImageLoad, 0);
    // 注册卸载桩函数
    IMG_AddUnloadFunction(ImageUnload, 0);
    // 注册退出函数
    PIN_AddFiniFunction(Fini, 0);
    // 开始执行，无返回
    PIN_StartProgram();
    return 0;
}
```

### 6. More Efficient Instruction Counting （trace 插桩）

功能：计算 BBL （单入口单出口）数量

执行和查看输出：

```shell
$ ../../../pin -t obj-intel64/inscount1.so -o inscount.out -- /bin/ls
Makefile          atrace.o     imageload.out  itrace      proccount
Makefile.example  imageload    inscount0      itrace.o    proccount.o
atrace            imageload.o  inscount0.o    itrace.out
$ cat inscount.out
Count 707208
```



原理：在每个 BBL 进行插桩来替代在每个指令进行插桩，在进行计数时，以 bbl 为单位，每次增加每个 bbl 中的指令数量。

源码 `source/tools/ManualExamples/inscount1.cpp`：

```cpp
#include <iostream>
#include <fstream>
#include "pin.H"
using std::cerr;
using std::endl;
using std::ios;
using std::ofstream;
using std::string;
ofstream OutFile;
// 保存指令的运行次数，设置为静态变量以帮助编译器优化 docount
static UINT64 icount = 0;
// 在每个 block 前都会被调用
VOID docount(UINT32 c) { icount += c; }
// Pin 在遇到一个新的block 时进行调用，插入对 docount 函数的调用
VOID Trace(TRACE trace, VOID* v)
{
    // 访问 trace 中的每个 bbl
    for (BBL bbl = TRACE_BblHead(trace); BBL_Valid(bbl); bbl = BBL_Next(bbl))
    {
        // 在每个 bbl 前插入对 docount 函数的调用，传入指令数量
        BBL_InsertCall(bbl, IPOINT_BEFORE, (AFUNPTR)docount, IARG_UINT32, BBL_NumIns(bbl), IARG_END);
    }
}
KNOB< string > KnobOutputFile(KNOB_MODE_WRITEONCE, "pintool", "o", "inscount.out", "specify output file name");
// 退出函数
VOID Fini(INT32 code, VOID* v)
{
    // 写入到文件中，程序可能会关闭 cout 和 cerr
    OutFile.setf(ios::showbase);
    OutFile << "Count " << icount << endl;
    OutFile.close();
}
/* ===================================================================== */
/* Print Help Message                                                    */
/* ===================================================================== */
INT32 Usage()
{
    cerr << "This tool counts the number of dynamic instructions executed" << endl;
    cerr << endl << KNOB_BASE::StringKnobSummary() << endl;
    return -1;
}
/* ===================================================================== */
/* Main                                                                  */
/* ===================================================================== */
int main(int argc, char* argv[])
{
    // 初始化 pin
    if (PIN_Init(argc, argv)) return Usage();
    OutFile.open(KnobOutputFile.Value().c_str());
    // 注册插桩函数
    TRACE_AddInstrumentFunction(Trace, 0);
    // 注册退出函数
    PIN_AddFiniFunction(Fini, 0);
    // 开始执行，不返回
    PIN_StartProgram();
    return 0;
}
```

### 7. Procedure Instruction Count（routine插桩）

功能：计算一个 procedure 被调用的次数，以及每个 procedure 中执行的命令总数。

执行和检查输出：

```shell
$ ../../../pin -t obj-intel64/proccount.so -- /bin/grep proccount.cpp Makefile
proccount_SOURCES = proccount.cpp
$ head proccount.out
              Procedure           Image            Address        Calls Instructions
                  _fini       libc.so.6         0x40144d00            1           21
__deregister_frame_info       libc.so.6         0x40143f60            2           70
  __register_frame_info       libc.so.6         0x40143df0            2           62
              fde_merge       libc.so.6         0x40143870            0            8
            __init_misc       libc.so.6         0x40115824            1           85
            __getclktck       libc.so.6         0x401157f4            0            2
                 munmap       libc.so.6         0x40112ca0            1            9
                   mmap       libc.so.6         0x40112bb0            1           23
            getpagesize       libc.so.6         0x4010f934            2           26
$
```

源码 `source/tools/ManualExamples/proccount.cpp`：

```cpp
//
// This tool counts the number of times a routine is executed and
// the number of instructions executed in a routine
//
#include <fstream>
#include <iomanip>
#include <iostream>
#include <string.h>
#include "pin.H"
using std::cerr;
using std::dec;
using std::endl;
using std::hex;
using std::ofstream;
using std::setw;
using std::string;
ofstream outFile;
// 保存 procedure 的指令数
typedef struct RtnCount
{
    string _name;
    string _image;
    ADDRINT _address;
    RTN _rtn;
    UINT64 _rtnCount;
    UINT64 _icount;
    struct RtnCount* _next;
} RTN_COUNT;
// 每个 procedure 的指令数的链表
RTN_COUNT* RtnList = 0;
// 每条指令执行前调用
VOID docount(UINT64* counter) { (*counter)++; }
const char* StripPath(const char* path)
{
    const char* file = strrchr(path, '/');
    if (file)
        return file + 1;
    else
        return path;
}
// Pin 在一个新的 rtn 执行时调用该函数
VOID Routine(RTN rtn, VOID* v)
{
    // 对该routine设置一个计数器
    RTN_COUNT* rc = new RTN_COUNT;
  	// image unloaded 时， RTN 数据消失，所以在此处直接保存，后续 fini 中还要使用
    rc->_name     = RTN_Name(rtn);
    rc->_image    = StripPath(IMG_Name(SEC_Img(RTN_Sec(rtn))).c_str());
    rc->_address  = RTN_Address(rtn);
    rc->_icount   = 0;
    rc->_rtnCount = 0;
    // 添加到routines列表
    rc->_next = RtnList;
    RtnList   = rc;
    RTN_Open(rtn);
  	// 在routine入口处插入一个call，增加call计数
    RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)docount, IARG_PTR, &(rc->_rtnCount), IARG_END);
    // 对于routine中的每条指令
    for (INS ins = RTN_InsHead(rtn); INS_Valid(ins); ins = INS_Next(ins))
    {
      	// 插入对docount函数的调用，增加该rtn中的指令计数
        INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)docount, IARG_PTR, &(rc->_icount), IARG_END);
    }
    RTN_Close(rtn);
}
// 退出函数，打印每个procedure的名字和计数
VOID Fini(INT32 code, VOID* v)
{
    outFile << setw(23) << "Procedure"
            << " " << setw(15) << "Image"
            << " " << setw(18) << "Address"
            << " " << setw(12) << "Calls"
            << " " << setw(12) << "Instructions" << endl;
    for (RTN_COUNT* rc = RtnList; rc; rc = rc->_next)
    {
        if (rc->_icount > 0)
            outFile << setw(23) << rc->_name << " " << setw(15) << rc->_image << " " << setw(18) << hex << rc->_address << dec
                    << " " << setw(12) << rc->_rtnCount << " " << setw(12) << rc->_icount << endl;
    }
}
/* ===================================================================== */
/* Print Help Message                                                    */
/* ===================================================================== */
INT32 Usage()
{
    cerr << "This Pintool counts the number of times a routine is executed" << endl;
    cerr << "and the number of instructions executed in a routine" << endl;
    cerr << endl << KNOB_BASE::StringKnobSummary() << endl;
    return -1;
}
/* ===================================================================== */
/* Main                                                                  */
/* ===================================================================== */
int main(int argc, char* argv[])
{
    PIN_InitSymbols();
    outFile.open("proccount.out");
    
    if (PIN_Init(argc, argv)) return Usage();
    // 注册桩函数
    RTN_AddInstrumentFunction(Routine, 0);
    // 注册程序退出时的 fini函数
    PIN_AddFiniFunction(Fini, 0);
    // 开始执行，不返回
    PIN_StartProgram();
    return 0;
}

```

**下面是一些Pin的功能性特征说明样例。**

### 8. Using PIN_SafeCopy()

功能：从源内存区域复制指定数量的字节数到目的内存区域。即使源或目的区域不可访问，此函数也可保证安全返回给caller。此外，该API还可以读写程序的内存数据。

执行和查看输出：

```shell
$ ../../../pin -t obj-ia32/safecopy.so -- /bin/cp makefile obj-ia32/safecopy.so.makefile.copy
$ head safecopy.out
Emulate loading from addr 0xbff0057c to ebx
Emulate loading from addr 0x64ffd4 to eax
Emulate loading from addr 0xbff00598 to esi
Emulate loading from addr 0x6501c8 to edi
Emulate loading from addr 0x64ff14 to edx
Emulate loading from addr 0x64ff1c to edx
Emulate loading from addr 0x64ff24 to edx
Emulate loading from addr 0x64ff2c to edx
Emulate loading from addr 0x64ff34 to edx
Emulate loading from addr 0x64ff3c to edx
```

源码`source/tools/ManualExamples/safecopy.cpp`:

```cpp
#include <stdio.h>
#include "pin.H"
#include <iostream>
#include <fstream>
using std::cerr;
using std::endl;
std::ofstream* out = 0;
//=======================================================
//  Analysis routines
//=======================================================
// 从内存转移到寄存器中
ADDRINT DoLoad(REG reg, ADDRINT* addr)
{
    *out << "Emulate loading from addr " << addr << " to " << REG_StringShort(reg) << endl;
    ADDRINT value;
    PIN_SafeCopy(&value, addr, sizeof(ADDRINT));
    return value;
}
//=======================================================
// Instrumentation routines
//=======================================================
VOID EmulateLoad(INS ins, VOID* v)
{
    // Find the instructions that move a value from memory to a register
    if (INS_Opcode(ins) == XED_ICLASS_MOV && INS_IsMemoryRead(ins) && INS_OperandIsReg(ins, 0) && INS_OperandIsMemory(ins, 1))
    {
        // op0 <- *op1
        INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(DoLoad), IARG_UINT32, REG(INS_OperandReg(ins, 0)), IARG_MEMORYREAD_EA,IARG_RETURN_REGS, INS_OperandReg(ins, 0), IARG_END);
        // Delete the instruction
        INS_Delete(ins);
    }
}
/* ===================================================================== */
/* Print Help Message                                                    */
/* ===================================================================== */
INT32 Usage()
{
    cerr << "This tool demonstrates the use of SafeCopy" << endl;
    cerr << endl << KNOB_BASE::StringKnobSummary() << endl;
    return -1;
}
/* ===================================================================== */
/* Main                                                                  */
/* ===================================================================== */
int main(int argc, char* argv[])
{
    // Write to a file since cout and cerr maybe closed by the application
    out = new std::ofstream("safecopy.out");
    // 初始化Pin，初始化符号
    if (PIN_Init(argc, argv)) return Usage();
    PIN_InitSymbols();
    // 注册EmulateLoad函数以进行插桩
    INS_AddInstrumentFunction(EmulateLoad, 0);
    // 开始执行，不返回
    PIN_StartProgram();
    return 0;
}
```

### 9. Order of Instrumentation

Pin提供了多种方式来控制analysis call的执行顺序，主要取决于insertion action(IPOINT)和call order(CALL_ORDER)。

执行和查看输出：

```shell
$ ../../../pin -t obj-ia32/invocation.so -- obj-ia32/little_malloc
$ head invocation.out
After: IP = 0x64bc5e
Before: IP = 0x64bc5e
Taken: IP = 0x63a12e
After: IP = 0x64bc5e
Before: IP = 0x64bc5e
Taken: IP = 0x641c76
After: IP = 0x641ca6
After: IP = 0x64bc5e
Before: IP = 0x64bc5e
Taken: IP = 0x648b02
```

源码`source/tools/ManualExamples/invocation.cpp`：

```cpp
#include "pin.H"
#include <iostream>
#include <fstream>
using std::cerr;
using std::dec;
using std::endl;
using std::hex;
using std::ios;
using std::ofstream;
using std::string;
KNOB< string > KnobOutputFile(KNOB_MODE_WRITEONCE, "pintool", "o", "invocation.out", "specify output file name");
ofstream OutFile;
/*
 * Analysis routines
 */
VOID Taken(const CONTEXT* ctxt)
{
    ADDRINT TakenIP = (ADDRINT)PIN_GetContextReg(ctxt, REG_INST_PTR);
    OutFile << "Taken: IP = " << hex << TakenIP << dec << endl;
}
VOID Before(CONTEXT* ctxt)
{
    ADDRINT BeforeIP = (ADDRINT)PIN_GetContextReg(ctxt, REG_INST_PTR);
    OutFile << "Before: IP = " << hex << BeforeIP << dec << endl;
}
VOID After(CONTEXT* ctxt)
{
    ADDRINT AfterIP = (ADDRINT)PIN_GetContextReg(ctxt, REG_INST_PTR);
    OutFile << "After: IP = " << hex << AfterIP << dec << endl;
}
/*
 * Instrumentation routines
 */
VOID ImageLoad(IMG img, VOID* v)
{
    for (SEC sec = IMG_SecHead(img); SEC_Valid(sec); sec = SEC_Next(sec))
    {
      	// RTN_InsertCall()和INS_InsertCall()谁先出现谁先执行
      	// 在下面的代码中，IPOINT_AFTER在IPOINT_BEFORE之前执行。
        for (RTN rtn = SEC_RtnHead(sec); RTN_Valid(rtn); rtn = RTN_Next(rtn))
        {
            // 打开RTN.
            RTN_Open(rtn);
          	// IPOINT_AFTER通过在一个routine中对每个return指令插桩实现。
          	// Pin会尝试查找所有的return指令，成不成功则是另外一回事（有点可爱23333）。
            RTN_InsertCall(rtn, IPOINT_AFTER, (AFUNPTR)After, IARG_CONTEXT, IARG_END);
            // 检查routine中的每条指令
            for (INS ins = RTN_InsHead(rtn); INS_Valid(ins); ins = INS_Next(ins))
            {
                if (INS_IsRet(ins))
                {
                    // 插桩每条return指令
                    // IPOINT_TAKEN_BRANCH总是最后使用
                    INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)Before, IARG_CONTEXT, IARG_END);
                    INS_InsertCall(ins, IPOINT_TAKEN_BRANCH, (AFUNPTR)Taken, IARG_CONTEXT, IARG_END);
                }
            }
            // 关闭RTN.
            RTN_Close(rtn);
        }
    }
}
VOID Fini(INT32 code, VOID* v) { OutFile.close(); }
/* ===================================================================== */
/* Print Help Message                                                    */
/* ===================================================================== */
INT32 Usage()
{
    cerr << "This is the invocation pintool" << endl;
    cerr << endl << KNOB_BASE::StringKnobSummary() << endl;
    return -1;
}
/* ===================================================================== */
/* Main                                                                  */
/* ===================================================================== */
int main(int argc, char* argv[])
{
    //  初始化
    if (PIN_Init(argc, argv)) return Usage();
    PIN_InitSymbols();
    // 注册ImageLoad函数
    IMG_AddInstrumentFunction(ImageLoad, 0);
    PIN_AddFiniFunction(Fini, 0);
    // 写入到文件
    OutFile.open(KnobOutputFile.Value().c_str());
    OutFile.setf(ios::showbase);
    // 开始执行，无返回
    PIN_StartProgram();
    return 0;
}

```

### 10. Finding the Value of Function Arguments

功能：使用`RTN_InsertCall()`查看函数参数

执行和查看输出：

```shell
$ ../../../pin -t obj-intel64/malloctrace.so -- /bin/cp makefile obj-intel64/malloctrace.so.makefile.copy
$ cat malloctrace.out
malloc(0x5a1)
  returns 0x7f87d8ce2190
malloc(0x4a1)
  returns 0x7f87d8ce2740
malloc(0x10)
  returns 0x7f87d8ce2bf0
malloc(0x9d)
  returns 0x7f87d8ce2c00
malloc(0x28)
  returns 0x7f87d8ce2ca0
malloc(0x140)
  returns 0x7f87d8ce2cd0
malloc(0x26)
  returns 0x7f87d8ce2e10
free(0)
malloc(0x4b0)
  returns 0x7f87c4428000
malloc(0x26)
  returns 0x7f87c44284b0
malloc(0x22)
  returns 0x7f87c44284e0
free(0)
... ...
```

源码`source/tools/ManualExamples/malloctrace.cpp`:

```cpp
#include "pin.H"
#include <iostream>
#include <fstream>
using std::cerr;
using std::endl;
using std::hex;
using std::ios;
using std::string;
/* ===================================================================== */
/* Names of malloc and free */
/* ===================================================================== */
#if defined(TARGET_MAC)
#define MALLOC "_malloc"
#define FREE "_free"
#else
#define MALLOC "malloc"
#define FREE "free"
#endif
/* ===================================================================== */
/* Global Variables */
/* ===================================================================== */
std::ofstream TraceFile;
/* ===================================================================== */
/* Commandline Switches */
/* ===================================================================== */
KNOB< string > KnobOutputFile(KNOB_MODE_WRITEONCE, "pintool", "o", "malloctrace.out", "specify trace file name");
/* ===================================================================== */

/* ===================================================================== */
/* Analysis routines                                                     */
/* ===================================================================== */
VOID Arg1Before(CHAR* name, ADDRINT size) { TraceFile << name << "(" << size << ")" << endl; }
VOID MallocAfter(ADDRINT ret) { TraceFile << "  returns " << ret << endl; }

/* ===================================================================== */
/* Instrumentation routines                                              */
/* ===================================================================== */
VOID Image(IMG img, VOID* v)
{
  	// 对malloc和free函数进行插桩，打印出每个malloc或free函数的输入参数以及malloc的返回值
  	// 首先，查找malloc函数
    RTN mallocRtn = RTN_FindByName(img, MALLOC);
    if (RTN_Valid(mallocRtn))
    {
        RTN_Open(mallocRtn);
      	// 对查找到的malloc()函数进行插桩打印其参数
        RTN_InsertCall(mallocRtn, IPOINT_BEFORE, (AFUNPTR)Arg1Before, IARG_ADDRINT, MALLOC, IARG_FUNCARG_ENTRYPOINT_VALUE, 0,IARG_END);
      	// 打印返回值
        RTN_InsertCall(mallocRtn, IPOINT_AFTER, (AFUNPTR)MallocAfter, IARG_FUNCRET_EXITPOINT_VALUE, IARG_END);
        RTN_Close(mallocRtn);
    }
    // 查找free()
    RTN freeRtn = RTN_FindByName(img, FREE);
    if (RTN_Valid(freeRtn))
    {
        RTN_Open(freeRtn);
        // 插桩，打印输入参数
        RTN_InsertCall(freeRtn, IPOINT_BEFORE, (AFUNPTR)Arg1Before, IARG_ADDRINT, FREE, IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
                       IARG_END);
        RTN_Close(freeRtn);
    }
}
VOID Fini(INT32 code, VOID* v) { TraceFile.close(); }
/* Print Help Message                                                    */
INT32 Usage()
{
    cerr << "This tool produces a trace of calls to malloc." << endl;
    cerr << endl << KNOB_BASE::StringKnobSummary() << endl;
    return -1;
}
/* ===================================================================== */
/* Main                                                                  */
/* ===================================================================== */
int main(int argc, char* argv[])
{
    // 初始化
    PIN_InitSymbols();
    if (PIN_Init(argc, argv))
    {
        return Usage();
    }
    // 写入到文件
    TraceFile.open(KnobOutputFile.Value().c_str());
    TraceFile << hex;
    TraceFile.setf(ios::showbase);
    // 注册Image函数
    IMG_AddInstrumentFunction(Image, 0);
    PIN_AddFiniFunction(Fini, 0);
    // 开始执行，不返回
    PIN_StartProgram();
    return 0;
}
```

### 11. Instrumenting Threaded Applications

功能：在应用开启了线程环境下进行插桩，使用的callback为`ThreadStart()`和`ThreadFini()`。在使用时，为了防止与其他分析routine发生共享资源竞争的问题，可以使用`PIN_GetLock()`函数进行加锁处理。

执行和查看输出：

```shell
$ ../../../pin -t obj-ia32/malloc_mt.so -- obj-ia32/thread_lin
$ head malloc_mt.out
thread begin 0
thread 0 entered malloc(24d)
thread 0 entered malloc(57)
thread 0 entered malloc(c)
thread 0 entered malloc(3c0)
thread 0 entered malloc(c)
thread 0 entered malloc(58)
thread 0 entered malloc(56)
thread 0 entered malloc(19)
thread 0 entered malloc(25c)
```

源码`source/tools/ManualExamples/malloc_mt.cpp`：

```cpp
#include <stdio.h>
#include "pin.H"
using std::string;
KNOB< string > KnobOutputFile(KNOB_MODE_WRITEONCE, "pintool", "o", "malloc_mt.out", "specify output file name");
//==============================================================
//  Analysis Routines
//==============================================================
// Note:  threadid+1 作为PIN_GetLock()的参数使用，它的值也就是lock的值，所以不能为0
// lock会序列化对输出文件的访问。
FILE* out;
PIN_LOCK pinLock;

// 每次创建线程，该routine都会被调用执行。
VOID ThreadStart(THREADID threadid, CONTEXT* ctxt, INT32 flags, VOID* v)
{
    PIN_GetLock(&pinLock, threadid + 1); // 加锁
    fprintf(out, "thread begin %d\n", threadid);
    fflush(out);
    PIN_ReleaseLock(&pinLock);	// 解锁
}
// 每次销毁线程，该routine都会被调用执行
VOID ThreadFini(THREADID threadid, const CONTEXT* ctxt, INT32 code, VOID* v)
{
    PIN_GetLock(&pinLock, threadid + 1);
    fprintf(out, "thread end %d code %d\n", threadid, code);
    fflush(out);
    PIN_ReleaseLock(&pinLock);
}
// 每次调用malloc函数，该routine都会被调用执行
VOID BeforeMalloc(int size, THREADID threadid)
{
    PIN_GetLock(&pinLock, threadid + 1);
    fprintf(out, "thread %d entered malloc(%d)\n", threadid, size);
    fflush(out);
    PIN_ReleaseLock(&pinLock);
}
//====================================================================
// Instrumentation Routines
//====================================================================
// 对每个image都执行
VOID ImageLoad(IMG img, VOID*)
{
    RTN rtn = RTN_FindByName(img, "malloc");
    if (RTN_Valid(rtn))
    {
        RTN_Open(rtn);
        RTN_InsertCall(rtn, IPOINT_BEFORE, AFUNPTR(BeforeMalloc), IARG_FUNCARG_ENTRYPOINT_VALUE, 0, IARG_THREAD_ID, IARG_END);
        RTN_Close(rtn);
    }
}
// 在结束时执行一次
VOID Fini(INT32 code, VOID* v) { fclose(out); }
/* ===================================================================== */
/* Print Help Message                                                    */
/* ===================================================================== */
INT32 Usage()
{
    PIN_ERROR("This Pintool prints a trace of malloc calls in the guest application\n" + KNOB_BASE::StringKnobSummary() + "\n");
    return -1;
}
/* ===================================================================== */
/* Main                                                                  */
/* ===================================================================== */
int main(INT32 argc, CHAR** argv)
{
    // 初始化pin的lock
    PIN_InitLock(&pinLock);
    // 初始化pin
    if (PIN_Init(argc, argv)) return Usage();
    PIN_InitSymbols();
    out = fopen(KnobOutputFile.Value().c_str(), "w");
    // 注册ImageLoad函数
    IMG_AddInstrumentFunction(ImageLoad, 0);
    // 注册线程创建或结束时的分析routine
    PIN_AddThreadStartFunction(ThreadStart, 0);
    PIN_AddThreadFiniFunction(ThreadFini, 0);
    // 注册程序退出时的fini函数
    PIN_AddFiniFunction(Fini, 0);
    // 开始执行，不返回
    PIN_StartProgram();
    return 0;
}
```

### 12. Using TLS(Thread Local Storage)

功能：可以使工具创建线程特定的数据

执行和查看输出：

```shell
$ ../../../pin -t obj-ia32/inscount_tls.so -- obj-ia32/thread_lin
$ head
Count[0]= 237993
Count[1]= 213296
Count[2]= 209223
Count[3]= 209223
Count[4]= 209223
Count[5]= 209223
Count[6]= 209223
Count[7]= 209223
Count[8]= 209223
Count[9]= 209223
```

源码`source/tools/ManualExamples/inscount_tls.cpp`：

```cpp
#include <iostream>
#include <fstream>
#include "pin.H"
using std::cerr;
using std::cout;
using std::endl;
using std::ostream;
using std::string;
KNOB< string > KnobOutputFile(KNOB_MODE_WRITEONCE, "pintool", "o", "", "specify output file name");
INT32 numThreads = 0;
ostream* OutFile = NULL;
// 强制每个线程的数据存储在自己的数据缓存行中，确保多线程不会发生同一数据缓存行的竞争问题。
// 避免错误共享的问题。
#define PADSIZE 56 // 64 byte line size: 64-8
// 运行的指令计数
class thread_data_t
{
  public:
    thread_data_t() : _count(0) {}
    UINT64 _count;
    UINT8 _pad[PADSIZE];
};
// 存储在线程中的访问TLS的key，只在main函数中初始化一次
static TLS_KEY tls_key = INVALID_TLS_KEY;
// 该函数在每个block前调用
VOID PIN_FAST_ANALYSIS_CALL docount(UINT32 c, THREADID threadid)
{
    thread_data_t* tdata = static_cast< thread_data_t* >(PIN_GetThreadData(tls_key, threadid));
    tdata->_count += c;
}
VOID ThreadStart(THREADID threadid, CONTEXT* ctxt, INT32 flags, VOID* v)
{
    numThreads++;
    thread_data_t* tdata = new thread_data_t;
    if (PIN_SetThreadData(tls_key, tdata, threadid) == FALSE)
    {
        cerr << "PIN_SetThreadData failed" << endl;
        PIN_ExitProcess(1);
    }
}
// 遇到新的代码块时调用，插入对docount函数的调用
VOID Trace(TRACE trace, VOID* v)
{
    // 检查trace中的每个基本块
    for (BBL bbl = TRACE_BblHead(trace); BBL_Valid(bbl); bbl = BBL_Next(bbl))
    {
        // 对每个bbl插入对docount的调用，并传递参数：指令的数量
        BBL_InsertCall(bbl, IPOINT_ANYWHERE, (AFUNPTR)docount, IARG_FAST_ANALYSIS_CALL, IARG_UINT32, BBL_NumIns(bbl),
                       IARG_THREAD_ID, IARG_END);
    }
}
// 线程退出时调用
VOID ThreadFini(THREADID threadIndex, const CONTEXT* ctxt, INT32 code, VOID* v)
{
    thread_data_t* tdata = static_cast< thread_data_t* >(PIN_GetThreadData(tls_key, threadIndex));
    *OutFile << "Count[" << decstr(threadIndex) << "] = " << tdata->_count << endl;
    delete tdata;
}
// 程序退出时调用
VOID Fini(INT32 code, VOID* v) { *OutFile << "Total number of threads = " << numThreads << endl; }
/* ===================================================================== */
/* Print Help Message                                                    */
/* ===================================================================== */
INT32 Usage()
{
    cerr << "This tool counts the number of dynamic instructions executed" << endl;
    cerr << endl << KNOB_BASE::StringKnobSummary() << endl;
    return 1;
}
/* ===================================================================== */
/* Main                                                                  */
/* ===================================================================== */
int main(int argc, char* argv[])
{
    PIN_InitSymbols();
    if (PIN_Init(argc, argv)) return Usage();
    OutFile = KnobOutputFile.Value().empty() ? &cout : new std::ofstream(KnobOutputFile.Value().c_str());
    // 设置key
    tls_key = PIN_CreateThreadDataKey(NULL);
    if (tls_key == INVALID_TLS_KEY)
    {
        cerr << "number of already allocated keys reached the MAX_CLIENT_TLS_KEYS limit" << endl;
        PIN_ExitProcess(1);
    }
    // 注册线程创建时调用的ThreadStart函数
    PIN_AddThreadStartFunction(ThreadStart, NULL);
    // 注册线程结束时调用的ThreadFini函数
    PIN_AddThreadFiniFunction(ThreadFini, NULL);
    // 注册程序结束时的Fini函数
    PIN_AddFiniFunction(Fini, NULL);
    // 注册指令插桩时调用的Trace函数
    TRACE_AddInstrumentFunction(Trace, NULL);
    // Start the program, never returns
    PIN_StartProgram();
    return 1;
}
```

### 13. Finding the Static Properties of an Image

功能：不对binary文件进行插桩，静态获取文件的指令数量。

执行和查看输出：

源码`source/tools/ManualExamples/staticcount.cpp`：

```cpp
//
// This tool prints a trace of image load and unload events
//
#include <stdio.h>
#include <iostream>
#include "pin.H"
using std::cerr;
using std::endl;
// 在img加载时调用该函数，计算image中的静态指令数量
VOID ImageLoad(IMG img, VOID* v)
{
    UINT32 count = 0;
    for (SEC sec = IMG_SecHead(img); SEC_Valid(sec); sec = SEC_Next(sec))
    {
        for (RTN rtn = SEC_RtnHead(sec); RTN_Valid(rtn); rtn = RTN_Next(rtn))
        {
          	// 准备处理RTN，RTN并不会分解成bbl，只是INS的一个序列
            RTN_Open(rtn);
            for (INS ins = RTN_InsHead(rtn); INS_Valid(ins); ins = INS_Next(ins))
            {
                count++;
            }
            // 在处理完与RTN相关的数据后就进行释放，以节省空间
            RTN_Close(rtn);
        }
    }
    fprintf(stderr, "Image %s has  %d instructions\n", IMG_Name(img).c_str(), count);
}
/* ===================================================================== */
/* Print Help Message                                                    */
/* ===================================================================== */
INT32 Usage()
{
    cerr << "This tool prints a log of image load and unload events" << endl;
    cerr << " along with static instruction counts for each image." << endl;
    cerr << endl << KNOB_BASE::StringKnobSummary() << endl;
    return -1;
}
/* ===================================================================== */
/* Main                                                                  */
/* ===================================================================== */
int main(int argc, char* argv[])
{
    // 初始化符号
    PIN_InitSymbols();
    // 初始化pin
    if (PIN_Init(argc, argv)) return Usage();
    // 注册img加载后要调用的ImageLoad函数
    IMG_AddInstrumentFunction(ImageLoad, 0);
    // 开始执行，不返回
    PIN_StartProgram();
    return 0;
}
```

### 14. Instrumenting Child Processes

功能：在通过execv类命令获得进程开始前执行自定义的函数。

执行和查看输出：在执行时添加`-follow_execv`选项。

```shell
$ ../../../pin -follow_execv -t obj-intel64/follow_child_tool.so -- obj-intel64/follow_child_app1 obj-intel64/follow_child_app2

$ make follow_child_tool.test
```

![image-20211009163559737](https://cdn.jsdelivr.net/gh/AlexsanderShaw/BlogImages@main/img/vuln/shebei20211009163606.png)

源码`source/tools/ManualExamples/follow_child_tool.cpp`：

```cpp
#include "pin.H"
#include <iostream>
#include <stdio.h>
#include <unistd.h>
/* ===================================================================== */
/* Command line Switches */
/* ===================================================================== */
BOOL FollowChild(CHILD_PROCESS cProcess, VOID* userData)
{
    fprintf(stdout, "before child:%u\n", getpid());
    return TRUE;
}
/* ===================================================================== */
int main(INT32 argc, CHAR** argv)
{
    PIN_Init(argc, argv);
  	// 注册子进程刚创建时要执行的FollowChild函数
    PIN_AddFollowChildProcessFunction(FollowChild, 0);
  	// 开始执行，不返回
    PIN_StartProgram();
    return 0;
}
```

### 15. Instrumenting Before and After Forks

功能：使用`PIN_AddForkFunction()`和`PIN_AddForkFunctionProbed()`回调函数来在以下的FPOINT处执行自定义函数：

```text
FPOINT_BEFORE            Call-back in parent, just before fork.
FPOINT_AFTER_IN_PARENT   Call-back in parent, immediately after fork.
FPOINT_AFTER_IN_CHILD    Call-back in child, immediately after fork.
```

`PIN_AddForkFunction()`工作在JIT模式下，`PIN_AddForkFunctionProbed()`工作在Probe模式下。

执行和查看输出：

```shell
$ make fork_jit_tool.test
```

![image-20211009165327864](https://cdn.jsdelivr.net/gh/AlexsanderShaw/BlogImages@main/img/vuln/shebei20211009165328.png)

源码`source/tools/ManualExamples/fork_jit_tool.cpp`：

```cpp
#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>
#include <stdlib.h>
#include "pin.H"
#include <iostream>
#include <fstream>
using std::cerr;
using std::endl;
INT32 Usage()
{
    cerr << "This pin tool registers callbacks around fork().\n"
            "\n";
    cerr << KNOB_BASE::StringKnobSummary();
    cerr << endl;
    return -1;
}
pid_t parent_pid;
PIN_LOCK pinLock;
VOID BeforeFork(THREADID threadid, const CONTEXT* ctxt, VOID* arg)
{
    PIN_GetLock(&pinLock, threadid + 1);
    cerr << "TOOL: Before fork." << endl;
    PIN_ReleaseLock(&pinLock);
    parent_pid = PIN_GetPid();
}
VOID AfterForkInParent(THREADID threadid, const CONTEXT* ctxt, VOID* arg)
{
    PIN_GetLock(&pinLock, threadid + 1);
    cerr << "TOOL: After fork in parent." << endl;
    PIN_ReleaseLock(&pinLock);
    if (PIN_GetPid() != parent_pid)
    {
        cerr << "PIN_GetPid() fails in parent process" << endl;
        exit(-1);
    }
}
VOID AfterForkInChild(THREADID threadid, const CONTEXT* ctxt, VOID* arg)
{
    PIN_GetLock(&pinLock, threadid + 1);
    cerr << "TOOL: After fork in child." << endl;
    PIN_ReleaseLock(&pinLock);
    if ((PIN_GetPid() == parent_pid) || (getppid() != parent_pid))
    {
        cerr << "PIN_GetPid() fails in child process" << endl;
        exit(-1);
    }
}
int main(INT32 argc, CHAR** argv)
{
    PIN_InitSymbols();
    if (PIN_Init(argc, argv))
    {
        return Usage();
    }
    // Initialize the pin lock
    PIN_InitLock(&pinLock);
    // Register a notification handler that is called when the application
    // forks a new process.
    PIN_AddForkFunction(FPOINT_BEFORE, BeforeFork, 0);
    PIN_AddForkFunction(FPOINT_AFTER_IN_PARENT, AfterForkInParent, 0);
    PIN_AddForkFunction(FPOINT_AFTER_IN_CHILD, AfterForkInChild, 0);
    // Never returns
    PIN_StartProgram();
    return 0;
}
```
