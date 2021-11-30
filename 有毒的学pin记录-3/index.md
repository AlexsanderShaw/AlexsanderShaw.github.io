# 有毒的学Pin记录 -- 3


本文是Pin系列学习记录的第二篇，主要是官方文档的相关内容的整理总结。

<!--more-->

## 4. Callbacks

这部分主要介绍几个Pin的用于注册回调函数的API：

- [INS_AddInstrumentFunction](https://software.intel.com/sites/landingpage/pintool/docs/98437/Pin/html/group__INS__INSTRUMENTATION.html#ga1333734dbf7d552365a24cd945d5691d) (INSCALLBACK fun, VOID *val)：注册以指令粒度插桩的函数
- [TRACE_AddInstrumentFunction](https://software.intel.com/sites/landingpage/pintool/docs/98437/Pin/html/group__TRACE.html#gab2f19ff0a9198c83715eea79ada22503) (TRACECALLBACK fun, VOID *val)：注册以trace粒度插桩的函数
- [RTN_AddInstrumentFunction](https://software.intel.com/sites/landingpage/pintool/docs/98437/Pin/html/group__RTN.html#ga63bd82d1e10ee8c83d67529845f5ca46) (RTNCALLBACK fun, VOID *val)：注册以routine粒度插桩的函数
- [IMG_AddInstrumentFunction](https://software.intel.com/sites/landingpage/pintool/docs/98437/Pin/html/group__IMG.html#ga4a067152140ead3e23279ab2bd6cd723) (IMGCALLBACK fun, VOID *val)：注册以image粒度插桩的函数
- [PIN_AddFiniFunction](https://software.intel.com/sites/landingpage/pintool/docs/98437/Pin/html/group__PIN__CONTROL.html#gaa78c7b560975a6feffa420fadedc0627) (FINICALLBACK fun, VOID *val)：注册在应用程序退出前执行的函数，该类函数不进行插桩，可以有多个。
- [PIN_AddDetachFunction](https://software.intel.com/sites/landingpage/pintool/docs/98437/Pin/html/group__PIN__CONTROL.html#ga7501b4226bc92f358b7b361eea0929d2) (DETACHCALLBACK fun, VOID *val)：注册在Pin通过`PIN_Detach()`函数放弃对应用程序的控制权限之前执行的函数，一个进程只调用一次，可以被任何线程调用，此时Pin的内存并没有释放。

对于每个注册函数的第二个参数`val`将在“回调”时传递给回调函数。如果在实际的场景中不需要传递第二个参数，为了保证安全，可以传递将`val`的值设置为0进行传递。`val`的理想使用方式是传递一个指向类实例的指针，这样回调函数在取消引用该指针前需要将其转换回一个对象。

所有的注册函数都会返回一个`PIN_CALLBACK`对象，该对象可以在后续过程中用于操作注册的回调的相关属性。

### PIN callbacks manipulation API

在注册函数返回`PIN_CALLBACK`对象后，可以使用`PIN_CALLBACK`API对其进行操作，来检索和修改在Pin中已注册的回调函数的属性。

声明：

```cpp
typedef COMPLEX_CALLBACKVAL_BASE * 	PIN_CALLBACK
```

函数：

1. CALLBACK_GetExecutionOrder()

   声明：

   ```cpp
   VOID 	CALLBACK_GetExecutionOrder (PIN_CALLBACK callback)
   ```

   作用：获取已注册回调函数的执行顺序。越靠前，越早被执行。

   参数：`callback`，从\*_Add\*Funcxtion()函数返回的注册的回调函数

2. CALLBACK_SetExecutionOrder()

   声明：

   ```cpp
   VOID 	CALLBACK_SetExecutionOrder (PIN_CALLBACK callback, CALL_ORDER order)
   ```

   作用：设置已注册回调函数的执行顺序。越靠前，越早被执行。

   参数：`callback`，从\*_Add\*Funcxtion()函数返回的注册的回调函数；`order`，新设置的回调函数的执行顺序。

3. PIN_CALLBACK_INVALID()

   声明：

   ```cpp
   const PIN_CALLBACK PIN_CALLBACK_INVALID(0)
   ```

   PIN回调的无效值。

### CALL_ORDER

`CALL_ORDER`是一个枚举类型，预定义了`IARG_CALL_ORDER`的值。其作用就是当指令有多个分析函数调用时，控制每个分析函数的调用顺序，默认值为`CALL_ORDER_DEFAULT`。

- CALL_ORDER_FIRST：首先执行该调用，整数值为100.
- CALL_ORDER_DEFAULT：未指定`IARG_CALL_ORDER`时的默认值，整数值为200.
- CALL_ORDER_LAST：最后执行该调用，整数值为300.

在进行数值设定时，可以使用类似`CALL_ORDER_DEFAULT + 5`的格式来设置。

针对在相同插桩回调环境中的针对同一指令的、具备同样`CALL_ORDER`的多个分析调用，Pin会按照插入的顺序进行调用。

## 5. Mopdifying Application Instructions

虽然Pin的主要用途是对二进制程序进行插桩，但是它也可以实现对程序指令的修改。

### 5.1 实现方式

最简单的实现方式是插入一个分析routine来模拟指令执行，然后调用`INS_Delete()`来删除指令。也可以通过直接或间接插入程序执行流分支（使用`INS_InsertDirectJump`和`INS_InsertIndirectJump`）实现，这种方式会改变程序的执行流，但是会更容易实现指令模拟。

1. **INS_InsertDirectJump()**

   声明：

   ```cpp
   VOID INS_InsertDirectJump(INS ins, IPOINT ipoint, ADDRINT tgt)
   ```

   参数：

   - ins：输入的指令
   - ipoint：与ins相关的location（仅支持IPOINT_BEFORE和IPOINT_AFTER）
   - tgt：target的绝对地址

   作用：插入相对于给定指令的直接跳转指令，与`INS_Delete()`配合使用可以模拟控制流转移指令。

2. **INS_InsertIndirectJump()**

   声明：

   ```cpp
   VOID INS_InsertIndirectJump	(	INS 	ins, IPOINT 	ipoint, REG 	reg)	
   ```

   参数：

   - ins：输入的指令
   - ipoint：与ins相关的location（仅支持IPOINT_BEFORE和IPOINT_AFTER
   - reg：target的寄存器

   作用：插入相对于给定指令的间接跳转指令，与`INS_Delete()`配合使用可以模拟控制流转移指令。

### 5.2 指令内存修改

对于原始指令使用到的内存的访问，可以通过使用`INS_RewriteMemoryOperand`来引用通过分析routine计算得到的值来替代。

需要注意的是，对于指令的修改操作，会在所有的指令插桩操作完成后进行，因此在进行指令插桩时，插桩routine看到的都是原始的、没有经过修改的程序指令。

**INS_RewriteMemoryOperand()**

声明：

```cpp
VOID INS_RewriteMemoryOperand(INS ins, UINt32 memindex, REG newBase)
```

参数：

- ins：输入指令
- memindex：控制需要重写的内存操作数（0，1，...）
- newBase：包含新操作数地址的寄存器，通常是通过`PIN_ClainToolRegister`分配的临时寄存器

作用：更改此内存访问指令以饮用包含在给定特定寄存器中的虚拟内存地址。

在IA-32和Intel 64平台上，修改后的操作数仅使用具有新基址寄存器newBase的基址寄存器进行寻址。原始指令中该操作数的任何index， scale或者offset filed都会被删除。

该函数可以用于重写内存操作数，包括隐式的（如call、ret、push、pop），唯一不能重写的指令是第二个操作数大于0的`enter`。

newBase中的地址是中是该操作数将访问的最低地址，如果操作数在内存访问之前被指令修改，如push，则newBase中的值将不是堆栈指针，而是指令访问的内存地址。

用于内存地址重写的一个样例插桩代码如下：

```cpp
// 映射originalEa到一个翻译后的地址
static ADDRINT ProcessAddress(ADDRINT originalEa, ADDRINT size, UINT32 access);
...
   for (UINT32 op = 0; op<INS_MemoryOperandCount(ins); op++) // 首先遍历内存操作指令进行计数
   {
       UINT32 access = (INS_MemoryOperandIsRead(ins,op)    ? 1 : 0) |  // 判断是内存读还是内存写
                       (INS_MemoryOperandIsWritten(ins,op) ? 2 : 0);
       INS_InsertCall(ins, IPOINT_BEFORE,
                      AFUNPTR(ProcessAddress),
                      IARG_MEMORYOP_EA,   op,
                      IARG_MEMORYOP_SIZE, op,
                      IARG_UINT32,        access,
                      IARG_RETURN_REGS,   REG_INST_G0+i,
                      IARG_END);  // 在指令处进行插桩
       INS_RewriteMemoryOperand(ins, i, REG(REG_INST_G0+i));  // 重写内存指令的操作数
   }
```

## 6. Applying  a Pintool to an Application

命令行：

```shell
pin [pin-option]... -t [toolname] [tool-options]... -- [application] [application-option]..
```

### 6.1 Pin Cmdline Options

如下是Pin的命令行的完整option列表：

| Option                        | Description                                                  |
| ----------------------------- | ------------------------------------------------------------ |
| -follow_execv                 | 使用Pin执行由execv类系统调用产生的所有进程                   |
| -help                         | 帮助信息                                                     |
| -pause_tool <n>               | 暂停并打印PID以可以在tool加载后attach到debugger，处理过程在‘n’秒后重启 |
| -logfile                      | 指定log文件的名字和路径，默认路径为当前工作目录，默认文件名为pin.log |
| -unique_logfile               | 添加pid到log文件名中                                         |
| -error_file                   | 指定error文件的名字和路径，默认路径为当前工作目录。如果设置了error文件，则所有error都会写入到文件中，并且不会在console中显示。如果没有指定，则不创建文件。 |
| -unique_error_file            | 添加pid到error文件名中                                       |
| -injection <mode>             | <mode>的选项为dynamic， self， child， parent，只能在UNIX中使用，详看[Injection](https://software.intel.com/sites/landingpage/pintool/docs/98437/Pin/html/index.html#INJECTION)，默认使用dynamic。 |
| -inline                       | 内联简单的分析routine                                        |
| -log_inline                   | 在pin.log文件中记录哪些分析routine被设置成了内联             |
| -cc_memory_size          <n>  | 最大代码缓存，字节为单位。0为默认值，表示不做限制。必须设置为代码缓存块大小的对齐倍数。 |
| -pid <pid #>                  | 使用Pin和Pintool attach一个正在运行的进程                    |
| -pin_memory_range             | 限制Pin到一个内存范围内，0x80000000:0x90000000 or size: 0:0x10000000. |
| -restric_memory               | 阻止Pin的动态加载器使用该地址范围：0x10000000:0x20000000     |
| -pin_memory_size              | 限制Pin和Pintool可以动态分配的字节数。Pin分配的字节数定义为Pin分配的内存页数乘以页大小。 |
| -tool_load_option             | 加载有附加标志的tool。                                       |
| -t <toolname>                 | 指定加载的Pintool。                                          |
| -t64 <64-bit toolname>        | 指定针对Intel 64架构的64-bit的Pintool。                      |
| -p32 <toolname>               | 指定IA-32架构下的Pintool                                     |
| -p64 <toolname>               | 指定针对Intel 64架构的Pintool                                |
| -smc-support                  | 是否开启app的SMC功能，1开启，0关闭。默认开启                 |
| -smc_strict                   | 是否开启基本块内部的SMC，1开始，0关闭。默认关闭              |
| -appdebug                     | 调试目标程序，程序运行后立即在debugger中断下                 |
| -appdebug_enable              | 开启目标程序调试功能，但是在程序运行后不暂停                 |
| -appdebug_silent              | 当程序调试功能开启时，Pin打印消息告知如何连接外部debugger。但是在-appdebug_connection选项开启时不打印。 |
| -appdebug_exclude             | 当程序调试功能开启，并指定了-follw_execv时，默认在所有子进程上启用调试。 |
| -appdebug_allow_remote        | 允许debugger与Pin不运行在同一系统上，而是以远程方式进行连接。指定 -appdebug_connection 时会忽略该选项的值，因为 -appdebug_connection 明确指定了运行debugger的machine。 |
| -appdebug_connection          | 当程序开启调试时，Pin默认会开启一个TCP端口等待debugger的连接。在开启该选项时，会在debugger中开启一个TCP端口来等待Pin的连接，相当于反置了默认的机制。该选项的格式为"[ip]:port"，“ip”以点十进制格式表达，如果省略了ip，则会连接本地的端口，端口号为十进制表示。需要注意的是，debugger为GDB时，不使用该选项。 |
| -detach_reattach              | 允许在probe模式下进行detach和reattach，仅在Windows平台下使用。 |
| -debug_instrumented_processes | 允许debugger对经过插桩的进程进行attach，仅在Windows平台下使用。 |
| -show_asserts                 | 健全性检查                                                   |

此外，还支持如下的tool options，它们需要跟在tool名字后面，但是要在`--`符号前：

| Option                           | Description                                                  |
| -------------------------------- | ------------------------------------------------------------ |
| -logifle                         | 指定log文件的名字和路径，默认路径为当前工作目录，默认文件名为pintool.log |
| -unique_logfile                  | 添加pid到log文件名中                                         |
| -discard_line_info <module_name> | 忽略特定模块的信息，模块名应该为没有路径的短文件名，不能是符号链接 |
| -discard_line_info_all           | 忽略所有模块的信息                                           |
| -help                            | 帮助信息                                                     |
| -support_jit_api                 | 启用托管平台支持                                             |
| -short_name                      | 使用最短的RTN名称。                                          |
| -symbol_path  <list of paths>    | 指定用分号分隔的路径列表，用于搜索以查找符号和行信息。仅在Windows平台下使用。 |
| -slow_asserts                    | 健全性检查                                                   |

### 6.2 Instrumenting Applications on Intel(R) 64 Architectures

IA-32和Intel(R) 64架构的Pin kit是一个组合kit，均包含32-bit和64-bit的版本。这就为复杂的环境提供了极高的可运行性，例如一个稍微有点复杂的运行如下：

```shell
pin [pin-option]... -t64 <64-bit toolname> -t <32-bit toolname> [tool-options]...
-- <application> [application-option]..
```

需要注意的是：

- -t64选项需要用在-t选项的前面
- 当-t64和-t一起使用时，-t后面跟的时32-bit的tool。不推荐使用不带-t的-t64，因为在这种情况下，当给定32-bit应用程序时，Pin将在不应用任何工具的情况下运行该应用程序。
- [tool-option]会同时作用于64-bit和32-bit的tool，并且必须在-t <32-bit toolname>后面进行指定。

### 6.3 Injection

选项-injection仅在UNIX平台下可以使用，该选项控制着Pin注入到目标程序进程的方式。

默认情况下，建议使用dynamic模式。在该模式下，使用的是对父进程注入的方式，除非是系统内核不支持。子进程注入方式会创建一个pin的子进程，所以会看到pin进程和目标程序进程同时运行。使用父进程注入方式时，pin进程会在注入完成后退出，所以相对来说比较稳定。在不支持的平台上使用父进程注入方式可能出现意料之外的问题。

## 7. Writing a Pintool

### 7.1 Logging Messages from a Pintool

Pin提供了将Pintool的messages写入到文件的机制——`LOG()` api，在合适的获取message的位置使用即可。默认的文件名为pintool.log，存储路径为当前工作目录，可以使用-logfile选项来改变log文件的路径和名字。

```shell
LOG( "Replacing function in " + IMG_Name(img) + "\n" );
LOG( "Address = " + hexstr( RTN_Address(rtn)) + "\n" );
LOG( "Image ID = " + decstr( IMG_Id(img) ) + "\n" );
```

### 7.2 Performance Considerations When Writing a Pintool

Pintool的开发质量会很大程度上决定tool的性能如何，例如在进行插桩时的速度问题。将通过一个例子来介绍一些提高tool性能的技巧。

首先是插桩部分代码：

```cpp
VOID Instruction(INS ins, void *v)
{
      ...
      if ( [ins is a branch or a call instruction] )
      {
        INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR) docount2,
                       IARG_INST_PTR,
                       IARG_BRANCH_TARGET_ADDR,
                       IARG_BRANCH_TAKEN,
                       IARG_END);
      }
      ...
}
```

然后是分析代码：

```cpp
VOID docount2( ADDRINT src, ADDRINT dst, INT32 taken )
{
    if(!taken) return;
    COUNTER *pedg = Lookup( src,dst );
    pedg->_count++;
}
```

该工具的目的是计算控制流图中每个控制流变化的边界被遍历的频率。工作原理如下：插桩组件通过调用docount2对每个分支进行插桩。传入的参数为源分支和目标分支以及分支是否被执行。源分支和目标分支代表来控制流边界的源和目的。如果没有执行分支，控制流不会发生改变，因此分析routine会立即返回。如果执行了分支，就使用src和dst参数来查找与此边界相关的计数器，并增加计数器的值。

**Shifting Computation for Analysis to Instrumentation Code**

在一个典型的应用程序中，大概每5条指令构成一个分支，在这些指令执行时会调用`Lookup`函数，造成性能下降。我们思考这个过程可以发现，在指令执行时，每条指令只会调用一次插桩代码，但会多次调用分析代码。所以，可以想办法将计算工作从分析代码转移到插桩代码，这样就可以降低调用次数，从而提升性能。

首先，就大多数分支而言，我们可以在`Instruction()`中找到目标分支。对于这些分支，我们可以在`Instruction()`内部调用`Lookup()`而不是`docount2()`，对于相对较少的间接分支，我们仍然需要使用原来的方法。

因此，我们增加一个新的函数`docount`，原来的`docount2`函数保持不变：

```cpp
VOID docount( COUNTER *pedg, INT32 taken )
{
    if( !taken ) return;
    pedg->_count++;
}
```

相应地，修改插桩函数：

```cpp
VOID Instruction(INS ins, void *v)
{
      ...
    if (INS_IsDirectControlFlow(ins))
    {
        COUNTER *pedg = Lookup( INS_Address(ins),  INS_DirectControlFlowTargetAddress(ins) );
        INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR) docount,
                       IARG_ADDRINT, pedg,
                       IARG_BRANCH_TAKEN,
                       IARG_END);
    }
    else
    {
        INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR) docount2,
                       IARG_INST_PTR,
                       IARG_BRANCH_TARGET_ADDR,
                       IARG_BRANCH_TAKEN,
                       IARG_END);
    }
      ...
}
```

 在插桩函数内部根据不同的情况，执行不同的分析代码，避免对所有类型的指令都笼统地调用性能要求高`docount2	`函数。

最终实现的完整代码如下：

```cpp
/*! @file
 *  This file contains an ISA-portable PIN tool for tracing instructions
 */
#include <iostream>
#include <fstream>
#include <map>
#include <unistd.h>
#include "pin.H"
using std::cerr;
using std::endl;
using std::map;
using std::pair;
using std::string;

/* ===================================================================== */
/* Commandline Switches */
/* ===================================================================== */

KNOB< string > KnobOutputFile(KNOB_MODE_WRITEONCE, "pintool", "o", "edgcnt.out", "specify trace file name");
KNOB< INT32 > KnobFilterByHighNibble(KNOB_MODE_WRITEONCE, "pintool", "f", "-1",
                                     "only instrument instructions with a code address matching the filter");
KNOB< BOOL > KnobPid(KNOB_MODE_WRITEONCE, "pintool", "i", "0", "append pid to output");

/* ===================================================================== */
/* Print Help Message                                                    */
/* ===================================================================== */

static INT32 Usage()
{
    cerr << "This pin tool collects an edge profile for an application\n";
    cerr << "The edge profile is partial as it only considers control flow changes (taken\n";
    cerr << "branch edges, etc.). It is the left to the profile consumer to compute the missing counts.\n";
    cerr << "\n";

    cerr << "The pin tool *does* keep track of edges from indirect jumps within, out of, and into\n";
    cerr << "the application. Traps to the OS a recorded with a target of -1.\n";

    cerr << KNOB_BASE::StringKnobSummary() << endl;
    return -1;
}

/* ===================================================================== */
/* Global Variables */
/* ===================================================================== */

class COUNTER
{
  public:
    UINT64 _count; // 边界到达的次数，计数器

    COUNTER() : _count(0) {}
};

typedef enum
{
    ETYPE_INVALID,
    ETYPE_CALL,
    ETYPE_ICALL,
    ETYPE_BRANCH,
    ETYPE_IBRANCH,
    ETYPE_RETURN,
    ETYPE_SYSCALL,
    ETYPE_LAST
} ETYPE;

class EDGE
{
  public:
    ADDRINT _src;
    ADDRINT _dst;
    ADDRINT _next_ins;
    ETYPE _type; // 必须为整数形式

    EDGE(ADDRINT s, ADDRINT d, ADDRINT n, ETYPE t) : _src(s), _dst(d), _next_ins(n), _type(t) {}

    bool operator<(const EDGE& edge) const { return _src < edge._src || (_src == edge._src && _dst < edge._dst); }
};

string StringFromEtype(ETYPE etype)
{
    switch (etype)
    {
        case ETYPE_CALL:
            return "C";
        case ETYPE_ICALL:
            return "c";
        case ETYPE_BRANCH:
            return "B";
        case ETYPE_IBRANCH:
            return "b";
        case ETYPE_RETURN:
            return "r";
        case ETYPE_SYSCALL:
            return "s";
        default:
            ASSERTX(0);
            return "INVALID";
    }
}

typedef map< EDGE, COUNTER* > EDG_HASH_SET;

static EDG_HASH_SET EdgeSet;

/* ===================================================================== */

/*!
  对于已经进行过插桩的Edge，重用entry；否则创建一个新的。
 */

static COUNTER* Lookup(EDGE edge) // 查找边界
{
    COUNTER*& ref = EdgeSet[edge];

    if (ref == 0)
    {
        ref = new COUNTER();
    }

    return ref;
}

/* ===================================================================== */
// 分析routine代码

VOID docount(COUNTER* pedg) { pedg->_count++; }

/* ===================================================================== */
// 对于间接控制流，我们不知道边界，所以需要进行查找。

VOID docount2(ADDRINT src, ADDRINT dst, ADDRINT n, ETYPE type, INT32 taken)
{
    if (!taken) return;
    COUNTER* pedg = Lookup(EDGE(src, dst, n, type));
    pedg->_count++;
}

/* ===================================================================== */

VOID Instruction(INS ins, void* v) // 插桩函数
{
    if (INS_IsDirectControlFlow(ins)) // 如果是直接控制流（ins为控制流指令，目标地址由指令指针或立即数指定）
    {
        ETYPE type = INS_IsCall(ins) ? ETYPE_CALL : ETYPE_BRANCH; // 判断是否为call指令，是则返回ETYPE_CALL

        // 静态目标可以在这里进行一次映射
      	// 参数分别为当前指令地址、当前指令目标地址、下一指令地址、指令类型
        COUNTER* pedg = Lookup(EDGE(INS_Address(ins), INS_DirectControlFlowTargetAddress(ins), INS_NextAddress(ins), type)); 
      	// 插桩
        INS_InsertCall(ins, IPOINT_TAKEN_BRANCH, (AFUNPTR)docount, IARG_ADDRINT, pedg, IARG_END);
    }
    else if (INS_IsIndirectControlFlow(ins)) // 如果是间接控制流（ins为控制流指令，且目标地址通过内存或寄存器提供）
    {
        ETYPE type = ETYPE_IBRANCH; // 直接指定类型为间接控制流

        if (INS_IsRet(ins)) // 是否为ret或iret
        {
            type = ETYPE_RETURN;
        }
        else if (INS_IsCall(ins))
        {
            type = ETYPE_ICALL;
        }
				// 进行插桩
        INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)docount2, IARG_INST_PTR, IARG_BRANCH_TARGET_ADDR, IARG_ADDRINT, INS_NextAddress(ins), IARG_UINT32, type, IARG_BRANCH_TAKEN, IARG_END);
    }
    else if (INS_IsSyscall(ins))  //  如果是syscall指令
    {
        COUNTER* pedg = Lookup(EDGE(INS_Address(ins), ADDRINT(~0), INS_NextAddress(ins), ETYPE_SYSCALL));
        INS_InsertPredicatedCall(ins, IPOINT_BEFORE, (AFUNPTR)docount, IARG_ADDRINT, pedg, IARG_END);
    }
}

/* ===================================================================== */

inline INT32 AddressHighNibble(ADDRINT addr) { return 0xf & (addr >> (sizeof(ADDRINT) * 8 - 4)); }

/* ===================================================================== */
static std::ofstream* out = 0;

VOID Fini(int n, void* v) // 程序结束时的处理函数
{
    const INT32 nibble = KnobFilterByHighNibble.Value();

    *out << "EDGCOUNT        4.0         0\n"; // profile header, no md5sum
    UINT32 count = 0;

    for (EDG_HASH_SET::const_iterator it = EdgeSet.begin(); it != EdgeSet.end(); it++)
    {
        const pair< EDGE, COUNTER* > tuple = *it;
        // skip inter shared lib edges

        if (nibble >= 0 && nibble != AddressHighNibble(tuple.first._dst) && nibble != AddressHighNibble(tuple.first._src))
        {
            continue;
        }

        if (tuple.second->_count == 0) continue;

        count++;
    }

    *out << "EDGs " << count << endl;
    *out << "# src          dst        type    count     next-ins\n";
    *out << "DATA:START" << endl;

    for (EDG_HASH_SET::const_iterator it = EdgeSet.begin(); it != EdgeSet.end(); it++)
    {
        const pair< EDGE, COUNTER* > tuple = *it;

        // skip inter shared lib edges

        if (nibble >= 0 && nibble != AddressHighNibble(tuple.first._dst) && nibble != AddressHighNibble(tuple.first._src))
        {
            continue;
        }

        if (tuple.second->_count == 0) continue;

        *out << StringFromAddrint(tuple.first._src) << " " << StringFromAddrint(tuple.first._dst) << " "
             << StringFromEtype(tuple.first._type) << " " << decstr(tuple.second->_count, 12) << " "
             << StringFromAddrint(tuple.first._next_ins) << endl;
    }

    *out << "DATA:END" << endl;
    *out << "## eof\n";
    out->close();
}

/* ===================================================================== */
/* Main                                                                  */
/* ===================================================================== */

int main(int argc, char* argv[])
{
    if (PIN_Init(argc, argv)) // 初始化
    {
        return Usage();
    }

    string filename = KnobOutputFile.Value(); // 输出文件
    if (KnobPid)
    {
        filename += "." + decstr(getpid());
    }
    out = new std::ofstream(filename.c_str());

    INS_AddInstrumentFunction(Instruction, 0); // 注册插桩函数
    PIN_AddFiniFunction(Fini, 0); // 注册Fini函数

    // 开始执行，不返回

    PIN_StartProgram();

    return 0;
}

/* ===================================================================== */
/* eof */
/* ===================================================================== */

```

### 7.3 Eliminating Control Flow

上面新增的`docunt()`函数的代码十分简洁，极大地提升了性能。除此之外，还可以被Pin内联，进一步避免函数调用的开销。

但是现在的`docount()`函数中存在控制流，这有可能在进行内联时发生未知的改变。最好的解决办法是去掉函数中的控制流，这样进行内联时可以保证健壮性。

考虑到`docount()`函数的'taken'参数要么为0，要么为1，所以可以将函数代码修改为如下：

```cpp
VOID docount( COUNTER *pedg, INT32 taken )
{
    pedg->_count += taken;
}
```

如此修改后，`docunt()`函数就可以进行内联了，并且可以保证函数的健壮性。

### 7.4 Letting Pin Decide Where to Instrument

在某些情况下，我们不关心具体在什么位置进行插桩，只要保证插桩代码位于基本块内部即可。在这种情况下，我们可以将插桩位置的选择权交给Pin自身，Pin可以选择需要最少寄存器进行保存和恢复的插入点，提升性能。

一个样例如下：

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

// 记录运行的指令的数量，设置为静态变量方便编译器优化docount函数
static UINT64 icount = 0;

// 在每个块之前调用该函数
// 对calls使用fast linkage
VOID PIN_FAST_ANALYSIS_CALL docount(ADDRINT c) { icount += c; }

// Pin在遇到一个新块时调用，插入对docount 函数的调用
VOID Trace(TRACE trace, VOID* v)
{
    // 检查trace中的每个基本块
    for (BBL bbl = TRACE_BblHead(trace); BBL_Valid(bbl); bbl = BBL_Next(bbl))
    {

      	// 对每个bbl插入对docount函数的调用，将指令数量作为参数传递
      	// IPOINT_ANYWHERE参数允许Pin在bbl内部任意位置插入call以获取最好的性能
      	// 对call使用fast linkage
        BBL_InsertCall(bbl, IPOINT_ANYWHERE, AFUNPTR(docount), IARG_FAST_ANALYSIS_CALL, IARG_UINT32, BBL_NumIns(bbl), IARG_END);
    }
}

KNOB< string > KnobOutputFile(KNOB_MODE_WRITEONCE, "pintool", "o", "inscount.out", "specify output file name");

// 程序退出时调用
VOID Fini(INT32 code, VOID* v)
{
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
    // 初始化Pin
    if (PIN_Init(argc, argv)) return Usage();

    OutFile.open(KnobOutputFile.Value().c_str());

    // 注册插桩函数Trace
    TRACE_AddInstrumentFunction(Trace, 0);

    // 注册Fini函数
    PIN_AddFiniFunction(Fini, 0);

    // 开始执行，不返回
    PIN_StartProgram();

    return 0;
}


```

这里`IPOINT`是一个枚举类型，决定了分析call被插入到什么地方。插入的对象可以是：INS，BBL，TRACE，RTN，其完整可用的值如下：

- IPOINT_BEFORE：在插桩对象的第一条指令之前插入call，总是有效
- IPOINT_AFTER：在插桩对象的最后一条指令的失败路径处插入call
  - 如果是routine（RTN），在所有返回路径处插桩
  - 如果是instruction（INS），仅在`INS_IsValidForIpointAfter()`函数为真的情况下适用
  - 如果是BBL，仅在`BBL_HasFallThrough()`函数为真的情况下适用
  - 如果是TRACE，仅在`TRACE_HasFallThrough()`函数为真的情况下适用
- IPOINT_ANYWHERE：在插桩对象的任意位置插入call，不适用`INS_InsertCall()`和`INS_InsertThenCall()`函数
- IPOINT_TAKEN_BRANCH：在插桩对象的控制流的执行边界处插入call，仅适用于`INS_IsValidForIpointTakenBranch()`返回真的情况。

### 7.5 Using Fast Call Linkages

对于一些比较“小”的函数来说，对函数的调用开销有时与函数自身的运算开销基本相同，因此一些编译器会提供一些调用链接优化机制来降低开销。例如，IA-32下的gcc有一个在寄存器中传递参数的regparm属性。

Pin中有一定数量的备用链接，使用`PIN_FAST_ANALYSIS_CALL`来声明分析函数即可使用，而插桩函数`InsertCall`则需要使用`IARG_FAST_ANALYSIS_CALL`。如果二者只更改了一个，那么就可能出现传参错误。例如前面给出的源码例子就使用了fast call linkages：

```cpp
... ...
// 对分析函数使用fast linkage
VOID PIN_FAST_ANALYSIS_CALL docount(ADDRINT c) { icount += c; }

VOID Trace(TRACE trace, VOID* v)
{
    // 检查trace中的每个基本块
    for (BBL bbl = TRACE_BblHead(trace); BBL_Valid(bbl); bbl = BBL_Next(bbl))
    {

      	// 对插桩函数使用fast linkage
        BBL_InsertCall(bbl, IPOINT_ANYWHERE, AFUNPTR(docount), IARG_FAST_ANALYSIS_CALL, IARG_UINT32, BBL_NumIns(bbl), IARG_END);
    }
}
... ...
```

在对比较复杂的大型函数使用该方法时，效果并不明显，但不会造成性能的下降。

第二个调用链接优化是消除帧指针。如果使用gcc，则推荐加上"-fomit-frame-pointer"选项。Pin官方的标准Pintool的makefile包括该选项。与`PIN_FAST_ANALYSIS_CALL`一样，该选项对“小”函数的效果比较明显。需要注意的是，debugger会根据帧指针来显示堆栈回溯情况，所以如果想调试Pintool的话，就不要设置该选项。如果使用标准的Pintool的makefile来进行变异，则可以通过修改`OPT`选项来进行改变：

```shell
make OPT=-O0
```

### 7.6 Rewriting Conditional Analysis Code to Help Pin Inline 

Pin通过自动内联没有控制流变化的分析routine来提升插桩性能。但是有很多分析routine是有控制流的，最典型的就是有一个简单的“if-then”的条件语句，它只会执行少量的分析代码，并“then”部分只执行一次。为了将这类的语句转换为常规的没有控制流变化的语句，Pin提供了一些插桩API来重写分析routine。下面是一个重写的例子：

例如我们当前想要实现的一个分析routine的代码如下：

```cpp
// IP-sampling分析routine实现:

VOID IpSample(VOID *ip)
{
  	--icount;
  	if (icount == 0)
  	{
    		fprintf(trace, "%p\n", ip);
    		icount = N + rand() % M;
  	}
}
```

在原始的`IpSample()`函数中有一个明显的条件语句，会存在控制流的变化。如何消除该条件控制流的存在呢？

可以看到分析routine内部其实可以拆解为2部分功能：`icount`的自减和“if”语句，那么可以使用两个单独的函数实现。而且，前者比后者的执行频率要更高。拆解后的代码如下：

```cpp
/*
 *  IP-sampling分析routine实现:
 *
 *        VOID IpSample(VOID *ip)
 *        {
 *            --icount;
 *            if (icount == 0)
 *            {
 *               fprintf(trace, "%p\n", ip);
 *               icount = N + rand() % M;
 *            }
 *        }
 */
// 计算icount
ADDRINT CountDown()
{
    --icount;
    return (icount == 0);
}
// 打印当前指令的IP并且icount被重置为N和N+M中的一个随机数
VOID PrintIp(VOID* ip)
{
    fprintf(trace, "%p\n", ip);
    // 准备下次计算
    icount = N + rand() % M;
}
```

一个完整的实现消除控制流变化的代码如下：

```cpp
/* source/tools/ManualExamples/isampling.cpp */
#include <stdio.h>
#include <stdlib.h>
#include "pin.H"
FILE* trace;
const INT32 N = 100000;
const INT32 M = 50000;
INT32 icount = N;
/*
 *  IP-sampling分析routine实现:
 *
 *        VOID IpSample(VOID *ip)
 *        {
 *            --icount;
 *            if (icount == 0)
 *            {
 *               fprintf(trace, "%p\n", ip);
 *               icount = N + rand() % M;
 *            }
 *        }
 */
// 计算icount
ADDRINT CountDown()
{
    --icount;
    return (icount == 0);
}
// 打印当前指令的IP并且icount被重置为N和N+M中的一个随机数
VOID PrintIp(VOID* ip)
{
    fprintf(trace, "%p\n", ip);
    // 准备下次计算
    icount = N + rand() % M;
}

VOID Instruction(INS ins, VOID* v)
{
    // 每条指令执行后都会调用CountDown()
    INS_InsertIfCall(ins, IPOINT_BEFORE, (AFUNPTR)CountDown, IARG_END);
    // 只有当CountDown返回非0值时才会调用PrintIp() 
    INS_InsertThenCall(ins, IPOINT_BEFORE, (AFUNPTR)PrintIp, IARG_INST_PTR, IARG_END);
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
    PIN_ERROR("This Pintool samples the IPs of instruction executed\n" + KNOB_BASE::StringKnobSummary() + "\n");
    return -1;
}
/* ===================================================================== */
/* Main                                                                  */
/* ===================================================================== */
int main(int argc, char* argv[])
{
    trace = fopen("isampling.out", "w");
    if (PIN_Init(argc, argv)) return Usage();
    INS_AddInstrumentFunction(Instruction, 0);
    PIN_StartProgram();
    return 0;
}

```

使用条件插桩API `INS_InsertIfCall()`和`INS_InsertThenCall()`来告诉Pin只有当`CountDown()`执行结果非0时，才执行`PrintIp()`。这样一来，`CountDown()`函数就可以内联在Pin中，对于没有内联的`PrintIp()`则只有在满足条件时才会执行一次。

`INS_InsertThenCall()`插进去的函数只有在`INS_InsertIfCall()`插进去的函数返回非0值时才会执行。这个功能可以说是一个十分巧妙的功能。

## 8. Building Your Own Tool

在开发自己的Pintool时，可以copy一份example目录， 然后在`makefile.rules`文件中添加上自己的tool，可以以最简单的`MyPinTool`为模版。

### 8.1 Building a Tool From Within the Kit Directory Tree

如果直接修改`MyPinTool`，并且没有特殊的编译需求，则直接使用默认配置就好。如果要新增tool或者需要指定特殊的构建标志，则需要修改`makeifile.rules`文件。

构建YourTool.so(源文件为YourTool.cpp)：

```shell
make obj-intel64/YourTool.so
```

如果想编译成IA-32架构，则使用“obj-ia32”替换“obj-intel64”即可。

### 8.2 Building a Tool Out of the Kit Directory Tree

copy文件夹`MyPinTool`到指定位置子，然后编辑`makefile.rules`文件。

```shell
make PIN_ROOT=<path to Pin kit> obj-intel64/YourTool.so
```

要更改将创建工具的目录，可以从命令行覆盖 OBJDIR 变量：

```shell
make PIN_ROOT=<path to Pin kit> OBJDIR=<path to output dir> <path to output dir>/YourTool.so
```

## 9. Pin's makefile Infrastructure

### 9.1 The Config Directory

目录`source/tools/Config`中存放了make配置的基本文件，不要轻易修改这些文件，可以基于其中的模版文件进行更新。

![image-20211012171957115](https://cdn.jsdelivr.net/gh/AlexsanderShaw/BlogImages@main/img/vuln/shebei20211012171957.png)

下面对其中的几个关键文件进行说明：

- makefile.config：在include链中第一个应该include的文件。它保存了用户可用的所有相关标识和变量的文档，此外还包括特定于OS的配置文件。
- unix.vars：该文件包含makefile使用的一些架构变量和实用程序的Unix定义。
- makefile.default.rules：该文件包含默认的make目标、测试用例和构建规则。

### 9.2 The Test Directories

`source/tools`目录下的每个测试性质的目录中都包含makefile链中的两个文件：

![image-20211012172558700](https://cdn.jsdelivr.net/gh/AlexsanderShaw/BlogImages@main/img/vuln/shebei20211012172558.png)

- makefile：运行make时调用，不要修改。其中保存了makefile链的所有相关配置文件的包含指令，属于通用文件，在所有的测试目录中都是相同的。
- makefile.rules：目录特定文件，不同测试目录，文件内容不同。它保存了当前目录的逻辑，应该在目录中构建和运行的所有工具、应用程序和测试等都在该文件中进行定义。

### 9.3 Adding Tests, Tools and Applications to the makefile

下面介绍如何通过makefile构建二进制程序并运行测试。以下描述的变量都在`makefile.rules`文件的"Test targets"部分进行描述：

- TOOL_ROOTS：定义工具名称，不带文件扩展名，具体的文件扩展名将由make自动添加，例如YourTools.so；
- APP_ROOTS：定义应用程序，不带文件扩展名，具体的文件扩展名将由make自动添加，例如YourApp.exe；
- TEST_ROOTS：定义测试，不要加.test后缀，make会自动添加，例如YourTest.test。

### 9.4 Defining Build Rules for Tools and Applications

默认使用的构建规则是`source/tools/Config/makefile.default.rules`，输入为单一的c/cpp文件，生成相同名字的二进制程序。如果输入为多个源文件，且需要自定义构建规则，可以在`make.rules`文件的"Build rules"部分的末尾添加。如下是规则例子：

构建单一源文件且不进行优化：

```makefile
# Build the intermediate object file.
$(OBJDIR)YourTool$(OBJ_SUFFIX): YourTool.cpp
    $(CXX) $(TOOL_CXXFLAGS_NOOPT) $(COMP_OBJ)$@ $<

# Build the tool as a dll (shared object).
$(OBJDIR)YourTool$(PINTOOL_SUFFIX): $(OBJDIR)YourTool$(OBJ_SUFFIX)
    $(LINKER) $(TOOL_LDFLAGS_NOOPT) $(LINK_EXE)$@ $< $(TOOL_LPATHS) $(TOOL_LIBS)
```

构建多源文件且进行优化：

```makefile
# Build the intermediate object file.
$(OBJDIR)Source1$(OBJ_SUFFIX): Source1.cpp
    $(CXX) $(TOOL_CXXFLAGS) $(COMP_OBJ)$@ $<

# Build the intermediate object file.
$(OBJDIR)Source2$(OBJ_SUFFIX): Source2.c Source2.h
    $(CC) $(TOOL_CXXFLAGS) $(COMP_OBJ)$@ $<

# Build the tool as a dll (shared object).
$(OBJDIR)YourTool$(PINTOOL_SUFFIX): $(OBJDIR)Source1$(OBJ_SUFFIX) $(OBJDIR)Source2$(OBJ_SUFFIX) Source2.h
    $(LINKER) $(TOOL_LDFLAGS_NOOPT) $(LINK_EXE)$@ $(^:%.h=) $(TOOL_LPATHS) $(TOOL_LIBS)
```

### 9.5 Defining Test Recipes in makefile.rules

在"Test recipes"部分自定义自己的测试需求，例如：

```makefile
YourTest.test: $(OBJDIR)YourTool$(PINTOOL_SUFFIX) $(OBJDIR)YourApp$(EXE_SUFFIX)
    $(PIN) -t $< -- $(OBJDIR)YourApp$(EXE_SUFFIX)
```

### 9.6 Useful make Variables and Flags

摘取`makefile.config`中几个重点的标志进行说明：

`IN_ROOT`：在套件外构建工具时指定Pin套件的位置。
`CC`: 指定工具的默认c编译器。
`CXX`：指定工具的默认c++编译器
`APP_CC`：指定应用程序的默认 c 编译器。如果未定义，APP_CC 将与 CC 相同。
`APP_CXX`：指定应用程序的默认 c++ 编译器。如果未定义，APP_CXX 将与 CXX 相同。
`TARGET`：指定默认目标架构，例如交叉编译。
`ICC`: 使用英特尔编译器构建工具时指定 ICC=1。
`DEBUG`: 当指定 DEBUG=1 时，在构建工具和应用程序时会生成调试信息。此外，不会执行任何编译和/或链接优化。
