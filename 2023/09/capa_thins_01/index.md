# capa things 01


使用几篇文章来详细介绍一下capa这款工具的原理、使用和在现实生产环境中的利用。

<!--more-->

# Capa Things

## 1. Basic Knowledge

Capa是FilreEye(Mandiant)公司开源的静态分析工具，旨在检测和识别恶意软件的高级静态行为，同时支持IDA插件操作和安装服务及HTTP通信，方便安全人员快速定位恶意代码，且能与ATT&CK框架和MBC进行映射。

通常能分析的样本格式：

- PE文件
- ELF文件
- .NET模块
- ShellCode文件

source code地址：

- [capa工具地址](https://github.com/mandiant/capa)

工具的运行结果如下所示，它能有效反映恶意软件在ATT&CK框架中的技战术特点：

```shell
(base) PS C:\Users\v4le1an\Desktop\tmp> .\capa.exe .\2b555547ea2cae583ba9c38a3891f316fc787f5f5048c94787bee2d16983e8cc
┍━━━━━━━━━━━━━━━━━━━━━━━━┯━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┑
│ md5                    │ 59059b2be273f57b45adc085ab631617                                                              │
│ sha1                   │ b78669cd7f0bb201b02878c68b309f0c40d85f6f                                                      │
│ sha256                 │ 2b555547ea2cae583ba9c38a3891f316fc787f5f5048c94787bee2d16983e8cc                              │
│ os                     │ windows                                                                                       │
│ format                 │ pe                                                                                            │
│ arch                   │ i386                                                                                         │
│ path                   │ C:/Users/v4le1an/Desktop/tmp/2b555547ea2cae583ba9c38a3891f316fc787f5f5048c94787bee2d16983e8cc │
┕━━━━━━━━━━━━━━━━━━━━━━━━┷━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┙

┍━━━━━━━━━━━━━━━━━━━━━━━━┯━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┑
│ ATT&CK Tactic          │ ATT&CK Technique                                                                   │
┝━━━━━━━━━━━━━━━━━━━━━━━━┿━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┥
│ DEFENSE EVASION        │ File and Directory Permissions Modification T1222                                  │
│                        │ Modify Registry T1112                                                              │
│                        │ Obfuscated Files or Information T1027                                              │
│                        │ Virtualization/Sandbox Evasion::System Checks T1497.001                            │
├────────────────────────┼────────────────────────────────────────────────────────────────────────────────────┤
│ DISCOVERY              │ File and Directory Discovery T1083                                                 │
│                        │ Process Discovery T1057                                                            │
│                        │ Query Registry T1012                                                               │
│                        │ System Information Discovery T1082                                                 │
│                        │ System Service Discovery T1007                                                     │
├────────────────────────┼────────────────────────────────────────────────────────────────────────────────────┤
│ EXECUTION              │ Shared Modules T1129                                                               │
│                        │ System Services::Service Execution T1569.002                                       │
├────────────────────────┼────────────────────────────────────────────────────────────────────────────────────┤
│ PERSISTENCE            │ Create or Modify System Process::Windows Service T1543.003                         │
├────────────────────────┼────────────────────────────────────────────────────────────────────────────────────┤
│ PRIVILEGE ESCALATION   │ Access Token Manipulation T1134                                                    │
┕━━━━━━━━━━━━━━━━━━━━━━━━┷━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┙

┍━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┯━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┑
│ MBC Objective               │ MBC Behavior                                                                  │
┝━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┿━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┥
│ ANTI-BEHAVIORAL ANALYSIS    │ Virtual Machine Detection [B0009]                                             │
├─────────────────────────────┼───────────────────────────────────────────────────────────────────────────────┤
│ COMMAND AND CONTROL         │ C2 Communication::Receive Data [B0030.002]                                    │
│                             │ C2 Communication::Send Data [B0030.001]                                       │
├─────────────────────────────┼───────────────────────────────────────────────────────────────────────────────┤
│ COMMUNICATION               │ DNS Communication::Resolve [C0011.001]                                        │
│                             │ Socket Communication::Create TCP Socket [C0001.011]                           │
│                             │ Socket Communication::Initialize Winsock Library [C0001.009]                  │
│                             │ Socket Communication::Receive Data [C0001.006]                                │
│                             │ Socket Communication::Send Data [C0001.007]                                   │
├─────────────────────────────┼───────────────────────────────────────────────────────────────────────────────┤
│ DATA                        │ Checksum::CRC32 [C0032.001]                                                   │
│                             │ Encode Data::XOR [C0026.002]                                                  │
├─────────────────────────────┼───────────────────────────────────────────────────────────────────────────────┤
│ DEFENSE EVASION             │ Obfuscated Files or Information::Encoding-Standard Algorithm [E1027.m02]      │
├─────────────────────────────┼───────────────────────────────────────────────────────────────────────────────┤
│ DISCOVERY                   │ File and Directory Discovery [E1083]                                          │
│                             │ System Information Discovery [E1082]                                          │
├─────────────────────────────┼───────────────────────────────────────────────────────────────────────────────┤
│ FILE SYSTEM                 │ Create Directory [C0046]                                                      │
│                             │ Get File Attributes [C0049]                                                   │
│                             │ Move File [C0063]                                                             │
│                             │ Read File [C0051]                                                             │
│                             │ Set File Attributes [C0050]                                                   │
│                             │ Writes File [C0052]                                                           │
├─────────────────────────────┼───────────────────────────────────────────────────────────────────────────────┤
│ OPERATING SYSTEM            │ Registry::Delete Registry Key [C0036.002]                                     │
│                             │ Registry::Query Registry Value [C0036.006]                                    │
│                             │ Registry::Set Registry Key [C0036.001]                                        │
├─────────────────────────────┼───────────────────────────────────────────────────────────────────────────────┤
│ PROCESS                     │ Create Process [C0017]                                                        │
│                             │ Create Thread [C0038]                                                         │
│                             │ Terminate Thread [C0039]                                                      │
┕━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┷━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┙

┍━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┯━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┑
│ Capability                                           │ Namespace                                            │
┝━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┿━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┥
│ reference anti-VM strings targeting Xen              │ anti-analysis/anti-vm/vm-detection                   │
│ receive data (2 matches)                             │ communication                                        │
│ send data (2 matches)                                │ communication                                        │
│ resolve DNS                                          │ communication/dns                                    │
│ initialize Winsock library                           │ communication/socket                                 │
│ create TCP socket (2 matches)                        │ communication/socket/tcp                             │
│ hash data with CRC32                                 │ data-manipulation/checksum/crc32                     │
│ encode data using XOR (3 matches)                    │ data-manipulation/encoding/xor                       │
│ get common file path (2 matches)                     │ host-interaction/file-system                         │
│ create directory                                     │ host-interaction/file-system/create                  │
│ check if file exists                                 │ host-interaction/file-system/exists                  │
│ enumerate files recursively                          │ host-interaction/file-system/files/list              │
│ get file attributes (2 matches)                      │ host-interaction/file-system/meta                    │
│ get file size                                        │ host-interaction/file-system/meta                    │
│ set file attributes (7 matches)                      │ host-interaction/file-system/meta                    │
│ move file (3 matches)                                │ host-interaction/file-system/move                    │
│ read file on Windows                                 │ host-interaction/file-system/read                    │
│ write file on Windows (2 matches)                    │ host-interaction/file-system/write                   │
│ get disk information                                 │ host-interaction/hardware/storage                    │
│ print debug messages                                 │ host-interaction/log/debug/write-event               │
│ get system information on Windows                    │ host-interaction/os/info                             │
│ create process on Windows (3 matches)                │ host-interaction/process/create                      │
│ modify access privileges                             │ host-interaction/process/modify                      │
│ enumerate process modules                            │ host-interaction/process/modules/list                │
│ query or enumerate registry value (6 matches)        │ host-interaction/registry                            │
│ delete registry key (3 matches)                      │ host-interaction/registry/delete                     │
│ query service status (2 matches)                     │ host-interaction/service                             │
│ create service                                       │ host-interaction/service/create                      │
│ delete service                                       │ host-interaction/service/delete                      │
│ modify service                                       │ host-interaction/service/modify                      │
│ start service                                        │ host-interaction/service/start                       │
│ create thread                                        │ host-interaction/thread/create                       │
│ terminate thread                                     │ host-interaction/thread/terminate                    │
│ link function at runtime on Windows (3 matches)      │ linking/runtime-linking                              │
│ persist via Windows service (2 matches)              │ persistence/service                                  │
┕━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┷━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┙
```

**备注**
需要注意的是，上面是默认输出模式，此外还支持“-j”输出成json格式。根据实际的测试结果看，json的输出信息会更全面，尤其是ATT&CK信息。上面的默认输出测试了几个样本，发现不输出T1055的Process Injection，但是如果使用json格式则会输出改ttp。

### 安装方式

capa目前有3三种使用方式，一种是直接使用github的[release](https://github.com/mandiant/capa/releases)，另外还可以作为库或者第三方集成工具使用，详细参考[capa installation](https://github.com/mandiant/capa/blob/master/doc/installation.md)。

### 检测规则

capa自带了一些内置检测规则，github地址为[capa-rules规则地址](https://github.com/mandiant/capa-rules/tree/eba332e702d88927b5816770a9853dd0b3fbc47a)。此外，capa还支持并鼓励添加自定义规则，这样就可以实现高度定制化。例如：

![image.png](https://raw.githubusercontent.com/AlexsanderShaw/BlogImages/main/img/2023/202309081550472.png)

### 测试集

capa提供了一些[capa-testfiles](https://github.com/mandiant/capa-testfiles)，测试数据说明如下：

* File name
  * MD5 or SHA256 hash, all lower case, e.g.
    * `d41d8cd98f00b204e9800998ecf8427e`
    * `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855`
  * Descriptive name, e.g.
    * `kernel32`
    * `Practical Malware Analysis Lab 01-01`
* File extension
  * `.exe_`
  * `.dll_`
  * `.sys_`
  * `.elf_`
  * `.raw32` (32-bit shellcode)
  * `.raw64` (64-bit shellcode)
  * `.cs_` (C# source code)
  * `.aspx_` (ASP.NET source code)
  * `.py_` (Python source code)
* Directories
  * `/`: native test binaries
  * `/dotnet`: .NET test binaries
  * `/sigs`: test signatures
  * `/source`: source language test files e.g. C# and Python

## 2. Capa原理详解

首先给出Mandiant关于该工具的第一篇blog-[capa: Automatically Identify Malware Capabilities](https://www.mandiant.com/resources/blog/capa-automatically-identify-malware-capabilities)。

### 1. 工具背景

在分析程序是否为恶意、程序在攻击期间所扮演的角色、潜在的功能和攻击者的意图时，通常需要经验丰富的恶意软件分析师来完成。他们可以快速对未知二进制文件进行分类以获取初步了解并进一步深入分析。然而，这绝大程度上取决于恶意软件分析师的个人能力和专家经验，对于能力或者经验不足的分析师很难区分正常和恶意样本，并且字符串、floss或者pe检测工具显示的细节一般比较底层，比较难统计样本的宏观行为特征。

### 2. 恶意软件分类

这里以某个恶意软件为例，下图展示了文件的字符串和导入表信息，通过这些信息，恶意软件分析师利用字符串和导入表中的特殊API会猜测程序的功能。

- 该程序会创建互斥锁、启动进程、网络通信（IP地址为127.26.152.13）
- Winsock(WS2_32)导入会猜测网络功能，但是没有函数名，可能是按照序号导入。

![image.png](https://raw.githubusercontent.com/AlexsanderShaw/BlogImages/main/img/2023/202309081550474.png)

通过动态分析可以进一步了解程序的其他功能，而动态分析通常依赖与沙箱。沙箱报告或者动态分析工具仅限于从执行代码路径中捕获行为，例如连接命令和控制(C2)服务器后触发的功能。一般情况下，我们不建议使用实时互联网连接来分析恶意软件。因此，需要对它进行逆向。如下所示，利用IDA对程序的主要功能进行反编译：

![image.png](https://raw.githubusercontent.com/AlexsanderShaw/BlogImages/main/img/2023/202309081550267.png)

我们可以发现样本具备如下功能；

- 创建互斥锁以确保只有一个实例在运行
- 创建一个TCP socket
- 连接IP地址127.26.152.13，端口为80
- 发送和接收数据
- 将收到的数据和“sleep”和“exec”命令字符串进行对比
- 创建新进程

尽管并不是每个code path都会在每次运行时执行到，但是我们可以判断该样本具有执行这些行为的能力。此外，通过结合各个结论，可以推断该样本是一个后门，可以运行由硬编码的C2 server指定的任意程序。

### 3. 自动识别能力

在实际的生产环境中，恶意软件的分析并不会这么简单，意图识别需要通过包含数百或数千个函数的二进制文件进行传播。此外，逆向水平的高低决定了我们对样本分析的深度。

capa提供的思路是将人工的判断逻辑自动化到工具中，例如API调用、字符串、敞亮和其他功能的重复模式中识别程序中的功能，提供了一种通用且灵活的方式来编纂专业知识，也就是说把专家经验落地到自动化工具中。在运行capa时，它会将特征和模式识别为自动化的人工步骤，从而产生可以推动后续调查步骤的高级结论。例如，capa识别出未加密的http通信功能，那么我们就可以到代理日志或者其他网路跟踪数据中进一步筛查。

### 4. capa的能力

下面的输出会展示此实例中所有已识别的样本功能：

- 左侧的每个条目描述一个功能类别
- 右侧的关联namespace有助于对相关功能进行分组

![image.png](https://raw.githubusercontent.com/AlexsanderShaw/BlogImages/main/img/2023/202309081550736.png)

下面的图则显示了capa对“create TCP socket”的具体输出，通过这个信息我们可以检查二进制文件相关特征的具体位置，此外，还可以利用语法规则推测它们低级功能的逻辑树组成。

![image.png](https://raw.githubusercontent.com/AlexsanderShaw/BlogImages/main/img/2023/202309081550005.png)

### 5. 工作原理

capa包含两个核心组件，通过算法对未知程序进行分类。

- 代码分析引擎从文件中提取特征，例如字符串、反汇编和控制流
- 逻辑分析引擎查找符合通用规则格式的特征组合。当找到匹配项时，capa会报告规则描述的功能。

#### 特征提取

代码分析引擎会从程序中提取低级特征，所有的特征与人工可能识别的特征一样，例如字符串或者数字，并且capa可以解释这些数据。这些功能通常为两大类：文件功能和反汇编功能。

文件特征是从原始文件数据及其结构中提取的，例如PE文件头、字符串、导入表、导出的函数和节名称。

反汇编特征是从文件的高级静态分析中提取的，这会进行反汇编和重建控制流。下图显示了选定的反汇编功能，包括API调用、指令助记符、数字和字符串的引用。

![image.png](https://raw.githubusercontent.com/AlexsanderShaw/BlogImages/main/img/2023/202309081550497.png)

capa在设计时考虑了灵活且可扩展的特征提取，这使得capa可以轻松地集成在其他的代码分析后端。目前，capa 独立版本依赖于vivisect分析框架。如果使用 IDA Pro，还可以使用 IDAPython 后端运行 capa。请注意，有时代码分析引擎之间的差异可能会导致不同的功能集，从而导致不同的结果。幸运的是，这在实践中通常不是一个严重的问题。

#### 能力规则

capa 规则使用特征的结构化组合来描述可以在程序中实现的功能。如果所有必需的功能都存在，capa 就会断定该程序包含该功能。

capa 规则是包含元数据和表达其逻辑的语句树的 YAML 文档。除此之外，规则语言还支持逻辑运算符和计数。在下图中，“create TCP socket”规则规定数字 6、1 和 2 以及对API 函数套接字或WSASocket的调用必须出现在单个基本块的范围内。基本块将汇编代码分组在非常低的级别，这使得它们成为匹配紧密相关的代码段的理想位置。除了基本块之外，capa还支持函数和文件级别的匹配。函数作用域将反汇编函数中的所有功能联系在一起，而文件作用域包含整个文件中的所有功能。

![image.png](https://raw.githubusercontent.com/AlexsanderShaw/BlogImages/main/img/2023/202309081551737.png)

下图突出显示了规则元数据，该元数据使cap 能够向用户显示高级、有意义的结果。规则名称描述了所识别的功能，而命名空间将其与技术或分析类别相关联。我们已经在capa输出的功能表中看到了名称和命名空间。元数据部分还可以包括作者或示例等字段。我们使用示例来引用我们知道存在功能的文件和偏移量，从而能够对每个规则进行单元测试和验证。此外，capa 规则可以作为现实恶意软件中行为的重要文档，因此请随意保留一份副本作为参考。在以后的文章中，我们将讨论其他元信息，包括 capa 对 ATT&CK 和恶意软件行为目录框架的支持。

![image.png](https://raw.githubusercontent.com/AlexsanderShaw/BlogImages/main/img/2023/202309081551345.png)


