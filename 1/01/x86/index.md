# 

# Linux操作系统的大千世界——OS——x86架构


# Linux操作系统的大千世界——OS——x86架构

## 前言

完整的计算机由操作系统和硬件组成，必须两者兼备，而且两者要完美适配才能良好运作。操作系统的数量屈指可数，但是在操作系统下面的硬件却是千千万万。如何做到操作系统兼容各类各式的硬件环境呢？大家都协议一个通用的架构，大家都适配这个架构好了。于是，一个业内通用的架构——x86架构诞生了。

## 一、计算机的工作模式

计算机的硬件根据功能划分成各自独立的产品，在进行组装时需要按照一定的顺序将复杂的设备和连接线安装好。如何安装我知道，但是为什么要这么安装呢？

下图为一个硬件图和计算机的逻辑图，从这里我们可以大概看到计算机的工作模式：

![image-20210708101440275](https://cdn.jsdelivr.net/gh/AlexsanderShaw/BlogImages@main/img/vuln/shebeiimage-20210708101440275.png)

**CPU**，Central Processing Unit，计算机核心中的核心，所有设备的运作均围绕CPU展开。

**总线**，Bus，CPU连接其他设备时使用，即主板上数量庞大的集成电路，组成了CPU和其他设备的高速通信通道。

**内存**，Memory，保存CPU计算的中间结果，使得CPU在后续运算中可以使用临时保存的计算数据。

**其他设备**，显示器、磁盘、可移动存储介质等。

### 1. CPU和内存如何进行配合？

CPU可以划分为3个单元：运算单元、数据单元和控制单元。运算单元专注计算，所使用的数据、计算的结果由数据单元保存（这里需要注意的一点是，虽然CPU可以通过内存总线与内存通信，计算使用的数据和计算结果可以保存在内存中，但是这样速度很慢，每次通过总线传输会很消耗时间，所以CPU内部专门开发了一个数据单元，保存临时、少量的计算数据，这样速度会大幅提升）。数据单元包括CPU内部的缓存和寄存器组，空间小，速度快，仅用于临时存放运算数据。控制单元则负责任务分发和调度，用于获取下一条指令，然后执行，会指导运算单元从数据单元中取出多少数据、怎样进行计算、计算结果放在数据单元的何处等。

![img](https://cdn.jsdelivr.net/gh/AlexsanderShaw/BlogImages@main/img/vuln/shebei3afda18fc38e7e53604e9ebf9cb42023.jpeg)

程序运行后，每个进程会有自己独立的内存空间，例如图中进程A和进程B，互相隔离。程序的运行一般流程是开辟出一篇内存空间，程序的磁盘上的二进制文件被加载到内存空间中，形成代码段、数据段等。进程A和进程B在成功加载后，彼此的运行空间互相隔离，但是并**不连续**，这里的不连续是指分配的内存空间在物理上不一定是连续的，这主要与Linux操作系统的内存分配机制有关，后续会做详细深入分析。而且除了上图中的代码段和数据段，还会有其他的段。

程序运行中需要操作的数据和产生的运算结果，会存放在数据段中。**CPU如何执行程序，操作这些数据，产生运算结果，并写回内存呢？**

CPU的控制单元中有一个**指令指针寄存器**，保存了下一条指令在内存中的地址。控制单元会从代码段中不断获取指令的地址放入该进村其中，在执行时直接读取该寄存器，就可以知道下一条要执行的指令了。

指令一般分两部分，第一部分是做什么操作，第二部分是该操作要操作的数据。要执行这条指令，需要将第一部分交给运算单元，第二部分交给数据单元，数据单元根据数据的地址，从数据段里读到数据寄存器中，然后再参与运算。运算单元做完运算，产生的结果暂存在数据单元的数据寄存器中，等待指令将其写回到内存中的数据段中。

### 2. 进程切换

上面所讲的各种操作均在进程A中进行，那么进程B呢？CPU里有两个专门的寄存器保存当前处理进程的代码段、数据段的起始地址。如果寄存器里保存的是进程A的地址，那么就执行进程A的指令；如果切换为进程B的地址，那么就执行进程B的指令，这个过程称为**进程切换**(Process Switch)。

进程切换是多任务系统的必备操作，后续会进行深入分析。

### 3. 地址总线和数据总线

CPU和内存的数据传输主要靠总线，总线在整体上分为两类：

- 地址总线(Address Bus)，访问地址数据，即读取内存中何处的数据
- 数据总线(Data Bus)，读取到的数据

地址总线的位数，决定了能访问的地址范围。如何理解？例如总线只有2位，那么能访问的地址就为00、01、10、11这4个地址，如果是3位就可以访问8个地址，所以地址总线位数越多，能访问的地址范围就越广。

数据总线的位数，决定了一次可以读多少数据。如何理解？例如总线只有2位，那么CPU一次只能拿2位，想要拿8位，就需要读4次。所以数据总线位数越多，一次可以读取的数据就越多，访问速度也就越快。

### 4. x86架构

**x86**泛指一系列基于[Intel 8086](https://baike.baidu.com/item/Intel 8086)且向后兼容的[中央处理器](https://baike.baidu.com/item/中央处理器)[指令集架构](https://baike.baidu.com/item/指令集架构)。最早的8086处理器于1978年由[Intel](https://baike.baidu.com/item/Intel)推出，为16位[微处理器](https://baike.baidu.com/item/微处理器)。但是让x86真正得到推广的，是IBM。因为IBM的PC卖得太好，被起诉垄断，无奈之下公开了一些技术，这使得业内其他品牌逐步都开始采用IBM的“Intel 8088芯片+MS-DOS”的PC模式。Intel的技术因此成为了行业的开放事实标准。由于该系列开端与8086，因此称为x86架构。

虽然后来的Intel的CPU的数据总线和地址总线越来越宽，处理能力越来越强，但是始终坚持标准、开放、兼容的原则，因此构建了一个庞大的软硬件生态。

部分芯片和总线数据如下：

| 型号  | 总线位宽 | 地址位 | 寻址空间   |
| ----- | -------- | ------ | ---------- |
| 8080  | 8        | 16     | 64k (2^16) |
| 8086  | 16       | 20     | 1M (2^20)  |
| 8088  | 8        | 20     | 1M (2^20)  |
| 80386 | 32       | 32     | 4G (2^32)  |

## 三、8086的原理

x86中最经典的一款处理器就是8086处理器，至今为止很多操作系统仍然保持对该处理器的兼容性。

下图为CPU内部组件构成图：

![img](https://cdn.jsdelivr.net/gh/AlexsanderShaw/BlogImages@main/img/vuln/shebei2dc8237e996e699a0361a6b5ffd4871c.jpeg)

数据单元，包含8个16位的寄存器：AX、BX、CX、DX、SP、BP、SI、DI。其中，AX、BX、CX、DX可以拆分成2个8位的寄存器使用：AH、AL、BH、BL、CH、CL、DH、DL。H代表High，表示高位，L代表Low，表示地位。这样以来，长数据可以直接使用完整的寄存器，而短数据也可以妥善处理。

控制单元，IP（Instruction Pointer Register）寄存器即指令指针寄存器，用于确定下一条指令的地址。CPU根据该寄存器不断将指令从内存的代码段中加载到指令队列里，然后交给运算单元执行。4个段寄存器，CS、DS、SS、ES寄存器，则用于进程切换中。CS指代码段寄存器（Code Segment Register），通过它可以找到代码在内存中的地址；DS是数据段寄存器，通过它可以找到数据在内存中的地址。SS是栈寄存器（Stack Segment Register），一般存放堆栈段的首地址，配合SP或BP使用，ES是附加段寄存器（Extra Segment）。当前面的段寄存器不够用时，可以使用ES寄存器。

进行运算时如何加载内存中的数据呢？

1. 通过DS确定数据段地址
2. 通过寄存器确定偏移量（Offset），确定待用数据在段中的偏移（代码段的偏移量会存放在IP寄存器，数据段的偏移量存放在通用寄存器中）
3. 通过"起始地址 * 16 + 偏移量"确定最终地址

这里需要注意，CS和DS均为16位，IP也是16位，即起始地址和偏移量都是16位，但是8086的地址总线时20位，所以需要通过上面的公式计算出最终的数据地址。

根据地址总线长度，8086的最大寻址能力为1M。且因为偏移量为16位，所以一个段的最大的大小为2^16=64K。

## 四、32位处理器

核心就是扩展总线位宽，扩大内存。地址总线变为32根，寻址能力达到2^32=4G。如何使得硬件保持兼容呢？

首先，扩展通用寄存器，将8个16位寄存器扩展为32位，但是依然可以保留16位和8位的使用方式（8位的使用只能在低位，如果高位也切割，就会不兼容）。IP寄存器扩展成32位，同时兼容16位。本质上，思想跟8086的思想是一样的，只是硬件做了升级。

![img](https://cdn.jsdelivr.net/gh/AlexsanderShaw/BlogImages@main/img/vuln/shebeie3f4f64e6dfe5591b7d8ef346e8e8884.jpeg)

回顾一下8086的寻址方式，20位地址的使用其实是有点尴尬的，结果还导致必须使用“起始地址 * 16 + 偏移量”的方式来计算实际地址。如果寄存器全部变成32位，4G的内存空间都可以访问到，是不是可以省去计算公式呢？

在32位寄存器的系统中，CS、DS、SS、ES仍然为16位，但不再是段的起始地址。段的起始地址放在内存的某个地方，这个地方是一个表格，表格中的每一项都是一个**段描述符（Segment Descriptor）**，段描述符中放的才是真正的段的起始地址。而段寄存器则存放具体是表格中的哪一项，称为**选择子（Selector）**。这样，就将从一个段寄存器直接获取段的起始地址，变成先间接地从段寄存器后的表格中的一项，然后从表格的一项中后去真正的段起始地址。实际上为了快速拿到段起始地址，段寄存器会从内存中拿到CPU的描述符高速缓存器中。（这个保存各个段的起始地址的表格其实是GDT（Global Descriptor Table，全局描述符表）和LDT（Local Descriptor Table，局部描述符表））

32位这种设计方案的思想很值得大家好好琢磨，单纯地寻址总是要比计算+寻址地速度快的。个人认为，这种方案可以说纠正了20位地址总线的一种技术落后导致的设计错误，而且这种方案远远比20位的更灵活。

但是这样会导致不兼容问题的出现，怎么办？大的小的我都要。

32位架构下，出现了实模式（Real Pattern）和保护模式（Protect Pattern）。实模式就是前面的运行模式，保护模式就是后面的运行模式。在系统刚启动时，运行在实模式，运行成功后变为保护模式。这其实是一种通过切换模式实现兼容的方案。可见技术的发展，也影响着人的思想的发展。

## 五、参考

专栏 -- 《趣谈Linux操作系统》
