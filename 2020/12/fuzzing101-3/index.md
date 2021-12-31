# Fuzzing 101 -- 3


本文是Fuzzing101系列第三篇，fuzz的对象为 tcpdump。

<!--more-->

## 1. Basic Info

| Target  | CVES to find                      | Time estimated | Main topics                                |
| ------- | --------------------------------- | -------------- | ------------------------------------------ |
| TCPdump | CVE-2017-13028 | 4hous         | ASAN |

- CVE-2017-13028: Out-of-bounds Read vulneratibily.

## 2. Learning Target 

1. 什么是 ASAN(Address Sanitizer)，一个运行时内存错误检测工具
2. 如何使用ASAN进行fuzz
3. 使用ASAN对crash进行分类

## 3. Fuzzing

### 1. Workflow

1. 确定如何进行TCpdump的fuzz工作
2. 在fuzz时开启ASAN功能
3. 实际的fuzz过程
4. 追踪crash，找到对应的漏洞的poc
6. 修复漏洞

### 2. Solution

#### 1. Download and build target

首先创建待fuzz的 TCPdump 环境，进行编译待用：

```SHELL
cd $HOME/Desktop/Fuzz/training/fuzzing_tcpdump

# download and uncompress tcpdump-4.9.2.tar.gz
wget https://github.com/the-tcpdump-group/tcpdump/archive/refs/tags/tcpdump-4.9.2.tar.gz
tar -xzvf tcpdump-4.9.2.tar.gz

# download and uncompress libpcap-1.8.1.tar.gz
wget https://github.com/the-tcpdump-group/libpcap/archive/refs/tags/libpcap-1.8.1.tar.gz
tar -xzvf libpcap-1.8.1.tar.gz

# build and install
cd libpcap-libpcap-1.8.1/
./configure --enable-shared=no --prefix="$HOME/Desktop/Fuzz/training/fuzzing_tcpdump/install/"
make
make install

# build and install tcpdump
cd ..
cd tcpdump-tcpdump-4.9.2/
CPPFLAGS=-I$HOME/Desktop/Fuzz/training/fuzzing_tcpdump/install/include/ LDFLAGS=-L$HOME/Desktop/Fuzz/training/fuzzing_tcpdump/install/lib/ ./configure --prefix="$HOME/Desktop/Fuzz/training/fuzzing_tcpdump/install/"
make
make install

# test
$HOME/Desktop/Fuzz/training/fuzzing_tcpdump/install/sbin/tcpdump -h
```

以上安装不报错的话，可以正常启动 tcpdump ：

![image-20210823194623167](https://cdn.jsdelivr.net/gh/AlexsanderShaw/BlogImages@main/img/vuln/shebei20210823194623.png)

#### 2. Seed corpus creation

在 `tests` 文件夹中有很多的测试样例：

![image-20210823194813181](https://cdn.jsdelivr.net/gh/AlexsanderShaw/BlogImages@main/img/vuln/shebei20210823194813.png)

运行样例的命令如下：

```shell
$HOME/Desktop/Fuzz/training/fuzzing_tcpdump/install/sbin/tcpdump -vvvvXX -ee -nn -r [.pcap file]
# -vvvv 输出极为详细的信息
# -XX 把协议头和包内容都原原本本的显示出来（tcpdump会以16进制和ASCII的形式显示）
# -ee 在输出行打印出数据链路层的头部信息，包括源mac和目的mac，以及网络层的协议
# -nn 指定将每个监听到的数据包中的域名转换成IP、端口从应用名称转换成端口号后显示
# -r 指定文件
```

运行结果大概如下：

![image-20210823195058951](https://cdn.jsdelivr.net/gh/AlexsanderShaw/BlogImages@main/img/vuln/shebei20210823195058.png)

#### 3. AddressSanitizer

`AddressSanitizer(ASAN)` 是一个C和C++的内存错误检测工具，2011年由Google的研究员开发。

它包括一个编译器检测模块和一个运行时库，该工具可以发现对堆、栈和全局对象的越界访问、释放后重利用、双重释放和内存泄漏错误。

AddressSanitizer 是开源的，并且从 3.1 版开始与 LLVM 编译器工具链集成。虽然它最初是作为 LLVM 的项目开发的，但它已被移植到 GCC 并包含在 GCC >= 4.8 的版本中 。

更多内容请参考[AddressSanitizer](https://clang.llvm.org/docs/AddressSanitizer.html)。

本文我们主要是为了在fuzz时开启ASAN，所以先删除上面已经编译好的对象文件和可执行文件：

```shell
rm -r $HOME/fuzzing_tcpdump/install
cd $HOME/fuzzing_tcpdump/libpcap-libpcap-1.8.1/
make clean

cd $HOME/fuzzing_tcpdump/tcpdump-tcpdump-4.9.2/
make clean
```

clean 完成后，在进行make前附加 `AFL_USE_ASAN=1` 的编译选项：

```shell
cd $HOME/Desktop/Fuzz/training/fuzzing_tcpdump/libpcap-libpcap-1.8.1/
export LLVM_CONFIG="llvm-config-12"
CC=afl-clang-lto ./configure --enable-shared=no --prefix="$HOME/Desktop/Fuzz/training/fuzzing_tcpdump/install/"
AFL_USE_ASAN=1 make
AFL_USE_ASAN=1 make install

cd $HOME/Desktop/Fuzz/training/fuzzing_tcpdump/tcpdump-tcpdump-4.9.2/
CC=afl-clang-lto CPPFLAGS=-I$HOME/Desktop/Fuzz/training/fuzzing_tcpdump/install/include/ LDFLAGS=-L$HOME/Desktop/Fuzz/training/fuzzing_tcpdump/install/lib/ ./configure --prefix="$HOME/Desktop/Fuzz/training/fuzzing_tcpdump/install/"

CC=afl-clang-lto CPPFLAGS=-I$HOME/Desktop/Fuzz/training/fuzzing_tcpdump/install/include/ LDFLAGS=-L$HOME/Desktop/Fuzz/training/fuzzing_tcpdump/install/lib/ ./configure --prefix="$HOME/Desktop/Fuzz/training/fuzzing_tcpdump/install/"


AFL_USE_ASAN=1 make
AFL_USE_ASAN=1 make install
```

#### 4. Fuzzing

执行 `afl-fuzz` :

```shell
afl-fuzz -m none -i $HOME/Desktop/Fuzz/fuzzing_tcpdump/tcpdump-tcpdump-4.9.2/tests/ -o $HOME/Desktop/Fuzz/fuzzing_tcpdump/out/ -s 123 -- $HOME/Desktop/Fuzz/fuzzing_tcpdump/install/sbin/tcpdump -vvvvXX -ee -nn -r @@
```

备注：这里指定了 `-m none` 选项是取消了AFL的内存使用限制，因为在64-bit系统下，ASAN会占用较多的内存。

### 3. Crashes

最终跑得的结果如下：

![img](https://github.com/antonio-morales/Fuzzing101/raw/main/Exercise%203/Images/Image3.png)

## 4. Triage

对使用了ASAN 进行build的程序进行debug是一件十分容易的事情，只要直接将crash文件喂给程序运行即可，然后就可以得到crash的相关信息，包括函数的执行追踪：

![img](https://cdn.jsdelivr.net/gh/AlexsanderShaw/BlogImages@main/img/vuln/shebei20210824081203.png)

## 5. Fix

官方的修复地址：

- https://github.com/the-tcpdump-group/tcpdump/commit/29e5470e6ab84badbc31f4532bb7554a796d9d52

后续将对该漏洞进行深入分析和补丁分析，待完善。

