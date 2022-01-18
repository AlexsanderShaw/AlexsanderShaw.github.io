# Fuzzing 101 -- 8


本文是Fuzzing101系列第八篇，fuzz的对象为 Adobe Reader 。

<!--more-->

## 1. Basic Info

> 一个 OOB read vulneratibily.

## 2. Learning Target

1. 使用 AFL++ 的 QEMU 模式来对闭源软件进行 fuzz
2. 在 QEMU 模式下开启 persistent mode
3. 练习如何使用 QASAN ，一个二进制层面的 sanitizer

## 3. Fuzzing

### 1. Workflow

1. 安装 AFL++ 的 QEMU
2. 创建一个 PDF 的语料库
3. 开启 persistent mode
4. 使用 QEMU 模式对 Adobe Reader 进行 fuzz，直到出现crash
5. 使用造成crash的poc重现crash
6. 修复漏洞

### 2. Solution

#### 1. Download and build target

首先安装 AFL++ 的 QEMU 模式，使用下面的命令来进行检测是否安装：

```shell
afl-qemu-trace --help
```

![image-20220117194951793](https://cdn.jsdelivr.net/gh/AlexsanderShaw/BlogImages@main/img/202201171949836.png)

这种显示表明已经安装成功了。如果不能，则需要额外安装：

```shell
sudo apt install ninja-build libc6-dev-i386
cd ~/Desktop/v4ler1an/AFLplusplus/qemu_mode/
CPU_TARGET=i386 ./build_qemu_support.sh
make distrib
sudo make install
```

然后安装 Adobe Reader ：

```shell
# install dependencies
sudo apt-get install libxml2:i386

# download and uncompress 
wget ftp://ftp.adobe.com/pub/adobe/reader/unix/9.x/9.5.1/enu/AdbeRdr9.5.1-1_i386linux_enu.deb

# install
sudo dpkg -i AdbeRdr9.5.1-1_i386linux_enu.deb
```

安装完成后，检测是否成功：

```shell
/opt/Adobe/Reader9/bin/acroread
```

安装成功后会出现如下信息：

![image-20220117202727694](https://cdn.jsdelivr.net/gh/AlexsanderShaw/BlogImages@main/img/202201172027736.png)

![image-20220117203146217](https://cdn.jsdelivr.net/gh/AlexsanderShaw/BlogImages@main/img/202201172031253.png)

#### 2. Seed corpus creation

从 SafeDocs “Issue Tracker” 下载语料，或者从[这里](https://www.pdfa.org/a-new-stressful-pdf-corpus/)使用更多的 PDF 语料。

```shell
# download and uncompress 
wget https://corpora.tika.apache.org/base/packaged/pdfs/archive/pdfs_202002/libre_office.zip
unzip libre_office.zip -d extracted
```

这里因为 PDF 格式的文件一般会比较大，所以我们先筛选小于 2KB 的文件来加快 fuzz 速度：

```shell
mkdir -p $HOME/Desktop/Fuzz/training/fuzzing_adobereader/afl_in
find ./extracted -type f -size -2k \
    -exec cp {} $HOME/Desktop/Fuzz/training/fuzzing_adobereader/afl_in \;
```

#### 3. Fuzzing

这里在执行 fuzz 时，有两种方式：

第一种是直接使用 `-Q` 选项开启 QEMU mode。

这里有一个需要注意的问题，因为前面运行的 `/opt/Adobe/Reader9/bin/acroread` 是一个 shell 脚本，并不是实际的二进制文件。真正的二进制文件是 `/opt/Adobe/Reader9/Reader/intellinux/bin/acroread`。这里需要设置一下两个环境变量：`ACRO_INSTALL_DIR` 和 `ACRO_CONFIG`。然后， 通过 `LD_LIBRARY_PATH` 指定加载共享库的路径。所以最终执行的 fuzz 命令如下：

```shell
ACRO_INSTALL_DIR=/opt/Adobe/Reader9/Reader ACRO_CONFIG=intellinux LD_LIBRARY_PATH=$LD_LIBRARY_PATH:'/opt/Adobe/Reader9/Reader/intellinux/lib' afl-fuzz -Q -i ./afl_in/ -o ./afl_out/ -t 2000 -- /opt/Adobe/Reader9/Reader/intellinux/bin/acroread -toPostScript @@
```

![image-20220118163556811](https://cdn.jsdelivr.net/gh/AlexsanderShaw/BlogImages@main/img/202201181635848.png)

但是这种方式很慢，我们需要想办法提升 fuzz 速度。

第二种就是使用 AFL 的 persistent 模式。这种模式可以用在有源码的情况下，也可以用在只有二进制文件的情况下。在有源码时，我们可以直接在源码的合适的位置插入如下代码来实现 persistent 模式：

```c
while(__AFL_LOOP(10000)){
	/* Read input data. */
    /* Call library code to be fuzzed. */
    /* Reset state. */
}
```

对于 persistent 模式的详细介绍可以阅读[这里](https://github.com/AFLplusplus/AFLplusplus/blob/stable/instrumentation/README.persistent_mode.md)。

而对于只有二进制文件的情况，整体思路上是一样的，也是找到合适的位置设置循环。分析二进制文件的函数地址可以使用常规的 IDA 等工具进行反编译来获取，这里使用一种简单的工具 —— valgrind。我们使用其中的 `callgrind` 来分析程序运行的时间和调用过程，来判断合适的位置：

```shell
sudo apt-get install valgrind
sudo apt-get install kcachegrind
```

然后，使用下面的命令来生成一个 callgrind report：

```shell
ACRO_INSTALL_DIR=/opt/Adobe/Reader9/Reader ACRO_CONFIG=intellinux LD_LIBRARY_PATH=/opt/Adobe/Reader9/Reader/intellinux/lib valgrind --tool=callgrind /opt/Adobe/Reader9/Reader/intellinux/bin/acroread -toPostScript [samplePDF]
```

![image-20220118164536311](https://cdn.jsdelivr.net/gh/AlexsanderShaw/BlogImages@main/img/202201181645405.png)

上述命令会在当前目录下生成一个 `callgrind.out` 文件，然后使用 `kcachegrind` 来读取：

```shell
kcachegrind
```

读取出的信息如下：

![image-20220118171410481](https://cdn.jsdelivr.net/gh/AlexsanderShaw/BlogImages@main/img/202201181714573.png)

这里我们选择地址 `0x08546a00` 。选择的原则是尽可能选择那些只执行了一次，并且可以使得 AFL++ 的 stability 值能在 90% 以上的地址。所以使用的命令为：

```shell
AFL_QEMU_PERSISTENT_ADDR=0x08546a00 ACRO_INSTALL_DIR=/opt/Adobe/Reader9/Reader ACRO_CONFIG=intellinux LD_LIBRARY_PATH=$LD_LIBRARY_PATH:'/opt/Adobe/Reader9/Reader/intellinux/lib' afl-fuzz -Q -i ./afl_in/ -o ./afl_out/ -t 2000 -- /opt/Adobe/Reader9/Reader/intellinux/bin/acroread -toPostScript @@
```

我们指定了变量 `AFL_QEMU_PERSISTENT_ADDR` 为上面选择的地址。这次的fuzz速度会有提升：

![image-20220118171741647](https://cdn.jsdelivr.net/gh/AlexsanderShaw/BlogImages@main/img/202201181721726.png)

## 3. Triage

在发生 crash 之后，我们来检测这个 OOB read 漏洞：

```shell
ACRO_INSTALL_DIR=/opt/Adobe/Reader9/Reader ACRO_CONFIG=intellinux LD_LIBRARY_PATH=opt/Adobe/Reader9/Reader/intellinux/lib /usr/local/bin/afl-qemu-trace -- /opt/Adobe/Reader9/Reader/intellinux/bin/acroread -toPostScript [crashFilePath] 
```

如果按照上面的常规的命令来执行 trace，会报页错误。所以我们使用另外一种方法—— [QASAN](https://github.com/andreafioraldi/qasan)

```shell
AFL_USE_QASAN=1 ACRO_INSTALL_DIR=/opt/Adobe/Reader9/Reader ACRO_CONFIG=intellinux LD_LIBRARY_PATH=opt/Adobe/Reader9/Reader/intellinux/lib /usr/local/bin/afl-qemu-trace -- /opt/Adobe/Reader9/Reader/intellinux/bin/acroread -toPostScript [crashFilePath] 
```

然后就能看到触发的 stacktrace：

![image-20220118172058675](https://cdn.jsdelivr.net/gh/AlexsanderShaw/BlogImages@main/img/202201181720756.png)
