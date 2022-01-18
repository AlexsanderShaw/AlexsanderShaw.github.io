# 

# Fuzzing 101 -- 4


本文是Fuzzing101系列第四篇，fuzz的对象为 LibTIFF 。

<!--more-->

## 1. Basic Info

| Target  | CVES to find  | Time estimated | Main topics                    |
| ------- | ------------- | -------------- | ------------------------------ |
| LibTIFF | CVE-2016-9297 | 3hous          | measure the code coverage data |

> CVE-2017-13028: Out-of-bounds Read vulneratibily.

## 2. Learning Target 

1. 什么是 Code Coverage，代码覆盖率
2. 使用 LCOV 对代码覆盖率进行测量
3. 如何通过代码覆盖率的优化提升Fuzzing性能

## 3. Fuzzing

### 1. Workflow

1. 开启 ASan 功能，对 LibTiff 库进行fuzz
2. 分析 crash ，找到对应漏洞的 PoC
3. 测量该 PoC 的代码覆盖率情况
4. 修复漏洞

### 2. Solution

#### 1. Download and build target

首先创建待 fuzz 的 LibTiff 环境，进行编译待用：

```SHELL
cd $HOME/Desktop/Fuzz/training
mkdir fuzzing_tiff && cd fuzzing_tiff/

# download and uncompress the target
wget https://download.osgeo.org/libtiff/tiff-4.0.4.tar.gz
tar -xzvf tiff-4.0.4.tar.gz

# make and install libtiff
cd tiff-4.0.4/
./configure --prefix="$HOME/Desktop/Fuzz/training/fuzzing_tiff/install/" --disable-shared
make
make install


# test the target program
$HOME/Desktop/Fuzz/training/fuzzing_tiff/install/bin/tiffinfo -D -j -c -r -s -w $HOME/Desktop/Fuzz/training/fuzzing_tiff/tiff-4.0.4/test/images/palette-1c-1b.tiff

```

以上安装不报错的话，可以正常调用 LibTiff 库 ：

![image-20210909173303686](https://cdn.jsdelivr.net/gh/AlexsanderShaw/BlogImages@main/img/vuln/shebei20210909173303.png)

在上面的启动命令中，基本开启了软件的所有参数，这样有利于在进行fuzz时执行更多的代码路径，从而获得更高的代码覆盖率。

#### 2. Seed corpus creation

直接使用 `test/images` 文件夹下的测试用例作为本次fuzz的语料。

#### 3. Code Coverage

代码覆盖率是一种软件指标，表达了每行代码被触发的次数。通过使用代码覆盖率，我们可以了解 fuzzer 已经到达了代码的哪些部分，并可视化了 fuzzing 过程。

首先，需要安装 `lcov`：

```shell
sudo apt install lcov
```

然后，我们使用 `--coverage`选项来重建libTIFF库：

```shell
rm -r $HOME/Desktop/Fuzz/training/fuzzing_tiff/install
cd $HOME/Desktop/Fuzz/training/fuzzing_tiff/tiff-4.0.4/
make clean
  
CFLAGS="--coverage" LDFLAGS="--coverage" ./configure --prefix="$HOME/Desktop/Fuzz/training/fuzzing_tiff/install/" --disable-shared
make
make install
```

然后使用下面的指令来进行代码覆盖率收集：

```shell
cd $HOME/Desktop/Fuzz/training/fuzzing_tiff/tiff-4.0.4/
lcov --zerocounters --directory ./   # 重置计数器
lcov --capture --initial --directory ./ --output-file app.info
$HOME/Desktop/Fuzz/training/fuzzing_tiff/install/bin/tiffinfo -D -j -c -r -s -w $HOME/Desktop/Fuzz/training/fuzzing_tiff/tiff-4.0.4/test/images/palette-1c-1b.tiff
lcov --no-checksum --directory ./ --capture --output-file app2.info # 返回“基线”覆盖数据文件，其中包含每个检测行的零覆盖
```

最后，生成HTML输出：

```shell
genhtml --highlight --legend -output-directory ./html-coverage/ ./app2.info
```

一切顺利的话，会生成以下文件：

![image-20210909173323318](/Users/yaoyao/Library/Application%20Support/typora-user-images/image-20210909173323318.png)

打开生成的 `index.html` 会看到如下结果：

![image-20210909173345104](https://cdn.jsdelivr.net/gh/AlexsanderShaw/BlogImages@main/img/vuln/shebei20210909173345.png)

#### 4. Fuzzing

重新编译：

```shell
rm -r $HOME/Desktop/Fuzz/training/fuzzing_tiff/install
cd $HOME/Desktop/Fuzz/training/fuzzing_tiff/tiff-4.0.4/
make clean

export LLVM_CONFIG="llvm-config-12"
CC=afl-clang-lto ./configure --prefix="$HOME/Desktop/Fuzz/training/fuzzing_tiff/install/" --disable-shared
# 开启AFL_USE_ASAN
AFL_USE_ASAN=1 make -j4
AFL_USE_ASAN=1 make install
```

执行 `afl-fuzz` :

```shell
afl-fuzz -m none -i $HOME/Desktop/Fuzz/training/fuzzing_tiff/tiff-4.0.4/test/images/ -o $HOME/Desktop/Fuzz/training/fuzzing_tiff/out/ -s 123 -- $HOME/Desktop/Fuzz/training/fuzzing_tiff/install/bin/tiffinfo -D -j -c -r -s -w @@
```

### 3. Crashes

最终跑得的结果如下：

![image-20210909173359342](https://cdn.jsdelivr.net/gh/AlexsanderShaw/BlogImages@main/img/vuln/shebei20210909173359.png)

## 4. Triage

ASan追踪结果如下：

![image-20210909173412017](https://cdn.jsdelivr.net/gh/AlexsanderShaw/BlogImages@main/img/vuln/shebei20210909173412.png)

![image-20210909173424407](https://cdn.jsdelivr.net/gh/AlexsanderShaw/BlogImages@main/img/vuln/shebei20210909173424.png)

## 5. Fix

官方的修复地址：

- https://github.com/the-tcpdump-group/tcpdump/commit/29e5470e6ab84badbc31f4532bb7554a796d9d52

后续将对该漏洞进行深入分析和补丁分析，待完善。



官方的修复地址：

- https://github.com/the-tcpdump-group/tcpdump/commit/29e5470e6ab84badbc31f4532bb7554a796d9d52

后续将对该漏洞进行深入分析和补丁分析，待完善。



