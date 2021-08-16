# Fuzzing 101 -- 2


本文是Fuzzing101系列第二篇，fuzz的对象为libexif库。

<!--more-->

## 1. Basic Info

| Target  | CVES to find                      | Time estimated | Main topics                                |
| ------- | --------------------------------- | -------------- | ------------------------------------------ |
| libexif | CVE-2009-3895, <br/>CVE-2012-2836 | 3hous          | aft-clang-lto, fuzz libraries, Eclipse IDE |
||||

- CVE-2009-3895: heap-based buffer overflow vulnerability.
- CVE-2012-2836: out-of-bounds read vulnerability.

## 2. Learning Target 

1. 如何对使用了外部库的应用进行fuzz
2. 使用 `afl-clang-lto` 进行fuzz，它比 `afl-clang-fast` 的速度更快
3. 使用 Eclipse IDE进行动态调试

## 3. Fuzzing

### 1. Workflow

1. 寻找使用了 `libexif` 库的应用接口
2. 创建 exif 样例的种子语料库
3. 使用 afl-clang-lto 编译 libexif 和选择的应用程序
4. 对 libexif 进行fuzz
5. 对 crash 进行分类过滤，确认每个漏洞的 PoC
6. 修复漏洞

### 2. Solution

#### 1. Download and build target

首先创建待fuzz的 libexif 环境，进行编译待用：

```shell
# download
wget https://github.com/libexif/libexif/archive/refs/tags/libexif-0_6_14-release.tar.gz
tar -xzvf libexif-0_6_15-release.tar.gz

# build and install libexif
cd libexif-libexif-0_6_15-release/
sudo apt install autopoint libtool gettext libpopt-dev
autoreconf -fvi
./configure --enable-shared=no --prefix="$HOME/Desktop/Fuzz/training/fuzzing_libexif/install/"
make
make install

# choosing an interface application
wget https://github.com/libexif/exif/archive/refs/tags/exif-0_6_15-release.tar.gz
tar -xzvf exif-0_6_15-release.tar.gz
# build and install exif command-line utility
cd ..
cd exif-exif-0_6_15-release/
autoreconf -fvi
./configure --enable-shared=no --prefix="$HOME/Desktop/Fuzz/traning/fuzzing_libexif/install/" PKG_CONFIG_PATH=$HOME/Desktop/Fuzz/traning/fuzzing_libexif/install/lib/pkgconfig
make
make install

```

备注：这里的libexif的版本最好选用 0_6_15 版本，14的版本make install会一直报错，而且没有出现过官方issue。为节省时间，更换了版本。

#### 2. Seed corpus creation

创建种子语料库，这里选用的是github上公开的一个exif的样例库：https://github.com/ianare/exif-samples。 

```shell
# download and unzip
cd $HOME/Desktop/Fuzz/training/fuzzing_libexif
wget https://github.com/ianare/exif-samples/archive/refs/heads/master.zip
unzip master.zip
```

安装完成后，使用 `exif` 检测一下样本，可以成功识别即可。

#### 3. aft-clang-lto instrumentation

使用 `afl-clang-lto` 重新对 libexif 和 exif 进行编译：

```shell
# recompile libexif with afl-clang-lto
rm -r $HOME/Desktop/Fuzz/training/fuzzing_libexif/install
cd $HOME/Desktop/Fuzz/training/fuzzing_libexif/libexif-libexif-0_6_15-release/
make clean
export LLVM_CONFIG="llvm-config-12" # llvm-config-version at least is 11
CC=afl-clang-lto ./configure --enable-shared=no --prefix="$HOME/Desktop/Fuzz/training/fuzzing_libexif/install/"
make
make install

# recompile exif with afl-clang-lto
cd $HOME/fuzzing_libexif/exif-exif-0_6_15-release
make clean
export LLVM_CONFIG="llvm-config-11"
CC=afl-clang-lto ./configure --enable-shared=no --prefix="$HOME/fuzzing_libexif/install/" PKG_CONFIG_PATH=$HOME/fuzzing_libexif/install/lib/pkgconfig
make
make install
```

#### 4. Start fuzz

编译完成后，可以使用afl++在 `afl-clang-lto` 模式下开始进行fuzz：

```shell
afl-fuzz -i $HOME/Desktop/Fuzz/training/fuzzing_libexif/exif-samples-master/jpg/ -o $HOME/Desktop/Fuzz/training/fuzzing_libexif/out/ -s 123 -- $HOME/Desktop/Fuzz/training/fuzzing_libexif/install/bin/exif @@
```

### 3. Crashes

最终跑得的结果如下（因为自动跑的，所以cycle超了）：

![image-20210816192229146](https://cdn.jsdelivr.net/gh/AlexsanderShaw/BlogImages@main/img/vuln/shebei20210816192235.png)

## 4. Debug

### 1. Eclipse setup

```shell
# install java
sudo apt install default-jdk

# download and run Eclipse
wget https://download.eclipse.org/technology/epp/downloads/release/2021-06/R/eclipse-cpp-2021-06-R-linux-gtk-x86_64.tar.gz
tar -zxvf eclipse-cpp-2021-06-R-linux-gtk-x86_64.tar.gz
```

解压完成后，进入文件夹，运行 `eclipse` 即可。

导入项目：选择 `File -> Import ` ， 然后选择 `C/C++`  里的 `Existing code as makefile project` 。然后选择 `Linux GCC` ，并选择代码路径。

调试：选择 `run -> Debug Configurations`，然后选择exif项目并且选定exif 可执行程序，然后设置 `Arguments` 中为crash 的绝对路径名，最后点击 `Debug` 即可。调试过程中，直接 `F8` 或者 `run -> Resume` 可以直接来到crash 现场。

#### 2. Eclipse crash debug

最后就是使用Eclipse进行crash的debug了，这个就不做记录了，需要花时间调试每个crash文件。

![image-20210816194955674](https://cdn.jsdelivr.net/gh/AlexsanderShaw/BlogImages@main/img/vuln/shebei20210816194955.png)




