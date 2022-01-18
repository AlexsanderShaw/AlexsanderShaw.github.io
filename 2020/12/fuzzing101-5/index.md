# Fuzzing 101 -- 5


本文是Fuzzing101系列第五篇，fuzz的对象为 LibXML2 。

<!--more-->

## 1. Basic Info

| Target  | CVES to find  | Time estimated | Main topics                    |
| ------- | ------------- | -------------- | ------------------------------ |
| LibXML2 | CVE-2017-9048 | 3hous          | measure the code coverage data |

> CVE-2017-13028: Out-of-bounds Read vulneratibily.

## 2. Learning Target

1. 在fuzzer中使用自定义词典
2. 使用多个内核并行进行fuzz

## 3. Fuzzing

### 1. Workflow

1. 找到一个使用LibXML2共享库的应用程序
2. 复制SampleInput.xml文件到AFL的input目录
3. 创建fuzzing XML的常规目录
4. 开始fuzz，直到出现crash
5. 使用造成crash的poc重现crash
6. 修复漏洞

### 2. Solution

#### 1. Download and build target

首先创建待fuzz的LibXML2环境，进行编译待用：

```SHELL
cd $HOME
mkdir Fuzzing_libxml2 && cd Fuzzing_libxml2

# download and uncompress the target
wget http://xmlsoft.org/download/libxml2-2.9.4.tar.gz
tar xvf libxml2-2.9.4.tar.gz && cd libxml2-2.9.4/

# build and install libtiff
sudo apt-get install python-dev
CC=afl-clang-lto CXX=afl-clang-lto++ CFLAGS="-fsanitize=address" CXXFLAGS="-fsanitize=address" LDFLAGS="-fsanitize=address" ./configure --prefix="$HOME/Fuzzing_libxml2/libxml2-2.9.4/install" --disable-shared --without-debug --without-ftp --without-http --without-legacy --without-python LIBS='-ldl'
make -j$(nproc)
make install

# test the target program
./xmllint --memory ./test/wml.xml
```

以上安装不报错的话，可以正常调用LibXML库 ：

![image-20211102103036227](https://cdn.jsdelivr.net/gh/AlexsanderShaw/BlogImages@main/img/vuln/shebei20211102103041.png)

注意一下上面的warning，有提示如果出现AFL++崩溃的情况，可以考虑讲AFL_MAP_SIZE的大小设置为146056.

#### 2. Seed corpus creation

这里直接使用SampleInput.xml做为XML的样例：

```xml
<!DOCTYPE a []>
```

#### 3. Custom dictionary

这里直接使用AFL++提供的XML的dict：

```shell
mkdir dictionaries && cd dictionaries
wget https://github.com/AFLplusplus/AFLplusplus/blob/stable/dictionaries/xml.dict
cd ..
```

#### 4. Fuzzing

执行 `afl-fuzz` ，采用并行方式进行fuzz:

```shell
afl-fuzz -m none -i ./afl_in -o afl_out -s 123 -x ./dictionaries/xml.dict -M master -- ./xmllint --memory --noenc --nocdata --dtdattr --loaddtd --valid --xinclude @@

afl-fuzz -m none -i ./afl_in -o afl_out -s 234 -x ./dictionaries/xml.dict -S slave1 -- ./xmllint --memory --noenc --nocdata --dtdattr --loaddtd --valid --xinclude @@
```

![image-20211102144945349](https://cdn.jsdelivr.net/gh/AlexsanderShaw/BlogImages@main/img/vuln/shebei20211102144945.png)

### 3. Crashes

最终没有跑出来crash（肯定是哪里出了问题）：

![Snipaste_2021-11-02_23-13-12](https://cdn.jsdelivr.net/gh/AlexsanderShaw/BlogImages@main/img/vuln/shebei20211103091624.jpeg)

## 4. Triage

这里直接使用的是教程里的：

```shell
./xmllint --memory --noenc --nocdata --dtdattr --loaddtd --valid --xinclude './afl_out/default/crashes/id:000000,sig:06,src:003963,time:12456489,op:havoc,rep:4'
```

![image-20211103100115327](https://cdn.jsdelivr.net/gh/AlexsanderShaw/BlogImages@main/img/vuln/shebei20211103100115.png)

## 5. Fix

官方的修复地址：

- https://github.com/GNOME/libxml2/commit/932cc9896ab41475d4aa429c27d9afd175959d74

后续将对该漏洞进行深入分析和补丁分析，待完善。

