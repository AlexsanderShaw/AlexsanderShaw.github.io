# 多版本gcc共存方案


## 前言

有时需要进行交叉编译的时候，可能需要在高版本的架构上编译一个低版本的工具来运行到一个旧平台上。高版本的架构一般自带的都是高版本工具，这样编译出来的工具无法在低版本架构上运行，所以就有了多版本编译器共存的情况。这里我们以 gcc 为例简单说一下多版本 gcc 共存的解决方案，其实很简单。

## 安装低版本gcc/g++

在高版本的 Linux 上的源里是不能直接 apt 去安装低版本的 gcc/g++ 的，所以这里简单记录下如何在高版本的 Ubuntu 上也可以直接 apt 安装。

1. 换源

   既然高版本的源里没有安装包，直接更新一下低版本的源好了。以 gcc-4.8 为例，这里首先把 ubuntu 16.04 的源更新到 /etc/apt/sources.list中去：

    ```c
    # official
    deb http://dk.archive.ubuntu.com/ubuntu/ xenial main
    deb http://dk.archive.ubuntu.com/ubuntu/ xenial universe

    # 国内源aliyun
    deb http://mirrors.aliyun.com/ubuntu/ xenial main
    deb-src http://mirrors.aliyun.com/ubuntu/ xenial main
    deb http://mirrors.aliyun.com/ubuntu/ xenial-updates main
    deb-src http://mirrors.aliyun.com/ubuntu/ xenial-updates main
    deb http://mirrors.aliyun.com/ubuntu/ xenial universe
    deb-src http://mirrors.aliyun.com/ubuntu/ xenial universe
    deb http://mirrors.aliyun.com/ubuntu/ xenial-updates universe
    deb-src http://mirrors.aliyun.com/ubuntu/ xenial-updates universe
    deb http://mirrors.aliyun.com/ubuntu/ xenial-security main
    deb-src http://mirrors.aliyun.com/ubuntu/ xenial-security main
    deb http://mirrors.aliyun.com/ubuntu/ xenial-security universe
    deb-src http://mirrors.aliyun.com/ubuntu/ xenial-security universe
    ```

    然后 `sudo apt update` 一下，把包资源更新进来。

2. 安装

   可以先查看一下版本信息：`sudo apt-cache policy gcc-4.8` ，作用类似于搜索，下面所有能安装的子版本都会列出来。然后直接 `apt install` 对应的版本即可。
   这种方法不管想安装什么版本的旧软件，只要有对应的更新源即可。

## 版本控制

1. 第一种方法：

    直接在使用时指定 CC 或 CXX，跟上对应版本的 gcc/g++ 的绝对路径即可。个人感觉这样会更方便一点，只要在编译的时候指定一下变量即可。

2. 第二种方法：

    设置优先级：

    ```shell
    $ sudo update-alternatives --install /usr/bin/gcc gcc /usr/bin/gcc-4.8 40
    $ sudo update-alternatives --install /usr/bin/gcc gcc /usr/bin/gcc-9 90
    $ sudo update-alternatives --install /usr/bin/g++ g++ /usr/bin/g++4.8 40
    $ sudo update-alternatives --install /usr/bin/g++ g++ /usr/bin/g++-9 90
    # 
    ```

    数字越大，表示优先级越高，上面的例子中就是优先使用 `gcc-9` ，这个具体的数字不用特别关注，只要能体现出来大小来表达优先级就可以。

    删除设置的优先级：

    ```shell
    $ sudo update-alternatives --remove /usr/bin/g+±4.8
    ```

    切换版本可以通过以下命令：

    ```shell
    $ sudo update-alternatives --config gcc
    $ sudo update-alternatives --config g++
    ```

    选择对应的数字即可，然后回车即可切换版本。

