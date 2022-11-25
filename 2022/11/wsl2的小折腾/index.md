# WSL2的小折腾


瞎折腾了一下WSL2，真的很香啊～

<!--more-->


## TL;DR

缘由可能谁都想不到，我在吃饭的时候刷手机，看到一个今年 DefCON上LiveCTF的视频，发现 perfect r※※※t 在解题的时候用的是wsl。其实这东西很早之前我试过，但是当时出于没有图形化界面和文件copy等操作的不方面的考虑（其实最主要是看到很多评论说有bug，我是图稳定，不是为了去解决各种bug），没有深入去使用，只是安装完，体验了一下，官方文档都没看的那种体验，就卸载了。但是，我看视频的时候，发现  perfect r※※※t 居然可以直接在WSL里启动Windows上的IDA。这把我惊艳到了！（没有去看这个功能什么时候出现的，但是就是一见钟情的感觉~）这样的话，我可以直接在WSL里把题目下载下来，然后直接在命令行把IDA拉起来，写exp的话可以直接在命令行把code拉起来，也就是说，不管是基于Linux还是Windows的操作，都可以直接在WSL里完成，完全不需要去手动找软件、拖文件这些操作，简直丝滑~于是，开始折腾。

## WSL2 不太重要的简介

首先给出Microsoft的[官方文档](https://learn.microsoft.com/en-us/windows/wsl/)，强烈建议直接看官方的原版英文文档。基本上后续遇到的问题，在这里都会有对应的解答，不是全部，是大部分。

这里贴一部分，不想去看官方文档的听我给你白话白话吧：

>WSL，全称“Windows Subsystem for Linux”，就是Windows下的Linux子系统，它是微软为开发者在Windows上开发的一个GNU/Linux环境，包括常规的命令行工具、基础设置和应用。有了它，你不需要再安装虚拟机，可以直接通过Windows去到一个Linux环境中，低耗能、高效率。

在WSL中，你可以进行的操作：

- 直接通过Microsoft Store安装GNU/Linux的发行版本；
- 运行常规的命令行工具，例如 `grep`, `sed`, `awk` 和其他的 ELF-64 二进制程序；
- 运行 Bash shell scripts和GNU/Linux命令行工具，包括：
  - Tools: vim, emacs, tmux
  - Languages: [NodeJS](https://learn.microsoft.com/en-us/windows/nodejs/setup-on-wsl2), Javascript, [Python](https://learn.microsoft.com/en-us/windows/python/web-frameworks), Ruby, C/C++, C# & F#, Rust, Go, etc.
  - Services: SSHD, [MySQL](https://learn.microsoft.com/en-us/windows/wsl/tutorials/wsl-database), Apache, lighttpd, [MongoDB](https://learn.microsoft.com/en-us/windows/wsl/tutorials/wsl-database), [PostgreSQL](https://learn.microsoft.com/en-us/windows/wsl/tutorials/wsl-database).
- 使用你安装的GNU/Linux发行版的包管理工具安装软件；
- 使用 Unix-like 命令行 shell 调用 Windows 应用程序；
- 在 Windows 上调用 GNU/Linux 应用程序；
- 直接在Windows的桌面环境中[运行GNU/Linux图形化程序](https://learn.microsoft.com/en-us/windows/wsl/tutorials/gui-apps)；
- [使用GUP加速](https://learn.microsoft.com/en-us/windows/wsl/tutorials/gpu-compute)进行机器学习、数据分析和其他的高性能计算场景。

基本上就是一个“加强版”的Linux，加强的点在于打通了虚拟环境中的Linux与物理环境的Windows的沟通和联系，不仅仅是软件层面，甚至是到达了硬件层面，可以直接使用GPU的算力。我对虚拟化不太熟悉，不知道常规的VMWare和Virtual Box这种软件是否也能实现这种效果。

**WSL1还是WSL2？**

这里比较推荐首先看下[What is the Windows Subsystem for Linux (WSL)?](https://learn.microsoft.com/en-us/windows/wsl/about)、[What's new with WSL 2?](https://learn.microsoft.com/en-us/windows/wsl/compare-versions#whats-new-in-wsl-2)、[Comparing WSL 1 and WSL 2](https://learn.microsoft.com/en-us/windows/wsl/compare-versions)这三部分的内容，至少你要懂得你正在鼓捣的是什么东西。而且，WSL是有两个版本的，我们作为用户先不管内部变化，最直观的不同是安装方式和步骤的不一样。非要对比feature的话，这里给个直观图：

![image-20221125111809657](https://cdn.jsdelivr.net/gh/AlexsanderShaw/BlogImages@main/img/202211251118725.png)

看了这个图之后，我果断选择了WSL2，毕竟 `Full Linux Kernel` 的支持在那太耀眼了。但是需要注意的是，WSL2对Windows版本是有要求的，必须是 `Windows 11 or Windows 10, Version 1903, Build 18362 or later`。如果你的系统版本低于这个，我的个人建议是升级系统版本去使用WSL2，尽可能不再去使用WSL1（bug多，且修复率低到离谱。我一度怀疑是不是WSL1的bug到了不值得再修复而开发了WSL2）。

## WSL2的安装和配置

### Install

1. 版本检查

​	首先系统版本要求Windows 10版本 2004 及更高版本（内部版本 19041 及更高版本）或 Windows 11，我还是比较建议大家升级Windows 11的，目前为止还没有发现让我忍受不了的Bug。

2. 启用虚拟功能和虚拟机平台功能

   可以先查看一下自己是否已经开启了虚拟化支持：`任务管理器->性能`

   ![image-20221125140159448](https://cdn.jsdelivr.net/gh/AlexsanderShaw/BlogImages@main/img/202211251401506.png)

   然后开启`适用于Linux的Windows子系统`功能，有两种方式，第一种是管理员启动PowerShell，执行：

   `dism.exe /online /enable-feature /featurename:Microsoft-Windows-Subsystem-Linux /all /norestart`，另外一种是通过GUI来开启，`控制面板 -> 程序和功能 -> 启用或关闭Windows功能 `：

   ![image-20221125140516847](https://cdn.jsdelivr.net/gh/AlexsanderShaw/BlogImages@main/img/202211251405922.png)

​		然后启用`虚拟机平台`功能：`dism.exe /online /enable-feature /featurename:VirtualMachinePlatform /all /norestart`，GUI的在上面已经点上了。

3. 更新 Linux 内核：

   这一步是一定要做的，避免出现各种奇奇怪怪的问题（别问我怎么知道的-。-）：`wsl --update`。这里在更新完内核之后，最好是重启一下系统，避免在后面安装发行版的时候出问题。

4. 设置WSL2为默认版本：

   这一步问题不大，毕竟使用WSL2默认也会是2版本，但是为了保险，还是设置一下，毕竟在一些情况下是可以跳转到1版本的：`wsl --set-default-version 2`

### Setting

发行版我这里选择的是Ubuntu，用习惯了，而且选的是22.04版本，因为我的一些项目需要使用的Python版本要求较高，需要是3.10。

>踩坑：
>
>这里我本来是上的20.04版本的Ubuntu，它的默认Python版本是3.8，然后在跑项目的时候出现了问题。我就想着再弄个多Python环境，虽然设置默认Python版本是新下载的3.10，但是在apt install的时候还是会用系统的Python。但是，我又不想更改系统全局Python版本（鬼知道会出现什么问题-。-）。
>
>在安装pip的时候，也是使用的系统版本Python，所以下载下来的pip都是基于3.8的。所以我就用get-pip.py去安装3.10的pip，但是遇到了网速问题，根本下载不下来，上了代理也是不管用，不知道为什么。
>
>被网络问题搞烦了之后，我就决定换最新的22版本了。一开始主要是担心可能会存在适配问题不稳定，所以先上了使用最多的20版本，但是现在实在是不想去解决20版本上的Python环境问题了。好吧，我承认我懒了~

直接在 Microsoft Store 搜索 Ubuntu，选择22版本下载即可。如果你的地区在CN，退掉你的代理，网速会快一些。

下载安装完成后，在开始菜单和应用程序列表中也会出现新增的Ubuntu 22.04：

![image-20221125141852932](https://cdn.jsdelivr.net/gh/AlexsanderShaw/BlogImages@main/img/202211251418026.png)

点击启动，然后根据提示建立用户和设置密码，即可安装完成。

然后在 terminal 中查看安装情况：

![image-20221125142231564](https://cdn.jsdelivr.net/gh/AlexsanderShaw/BlogImages@main/img/202211251422673.png)

进入到这个Ubuntu有两种方式，第一种是直接点击这个应用，会弹出一个shell：

![image-20221125142014911](https://cdn.jsdelivr.net/gh/AlexsanderShaw/BlogImages@main/img/202211251420951.png)

这种我不喜欢，所以我选择直接在 Terminal 中直接输入 `ubuntu2204.exe` 来启动（只打ubuntu即可，会自动补全）：

![image-20221125142341535](https://cdn.jsdelivr.net/gh/AlexsanderShaw/BlogImages@main/img/202211251423667.png)

退出的话可以直接 `exit` 是注销登录，但是系统还是在后台执行的。可以用 `wsl --shutdown ` 来关掉后台运行的Ubuntu。（shutdown会将所有的发行都关掉-。-也就是说，如果你跑了两个Ubuntu，两个都会被关机。）关掉单个发行可以用 `wsl --terminate <distro>` 这种命令，就只会关掉你指定的发行版本了。

## Ubuntu的优化和配置

### 1. 常规Ubuntu配置

进来之后，可以进行常规的Ubuntu的配置。

在安装之前，搜了一些关于qemu的问题，但是我这里在安装的时候直接apt安装的，没有什么问题。也可以正常使用，估计是WSL2版本升级已经解决了网上存在的一些Bug。（如果是用WSL1的话，你还要额外配置qemu-kvm等很多东西，反正我是嫌麻烦。）

### 2. 与Windows交互

#### 1. 文件共享

WSL里面会自动将Windows的文件盘挂在到/mnt目录下，所以可以在/mnt目录下看到Windows的各个盘的文件，这是默认配置，不需要设置。此外，在Windows的文件资源管理器里，在左边的目录的最下面会有一个 `Linux` ，里面就是WSL安装的发行版本的文件系统。

![image-20221125145610544](https://cdn.jsdelivr.net/gh/AlexsanderShaw/BlogImages@main/img/202211251456576.png)

![image-20221125145635456](https://cdn.jsdelivr.net/gh/AlexsanderShaw/BlogImages@main/img/202211251456528.png)

所以你把要分析的文件放在什么位置都没有关系，两个系统都可以很方便地去访问到。

#### 2. 应用调用

WSL可以直接调用Windows的应用程序，这是因为WSL默认会把Windows的环境变量也包含进来：

![image-20221125145753318](https://cdn.jsdelivr.net/gh/AlexsanderShaw/BlogImages@main/img/202211251457436.png)

但是这样很多人不喜欢，因为系统隔离性很差，在执行命令的时候，不太容易区分，很容易在Linux中把Windows的工具给拉起来：

![image-20221125145904035](https://cdn.jsdelivr.net/gh/AlexsanderShaw/BlogImages@main/img/202211251459075.png)

去掉Windows环境变量也比较简单，在 wsl 下新建 /etc/wsl.conf 配置文件，并编辑如下内容：

```shell
 [interop]
 appendWindowsPath = false
```

然后重启 WSL 即可。

但是我个人感觉把，为了只在命令行工作，我是保留了Windows的环境变量的，因为这样我全程都可以在WSL中工作，不需要来回切换环境。尤其是对于开发来说，其实可以设置一个环境变量，在两个系统中通用。这本来是WSL的一个亮点，应该好好加以利用。

如果你实在忍受不了这么多的环境变量，就在 PATH 后面单独加上工具的路径，就是/mnt开头，就像上面的图里的最后两个。

#### 3. 网络代理

WSL配置代理也比较方便，但是网上的一些教程存在问题，所以需要实践一下。

代理，无非就是设置http、https、socks的转发嘛，但是对于WSL来说，有几个点需要注意一下：

首先，要确保你的代理软件是开了LAN的代理功能的，这样才能转到WSL那边去：

![image-20221125150713322](https://cdn.jsdelivr.net/gh/AlexsanderShaw/BlogImages@main/img/202211251507359.png)

然后，代理的IP地址不是写WSL自身的IP地址，而是写网关地址，也就是Windows中的WSL地址：

![image-20221125150620740](https://cdn.jsdelivr.net/gh/AlexsanderShaw/BlogImages@main/img/202211251506786.png)

最后，就是常规的 export 命令了，这里给出一个脚本：

```shell
✨🌊 v4ler1an ~ ➜ cat proxy.sh
#!/bin/sh
hostip=$(cat /etc/resolv.conf | grep nameserver | awk '{ print $2 }')
wslip=$(hostname -I | awk '{print $1}')
port=7890

PROXY_HTTP="http://${hostip}:${port}"

set_proxy(){
  export http_proxy="${PROXY_HTTP}"
  export HTTP_PROXY="${PROXY_HTTP}"

  export https_proxy="${PROXY_HTTP}"
  export HTTPS_proxy="${PROXY_HTTP}"

  export ALL_PROXY="${PROXY_SOCKS5}"
  export all_proxy=${PROXY_SOCKS5}

  git config --global http.https://github.com.proxy ${PROXY_HTTP}
  git config --global https.https://github.com.proxy ${PROXY_HTTP}

  echo "[+] Proxy has been opened."
  echo "[+] Git uses proxy too."
}

unset_proxy(){
  unset http_proxy
  unset HTTP_PROXY
  unset https_proxy
  unset HTTPS_PROXY
  unset ALL_PROXY
  unset all_proxy
  git config --global --unset http.https://github.com.proxy
  git config --global --unset https.https://github.com.proxy

  echo "[+] Proxy has been closed."
  echo "[+] Git setting has been cleaned."
}

test_setting(){
  echo "[+] Host IP: " ${hostip}
  echo "[+] WSL IP: " ${wslip}
  echo "[+] Try to connect to Google..."
  resp=$(curl -I -s --connect-timeout 5 -m 5 -w "%{http_code}" -o /dev/null www.google.com)
  if [ ${resp} = 200 ]; then
    echo "[+] Proxy setup succeeded!"
  else
    echo "[+] Proxy setup failed!"
  fi
}

if [ "$1" = "set" ]
then
  set_proxy

elif [ "$1" = "unset" ]
then
  unset_proxy

elif [ "$1" = "test" ]
then
  test_setting
else
  echo "[+] Unsupported arguments."
fi
```

然后再设置一下alias就可以了：

```shell
alias proxy='source ~/proxy.sh set'
alias unproxy='source ~/proxy.sh unset'
alias ptest='source ~/proxy.sh test'
```

## WSL2踩坑

### 1. 参考的对象类型不支持尝试的操作

对应的英文信息是：`The attempted operation is not supported for the type of object referenced.`，有很大可能在第一次运行安装的Linux的时候就出现这个问题，不解决的话用户创建不了，系统进不去。

**Solution**

之前从来没有遇到过这种问题，Microsoft 官方文档也没有看到对应的问题和 Solution，后来去看了WSL的issue，发现了一个相关的[issue](https://github.com/microsoft/WSL/issues/4177)，发现这个问题是跟VPN有关。

如果你的电脑上安装了VPN软件，可能会修改主机操作系统的VPN相关的设置，这个时候**可能**会出现这个问题，解决方案也比较简单，有两种方式，一种是临时的：执行一下 `netsh winsock reset` 就可以解决这个问题，但是有可能在重启系统后就失效；一种是非临时的，需要在注册表新增一个项，这种在重启主机系统后还会有效：

```shell
Windows Registry Editor Version 5.00

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WinSock2\Parameters\AppId_Catalog\0408F7A3]
"AppFullPath"="C:\\\\windows\\\\system32\\\\wsl.exe"
"PermittedLspCategories"=dword:80000000
```

把上面的内容保存成一个 reg 文件，然后管理员运行即可新增对应注册表项。

这个问题从Windows 10的时候就存在，但是直到Windows 11的最新版本，还没有解决。虽然网上有了经过验证的有效的解决方案，但是微软官方始终没有解决这个问题。我感觉WSL的开发者应该是有心无力，毕竟WSL的定位应该还只是一个应用级别的软件，而不像Windows系统中VPN组件这么核心。因为目前这个问题的出现大概率跟VPN模块有关，如果要修复，很有可能会涉及到VPN模块和网络模块，那就不是WSL的开发者自己能搞得定的了。

对了，解决方案里还有一个什么工具可以解决这个问题，但是我个人还是建议能不用工具就不用工具，直接写个注册表也不是很麻烦。

### 2. pip安装超时

前面有说我是安装过20版本的Ubuntu的，当时想装一个python 3.10和对应的pip，但是遇到了pip安装不上的问题，其实命令很简单：

```shell
curl https://bootstrap.pypa.io/get-pip.py -o get-pip.py
python3 get-pip.py
```

但是在执行后面的py文件的时候，首先是网络连接慢，可以理解，毕竟pypi他们之前就出现过网络问题，所以这个时候最好是开代理。然后，我使用sudo命令去执行了第二个命令，发现还是么有网速，死活下载不下来那个2.1M的文件。最后，去掉了sudo，秒安装-。-。这个怪我自己。然后，在更新的时候：

```shell
python3 -m pip install --upgrade pip
```

这个时候我已经设置了默认python为新装的python3.10，又遇到了网络问题，更新不了，开代理也没有用。

最后，妥协了，用的国内的源-。-：

```shell
python3 -m pip install --upgrade pip -i http://mirrors.aliyun.com/pypi/simple/ 
```

到这里基本解决了python3.10和pip的问题，但是在后面安装我的那个工具的时候，发现它还是会默认使用系统的python3.8，而且在apt的时候，下载的也是python3.8的依赖。这个时候我已经心态爆炸，懒得去弄了，所以后面换了22版本的Ubuntu。

其实python多版本的问题直接用pyenv就可以解决，但就是头铁，不想装这么多乱七八糟的东西，奔着死活不用就想去解决问题的态度，我换了系统版本。






