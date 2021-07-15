# QEMU + Busybox 模拟 Linux 内核环境


# QEMU + Busybox 模拟 Linux 内核环境

## 前言

最近转Linux平台，开始深入Linux内核相关，总结一下进行Linux内核环境模拟流程。结合Linux的内核源码一起，效果会比较好。

## 准备环境

### 主机环境

Ubuntu 18.04

Linux ubuntu 5.4.0-58-generic #64~18.04.1-Ubuntu SMP Wed Dec 9 17:11:11 UTC 2020 x86_64 x86_64 x86_64 GNU/Linux

### 需要使用的软件

使用主流的qemu+busybox进行模拟，底层的模拟实现软件内部完成，可以将重心放在内核调试上，避免在环境上浪费过多时间。qemu模拟器原生即支持gdb调试器，所以可以方便地使用gdb的强大功能对操作系统进行调试。

1. 首先安装qemu，依次执行以下命令：

    ```bash
    sudo apt-get install qemu 
    sudo apt-get install qemu-system
    sudo apt-get install qemu-user-static
    ```

    这里不建议使用源码编译的方式进行安装，个人建议是节省时间在核心工作上，工具越快搭建好越能提升效率。源码编译涉及到编译器和主机环境各异性的问题，中间可能出现各种情况，浪费时间。（注意，安装好后，无法直接qemu无法运行，需要使用`qemu-system-i386, qemu-system-x86_64, qemu-system-arm`这种格式的命令进行运行。如果嫌麻烦，可以设置软链接。）

2. 安装busybox，直接busybox的github上拖源码下来即可。在实际进行文件系统制作的时候再进行其他操作。

3. 最后是下载想进行编译的Linux内核源码，这里给出一个各个版本的[Linux内核源码集合](http://ftp.sjtu.edu.cn/sites/ftp.kernel.org/pub/linux/kernel/)。

## 编译调试版内核

### 编译正常流程

首先对Linux内核进行编译：

```bash
cd linux-3.18.6
make menuconfig
make bzImage
```

注意，这里在进入`menuconfig`后，需要开启内核参数`CONFIG_DEBUG_INFO`和`CONFIG_GDB_SCRIPTS`。gdb提供了python接口进行功能扩展，内核基于python接口实现了一系列辅助脚本来简化内核的调试过程。

```bash
Kernel hacking  ---> 
    [*] Kernel debugging
    Compile-time checks and compiler options  --->
        [*] Compile the kernel with debug info
        [*]   Provide GDB scripts for kernel debuggin
```

### 编译可能遇到的问题

执行make bzImage时遇到的问题：

1. `fatal error: linux/compiler-gcc7.h: No such file or directory`

    提示缺少compiler-gcc7.h这个文件，是由于内核版本较低和gcc版本不匹配造成的有三种解决方法：

        1.在内核文件夹中include/linux目录下找到compiler-gcc4.h文件，不同内核版本可能不一样，也有可能是compiler-gcc3.h,将它重命名为compiler-gcc7.h。然后重新编译一下就好了。

        2.在新的内核源码中拷贝一个compiler-gcc7.h，将它拷贝到内核文件夹include/linux目录下，重新编译即可。

        3.重装一个版本低一点的gcc。

2. `fatal error: asm/types.h: No such file or directory`

    linux添加到asm-generic的软链接: `ln -s /usr/include/asm-generic asm`

## 制作initramfs根文件系统

Linux启动阶段，boot loader加载完内核文件vmlinuz之后，便开始挂载磁盘根文件系统。挂载操作需要磁盘驱动，所以挂载前要先加载驱动。但是驱动位于`/lib/modules`，不挂载磁盘就访问不到，形成了一个死循环。`initramfs`根文件系统就可以解决这个问题，其中包含必要的设备驱动和工具，boot loader会加载initramfs到内存中，内核将其挂载到根目录，然后运行`/init`初始化脚本，去挂载真正的磁盘根文件系统。

### 编译busybox

首先需要注意，busybox默认编译的文件系统是和主机OS一样的位数，也就是Ubuntu是x86的，编译出的文件系统就是x86的，如果Ubuntu是x64的，编译出的文件系统是x64的。要保持前面编译的Linux内核和文件系统的位数一样。

```bash
cd busybox-1.32.0
make menuconfig
make -j 20
make install
```

进入menu后，修改参数如下：

![busybox_settings](https://cdn.jsdelivr.net/gh/AlexsanderShaw/BlogImages@main/img/CVE-2020-16899/busybox_menuconfig.png)

其次，修改为静态链接：

```bash
Settings  --->
    [*] Build static binary (no shared libs)
```

然后再执行make和install操作。

### 创建initramfs

编译成功后，会生成`_install`目录，其内容如下：

```bash
$ ls _install 
bin  linuxrc  sbin  usr
```

依次执行如下命令：

```bash
mkdir initramfs
cd initramfs
cp ../_install/* -rf ./
mkdir dev proc sys
sudo cp -a /dev/{null, console, tty, tty1, tty2, tty3, tty4} dev/
rm linuxrc
vim init
chmod a+x init
```

其中`init`文件的内容如下：

```bash
#!/bin/busybox sh         
mount -t proc none /proc  
mount -t sysfs none /sys  

exec /sbin/init
```

在创建的initramfs中包含busybox可执行程序、必须的设备文件、启动脚本`init`，且`init`只挂载了虚拟文件系统`procfs`和`sysfs`，没有挂载磁盘根文件系统，所有操作都在内存中进行，不会落地。

最后打包initramfs：

```bash
find . -print0 | cpio --null -ov --format=newc | gzip -9 > ../initramfs.cpio.gz
```

## 启动内核

```bash
qemu-system-i386 -s -kernel /path/to/bzImage -initrd initramfs.cpio.gz -nographic -append "console=ttyS0"
```

参数说明：
- `-s`是`-gdb tcp::1234`缩写，监听1234端口，在GDB中可以通过`target remote localhost:1234`连接；
- `-kernel`指定编译好的调试版内核；
- `-initrd`指定制作的initramfs;
- `-nographic`取消图形输出窗口；
- `append "console=ttyS0"`将输出重定向到console，将会显示在标准输出stdio。

启动后的根目录，就是initramfs中包含的内容：

![qemu_success](https://cdn.jsdelivr.net/gh/AlexsanderShaw/BlogImages@main/img/CVE-2020-16899/qemu_success.png)

至此，一个简单的内核就算编译完成了，可以挂gdb进行调试了。

