# Linux开机引导和启动过程详解



# Linux开机引导和启动过程详解

## 一、概述

操作系统的启动过程本质上分为2个阶段：`boot`（引导）阶段和`startup`（启动）阶段。引导阶段开始于打开电源剋管，结束于内核初始化完成和`systemd`进程成功运行；启动阶段接管了剩余的其他的工作，一直到OS进入可操作状态。其涵盖的内容可以用下图表示：

![总体](https://cdn.jsdelivr.net/gh/AlexsanderShaw/BlogImages@main/img/CVE-2020-16899/总体概览.jpg)

本文主要以[GRUB](https://zh.wikipedia.org/wiki/GNU_GRUB)和[systemd](https://zh.wikipedia.org/wiki/Systemd)为载体，尽可能详细地描述OS的引导和启动过程。

## 二、引导过程

引导过程的初始化可以通过2种方式实现：关机状态下的电源开启，开机状态的OS重启。其过程主要有以下几个阶段：

### 1. 硬件启动流程

#### 1. BIOS上电自检（POST）

BIOS的第一步是上电自检，检查硬件的基本功能是否正常。如果POST失败，那么引导过程失败，电脑启动失败。POST检查成功后，产生一个BIOS中断 -- [INT 13H](https://zh.wikipedia.org/wiki/BIOS%E4%B8%AD%E6%96%B7%E5%91%BC%E5%8F%AB)，该中断指向某个接入的可引导设备的引导扇区。它所找到的包含有效的引导记录的第一个引导扇区将被装在到内存0x7c00处，并且控制权也将从引导扇区转移到此段代码。也就是说，该中断指向的中断服务程序实际上就是磁盘服务程序，其主要用途就是将指定扇区的代码加载到内存的指定位置。

BIOS中包含了CPU的相关信息、设备启动顺序信息、硬盘信息、内存信息、时钟信息、PnP特性等，因此BIOS信息对于计算机来说十分重要。只有顺利通过BIOS自检，计算机才能继续后续流程，知道应该去读取哪个硬件设备。在BIOS将OS的控制权交给硬盘的第一个扇区后，就开始由Linux来控制系统了。

#### 2. 读取MBR

POST结束后，BIOS会在接入的磁盘中查找引导记录，其通常位于MBR，它加载它找到第一个引导记录到内存中，并开始执行代码。MBR是磁盘上第0磁道的第一个扇区 -- Master Boot Record，大小为512字节，里面存放了预启动信息、分区表信息，总体可分为2部分：第一部分为引导（PRE-BOOT）区，大小为446字节，其内容为引导代码，这446字节的文件通常被叫做引导镜像(boot.img)；第二部分为分区表（PARTITION PABLE），大小为66字节，记录硬盘分区信息。（MBR的详细描述可见文章[MBR详述](http://www.v4ler1an.com/2020/11/mbr/)）

系统找到BIOS指定的磁盘的MBR后，就将其复制到0x7c00地址所处的物理内存中。这里被复制的内容，就是boot loader，常见的有lilo，grub，grub2等。

由于这一阶段的引导代码的空间只有446字节，所以无法完成理解文件系统结构等功能，因此需要再找一个位于引导记录和设备第一个分区之间的位置来实现更多功能。而这个位置，就是boot loader所在位置。

### 2. Boot Loader启动引导阶段

boot loader是在OS内核运行之前运行的一段小程序。通过这段小程序，可以初始化硬件设备、建立内存空间的映射图等，从而将系统的软硬件环境设置完备，为OS内核做好一切准备工作。

#### 1. Stage 1

Stage1阶段所执行的代码为在执行系统安装时就预先写入到MBR的Boot Loader中的代码，其主要作用是将磁盘0磁道第2扇区的内容读入内存并执行，它是Stage 1.5阶段或Staget 2阶段的入口。

#### 2. Stage 1.5

由于一些历史技术原因，在第一个分区的开始位置在扇区63和MBR之间遗留了62个512字节的扇区（总计31744字节）。该区域就可以用于存储完善功能的实现代码core.img，大小为25389字节。此时，该空间中可以容纳一些通用的文件系统驱动程序，如标准的ext，fat等。

Stage 1.5阶段是Stage 1阶段和Stage 2阶段的中间桥梁。Stage 1.5阶段具有识别启动分区文件系统的能力，此后GRUB程序便有能力去访问/boot分区下/grub目录下的Stage 2文件，并将Stage 2载入内存执行。

#### 3. Stage 2

Stage 2阶段时，所有的文件都已存放在/boot/grub目录及其子目录下。Stage 2阶段执行时，首先会解析GRUB程序的配置文件`grub.conf`，并依配置文件决定是否显示系统启动菜单（列出可被加载执行的内核列表）。然后加载内核镜像到内存中，通过`initrd`程序建立Ramdisk内存虚拟根文件系统。此时控制权将转交给内核程序。

以上各个Stage中GURB和MBR的情况如下图：

![grub_mbr](https://cdn.jsdelivr.net/gh/AlexsanderShaw/BlogImages@main/img/CVE-2020-16899/1920px-GNU_GRUB_on_MBR_partitioned_hard_disk_drives.svg.png)

### 3. 内核引导流程

内核引导阶段主要通过在内存中建立虚拟根文件系统实现相关设备的驱动并建立和切换到真正的根文件系统。内核文件均以一种自解压的压缩格式存储以节省空间，它与一个初始化的内存映像和存储设备映射表都存储于/boot目录下。

在选定的内核加载到内存中并开始执行后，在其进行任何工作之前，内核文件首先必须从压缩格式解压自身，此时屏幕一般会输出“Uncom pressing Linux”的提示，当解压缩完成后，输出“OK, booting the kernel”。

解压内核镜像加载到内存，以及`initrd`程序建立Ramdisk内存虚拟根文件系统后，内核开始驱动基本硬件，并调用虚拟根文件系统中的`init`程序加载驱动模块初始化系统中各种设备的相关配置工作，其中包括CPU、I/O、存储设备等。当所需的驱动程序加载完后，会根据grub.conf配置文件中“root=XXX”部分所指定的内容创建一个根设备，然后将根文件系统以只读的方式挂载，并切换到真正的根文件系统上，同时调用系统进程的老祖宗进程/sbin/init程序，进入系统初始化阶段。

这里涉及到一个关键函数：`start_kernel()`函数（后续将单独出一篇文章进行该函数的调试），它主要执行了以下操作：

1. 在屏幕上打印出当前的内核版本信息。
2. 执行`setup_arch()`，对系统结构进行设置。
3. 执行`sched_init()`，对系统的调度机制进行初始化。先是对每个可用CPU上的`runqueque`进行初始化;然后初始化0号进程(其task struct和系统空M堆栈在`startup_32()`中己经被分配)为系统idle进程，即系统空闲时占据CPU的进程。
4. 执行`parse_early_param()`和`parsees_args()`解析系统启动参数。
5. 执行`trap_in itQ`，先设置了系统中断向量表。0－19号的陷阱门用于CPU异常处理;然后初始化系统调用向量;最后调用cpu_init()完善对CPU的初始化，用于支持进程调度机制，包括设定标志位寄存器、任务寄存器、初始化程序调试相关寄存器等等。
6. 执行`rcu_init()`，初始化系统中的Read-Copy Update互斥机制。
7. 执行`init_IRQ()`函数，初始化用于外设的中断，完成对IDT的最终初始化过程。
8. 执行`init_timers()`, `softirq_init()`和`time_init()`函数，分别初始系统的定时器机制，软中断机制以及系统日期和时间。
9. 执行`mem_init()`函数，初始化物理内存页面的page数据结构描述符，完成对物理内存管理机制的创建。
10. 执行`kmem_cache_init()`,完成对通用slab缓冲区管理机制的初始化工作。
11. 执行`fork_init()`，计算出当前系统的物理内存容量能够允许创建的进程(线程)数量。
12. 执行`proc_caches_init()`, `bufer_init()`, `unnamed_dev_init()` ,`vfs_caches_init()`, `signals_init()`等函数对各种管理机制建立起专用的slab缓冲区队列。
13. 执行`proc_root_init()`函数，对虚拟文件系统/proc进行初始化。

在`start_kenrel()`的结尾，内核通过`kenrel_thread()`创建出第一个系统内核线程(即1号进程)，该线程执行的是内核中的`init()`函数，负责的是下一阶段的启动任务。最后调用cpues_idle()函数:进入了系统主循环体口默认将一直执行`default_idle()`函数中的指令，即CPU的halt指令，直到就绪队列中存在其他进程需要被调度时才会转向执行其他函数。此时，系统中唯一存 在就绪状态的进程就是由`kerne_hread()`创建的init进程(内核线程)，所以内核并不进入`default_idle()`函数，而是转向`init()`函数继续启动过程。

完成以上过程后，Linux内核已可以正常运行。

### 4. 系统初始化流程

该步骤主要完成通过/sbin/init,init程序准备软件运行坏境，启动系统服务

通过/etc/inittab文件确定运行级别，然后去执行系统初始化脚本/etc/rc.sysinit,为用户初始化用户空间环境，在完成初始化后，根据运行级别，系统开始对应级别的目录启动服务，关闭那些不要的服务（里面S99local -> ../rc.local）用户自动服务启动脚本。

#### 关键文件详解

##### 1. 系统启动级别：`/etc/inittab`文件

```bash
# inittab is only used by upstart for the default runlevel.
#
# ADDING OTHER CONFIGURATION HERE WILL HAVE NO EFFECT ON YOUR SYSTEM.
#
# System initialization is started by /etc/init/rcS.conf
#
# Individual runlevels are started by /etc/init/rc.conf
#
# Ctrl-Alt-Delete is handled by /etc/init/control-alt-delete.conf
#
# Terminal gettys are handled by /etc/init/tty.conf and /etc/init/serial.conf,
# with configuration in /etc/sysconfig/init.
#
# For information on how to write upstart event handlers, or how
# upstart works, see init(5), init(8), and initctl(8).
#
# Default runlevel. The runlevels used are:
#   0 - halt (Do NOT set initdefault to this) 关机
#   1 - Single user mode 单用户模式，root用户，无需认证，维护模式；
#   2 - Multiuser, without NFS (The same as 3, if you do not have networking)， 多用户模式，会启动网络功能，但是不会启动NFS，维护模式；
#   3 - Full multiuser mode 完全功能模式，文本界面；
#   4 - unused 预留
#   5 - X11 完全功能模式，图形界面，此处使用的图形界面为X11
#   6 - reboot (Do NOT set initdefault to this)   重启
#
id:3:initdefault:
```

##### 2. 系统初始化脚本：`/etc/rc.d/rc.sysinit`

该文件在各个不同的发布版本中存在不同，此处仅以centos作为样例进行解释。

`/etc/rc.v/rc.sysinit`主要的工作大概有以下几项：

1. 获取网络环境和主机类型：读取网络设置文件`/etc/sysconfig/network`，获取主机名以及网关等网络环境；

2. 测试与挂载内存设备`/proc`和USB设备`/sys`：除挂载内存设备外，还会主动检查系统上是否存在USB设备，如果有，则载入对应的驱动，并挂载USB的文件系统；

3. 判断是否启动SELinux：SELinux，全称Security Enhance Linux套件，其主要作用是强化Linux操作环境的安全性；

4. 周边设备的检查与PnP(Plug and Play）参数的测试：根据内核在开机时的检查结果（/proc/sys/kernel/modprobe）开始i 进行ide/scsi/network/audio等周边设备的检查，并利用已装在的kernel模块进行PnP设备的参数测试；

5. 载入用户自定义模块：用户可以在`/etc/sysconfig/modules/*.modules`设置要加载的模块；

6. 载入内核的相关设置：系统会主动读取`/etc/sysctl.conf`的内容，根据其配置设置内核各选项；

7. 设置系统时间；

8. 设置console样式；

9. 设置RAID和LVM等功能；

10. 使用fsck进行磁盘文件系统检查；

11. 进行磁盘容量quota的转换（非必要）；

12. 重新以可读模式挂载系统磁盘；

13. 启动quota功能；

14. 启动系统随机装置（产生随机数功能）；

15. 清除开机过程中的缓存内容；

16. 将开机过程中的相关信息写入到`/var/log/dmesg`文件中。

```bash
#!/bin/bash
#
# /etc/rc.d/rc.sysinit - run once at boot time
#
# Taken in part from Miquel van Smoorenburg's bcheckrc.
#

# 获取主机名
HOSTNAME=$(/bin/hostname)

set -m

# 如果存在/etc/sysconfig/network则执行
if [ -f /etc/sysconfig/network ]; then
    . /etc/sysconfig/network
fi
# 执行后HOSTNAME如果为空或“(none)”，则设置主机名为localhost
if [ -z "$HOSTNAME" -o "$HOSTNAME" = "(none)" ]; then
    HOSTNAME=localhost
fi

# 挂在/proc和/sys，这样fsck才能使用卷标
if [ ! -e /proc/mounts ]; then
	mount -n -t proc /proc /proc   # -n表示不写/etc/mtab，因为此时的/为只读
	mount -n -t sysfs /sys /sys >/dev/null 2>&1 # 将/sys目录以sysfs格式挂载到/sys目录下
fi
# 如果存在/prc/bus/usb目录，则挂载usbfs到usb下
if [ ! -d /proc/bus/usb ]; then
	modprobe usbcore >/dev/null 2>&1 && mount -n -t usbfs /proc/bus/usb /proc/bus/usb
else
	mount -n -t usbfs /proc/bus/usb /proc/bus/usb
fi

# 挂载/etc/fstab文件中定义的所有文件系统
#remount /dev/shm to set attributes from fstab #669700
mount -n -o remount /dev/shm >/dev/null 2>&1
#remount /proc to set attributes from fstab #984003
mount -n -o remount /proc >/dev/null 2>&1

# 执行functions文件，该文件提供来很多有用的函数，具体内容可见参考文献5
. /etc/init.d/functions

PLYMOUTH=
[ -x /bin/plymouth ] && PLYMOUTH=yes # 在启动时显示一个动画

# 激活udev和selinux
# 检查SELinux状态
SELINUX_STATE=
if [ -e "/selinux/enforce" ] && [ "$(cat /proc/self/attr/current)" != "kernel" ]; then
	if [ -r "/selinux/enforce" ] ; then
		SELINUX_STATE=$(cat "/selinux/enforce")
	else
		# 如果无法成功读取，则直接置1
		SELINUX_STATE=1
	fi
fi

if [ -n "$SELINUX_STATE" -a -x /sbin/restorecon ] && __fgrep " /dev " /proc/mounts >/dev/null 2>&1 ; then
	/sbin/restorecon -R -F /dev 2>/dev/null
fi

disable_selinux() {
	echo $"*** Warning -- SELinux is active"
	echo $"*** Disabling security enforcement for system recovery."
	echo $"*** Run 'setenforce 1' to reenable."
	echo "0" > "/selinux/enforce"
}

relabel_selinux() {
    # if /sbin/init is not labeled correctly this process is running in the
    # wrong context, so a reboot will be required after relabel
    AUTORELABEL=
    . /etc/selinux/config
    echo "0" > /selinux/enforce
    [ -n "$PLYMOUTH" ] && plymouth --hide-splash

    if [ "$AUTORELABEL" = "0" ]; then
	echo
	echo $"*** Warning -- SELinux ${SELINUXTYPE} policy relabel is required. "
	echo $"*** /etc/selinux/config indicates you want to manually fix labeling"
	echo $"*** problems. Dropping you to a shell; the system will reboot"
	echo $"*** when you leave the shell."
	start rcS-emergency

    else
	echo
	echo $"*** Warning -- SELinux ${SELINUXTYPE} policy relabel is required."
	echo $"*** Relabeling could take a very long time, depending on file"
	echo $"*** system size and speed of hard drives."

	/sbin/fixfiles -F restore > /dev/null 2>&1
    fi
    rm -f  /.autorelabel
    # at this point fsck was already executed see bz1236062
    [ -f /forcefsck ] && rm -f /forcefsck

    echo $"Unmounting file systems"
    umount -a
    mount -n -o remount,ro /
    echo $"Automatic reboot in progress."
    reboot -f
}

# 设置欢迎信息
# Print a text banner.
echo -en $"\t\tWelcome to "
read -r system_release < /etc/system-release  # 读取系统发行版本
if [[ "$system_release" == *"Red Hat"* ]]; then
 [ "$BOOTUP" = "color" ] && echo -en "\\033[0;31m"
 echo -en "Red Hat"
 [ "$BOOTUP" = "color" ] && echo -en "\\033[0;39m"
 PRODUCT=$(sed "s/Red Hat \(.*\) release.*/\1/" /etc/system-release)
 echo " $PRODUCT"
elif [[ "$system_release" == *Fedora* ]]; then
 [ "$BOOTUP" = "color" ] && echo -en "\\033[0;34m"
 echo -en "Fedora"
 [ "$BOOTUP" = "color" ] && echo -en "\\033[0;39m"
 PRODUCT=$(sed "s/Fedora \(.*\) \?release.*/\1/" /etc/system-release)
 echo " $PRODUCT"
elif [[ "$system_release" =~ "CentOS" ]]; then
 [ "$BOOTUP" = "color" ] && echo -en "\\033[0;36m"
 echo -en "CentOS"
 [ "$BOOTUP" = "color" ] && echo -en "\\033[0;39m"
 PRODUCT=$(sed "s/CentOS \(.*\) \?release.*/\1/" /etc/system-release)
 echo " $PRODUCT"
else
 PRODUCT=$(sed "s/ release.*//g" /etc/system-release)
 echo "$PRODUCT"
fi

# Only read this once.
# 读取/proc/cmdline，这是内核启动时的参数，赋予了变量cmdline
cmdline=$(cat /proc/cmdline)

# 初始化硬件
# 查找/proc/sys/kernel/modprobe文件（该文件告诉内核用什么命令来加载模块）
if [ -f /proc/sys/kernel/modprobe ]; then
    # 如果$cmdline变量的值含有nomodules且存在/proc/modprobe，则使用sysctl
    # 设置kernel.modprobe为/sbin/modprobe命令
   if ! strstr "$cmdline" nomodules && [ -f /proc/modules ] ; then
       sysctl -w kernel.modprobe="/sbin/modprobe" >/dev/null 2>&1
   else
       # 不存在modprobe，则使用sysctl设置kernel.modprobe为/bin/true
       sysctl -w kernel.modprobe="/bin/true" >/dev/null 2>&1
   fi
fi

touch /dev/.in_sysinit >/dev/null 2>&1

# Set default affinity
if [ -x /bin/taskset ]; then
   if strstr "$cmdline" default_affinity= ; then
     for arg in $cmdline ; do
         if [ "${arg##default_affinity=}" != "${arg}" ]; then
             /bin/taskset -p ${arg##default_affinity=} 1
             /bin/taskset -p ${arg##default_affinity=} $$
         fi
     done
   fi
fi

nashpid=$(pidof nash 2>/dev/null)
[ -n "$nashpid" ] && kill $nashpid >/dev/null 2>&1
unset nashpid

apply_sysctl

/sbin/start_udev

# 加载其他用户自定义的模块
for file in /etc/sysconfig/modules/*.modules ; do
  [ -x $file ] && $file
done

# 加载模块
if [ -f /etc/rc.modules ]; then
	/etc/rc.modules
fi

mount -n /dev/pts >/dev/null 2>&1
[ -n "$SELINUX_STATE" ] && restorecon -F /dev/pts >/dev/null 2>&1

# 配置内核参数
update_boot_stage RCkernelparam
apply_sysctl

# 设置主机名
update_boot_stage RChostname
action $"Setting hostname ${HOSTNAME}: " hostname ${HOSTNAME}
[ -n "${NISDOMAIN}" ] && domainname ${NISDOMAIN}

# 等待存储同步
{ rmmod scsi_wait_scan ; modprobe scsi_wait_scan ; rmmod scsi_wait_scan ; } >/dev/null 2>&1

# 设备映射及相关初始化操作
if ! __fgrep "device-mapper" /proc/devices >/dev/null 2>&1 ; then
       modprobe dm-mod >/dev/null 2>&1
fi

if [ -f /etc/crypttab ]; then
    init_crypto 0
fi

if ! strstr "$cmdline" nompath && [ -f /etc/multipath.conf -a \
		-x /sbin/multipath ]; then
	modprobe dm-multipath > /dev/null 2>&1
	/sbin/multipath -v 0
	if [ -x /sbin/kpartx ]; then
                action_silent $"Add partition mappings: " /sbin/dmsetup ls --target multipath --exec "/sbin/kpartx -a -p p"
	fi
fi

if ! strstr "$cmdline" nodmraid && [ -x /sbin/dmraid ]; then
	modprobe dm-mirror >/dev/null 2>&1
	dmraidsets=$(LC_ALL=C /sbin/dmraid -s -c -i)
	if [ "$?" = "0" ]; then
		for dmname in $dmraidsets; do
			if [[ "$dmname" == isw_* ]] && \
			   ! strstr "$cmdline" noiswmd; then
				continue
			fi
                        action_silent $"Activate software (ATA)RAID: " /sbin/dmraid -ay -i --rm_partitions -p "$dmname"
			/sbin/kpartx -a -p p "/dev/mapper/$dmname"
		done
	fi
fi

# 启动MD设备
# Start any MD RAID arrays that haven't been started yet
[ -r /proc/mdstat -a -r /dev/md/md-device-map ] && action $"Run MD devices: " /sbin/mdadm -IRs

if [ -x /sbin/lvm ]; then
	if [ ! -f /.nolvm ] && ! strstr "$cmdline" nolvm ; then
		action $"Setting up Logical Volume Management:" /sbin/lvm vgchange -a ay --sysinit --ignoreskippedcluster
	else
		echo $"Logical Volume Management disabled at boot."
	fi
fi

if [ -f /etc/crypttab ]; then
    init_crypto 0
fi

if [ -f /fastboot ] || strstr "$cmdline" fastboot ; then
	fastboot=yes
fi

if [ -f /fsckoptions ]; then
	fsckoptions=$(cat /fsckoptions)
fi

if [ -f /forcefsck ] || strstr "$cmdline" forcefsck ; then
	fsckoptions="-f $fsckoptions"
elif [ -f /.autofsck ]; then
	[ -f /etc/sysconfig/autofsck ] && . /etc/sysconfig/autofsck
	if [ "$AUTOFSCK_DEF_CHECK" = "yes" ]; then
		AUTOFSCK_OPT="$AUTOFSCK_OPT -f"
	fi
	if [ -n "$AUTOFSCK_SINGLEUSER" ]; then
		[ -n "$PLYMOUTH" ] && plymouth --hide-splash
		echo
		echo $"*** Warning -- the system did not shut down cleanly. "
		echo $"*** Dropping you to a shell; the system will continue"
		echo $"*** when you leave the shell."
		[ -n "$SELINUX_STATE" ] && echo "0" > /selinux/enforce
		start rcS-emergency
		[ -n "$SELINUX_STATE" ] && echo "1" > /selinux/enforce
		[ -n "$PLYMOUTH" ] && plymouth --show-splash
	fi
	fsckoptions="$AUTOFSCK_OPT $fsckoptions"
fi

if [ "$BOOTUP" = "color" ]; then
	fsckoptions="-C $fsckoptions"
else
	fsckoptions="-V $fsckoptions"
fi

READONLY=
if [ -f /etc/sysconfig/readonly-root ]; then
	. /etc/sysconfig/readonly-root
fi
if strstr "$cmdline" readonlyroot ; then
	READONLY=yes
	[ -z "$RW_MOUNT" ] && RW_MOUNT=/var/lib/stateless/writable
	[ -z "$STATE_MOUNT" ] && STATE_MOUNT=/var/lib/stateless/state
fi
if strstr "$cmdline" noreadonlyroot ; then
	READONLY=no
fi

if [ "$READONLY" = "yes" -o "$TEMPORARY_STATE" = "yes" ]; then

	mount_empty() {
		if [ -e "$1" ]; then
			echo "$1" | cpio -p -vd "$RW_MOUNT" &>/dev/null
			mount -n --bind "$RW_MOUNT$1" "$1"
		fi
	}

	mount_dirs() {
		if [ -e "$1" ]; then
			mkdir -p "$RW_MOUNT$1"
			find "$1" -type d -print0 | cpio -p -0vd "$RW_MOUNT" &>/dev/null
			mount -n --bind "$RW_MOUNT$1" "$1"
		fi
	}

	mount_files() {
		if [ -e "$1" ]; then
			cp -a --parents "$1" "$RW_MOUNT"
			mount -n --bind "$RW_MOUNT$1" "$1"
		fi
	}

	# 暂存空间的通用安装选项，与后备存储类型无关
	mountopts=

	# 扫描分区以进行本地暂存
	rw_mount_dev=$(blkid -t LABEL="$RW_LABEL" -l -o device)

	# 首先尝试从/etc/fstab挂载暂存存储，然后从具有适当标签的任何分区挂载。 
    # 如果任何一个成功，需将暂存存储区清理干净。 
    # 如果两者均失败，则通过tmpfs挂载临时存储。
	if mount $mountopts "$RW_MOUNT" > /dev/null 2>&1 ; then
		rm -rf "$RW_MOUNT" > /dev/null 2>&1
	elif [ x$rw_mount_dev != x ] && mount $rw_mount_dev $mountopts "$RW_MOUNT" > /dev/null 2>&1; then
		rm -rf "$RW_MOUNT"  > /dev/null 2>&1
	else
		mount -n -t tmpfs $RW_OPTIONS $mountopts none "$RW_MOUNT"
	fi

	for file in /etc/rwtab /etc/rwtab.d/* /dev/.initramfs/rwtab ; do
		is_ignored_file "$file" && continue
	[ -f $file ] && cat $file | while read type path ; do
			case "$type" in
				empty)
					mount_empty $path
					;;
				files)
					mount_files $path
					;;
				dirs)
					mount_dirs $path
					;;
				*)
					;;
			esac
			[ -n "$SELINUX_STATE" -a -e "$path" ] && restorecon -R "$path"
		done
	done

	# Use any state passed by initramfs
	[ -d /dev/.initramfs/state ] && cp -a /dev/.initramfs/state/* $RW_MOUNT

	# In theory there should be no more than one network interface active
	# this early in the boot process -- the one we're booting from.
	# Use the network address to set the hostname of the client.  This
	# must be done even if we have local storage.
	ipaddr=
	if [ "$HOSTNAME" = "localhost" -o "$HOSTNAME" = "localhost.localdomain" ]; then
		ipaddr=$(ip addr show to 0.0.0.0/0 scope global | awk '/[[:space:]]inet / { print gensub("/.*","","g",$2) }')
		for ip in $ipaddr ; do
			HOSTNAME=
			eval $(ipcalc -h $ip 2>/dev/null)
			[ -n "$HOSTNAME" ] && { hostname ${HOSTNAME} ; break; }
		done
	fi

	# Clients with read-only root filesystems may be provided with a
	# place where they can place minimal amounts of persistent
	# state.  SSH keys or puppet certificates for example.
	#
	# Ideally we'll use puppet to manage the state directory and to
	# create the bind mounts.  However, until that's all ready this
	# is sufficient to build a working system.

	# First try to mount persistent data from /etc/fstab, then any
	# partition with the proper label, then fallback to NFS
	state_mount_dev=$(blkid -t LABEL="$STATE_LABEL" -l -o device)
	if mount $mountopts $STATE_OPTIONS "$STATE_MOUNT" > /dev/null 2>&1 ; then
		/bin/true
	elif [ x$state_mount_dev != x ] && mount $state_mount_dev $mountopts "$STATE_MOUNT" > /dev/null 2>&1;  then
		/bin/true
	elif [ ! -z "$CLIENTSTATE" ]; then
		# No local storage was found.  Make a final attempt to find
		# state on an NFS server.

		mount -t nfs $CLIENTSTATE/$HOSTNAME $STATE_MOUNT -o rw,nolock
	fi

	if [ -w "$STATE_MOUNT" ]; then

		mount_state() {
			if [ -e "$1" ]; then
				[ ! -e "$STATE_MOUNT$1" ] && cp -a --parents "$1" "$STATE_MOUNT"
				mount -n --bind "$STATE_MOUNT$1" "$1"
			fi
		}

		for file in /etc/statetab /etc/statetab.d/* ; do
			is_ignored_file "$file" && continue
			[ ! -f "$file" ] && continue

			if [ -f "$STATE_MOUNT/$file" ] ; then
				mount -n --bind "$STATE_MOUNT/$file" "$file"
			fi

			for path in $(grep -v "^#" "$file" 2>/dev/null); do
				mount_state "$path"
				[ -n "$SELINUX_STATE" -a -e "$path" ] && restorecon -R "$path"
			done
		done

		if [ -f "$STATE_MOUNT/files" ] ; then
			for path in $(grep -v "^#" "$STATE_MOUNT/files" 2>/dev/null); do
				mount_state "$path"
				[ -n "$SELINUX_STATE" -a -e "$path" ] && restorecon -R "$path"
			done
		fi
	fi

        if mount | grep -q /var/lib/nfs/rpc_pipefs ; then
                mount -t rpc_pipefs sunrpc /var/lib/nfs/rpc_pipefs && service rpcidmapd restart
        fi
fi

if [[ " $fsckoptions" != *" -y"* ]]; then
	fsckoptions="-a $fsckoptions"
fi

_RUN_QUOTACHECK=0
if [ -f /forcequotacheck ] || strstr "$cmdline" forcequotacheck ; then
	_RUN_QUOTACHECK=1
fi
if [ -z "$fastboot" -a "$READONLY" != "yes" ]; then

        STRING=$"Checking filesystems"
	echo $STRING
	fsck -T -t noopts=_netdev -A $fsckoptions
	rc=$?

	if [ "$rc" -eq "0" ]; then
		success "$STRING"
		echo
	elif [ "$rc" -eq "1" ]; then
	        passed "$STRING"
		echo
	elif [ "$rc" -eq "2" -o "$rc" -eq "3" ]; then
		echo $"Unmounting file systems"
		umount -a
		mount -n -o remount,ro /
		echo $"Automatic reboot in progress."
		reboot -f
        fi

        # A return of 4 or higher means there were serious problems.
	if [ $rc -gt 1 ]; then
		[ -n "$PLYMOUTH" ] && plymouth --hide-splash

		failure "$STRING"
		echo
		echo
		echo $"*** An error occurred during the file system check."
		echo $"*** Dropping you to a shell; the system will reboot"
		echo $"*** when you leave the shell."

                str=$"(Repair filesystem)"
		PS1="$str \# # "; export PS1
		[ "$SELINUX_STATE" = "1" ] && disable_selinux
		start rcS-emergency

		echo $"Unmounting file systems"
		umount -a
		mount -n -o remount,ro /
		echo $"Automatic reboot in progress."
		reboot -f
	elif [ "$rc" -eq "1" ]; then
		_RUN_QUOTACHECK=1
	fi
fi

remount_needed() {
  local state oldifs
  [ "$READONLY" = "yes" ] && return 1
  state=$(LC_ALL=C awk '/ \/ / && ($3 !~ /rootfs/) { print $4 }' /proc/mounts)
  oldifs=$IFS
  IFS=","
  for opt in $state ; do
	if [ "$opt" = "rw" ]; then
		IFS=$oldifs
		return 1
	fi
  done
  IFS=$oldifs
  return 0
}

# 重新以可读可写模式挂载根文件系统
update_boot_stage RCmountfs
if remount_needed ; then
  action $"Remounting root filesystem in read-write mode: " mount -n -o remount,rw /
fi

# 清理SELinux labels
if [ -n "$SELINUX_STATE" ]; then
   restorecon /etc/mtab /etc/ld.so.cache /etc/blkid/blkid.tab /etc/resolv.conf >/dev/null 2>&1
fi

# If relabeling, relabel mount points.
if [ -n "$SELINUX_STATE" -a "$READONLY" != "yes" ]; then
    if [ -f /.autorelabel ] || strstr "$cmdline" autorelabel ; then
	restorecon $(awk '!/^#/ && $4 !~ /noauto/ && $2 ~ /^\// { print $2 }' /etc/fstab) >/dev/null 2>&1
    fi
fi

if [ "$READONLY" != "yes" ] ; then
	# 清理mtab
	(> /etc/mtab) &> /dev/null

	# 删除stale backups
	rm -f /etc/mtab~ /etc/mtab~~

	# 在/etc/mtab中输入已挂载的文件系统
	mount -f /
	mount -f /proc >/dev/null 2>&1
	mount -f /sys >/dev/null 2>&1
	mount -f /dev/pts >/dev/null 2>&1
	mount -f /dev/shm >/dev/null 2>&1
	mount -f /proc/bus/usb >/dev/null 2>&1
fi

# 挂载所有其他的文件系统（除了NFS和/proc）
# Mount all other filesystems (except for NFS and /proc, which is already
# mounted). Contrary to standard usage,
# filesystems are NOT unmounted in single user mode.
# The 'no' applies to all listed filesystem types. See mount(8).
if [ "$READONLY" != "yes" ] ; then
	action $"Mounting local filesystems: " mount -a -t nonfs,nfs4,smbfs,ncpfs,cifs,gfs,gfs2,glusterfs -O no_netdev
else
	action $"Mounting local filesystems: " mount -a -n -t nonfs,nfs4,smbfs,ncpfs,cifs,gfs,gfs2,glusterfs -O no_netdev
fi

# 检查是否需要完整的relable
if [ -n "$SELINUX_STATE" -a "$READONLY" != "yes" ]; then
    if [ -f /.autorelabel ] || strstr "$cmdline" autorelabel ; then
	relabel_selinux
    fi
else
    if [ -d /etc/selinux -a "$READONLY" != "yes" ]; then
        [ -f /.autorelabel ] || touch /.autorelabel
    fi
fi

# 根据需要重新分配磁盘配额
if [ X"$_RUN_QUOTACHECK" = X1 -a -x /sbin/quotacheck ]; then
	action $"Checking local filesystem quotas: " /sbin/quotacheck -anug
fi

if [ -x /sbin/quotaon ]; then
    action $"Enabling local filesystem quotas: " /sbin/quotaon -aug
fi

# 初始化伪随机数生成器
if [ -f "/var/lib/random-seed" ]; then
	cat /var/lib/random-seed > /dev/urandom
else
	[ "$READONLY" != "yes" ] && touch /var/lib/random-seed
fi
if [ "$READONLY" != "yes" ]; then
	chmod 600 /var/lib/random-seed
	dd if=/dev/urandom of=/var/lib/random-seed count=1 bs=4096 2>/dev/null
fi

if [ -f /etc/crypttab ]; then
    init_crypto 1
fi

# 该部分允许在启动做一些手动配置
if [ -f /.unconfigured ]; then

    if [ -x /bin/plymouth ]; then
        /bin/plymouth quit
    fi

    if [ -x /usr/bin/system-config-keyboard ]; then
	/usr/bin/system-config-keyboard
    fi
    if [ -x /usr/bin/passwd ]; then
        /usr/bin/passwd root
    fi
    if [ -x /usr/sbin/system-config-network-tui ]; then
	/usr/sbin/system-config-network-tui
    fi
    if [ -x /usr/sbin/timeconfig ]; then
	/usr/sbin/timeconfig
    fi
    if [ -x /usr/sbin/authconfig-tui ]; then
	/usr/sbin/authconfig-tui --nostart
    fi
    if [ -x /usr/sbin/ntsysv ]; then
	/usr/sbin/ntsysv --level 35
    fi

    # 重新读取网络配置数据
    if [ -f /etc/sysconfig/network ]; then
	. /etc/sysconfig/network

	# 重置主机名
	action $"Resetting hostname ${HOSTNAME}: " hostname ${HOSTNAME}
    fi

    rm -f /.unconfigured
fi

# 清理/.
rm -f /fastboot /fsckoptions /forcefsck /.autofsck /forcequotacheck /halt \
	/poweroff /.suspended &> /dev/null

# Do we need (w|u)tmpx files? We don't set them up, but the sysadmin might...
_NEED_XFILES=
[ -f /var/run/utmpx -o -f /var/log/wtmpx ] && _NEED_XFILES=1

# 清理/var.
rm -rf /var/lock/cvs/* /var/run/screen/*
find /var/lock /var/run ! -type d -exec rm -f {} \;
rm -f /var/lib/rpm/__db* &> /dev/null
rm -f /var/gdm/.gdmfifo &> /dev/null

[ "$PROMPT" != no ] && plymouth watch-keystroke --command "touch /var/run/confirm" --keys=Ii &

# 清理utmp/wtmp
> /var/run/utmp
touch /var/log/wtmp
chgrp utmp /var/run/utmp /var/log/wtmp
chmod 0664 /var/run/utmp /var/log/wtmp
if [ -n "$_NEED_XFILES" ]; then
  > /var/run/utmpx
  touch /var/log/wtmpx
  chgrp utmp /var/run/utmpx /var/log/wtmpx
  chmod 0664 /var/run/utmpx /var/log/wtmpx
fi
[ -n "$SELINUX_STATE" ] && restorecon /var/run/utmp* /var/log/wtmp* >/dev/null 2>&1

# 清理/tmp文件夹
[ -n "$SELINUX_STATE" ] && restorecon /tmp
rm -f /tmp/.X*-lock /tmp/.lock.* /tmp/.gdm_socket /tmp/.s.PGSQL.*
rm -rf /tmp/.X*-unix /tmp/.ICE-unix /tmp/.font-unix /tmp/hsperfdata_* \
       /tmp/kde-* /tmp/ksocket-* /tmp/mc-* /tmp/mcop-* /tmp/orbit-*  \
       /tmp/scrollkeeper-*  /tmp/ssh-* \
       /dev/.in_sysinit

# 创建ICE directory
mkdir -m 1777 -p /tmp/.ICE-unix >/dev/null 2>&1
chown root:root /tmp/.ICE-unix
[ -n "$SELINUX_STATE" ] && restorecon /tmp/.ICE-unix >/dev/null 2>&1

# 启动swap空间
update_boot_stage RCswap
# 启动所有swap分区，并跳过不存在的swap设备
action $"Enabling /etc/fstab swaps: " swapon -a -e
if [ "$AUTOSWAP" = "yes" ]; then
	curswap=$(awk '/^\/dev/ { print $1 }' /proc/swaps | while read x; do get_numeric_dev dec $x ; echo -n " "; done)
	swappartitions=$(blkid -t TYPE=swap -o device)
	if [ x"$swappartitions" != x ]; then
		for partition in $swappartitions ; do
			[ ! -e $partition ] && continue
			majmin=$(get_numeric_dev dec $partition)
			echo $curswap | grep -qw "$majmin" || action $"Enabling local swap partitions: " swapon $partition
		done
	fi
fi

# 安装 binfmt_misc
/bin/mount -t binfmt_misc none /proc/sys/fs/binfmt_misc > /dev/null 2>&1

# 开机时间配置文件
if [ -x /usr/sbin/system-config-network-cmd ]; then
  if strstr "$cmdline" netprofile= ; then
    for arg in $cmdline ; do
        if [ "${arg##netprofile=}" != "${arg}" ]; then
	    /usr/sbin/system-config-network-cmd --profile ${arg##netprofile=}
        fi
    done
  fi
fi
# 至此为止，已加载所有的基本模块，内核已开始运行。
# 可以dump除syslog，方便后续查看
[ -f /var/log/dmesg ] && mv -f /var/log/dmesg /var/log/dmesg.old
dmesg -s 131072 > /var/log/dmesg

# 在这里创建/.autofsck ,如果系统在这里崩溃了，下次重启就会出现fsck提示
touch /.autofsck &> /dev/null

[ "$PROMPT" != no ] && plymouth --ignore-keystroke=Ii
if strstr "$cmdline" confirm ; then
	touch /var/run/confirm
fi

# 同步完成文件操作的信息到rghb，告诉rghb服务器已经完成rc.sysinit了
if [ -x /bin/plymouth ]; then
    /bin/plymouth --sysinit
fi
```

##### 3. 脚本文件`/etc/rc.d/`

关闭/启动对应级别下的服务

```bash
[root@localhost ~]# ls /etc/rc.d/
init.d  rc  rc0.d  rc1.d  rc2.d  rc3.d  rc4.d  rc5.d  rc6.d  rc.local  rc.sysinit
```

脚本文件`/etc/rc.d/rc`作用为当级别切换时启动或停止服务；此脚本接受传递的参数给脚本中`$runlevel`变量，然后，读取`/etc/rc$runlevel.d/K*`和`/etc/rc$runlevel.d/S*`所有文件，这些文件就是为什么开机启动后，有些服务会自动启动，有些服务没有启动的原因。

```bash
[root@localhost ~]# ls /etc/rc.d/rc3.d/
K01smartd          K69rpcsvcgssd      K95rdma          S13cpuspeed          S25netfs      S82abrtd
K05wdaemon         K73winbind         K99rngd          S13irqbalance        S26acpid      S90crond
K10psacct          K74ntpd            S01sysstat       S13rpcbind           S26haldaemon  S95atd
K10saslauthd       K75ntpdate         S02lvm2-monitor  S15mdmonitor         S26udev-post  S99firstboot
K15htcacheclean    K75quota_nld       S08ip6tables     S22messagebus        S28autofs     S99local
K15httpd           K84wpa_supplicant  S08iptables      S23NetworkManager    S50bluetooth
K30spice-vdagentd  K87restorecond     S10network       S24nfslock           S50kdump
K50dnsmasq         K89netconsole      S11auditd        S24rpcgssd           S55sshd
K60nfs             K89rdisc           S11portreserve   S25blk-availability  S80postfix
K61nfs-rdma        K92pppoe-server    S12rsyslog       S25cups              S82abrt-ccpp
```

K*：要停止的服务，K##*，优先级，数字越小，越优先关闭，依赖的服务先关闭，然后再关闭被依赖的。

S*：要启动的服务，S##*，优先级，数字越小，越是优先启动，被依赖的服务先启动，而依赖的服务后启动。

这些文件都是链接文件，它们链接到了/etc/init.d/*目录下的各个程序的，例如ntpd这个脚本

```bash
[root@localhost ~]# ls /etc/rc.d/rc3.d/K74ntpd -ld
lrwxrwxrwx. 1 root root 14 Jul 25 08:38 /etc/rc.d/rc3.d/K74ntpd -> ../init.d/ntpd
```

##### 4. `checkconfig`

如何设置某一服务下次重启系统后是该关闭或者开启呢？可以使用chkconfig命令实现：

命令格式:

```bash
chkconfig [options] Service_Name [on|off] 
    Options： 
         --add              #→添加程序服务 
         --list             #→列出当前系统上所有的服务对应的级别是关闭还是启动 
         --del              #→删除某个服务(只是删除链接文件，不删除原文件) 
         --level [on|off]   #→指定某个服务对应哪些级别是on或off
```

用户自定义开机启动程序，可以根据自己的需求将一些执行命令或是写到脚本/etc/rc.d/rc.local.当开机时就可以自动加载啦！

```bash
[root@localhost ~]# ll /etc/rc.d/rc3.d/S99local 
lrwxrwxrwx. 1 root root 11 Jul 25 08:37 /etc/rc.d/rc3.d/S99local -> ../rc.local
```

### 5. 启动终端，用户登录shell

这一步是用户登录shell过程

如果没有改变级别，默认情况执行/sbin/mingetty打开6个纯文本终端，让用户输入用户名和密码。输入完成后，再调用login程序，核对密码。如果密码正确，就从文件 /etc/passwd 读取该用户指定的shell，然后启动这个shell。

## 参考链接

1. <https://linux.cn/article-8807-1.html>
2. <https://blog.51cto.com/zhang789/1851675>
3. <https://www.ruanyifeng.com/blog/2013/08/linux_boot_process.html>
4. <https://blog.51cto.com/433266/2173126>
5. <https://www.cnblogs.com/f-ck-need-u/p/7518142.html>


