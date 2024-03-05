# TryHackMe -- Net Sec Challenge


TryHackMe -- Net Sec Challenge

<!--more-->

# THM - Net Sec Challenge

## What is the highest port number being open less than 10,000?

指定端口范围扫描

```shell
sudo nmap -T4 -p1-10000 -vv [IP]
```

![image-20240305103940009](https://raw.githubusercontent.com/AlexsanderShaw/BlogImages/main/img/2023/202403051039109.png)

## There is an open port outside the common 1000 ports; it is above 10,000. What is it?

全端口扫描

```shell
sudo nmap -vv -T4 -p- [IP]
```

![image-20240305104203069](https://raw.githubusercontent.com/AlexsanderShaw/BlogImages/main/img/2023/202403051042108.png)

## How many TCP ports are open?

全端口扫描，统计TCP协议的端口，总计6个。

## What is the flag hidden in the HTTP server header?

使用nmap脚本`http-headers`:

```shell
┌──(v4ler1an㉿kali)-[~]
└─$ sudo nmap --script-help=http-headers
[sudo] password for v4ler1an:
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-03-04 21:56 EST

http-headers
Categories: discovery safe
https://nmap.org/nsedoc/scripts/http-headers.html
  Performs a HEAD request for the root folder ("/") of a web server and displays the HTTP headers returned.
```

本质上跟curl的请求差不多。

![image-20240305105800788](https://raw.githubusercontent.com/AlexsanderShaw/BlogImages/main/img/2023/202403051058827.png)

## What is the flag hidden in the SSH server header?

服务识别，或者使用telnet查看返回信息。

```shell
sudo nmap -sV -p22 [IP]
```

![image-20240305110217256](https://raw.githubusercontent.com/AlexsanderShaw/BlogImages/main/img/2023/202403051102295.png)

## We have an FTP server listening on a nonstandard port. What is the version of the FTP server?

非常规端口，服务识别，10021端口：

```shell
sudo nmap -sV -p10021 [IP]
```

![image-20240305110508037](https://raw.githubusercontent.com/AlexsanderShaw/BlogImages/main/img/2023/202403051105078.png)

## We learned two usernames using social engineering: `eddie` and `quinn`. What is the flag hidden in one of these two account files and accessible via FTP?

有用户名，需要登陆访问ftp获取文件，所以需要爆破密码。

```shell
hydra -L user.txt -P /usr/share/wordlists/rockyou.txt frp://[IP]:[PORT]
```

![image-20240305111816101](https://raw.githubusercontent.com/AlexsanderShaw/BlogImages/main/img/2023/202403051118144.png)

登陆然后查看文件，获得flag。



## Browsing to `http://10.10.208.24:8080` displays a small challenge that will give you a flag once you solve it. What is the flag?

访问:

![image-20240305112139454](https://raw.githubusercontent.com/AlexsanderShaw/BlogImages/main/img/2023/202403051121504.png)

大意就是使用nmap扫描，但是不要被IDS检查出来。直接用`-sN`选项即可。`-sN`选项是隐蔽扫描，通过构造特殊标记来绕过一些IDS：

```shell
sudo nmap -sN [IP]
```

![image-20240305112343929](https://raw.githubusercontent.com/AlexsanderShaw/BlogImages/main/img/2023/202403051123978.png)



##  总结

1. 基本原则：减少扫描次数
2. 扫描端口范围 -> 针对特定端口扫描 -> 指定特定脚本
3. 隐蔽扫描：-sN -sF -sX
