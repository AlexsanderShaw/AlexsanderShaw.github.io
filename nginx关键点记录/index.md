# Nginx核心知识点记录


记录一下Nginx中比较基础但很重要的关键知识点。

<!--more-->

## Nginx 核心技术

### 1. 设计目标

#### 1. 性能

1. 网络性能：使用 `epoll` 网络模型，在全异步模式下及多进程而非多线程模式的支持下，可以处理几万至几十万的并发请求。
2. 网路效率：使用长连接以减少建立、关闭带来的网络交互，同时使用压缩算法提高网络利用率。
3. 时延：使用带宽控制技术，使各会话之间带宽尽量相等

#### 2. 可靠性

采用主从机制以看门狗形式管理工作进程，一旦有工作进程崩溃，立刻启动新的进程代替。

#### 3. 伸缩性

使用组件技术，可以减少或增加使用的组件或使用自行开发的新组件，介入到HTTP请求处理的中间环节，改变处理行为。

#### 4. 简单性

多组件及多阶段的方式使一个HTTP处理过程被分成了11个小阶段，每个阶段都可以非常简单，容易理解和实现，HTTP处理过程变成了流水线模式。

#### 5. 可修改性

Nginx 定位专用的Web 服务器，需要具备动态修改配置、动态升级、动态部署的能力。

#### 6. 可见性

关键组件的运行情况可以被监控，如网络吞吐量、网络连接数、缓存使用情况等。

#### 7. 可移植性

跨平台能力，Nginx 支持Linux、Unix、Windows。

### 2. 架构

 整体上看，Nginx 使用了事件驱动的服务模型，在模块机制中专门定义了 `event` 模块实现事件驱动。在事件基础上，Nginx 使用了多阶段的异步模型，将处理过程（如HTTP请求）划分7、9或11个阶段，每个阶段都异步处理。将请求多阶段处理，可以进一步控制每个请求的总体处理时间，因为每个阶段都细化，不会出现某个阶段过多占用CPU处理时间的问题。

管理进程和工作进程的机制使 Nginx 可以充分利用多处理器机制。

下面分别介绍关键的技术：

#### 1. 事件驱动

Nginx 会注册各种时间处理器来处理事件，事件主要来源于网络和磁盘。`event` 模块负责收集、管理和分发事件，其他的模块都是事件的处理者和消费者，会根据注册的事件得到事件的分发。

在 `nginx.conf` 的 `event{}` 块中配置相应的事件模块，就可以启用对应事件模型，而且可以根据应用场景随时切换事件模块。`event` 模块被核心的 `ngx_event_module` 管理，它是核心模块。

Nginx 为不同的OS和不同内核版本提供了9个事件模块，分别为：`ngx_select_module`、`ngx_eventport_module`、`ngx_epoll_module`、`ngx_poll_module`、`ngx_devpoll_module`、`ngx_kqueue_module`、`ngx_aio_module`、`ngx_rtsig_module`、`ngx_select_module(Windows)`。

#### 2. 异步多阶段处理

Nginx 把一个请求划分成多个阶段，每个阶段都可以由事件分发器来分发，注册的阶段管理器（handler）进行对应阶段的处理。通俗来将，Nginx的多阶段划分相当于人为创造了很多事件。例如，获取一个静态文件的HTTP请求可以划分为下面的几个阶段：

1. 建立TCP连接阶段：收到TCP的SYN包
2. 开始接收请求：接收到TCP中的ACK包表示连接建立成功
3. 接收到用户请求并分析请求是否完整：接收到用户数据包
4. 接收到完整请求后开始处理：接收到用户数据包
5. 由静态文件读取部分内容：接收到用户数据包或接受到TCP中的ACK包，TCP窗口向前滑动。该过程可能多次触发，直到把文件全部读取
6. 发送完成后：收到最后一个包的ACK
7. 用户主动关闭连接：收到TCP中的FIN报文

每一个事件、每一个阶段均由 `event` 模块负责调用和激活，`event` 模块监听系统内核消息，以激活 Nginx 事件。

#### 3. 模块化

Nginx 除了少量的核心代码，其他功能均在模块中实现，新功能的扩展通过标准接口和数据结构开发新模块实现，无需改动核心代码和核心模块，这为 Nginx 带来良好的扩展性和可靠性。

Nginx 设计了6个基础类型模块（称为核心模块），实现了 Nginx 的6个主要部分，以及HTTP协议主流程，分别是：

- `ngx_core_module`:  管理配置等全局模块
- `ngx_events_module`: 管理所有事件类型模块
- `ngx_openssl_module`: 管理所有TLS/SSL模块
- `ngx_http_module`: 管理所有HTTP类型模块
- `ngx_mail_module`: 管理所有邮件类型模块
- `ngx_errlog_module`: 管理所有日志类模块

这6个核心模块只是定义了6类业务的业务流程，具体工具并不由这些模块执行，业务核心逻辑及具体请求处理由其下属模块进行实现。

框架程序只需关注如何调用核心模块，Nginx 的核心功能由核心模块完成，实现第一层流水线。核心模块之外是非核心模块，由对应的核心模块进行初始化和调用。非核心模块可以动态添加，通过重新编译包含进 Nginx，通过配置文件将模块使能。

#### 4. 管理进程和工作进程

管理进程作为工作进程的管理进程和父进程，还可以带来高可靠性：工作进程终止，管理进程可以及时启动新的实例接管。这种master + worker的模式具有以下优点：

1. 充分利用多核系统的并发处理能力，Nginx 的所有工作进程都是平等的，并且可以在 `nginx.conf` 中将工作进程和处理器一一绑定。
2. 负载均衡，工作进程间通过进程间通信实现负载均衡，请求容易被分配到负载较轻的工作进程中。
3. 状态监控，管理进程只负责启动、停止、监控工作进程。

#### 5. 内存池

Nginx 在内部实现了一个简单的内存池，每一个TCP连接建立时都会分配一个内存池，而在请求结束时销毁整个内存池，将之前分配的内存一次性归还给操作系统。Nginx 的内存池并不负责回收已经分配出去的内存，这些内存由请求方负责回收。

#### 6. 连接池

Nginx 为了减少反复创建TCP连接以及创建套接字的次数，从而提高网络响应速度，在内部提供了连接池机制。在Nginx 启动解读哪，管理进程在配置文件中解析出对应的配置，配置项放到配置结构体中。

注：配置指令中 `worker_connections` 配置的连接池大小是工作进程级别的，所以设计的连接池大小是 `worker_connections * worker_processes`。          

#### 7. 时间缓存

Nginx 为了减少对OS的时间函数 `gettimeofday` 的调用，自己内部对系统时间进行了缓冲，内部访问时间实际上访问了内存中的几个变量。

#### 8. 延迟关闭

Nginx 在要关闭连接时，并不会立刻关闭连接，而是先关闭TCP连接的写操作，等待一段时间后再关掉连接的读操作。

#### 9. keepalive

Nginx 中可以大量看到对 `keepalive` 的配置和API。

如果客户端的请求头中的 `connection` 为 `close`， 表示客户端需要关掉长连接；如果客户端的请求头中的 `connection` 为 `keepalive`，表示客户端需要打开长连接；如果没有该子炖啊，则根据协议，如果是 HTTP 1.0 则默认为 `close`， 如果是 HTTP 1.1 则默认为 `keepalive` 。

如果为 `keepalive` ， Nginx 会在输出完响应体后，设置当前连接的 `keepalive`属性，然后等待客户端的下一次请求。但是不会一直等待，会根据 `keepalive_timeout` 值决定等待时长。

## Nginx 的工作流程

### 1. Nginx 的启动流程

启动过程整体上可分为两部分：

1. 框架程序启动过程：创建各核心模块和非核心模块
2. 模块启动过程：模块内部完成自己的启动和初始化

完整的启动流程和各阶段说明如下：

![无标题-2021-07-20-0942 11.48.34](https://cdn.jsdelivr.net/gh/AlexsanderShaw/BlogImages@main/img/vuln/shebei无标题-2021-07-20-0942 11.48.34.png)

1. 启动时，Nginx 接收命令行参数，解析各主要参数，参数主要存放在 `nginx.conf` 文件中，所以最重要的参数是`nginx.conf`的路径；
2. 平滑升级指不重启服务进行升级，不重启管理进程而重启新版本的 Nginx 程序。旧的管理进程先调用 fork 函数创建新进程，然后新进程通过 execve 系统调用启动新版本管理进程，旧版本管理进程手心设置环境变量，新版本管理进程启动时检查对应环境变量判断为平滑升级，并对通过环境变量传递的旧版本 Nginx 服务监听的句柄做继承；
3. 框架通过调用核心模块的 `create_conf` 方法让核心模块创建用于存储对应配置信息的结构体创建核心模块，然后在后续的步骤中给予配置文件对环境和模块进行初始化，这里主要是为后面的配置文件解析做准备；
4. 调用配置模块的解析方法，解析 `nginx.conf` 中的配置项，调用对应核心模块的方法将属于各核心模块的配置项保存到核心模块的配置数据结构中； 
5. 调用所有核心模块的 `init_conf` 方法，用于让核心模块根据写入内部配置数据结构的数据对模块做处理和初始化；
6. 配置文件中可能配置了缓存文件、库文件、日志文件等，同时包括共享内存，该步骤对这些文件和共享内存进行创建、打开操作；
7. 对于配置了监听端口的模块，按配置开始监听配置的端口，一般HTTP模块、stream模块都会有监听端口；
8. 调用所有模块的 `init_module` 方法，使用配置信息初始化模块；
9. 如果 `niginx.conf` 中配置了 Ngins 为 master 模式，则创建管理进程——master进程；
10. 管理进程根据配置的工作进程数，使用一个循环将所需要的工作进程 fork 出来；
11. 管理进程根据配置解析过程时解析出来的配置信息，检查对应 path 配置是否配置值，如果进行了设置，则 fork 出独立的 `cache manager` 进程（与工作进程同级），主要作用为将后端服务器的 response 使用文件缓存下来，下次请求时不需要再向后端发送请求，一般用在 `upstream{}` 中。该进程会定期检查缓存状态、查看缓存总量是否超出限制，如果超出则删除最少使用的部分。此外，还会定期删除过期缓存的文件；
12. 管理进程根据配置解析过程时解析出来的配置信息，检查对应 path 配置是否设置了值，并 fork 出独立的`cache loader` 进程，并延迟1分钟运行。该进程主要用途是遍历配置文件中 `proxy_cache_path` 指定的缓存路径中所有的缓存文件，根据缓存文件进行索引重建，即在 Nginx 服务重启之前将之前的缓存文件重建索引；
13. 管理进程调用所有模块的 `init_process` 方法，此时工作进程的启动工作就完成了，工作进程进入消息循环中开始等待处理用户请求；
14. Nginx 为 single 模式，直接调用所有模块的 `init_process` 方法，直接启动完毕。单进程模式下，网络端口监听、数据处理等均由管理进程处理，多进程模式下，网络链接和数据处理等由工作进程处理。single 模式一般用于调试。

### 2. 配置加载流程

Nginx 服务通过 `nginx.conf` 配置文件实现，因为 Nginx 为多模块架构，在框架启动流程中，每个模块都会为自己创建一个配置信息数据结构，而框架又会调用模块 `init_conf` 接口，将配置项加载到模块一级。所有配置项中的配置以配置块为单位，而配置块又是与内部模块对应的。

#### 1. 配置文件详解

这里给出一个 `nginx.conf` 的详细解析：

```conf
#全局块
#user  nobody;
worker_processes  1;

#event块
events {
    worker_connections  1024;
}

#http块
http {
    #http全局块
    include       mime.types;
    default_type  application/octet-stream;
    sendfile        on;
    keepalive_timeout  65;
    #server块
    server {
        #server全局块
        listen       8000;
        server_name  localhost;
        #location块
        location / {
            root   html;
            index  index.html index.htm;
        }
        error_page   500 502 503 504  /50x.html;
        location = /50x.html {
            root   html;
        }
    }
    #这边可以有多个server块
    server {
      ...
    }
}
```

对该文件的各个部分的详细说明如下：

##### 1. 全局块

全局块是默认配置文件从开始到 events 块之间的一部分内容，主要设置一些影响 Nginx 服务器整体运行的配置指令，因此，这些指令的作用域是 Nginx 服务器全局。

通常包括配置运行 Nginx 服务器的用户（组）、允许生成的 worker process 数、Nginx 进程 PID 存放路径、日志的存放路径和类型以及配置文件引入等。

```
# 指定可以运行nginx服务的用户和用户组，只能在全局块配置
# user [user] [group]
# 将user指令注释掉，或者配置成nobody的话所有用户都可以运行
# user nobody nobody;
# user指令在Windows上不生效，如果你制定具体用户和用户组会报小面警告
# nginx: [warn] "user" is not supported, ignored in D:\software\nginx-1.18.0/conf/nginx.conf:2

# 指定工作线程数，可以制定具体的进程数，也可使用自动模式，这个指令只能在全局块配置
# worker_processes number | auto；
# 列子：指定4个工作线程，这种情况下会生成一个master进程和4个worker进程
# worker_processes 4;

# 指定pid文件存放的路径，这个指令只能在全局块配置
# pid logs/nginx.pid;

# 指定错误日志的路径和日志级别，此指令可以在全局块、http块、server块以及location块中配置。(在不同的块配置有啥区别？？)
# 其中debug级别的日志需要编译时使用--with-debug开启debug开关
# error_log [path] [debug | info | notice | warn | error | crit | alert | emerg] 
# error_log  logs/error.log  notice;
# error_log  logs/error.log  info;
```

##### 2. events 块

events 块涉及的指令主要影响 Nginx 服务器与用户的网络连接。常用到的设置包括是否开启对多 worker process 下的网络连接进行序列化，是否允许同时接收多个网络连接，选取哪种事件驱动模型处理连接请求，每个 worker process 可以同时支持的最大连接数等。

这一部分的指令对 Nginx 服务器的性能影响较大，在实际配置中应该根据实际情况灵活调整。

##### 3. http 块

http 块是 Nginx 服务器配置中的重要部分，代理、缓存和日志定义等绝大多数的功能和第三方模块的配置都可以放在这个模块中。

前面已经提到，http 块中可以包含自己的全局块，也可以包含 server 块，server 块中又可以进一步包含 location 块，在本书中我们使用 “http 全局块” 来表示 http 中自己的全局块，即 http 块中不包含在 server 块中的部分。

可以在 http 全局块中配置的指令包括文件引入、MIME-Type 定义、日志自定义、是否使用 sendfile 传输文件、连接超时时间、单连接请求数上限等。

```
# 常用的浏览器中，可以显示的内容有HTML、XML、GIF及Flash等种类繁多的文本、媒体等资源，浏览器为区分这些资源，需要使用MIME Type。换言之，MIME Type是网络资源的媒体类型。Nginx服务器作为Web服务器，必须能够识别前端请求的资源类型。

# include指令，用于包含其他的配置文件，可以放在配置文件的任何地方，但是要注意你包含进来的配置文件一定符合配置规范，比如说你include进来的配置是worker_processes指令的配置，而你将这个指令包含到了http块中，着肯定是不行的，上面已经介绍过worker_processes指令只能在全局块中。
# 下面的指令将mime.types包含进来，mime.types和ngin.cfg同级目录，不同级的话需要指定具体路径
# include  mime.types;

# 配置默认类型，如果不加此指令，默认值为text/plain。
# 此指令还可以在http块、server块或者location块中进行配置。
# default_type  application/octet-stream;

# access_log配置，此指令可以在http块、server块或者location块中进行设置
# 在全局块中，我们介绍过errer_log指令，其用于配置Nginx进程运行时的日志存放和级别，此处所指的日志与常规的不同，它是指记录Nginx服务器提供服务过程应答前端请求的日志
# access_log path [format [buffer=size]]
# 如果你要关闭access_log,你可以使用下面的命令
# access_log off;

# log_format指令，用于定义日志格式，此指令只能在http块中进行配置
# log_format  main '$remote_addr - $remote_user [$time_local] "$request" '
#                  '$status $body_bytes_sent "$http_referer" '
#                  '"$http_user_agent" "$http_x_forwarded_for"';
# 定义了上面的日志格式后，可以以下面的形式使用日志
# access_log  logs/access.log  main;

# 开启关闭sendfile方式传输文件，可以在http块、server块或者location块中进行配置
# sendfile  on | off;

# 设置sendfile最大数据量,此指令可以在http块、server块或location块中配置
# sendfile_max_chunk size;
# 其中，size值如果大于0，Nginx进程的每个worker process每次调用sendfile()传输的数据量最大不能超过这个值(这里是128k，所以每次不能超过128k)；如果设置为0，则无限制。默认值为0。
# sendfile_max_chunk 128k;

# 配置连接超时时间,此指令可以在http块、server块或location块中配置。
# 与用户建立会话连接后，Nginx服务器可以保持这些连接打开一段时间
# timeout，服务器端对连接的保持时间。默认值为75s;header_timeout，可选项，在应答报文头部的Keep-Alive域设置超时时间：“Keep-Alive:timeout= header_timeout”。报文中的这个指令可以被Mozilla或者Konqueror识别。
# keepalive_timeout timeout [header_timeout]
# 下面配置的含义是，在服务器端保持连接的时间设置为120 s，发给用户端的应答报文头部中Keep-Alive域的超时时间设置为100 s。
# keepalive_timeout 120s 100s

# 配置单连接请求数上限，此指令可以在http块、server块或location块中配置。
# Nginx服务器端和用户端建立会话连接后，用户端通过此连接发送请求。指令keepalive_requests用于限制用户通过某一连接向Nginx服务器发送请求的次数。默认是100
# keepalive_requests number;
```

##### 4. server 块

server 块和 “虚拟主机” 的概念有密切联系。

虚拟主机，又称虚拟服务器、主机空间或是网页空间，它是一种技术。该技术是为了节省互联网服务器硬件成本而出现的。这里的 “主机” 或“空间”是由实体的服务器延伸而来，硬件系统可以基于服务器群，或者单个服务器等。虚拟主机技术主要应用于 HTTP、FTP 及 EMAIL 等多项服务，将一台服务器的某项或者全部服务内容逻辑划分为多个服务单位，对外表现为多个服务器，从而充分利用服务器硬件资源。从用户角度来看，一台虚拟主机和一台独立的硬件主机是完全一样的。

在使用 Nginx 服务器提供 Web 服务时，利用虚拟主机的技术就可以避免为每一个要运行的网站提供单独的 Nginx 服务器，也无需为每个网站对应运行一组 Nginx 进程。虚拟主机技术使得 Nginx 服务器可以在同一台服务器上只运行一组 Nginx 进程，就可以运行多个网站。

在前面提到过，每一个 http 块都可以包含多个 server 块，而每个 server 块就相当于一台虚拟主机，它内部可有多台主机联合提供服务，一起对外提供在逻辑上关系密切的一组服务（或网站）。

和 http 块相同，server 块也可以包含自己的全局块，同时可以包含多个 location 块。在 server 全局块中，最常见的两个配置项是本虚拟主机的监听配置和本虚拟主机的名称或 IP 配置。

##### 5. listen 指令

server 块中最重要的指令就是 listen 指令，这个指令有三种配置语法。这个指令默认的配置值是：listen *:80 | *:8000；只能在 server 块种配置这个指令。

```
listen address[:port] [default_server] [ssl] [http2 | spdy] [proxy_protocol] [setfib=number] [fastopen=number] [backlog=number] [rcvbuf=size] [sndbuf=size] [accept_filter=filter] [deferred] [bind] [ipv6only=on|off] [reuseport] [so_keepalive=on|off|[keepidle]:[keepintvl]:[keepcnt]];


listen port [default_server] [ssl] [http2 | spdy] [proxy_protocol] [setfib=number] [fastopen=number] [backlog=number] [rcvbuf=size] [sndbuf=size] [accept_filter=filter] [deferred] [bind] [ipv6only=on|off] [reuseport] [so_keepalive=on|off|[keepidle]:[keepintvl]:[keepcnt]];


listen unix:path [default_server] [ssl] [http2 | spdy] [proxy_protocol] [backlog=number] [rcvbuf=size] [sndbuf=size] [accept_filter=filter] [deferred] [bind] [so_keepalive=on|off|[keepidle]:[keepintvl]:[keepcnt]];
```

listen 指令的配置非常灵活，可以单独制定 ip，单独指定端口或者同时指定 ip 和端口。

```
listen 127.0.0.1:8000;  #只监听来自127.0.0.1这个IP，请求8000端口的请求
listen 127.0.0.1; #只监听来自127.0.0.1这个IP，请求80端口的请求（不指定端口，默认80）
listen 8000; #监听来自所有IP，请求8000端口的请求
listen *:8000; #和上面效果一样
listen localhost:8000; #和第一种效果一致
```

关于上面的一些重要参数做如下说明：

- address：监听的 IP 地址（请求来源的 IP 地址），如果是 IPv6 的地址，需要使用中括号 “[]” 括起来，比如[fe80::1]等。

- port：端口号，如果只定义了 IP 地址没有定义端口号，就使用 80 端口。**这边需要做个说明：要是你压根没配置 listen 指令，那么那么如果 nginx 以超级用户权限运行，则使用`\*`:80，否则使用`\*`:8000**。多个虚拟主机可以同时监听同一个端口, 但是 server_name 需要设置成不一样；

- default_server：假如通过 Host 没匹配到对应的虚拟主机，则通过这台虚拟主机处理。具体的可以参考这篇[文章](https://segmentfault.com/a/1190000015681272)，写的不错。

- backlog=number：设置监听函数 listen() 最多允许多少网络连接同时处于挂起状态，在 FreeBSD 中默认为 - 1，其他平台默认为 511。

- accept_filter=filter，设置监听端口对请求的过滤，被过滤的内容不能被接收和处理。本指令只在 FreeBSD 和 NetBSD 5.0 + 平台下有效。filter 可以设置为 dataready 或 httpready，感兴趣的读者可以参阅 Nginx 的官方文档。

- bind：标识符，使用独立的 bind() 处理此 address:port；一般情况下，对于端口相同而 IP 地址不同的多个连接，Nginx 服务器将只使用一个监听命令，并使用 bind() 处理端口相同的所有连接。

- ssl：标识符，设置会话连接使用 SSL 模式进行，此标识符和 Nginx 服务器提供的 HTTPS 服务有关。

listen 指令的使用看起来比较复杂，但其实在一般的使用过程中，相对来说比较简单，并不会进行太复杂的配置。

##### 6. server_name 指令

用于配置虚拟主机的名称。语法是：

```
Syntax: server_name name ...;
Default:    
server_name "";
Context:    server
```

对于 name 来说，可以只有一个名称，也可以由多个名称并列，之间用空格隔开。每个名字就是一个域名，由两段或者三段组成，之间由点号 “.” 隔开。比如

```
server_name myserver.com www.myserver.com
```

在该例中，此虚拟主机的名称设置为 myserver.com 或 www. myserver.com。Nginx 服务器规定，第一个名称作为此虚拟主机的主要名称。

在 name 中可以使用通配符 “*”，但通配符只能用在由三段字符串组成的名称的首段或尾段，或者由两段字符串组成的名称的尾段，如：

```
server_name myserver.* *.myserver.com
```

另外 name 还支持正则表达式的形式。这边就不详细展开了。

由于 server_name 指令支持使用通配符和正则表达式两种配置名称的方式，因此在包含有多个虚拟主机的配置文件中，可能会出现一个名称被多个虚拟主机的 server_name 匹配成功。那么，来自这个名称的请求到底要交给哪个虚拟主机处理呢？Nginx 服务器做出如下规定：

a. 对于匹配方式不同的，按照以下的优先级选择虚拟主机，排在前面的优先处理请求。

- ① 准确匹配 server_name

- ② 通配符在开始时匹配 server_name 成功

- ③ 通配符在结尾时匹配 server_name 成功

- ④ 正则表达式匹配 server_name 成功

b. 在以上四种匹配方式中，如果 server_name 被处于同一优先级的匹配方式多次匹配成功，则首次匹配成功的虚拟主机处理请求。

有时候我们希望使用基于 IP 地址的虚拟主机配置，比如访问 192.168.1.31 有虚拟主机 1 处理，访问 192.168.1.32 由虚拟主机 2 处理。

这时我们要先网卡绑定别名，比如说网卡之前绑定的 IP 是 192.168.1.30，现在将 192.168.1.31 和 192.168.1.32 这两个 IP 都绑定到这个网卡上，那么请求这个两个 IP 的请求才会到达这台机器。

绑定别名后进行以下配置即可：

```
http
{
    {
       listen:  80;
       server_name:  192.168.1.31;
     ...
    }
    {
       listen:  80;
       server_name:  192.168.1.32;
     ...
    }
}
```

##### 7. location 块

每个 server 块中可以包含多个 location 块。在整个 Nginx 配置文档中起着重要的作用，而且 Nginx 服务器在许多功能上的灵活性往往在 location 指令的配置中体现出来。

location 块的主要作用是，基于 Nginx 服务器接收到的请求字符串（例如， server_name/uri-string），对除虚拟主机名称（也可以是 IP 别名，后文有详细阐述）之外的字符串（前例中 “/uri-string” 部分）进行匹配，对特定的请求进行处理。地址定向、数据缓存和应答控制等功能都是在这部分实现。许多第三方模块的配置也是在 location 块中提供功能。

在 Nginx 的官方文档中定义的 location 的语法结构为：

```
location [ = | ~ | ~* | ^~ ] uri { ... }
```

其中，uri 变量是待匹配的请求字符串，可以是不含正则表达的字符串，如 / myserver.php 等；也可以是包含有正则表达的字符串，如 .php$（表示以. php 结尾的 URL）等。为了下文叙述方便，我们约定，不含正则表达的 uri 称为 “标准 uri”，使用正则表达式的 uri 称为 “正则 uri”。

其中方括号里的部分，是可选项，用来改变请求字符串与 uri 的匹配方式。在介绍四种标识的含义之前，我们需要先了解不添加此选项时，Nginx 服务器是如何在 server 块中搜索并使用 location 块的 uri 和请求字符串匹配的。

在不添加此选项时，Nginx 服务器首先在 server 块的多个 location 块中搜索是否有标准 uri 和请求字符串匹配，如果有多个可以匹配，就记录匹配度最高的一个。然后，服务器再用 location 块中的正则 uri 和请求字符串匹配，当第一个正则 uri 匹配成功，结束搜索，并使用这个 location 块处理此请求；如果正则匹配全部失败，就使用刚才记录的匹配度最高的 location 块处理此请求。

了解了上面的内容，就可以解释可选项中各个标识的含义了：

- “=”，用于标准 uri 前，要求请求字符串与 uri 严格匹配。如果已经匹配成功，就停止继续向下搜索并立即处理此请求。

- “^～”，用于标准 uri 前，要求 Nginx 服务器找到标识 uri 和请求字符串匹配度最高的 location 后，立即使用此 location 处理请求，而不再使用 location 块中的正则 uri 和请求字符串做匹配。

- “～”，用于表示 uri 包含正则表达式，并且区分大小写。

- “～`*`”，用于表示 uri 包含正则表达式，并且不区分大小写。注意如果 uri 包含正则表达式，就必须要使用 “～” 或者“～*” 标识。

> 我们知道，在浏览器传送 URI 时对一部分字符进行 URL 编码，比如空格被编码为 “%20”，问号被编码为“%3f” 等。“～”有一个特点是，它对 uri 中的这些符号将会进行编码处理。比如，如果 location 块收到的 URI 为 “/html/%20/data”，则当 Nginx 服务器搜索到配置为“～ /html/ /data” 的 location 时，可以匹配成功。

##### 8. root 指令

这个指令用于设置请求寻找资源的跟目录，此指令可以在 http 块、server 块或者 location 块中配置。由于使用 Nginx 服务器多数情况下要配置多个 location 块对不同的请求分别做出处理，因此该指令通常在 location 块中进行设置。

```
root path
```

path 变量中可以包含 Nginx 服务器预设的大多数变量，只有 documentroot 和 realpath_root 不可以使用。

上面列举了 Nignx 中全局块、event 块和 http 块的一些配置指令，但是 Nginx 的指令远远不止这些。其实这边最主要的还是讲解整个配置文件的结构，如果大家要看比较全的指令介绍、模块介绍的话，建议去 Nginx 的官网。

#### 2. 配置文件加载和解析过程

1. 从Nginx 命令行得到配置文件路径
2. 调用所有核心模块的 `create_conf` 方法，生成配置项结构体
3. 框架代码解析 `nginx.conf` 核心模块部分
4. 调用所有核心模块的 `init_conf` 方法，解析对应的配置块。

## 参考文献

- [Nginx 官网](http://nginx.org/en/docs/)

- [操作系统能否支持百万连接?](https://cloud.tencent.com/developer/article/1114773)

- [Nginx 系列博客](https://www.cnblogs.com/itzgr/tag/Nginx/)

- [nginx 的 default_server 定义及匹配规则](https://segmentfault.com/a/1190000015681272)

- [W3C Nginx 教程](https://www.w3cschool.cn/nginx/nginx-d1aw28wa.html)
  https://www.cnblogs.com/54chensongxia/p/12938929.html
