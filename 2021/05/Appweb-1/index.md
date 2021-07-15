# Appweb Learning Notes


## 一、Appweb概述

Appweb是用于 Web 应用程序的嵌入式 Web 服务器。 它速度快，具备丰富的安全功能套件。 Appweb通过事件驱动的多线程内核托管对动态嵌入式 Web 应用程序进行了优化，可以提供快速响应、快速吞吐量和有效内存利用率。 它结构紧凑，只需使用 2MB 的内存（通常为 2-4MB）即可嵌入。

Appweb具有一组强大的功能，包括HTTP/1、HTTP/2、SSL/TLS、基本和摘要身份验证、虚拟主机、可加载模块、沙盒资源限制、日志记录、服务监控过程以及广泛的配置和编译控制。Appweb支持多种网络框架，包括ESP、PHP、Python、Perl 和 CGI。

作为部署最广泛的嵌入式 Web 服务器之一，Appweb被用于网络设备、电话、移动设备、消费和办公设备以及高速 Web 服务。

## 二、Appweb的优势和特点

### 1. 快速开发

创建动态设备管理应用程序的最简单且最具成本效益的方式。它具有嵌入式 Web 应用程序所需的所有功能，因此开发和发布后维护成本将显着降低。

### 2. 最小资源需求

快速和紧凑（最小需求仅2MB）。它只占用很少的系统资源，因此可以将重要的系统资源用于运行应用程序。

### 3. 灵活的开发环境

高度模块化，因此按照不同需求选择不同的功能。它支持运行时模块加载和广泛的编译时控制，这对于希望重新编译源码的开发者来说十分有用。

### 4. 安全性和可靠性

部署最广泛的嵌入式 Web 服务器之一，拥有大量用户对代码进行测试和优化。它有一个广泛的回归测试套件，对产品的压力测试远远超过正常环境中可能遇到的限制。完善的SSL/TLS、身份验证、沙盒指令和防御性策略等功能可最大程度保护用户免受攻击。

### 5. 性能

具有事件驱动、多线程内核的同类产品中最快的性能。Appweb使用基于 arena 的内存分配器来防止内存泄漏并提供最高性能，在 PC 类设备上每秒可以处理超过 40,000 个请求。

### 6. 规范性

支持 HTTP/1.0、HTTP/1.1、HTTP/2（仅限企业版）、CGI/1.1、SSL RFC 2246、HTTP RFC 2617等协议标准。

### 7. 可移植性

Appweb 已移植到 Linux、Windows、Mac OS 和 BSD，并支持以下 CPU 架构：ARM、MIPS、i386/X86/X86_64、PowerPC、SH 和 Sparc。

## 三、嵌入式设备应用

在嵌入式设备或应用中，web server功能的重要性次于设备必须运行的功能。因此，web server 必须最大限度地减少其资源需求，并且确定它放置在系统上的负载。

Appweb 根据这种特性进行深度优化：

- 快速并且只占用很小的内存资源（通常为2-4MB）
- 对系统资源的需求最小——通过可配置的资源限制
- ESP C Web 框架在不影响开发人员功能的情况下，运行时效率最高
- 默认安全，开发安全

## 四、Appweb 内部组件

Appweb 的核心是一个事件驱动的、多线程的 HTTP pipe，在它上面加载模块以提供特定于内容的处理并扩展其功能。

![modules](https://www.embedthis.com/images/appweb/modules.jpg)

Appweb 具有如下特点：

- 高性能多线程内核
- 动态模块加载的模块化结构
- HTTP/1， HTTP/2 和WebSocket 支持
- 带有过滤器的灵活的请求pipeline
- 可以有效避免内存泄漏的快速的专用内存分配器和垃圾回收
- 可移植运行时
- 使用沙盒控制资源消耗
- 安全可靠的运行时可防止常见的安全漏洞，例如缓冲区溢出漏洞。
- 兼容Apache配置
- 全面的日志和调试跟踪

### 1. Routing Engine

在现代 Web 应用程序中，一般需要根据功能对应用程序的不同部分进行划分，并对各个部分进行不同的处理。 例如可能只想将访问权限限制为经过身份验证的用户，或者希望缓存一些缓慢变化但动态的数据的输出，或者可能想要使用 RESTful URI（其中 URI 的含义取决于 HTTP method）。 原因有很多，但 Web 服务器必须提供一种方法来以不同方式处理各种 URI 的处理， Appweb 同样提供了路由引擎来处理该问题。

Appweb 具有高效灵活的路由引擎，允许以不同方式处理（路由）URI group。 路由在 `appweb.conf` 配置文件中创建，使用 `Route` 定义一组适用于 URI 组的处理指令。 `Route` 指令指定符合条件的请求所必须匹配的 URI 前缀，匹配策略可以是一个简单的字符串或正则表达式。 可以创建任意数量的路由，并按照它们在 `appweb.conf` 文件中定义的顺序进行处理。 路由也可以嵌套，以便内部路由继承外部路由块的定义。

![routing](https://www.embedthis.com/appweb/doc/images/routing.jpg)

当收到请求时，它会测试各种路由并选择最好的路由来处理请求。在此过程中，路由可能会根据需要重定向或重写请求。

一个常规的路由块如下所示：

```config
<Route /info>  # match request URIs that begin with "/info/"
    Documents "${DOCUMENT_ROOT}/info"
    AuthType basic example.com  # Use basic authentication
    Require secure              # Must be accessed over SSL
    Require ability edit        # Authenticated users must have the edit ability
    LimitRequestBody 100k       # Only requests less than 100K are accepted
    RequestTimeout 10secs       # Request must complete in < 10 seconds
    RequestParseTimeout 2secs   # Denial-of-service protection
</Route>
```

路由块中的部分常用指令如下：

- [SetHandler](https://embedthis.com/appweb/doc/users/dir/route.html#setHandler) —处理请求的请求handler (CGI, ESP, EJS, PHP, ...)
- [Documents](https://embedthis.com/appweb/doc/users/dir/route.html#documents) — 服务内容所在目录
- [AuthType](https://embedthis.com/appweb/doc/users/dir/auth.html#authType) — 认证协议：basic, digest or web form
- [Cache](https://embedthis.com/appweb/doc/users/dir/route.html#cache) — 如何缓存响应
- [Redirect](https://embedthis.com/appweb/doc/users/dir/route.html#redirect) — 响应重定向
- [AddLanguageDir](https://embedthis.com/appweb/doc/users/dir/route.html#addLanguageDir) — 多语言内容
- [Compress](https://embedthis.com/appweb/doc/users/dir/route.html#compress) —处理压缩的响应
- [Methods](https://embedthis.com/appweb/doc/users/dir/route.html#methods) — 允许的请求方法
- [Require](https://embedthis.com/appweb/doc/users/dir/auth.html#require) — 要求的用户凭据、规则或属性等
- [Limit*](https://embedthis.com/appweb/doc/users/security.html) — 安全沙箱限制
- [SSLCertificateFile](https://embedthis.com/appweb/doc/users/ssl.html) — SSL 配置

更多内容可以阅读 [Appweb Request Routing](https://embedthis.com/appweb/doc/users/routing.html) 和 [Appweb Configuration Directives](https://embedthis.com/appweb/doc/users/configuration.html#directives).

### 2. Pipeline Engine

Appweb 具备一个高效的、零拷贝的请求pipeline来处理请求，并生成对应的响应，这包括队列算法、数据包、缓冲区和时间调度。pipeline 的结构高度定制化，使用sendfile、异步 I/O 和向量化、离散/聚合的方式写入网络，以避免在写入网络之前在单个缓冲区中昂贵的数据和标头聚合消耗。

![pipeline](https://www.embedthis.com/images/appweb/pipeline.jpg)

Nginx 企业 Web 服务器将性能提升到一个新的水平并在许多站点中取代了 Apache。但是嵌入式 Web 服务器一般要比常规的 web server 的守护进程处理速度上慢得多。虽然拥有千兆字节的内存会有助于提高 Web 服务器的速度，但使用正确的架构和内部设计更为重要。 Appweb 使用了嵌入式 Web 服务器的最佳实践，使得在嵌入式环境中也能取得与 Nginx 相同的处理速度。

与 Nginx 一样，Appweb 使用非阻塞、基于事件的设计来异步处理请求，客户端的每个请求无需使用专有进程或线程。当请求待处理时，Appweb 使用事件来为请求提供服务。所以每个 worker 线程可能会被许多请求共享，这种机制确保了快速响应，同时消耗较少的资源。

Appweb 将基于事件的内核与高效的 pipeline 相结合。pipeline 包含一个对输入和输出的数据进行处理的阶段，该阶段主要包含了各种各样的过滤器，这些过滤器会对数据进行分块、排列、上传和缓存。为了节省内存，pipeline会以数据包的形式进行数据传输，而不进行数据复制，数据包有效地携带数据包头或尾，以便数据可以在不复制的情况下进行封包，这对于高效的 HTTP 分块至关重要。

![pipeline](https://www.embedthis.com/images/blog/pipeline.png)

pipeline 与网络通信并使用平台上可用的最有效的 I/O 原语。 Appweb 支持向量套接字写入、sendfile 和快速 O/S 事件机制，如 kqueue 和 epoll， 这种架构极大地提升了处理速度并Web 服务器的“体型”娇小。

### 3. Authentication Framework

Appweb 集成了一个完整的认证框架，其中包含：

- 用户登录登出机制
- 安全密码传输
- 灵活密码存储
- 用户凭据验证
- 控制特定用户或用户组对资源的访问

Appweb 提供了3种认证协议：basic， digest 以及 web-form。如果用户使用 web-form 输入登录凭据，Appweb 会自动转换为SSL传输以确保传输安全。密码将被加密保存在一个平面文件(flat file)中或者使用本机操作系统的密码机制。

用户通过身份认证后，将获得一组“属性”的授权，这些是通过 Appweb 基于角色的授权方案为每个用户配置的。每个路由（一组 URI）都可以配置为在授予用户访问权限之前需要某些“属性”。

Appweb 的认证架构主要包含以下2个组件：

- 认证用户名/密码存储
- 认证协议

#### 1. 认证用户名/密码存储

Appweb 有3种存储密码的方法：

- app - Application (custom) Password Database
- config - Configuration Directives in the app web.conf
- system - System Password Database

`app`存储是用户应用程序将密码存储在数据库或其他自定义的存储密码的地方，用户应用程序负责实现凭据验证回调。Appweb 将调用该回调来访问自定义密码存储并将提供的凭据与用户密码进行比较。如果有需要在运行时修改用户和密码的需求，该种存储方法为首选项。使用该方法需要使用`httpSetAuthVerifyByName` API 来注册回调函数，此时注册的回调可以应用于所有的路由；如果使用`httpSetAuthVerify` API 注册回调，则只能应用于具体的某一个路由。

`config` 存储通过 Appweb 配置文件中的`User`指令来管理密码，`authpass`程序创建密码，并在`appweb.conf`中进行定义。在不需要动态添加、删除或编辑用户名或密码时可以使用该种方法。

`system`存储则是使用系统密码数据库(e.g. /etc/password)

具体使用何种存储方式由`AuthStore`指令指定。例如：

```
AuthStore system
```

**创建密码**

创建密码使用`authpass`程序，如果使用应用程序定义数据库存储，则`AuthStore`应该设置成`app`，`authpass`程序创建的密码会存储在应用程序数据库中。

`authpass`的命令格式如下：

```shell
authpass [--cipher blowfish|md5] [--file auth.conf] [--password word] realm username roles...
```

`--file filename` 选项指定认证文件名称，如果未指定，密码将打印在标准输出上。 `authpass` 程序还可以修改配置文件中的密码定义。

`--cipher `选项指定用于散列/加密密码的密码。 默认为 MD5，，但blowfish更安全。 Blowfish 更适用于 Basic 和 Form 身份验证方案。

如果未使用 `--password` 选项，`authpass` 将提示输入密码。 `realm`定义了一组密码，并通过 `AuthType` 指令设置，通常设置为公司域或产品名称。

注：身份验证文件必须存储在 `Documents` 目录或任何提供内容的目录之外。

#### 2. 认证协议

认证协议定义了如何从用户处捕获用户凭据并提供给Appweb，Appweb 提供了不同的认证协议：

- [Application Authentication](https://www.embedthis.com/appweb/doc/users/authentication.html#app)

  应用程序身份验证使用特定于应用程序的方式来捕获用户名和密码。用户应用程序负责实现控制逻辑以捕获用户凭据并通过登录和注销过程重定向客户端。此协议最适用于使用服务器端 Web 框架（如 ESP）的应用程序。

- [Web Form Authentication](https://www.embedthis.com/appweb/doc/users/authentication.html#form)

  表单身份验证方案使用 HTML Web 表单让用户输入用户名和密码凭据，并使用 HTTP `Post` 请求将凭据提交给服务器进行验证。 使用此协议，可以通过`AuthType` 指令定义特定的登录和注销页面。 Appweb 管理登录/注销过程，如果身份验证成功，则会创建登录会话并将 cookie 返回到客户端的浏览器，包含 cookie 的后续请求将被自动验证并提供服务。

  要配置表单身份验证，`AuthType` 指令需要额外的参数来管理登录序列，包括指定登录网页、登录服务 URL、注销服务 URL、验证后显示的目标页面和注销后显示的目标页面。 格式为：

  ```
  AuthType form realm Login-Page Login-Service Logout-Service Logged-In-Destination Logged-Out-Destination
  ```

  该指令定义在登录序列期间使用的 URL。该指令根据这些 URL 的要求创建请求路由，允许未经身份验证的用户访问登录页面和登录服务。这些 `AuthType` 参数中的每一个都是可选的，可以指定为空字符串` "" `以省略。

  例如：

  ```
  <Route ^/>
       AuthType form example.com /public/login.html /login /logout //public/login.html
  </Route>
  
  <Route ^/public/>
      Profix /public
      Document public
      AuthType none
  </Route>
  ```

  此示例为所有请求启用表单身份验证，并将客户端浏览器重定向到`/public/login.html`，用户可以输入用户名和密码。登录网页应将用户名和密码提交给绑定到`/login` URL的登录服务。当需要注销时，客户端应向绑定到`/logout` URL的注销服务提交 HTTP POST 请求。`AuthType` 指令中的最后两个字段是客户端浏览器在登录和注销后将重定向到的目标 URL。第二个` /public` 路由无需身份验证即可访问“public”目录下的文档。

  `Login-Service` 是绑定到内部服务的 URL，用于接收用户名和密码并对用户进行身份验证。此服务期望使用输入字段“用户名”和“密码”通过 POST 数据提交用户名/密码。可以通过在 AuthType 指令中为 `Login-Service`指定空字符串`""`来提供自定义的登录和注销服务。如果使用自定义的登录服务，则应该调用`httpLogin`以根据配置的密码存储验证用户。

  **Web Form**

  这是一个最小示例登录页面：

  ```html
  <html><head><title>login.html</title></head>
  <body>
      <p>Please log in</p>
      <form name="details" method="post" action="/auth/login" >
          username <input type="text" name="username" value=''><br/>
          password <input type="password" name="password" value=''><br/>
          <input type="submit" name="submit" value="OK">
      </form>
  </body>
  </html>
  ```

  提交的两个字段必须命名为*username*和*password*以供“表单”身份验证方案使用。

  如果登录尝试成功，客户端将收到包含会话 cookie 的响应，并将被重定向到目标 URL。如果目标 URL 包含一个`referrer:`前缀并且登录请求在 HTTP 标头中包含一个引用 URL，那么该引用 URL 将用作目标而不是硬连接目标。

  注：“表单”身份验证机制以纯文本形式提交用户密码。为确保通信安全，应在使用 TLS/SSL 的安全连接上使用“表单”身份验证方案。

- [Basic Authentication](https://www.embedthis.com/appweb/doc/users/authentication.html#basic)

- [Digest Authentication](https://www.embedthis.com/appweb/doc/users/authentication.html#digest)

  Basic 和 Digest 身份验证是 HTTP/1.1 RFC2616 规范定义的 HTTP 协议机制。因为它们在 HTTP 协议级别运行，所以功能简单，且灵活性差。当客户端尝试访问受保护的内容时，客户端的浏览器会显示一个通用弹出对话框以提示用户输入凭据。


  应该只将基本和摘要式身份验证用作最后的手段。 Basic 和 Digest 身份验证标准使用弱密码，通过网络重复发送凭据，并且不够安全。基本身份验证在每个请求中以明文形式传输密码。摘要式身份验证使用弱 MD5 密码，并且两者都要求对所有请求使用 SSL 以确保最低限度的安全。此外，Basic 和 Digest 都不提供可靠的注销机制。注销适用于某些浏览器，但不适用于其他浏览器甚至同一浏览器的不同版本。

Appweb 身份验证框架十分全面，使开发人员不必将各个部分进行拼凑组合成一个认证方案。更为详细的内容可以参考[Authentication](https://embedthis.com/appweb/doc/users/authentication.html)。

#### 3. web框架

如果使用 ESP、PHP 或其他 Web 框架，则不应将扩展的`AuthType form`指令与 URL 一起使用。这是因为这些 web 框架集成了登录工具，在 web 框架中使用起来更自然。扩展的 `AuthType form`指令适合使用静态网页的网站，因为它可以在登录期间无缝管理浏览器页面转换。使用 ESP Web 框架时，请选择使用`AuthType app`身份验证协议。

#### 4. SSL加密

在考虑对发送或接收来自应用程序的敏感信息时，有两种基本的安全策略：

- 保证整个应用程序的安全
- 只保证包含登录页和登录服务在内的敏感信息的安全

Appweb 通过一种简单的方式保证整个应用的安全 -- 使用 `Redirect` 指令。这适用于 SSL 编码开销最小的更快的系统（在 PC 类系统上小于 5%）。但是对于更普通的嵌入式 CPU，SSL 加密开销可能会大得惊人，尤其是在使用大密钥时。

```
Redirect secure
```

这将自动通过 SSL 重定向所有请求，并且可能用于整个服务器或仅用于特定请求路由。

另外一种方法是仅保护登录页和登录/注销服务，通过在`AuthType` URLs  的前面加上`https://` 前缀即可：

```
AuthType form example.com https:///public/login.html https:///login /logout http:///
```

在登录时，会使用SSL加密，登录成功后会切换会http。

如果要保护应用程序的其他部分，可以定义重定向的路由：

```
<Route ^/sensitive/>
    Prefix /sensitive
    Documents top-secret
    Redirect secure
</Route>
```

### 4. Embedded Server Pages

ESP web Framework 可以说是 Appweb 中最优秀的部分，它是一个典型的MVC框架，可以容易地创建快速、动态的web应用。ESP是一个基于C的web框架，但不像一般的C编码，ESP框架的web页面支持嵌入式C编码。甚至，它支持网页修改时动态透明的重新编译和重新加载。它还检测并自动重新编译修改后的 ESP 控制器（用 C 编写）。这使得 ESP 的行为就像一个脚本化的 Web 框架。

为了解决C语言常见的内存分配和内存泄漏问题，ESP 使用了垃圾回收器在请求处理完成后来自动释放内存。

ESP 框架提供了一个应用生成器、web 页面模板引擎、MVC 框架、 HTML 控制库和 API 扩展来创建 web 应用程序。

![esp](https://embedthis.com/esp/doc/images/espArchitecture.jpg)

ESP 应用程序通常定义在一组目录中：

- cache — 缓存预编译的 ESP 控制器和页面
- client — 客户端 web 页内容、图片、样式等
- controllers — ESP 控制器方法
- layouts — 主页面布局
- db — 数据库和数据库迁移

可以使用以下命令来快速创建一个新的 ESP 应用程序：

```
mkdir blog
cd blog
esp install esp-html-mvc
```

关于 ESP 框架的内容十分丰富，可以单独拿出来详细说明，给出官网文档 [ESP Docs](https://www.embedthis.com/esp/doc/)。

## 五、安全性

web server 通常通过数量众多的安全测试来保证安全性，但是作用甚微，构建一个设计安全的 web server 远比通过测试保证安全的方式更有效。对于嵌入式 web server 更难保证安全性，因为要在低内存占用和不降低性能的前提下进行。

Appweb 通过使用一个安全的 Portable Runtime (MPR)， 从一开始就重点保证安全性。MPR 是一个跨平台层，它使得 Appweb 的超过97%的代码都是可移植的。它包括许多帮助创建安全应用的机制，比如它包括一个安全的字符串和缓冲区处理模块，以帮助消除困扰许多产品的缓冲区溢出问题。

## 六、沙箱

Appweb 引入沙箱来严格控制对系统资源的占用。这意味着在严格控制的范围内运行 Web 服务器，以便请求错误不会影响系统操作。 Appweb 还针对几种常见的拒绝服务攻击进行了加固。

Appweb 根据不同需求可做如下配置：

- 限制内存使用并且不允许超过内存限制的预定义的数值
- 拒绝过大的请求
- 拒绝过长的URL
- 由指定的用户帐户或用户组运行

基于以上基础，Appweb 提供了 Secure Sockets Layer 和摘要认证以及防御策略。


