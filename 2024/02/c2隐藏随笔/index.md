# CS隐藏随笔


记录下CS的特征去除、流量加密和IP隐藏的流程，以作备忘。

<!--more-->

# 前言

简单记录下C2的常规隐藏手法，以Cobalt Strike 4.9.1为例。

前期需要准备的东西：

- vps
- 域名
- cdn账号

# 端口特征修改

在teamserver文件中，给CS配置的默认端口为50050，我们可以根据需要修改为自己需要的端口号：

![image-20240226194303133](https://raw.githubusercontent.com/AlexsanderShaw/BlogImages/main/img/2023/202402261943178.png)

# 证书特征修改

Cobalt Strike默认使用的证书有三个：

- cobaltstrike.store：用于server和client的通信加密
- proxy.store：用于浏览器代理，client中的browser pivot功能
- ssl.store：假设在c2.profile配置文件中没有配置http-certificate选项，并且listener使用的是https，CS就会使用这个默认的证书文件。

cobaltstrike.store和ssl.store特征十分明显，已被厂商标记烂了，所以需要自生成替换掉这俩默认的证书。而且，默认使用的密码为123456.

这里使用的工具是`keytool`，一个Java数据证书的管理工具，keytool会将密钥(key)和证书(certificates)保存在一个keystore的文件中，后缀为.store。keytool可以用于生成新的.store，也可以用于查看.store的内容。

默认的cobaltstrike.store文件的内容：

[![img](https://raw.githubusercontent.com/AlexsanderShaw/BlogImages/main/img/2023/202402261953113.png)](https://img.nsg.cn/xxl/2021/12/8e83d480-9c99-4d2d-ba43-cfeec92f2f29.png)

假设使用下面的命令进行特征取出：

```shell
keytool -keystore cobaltstrike.store -storepass 123456 -keypass 123456 -genkey -keyalg RSA -alias 360.cn -dname "CN=360, OU=360.cn, O=Sofaware,L=Somewhere,ST=Cyberspace, C=CN"
# 参数说明如下# -keytool -keystore cobaltstrike.store -storepass 密码# -keypass 密码# -genkey -keyalg RSA# -alias google.com -dname CN=(名字与姓氏),# OU=(组织单位名称), O=(组织名称),# L=(城市或区域名称),# ST=(州或省份名称),# C=(单位的两字母国家代码)。
```

去除特征后的内容如下：

[![img](https://raw.githubusercontent.com/AlexsanderShaw/BlogImages/main/img/2023/202402261955236.png)](https://img.nsg.cn/xxl/2021/12/85577d4b-944c-4b4b-b51d-cefd52386edb.png)

但是这种方式并不推荐，我们还可以引入第三方证书来进行设置。

这里的证书将结合后面的cdn部分一起进行配置，主要是使用第三方的证书来去除特征，详细的配置步骤放在cdn配置部分中。

# 流量特征修改

## 域名

申请域名到https://www.namesilo.com，比较便宜，支持支付宝支付，注册可以使用临时邮箱和虚假身份。

购买完成后，进入Domain Manger，在自己的域名的最后的option部分，点击卡车图标，可以看到分配的DNS解析记录：

![namesilo域名列表](https://raw.githubusercontent.com/AlexsanderShaw/BlogImages/main/img/2023/202402262004265.png)

我们进入前面的图标，把默认解析记录给删除掉。

## cdn配置

这里使用cloud flare的免费级别的cdn加速即可。

首先绑定域名：

![image-20240226195916494](https://raw.githubusercontent.com/AlexsanderShaw/BlogImages/main/img/2023/202402261959542.png)

 输入前面获取的域名，选择最下面的免费计划，

进入站点后，点击左侧的dns，查看Cloud Flare的DNS，记录下两个ns记录：

![image-20240226200114587](https://raw.githubusercontent.com/AlexsanderShaw/BlogImages/main/img/2023/202402262001635.png)

回到namesilo网站， 进入Domain Manager，点击红框中的图标，设置DNS Server：

![image-20240226200619560](https://raw.githubusercontent.com/AlexsanderShaw/BlogImages/main/img/2023/202402262006609.png)

把Cloud Flare的两条NS记录添加上：

![image-20240226200713321](https://raw.githubusercontent.com/AlexsanderShaw/BlogImages/main/img/2023/202402262007370.png)

这样就实现了将自己的域名的所有解析功能都托管在Cloud Flare上，从而实现利用CDN的解析。

回到Cloud Flare的管理页面，添加两条DNS解析记录，IPv4地址写自己的vps服务器的外网ip：

![image-20240226200911538](https://raw.githubusercontent.com/AlexsanderShaw/BlogImages/main/img/2023/202402262009595.png)

这两条记录有一个是www，另外一个随意。

然后在`规则->页面规则`添加两条规则，url分别为`*.域名/*`、`.域名/*`，选取设置为`缓存级别`，级别为`绕过`:

![image-20221126012104555](https://raw.githubusercontent.com/AlexsanderShaw/BlogImages/main/img/2023/202402262011542.png)

等待Cloud Flare的CDN配置生效，时间大概在十几分钟到一个小时，可以查看cf的注册邮箱是否收到邮件。

激活成功后，可以ping一下自己的域名：

![image-20240226201652189](https://raw.githubusercontent.com/AlexsanderShaw/BlogImages/main/img/2023/202402262016245.png)

此时获得ip信息已经不是vps的外网ip，也可以多地ping检查一下：

![image-20240226201803399](https://raw.githubusercontent.com/AlexsanderShaw/BlogImages/main/img/2023/202402262018463.png)

## 证书和密钥

直接使用cloud flare创建证书和密钥，用于后续的加密通信。

创建证书，如下图：

![image-20221125115833161](https://raw.githubusercontent.com/AlexsanderShaw/BlogImages/main/img/2023/202402262020271.png)

![image-20221125115949205](https://raw.githubusercontent.com/AlexsanderShaw/BlogImages/main/img/2023/202402262020522.png)

生成之后，保存到本地的\*.pem和\*.key文件。

然后使用如下命令先生成certout.p12，再生成新的.store：

```shell
openssl pkcs12 -export -in 保存的源证书.pem -inkey 保存的私钥.key -out 输出的p12文件名(自定义).p12 -name 设置别名 -passout pass:设置密码
keytool -importkeystore -deststorepass 设置密码 -destkeypass 设置密码 -destkeystore 设置证书文件名.store -srckeystore 上面自定义的p12文件.p12 -srcstoretype PKCS12 -srcstorepass 上面设置的密码 -alias 设置别名
eg：
openssl pkcs12 -export -in cert.pem -inkey secret.key -out certout.p12 -name cloudflare_cert -passout pass:753015
keytool -importkeystore -deststorepass 753015 -destkeypass 753015 -destkeystore bk.store -srckeystore certout.p12 -srcstoretype PKCS12 -srcstorepass 753015 -alias cloudflare_cert
```

生成.store文件后，修改teamserver文件中的启动命令中对应的值，密码也直接修改。

这里需要记得开启SSL/TLS协议：

![image-20240227100655891](https://raw.githubusercontent.com/AlexsanderShaw/BlogImages/main/img/2023/202402271006069.png)

在浏览器到Cloud Flare和Cloud Flare到源服务器之间都需要开启SSL/TLS。我这里设置的是自签名的证书，因为前面都是我们自己生成的。

## 修改c2 profile文件

将random_c2profile项目生成随机profile进行二次修改
项目地址：https://github.com/threatexpress/random_c2_profile

（后续将根据情况再单独出profile文件的详细配置内容。）

将生成的证书信息填写：![image-20240226202904432](https://raw.githubusercontent.com/AlexsanderShaw/BlogImages/main/img/2023/202402262029535.png)



这里的keystore部分填写前面证书生成的.store文件；password部分需要与teamserver中的一致。

修改host-stager：
![](https://raw.githubusercontent.com/AlexsanderShaw/BlogImages/main/img/2023/202402262026225.jpg)

修改http-config：
![](/Users/v4ler1an/Documents/Learning/security/pentesting/cs/media/16477923063996/16477940420578.jpg)

修改http-get
![](https://raw.githubusercontent.com/AlexsanderShaw/BlogImages/main/img/2023/202402262026239.jpg)

修改http-post
![](/Users/v4ler1an/Documents/Learning/security/pentesting/cs/media/16477923063996/16477940830973.jpg)

修改完成后，使用`./c2lint [profile]`进行文件检查，没有错误就可以使用了。

![](https://raw.githubusercontent.com/AlexsanderShaw/BlogImages/main/img/2023/202402262026235.jpg)

注意：
1、http-get和http-post的Content-Type需要设置为"application/*; charset=utf-8"否则无法命令执行。
2、由于配置caddy需要匹配`/js/query-3.*`路径，所以http-get和http-post需设置成`/js/query-3.*`一样的路径，否则无法正常上线。

3、免费版的Cloud Flare对代理的端口有限制，只能改成如下端口：

- http：80、8080、8880、2052、2082、2086、2095
- https：443、2053、2083、2087、2096、8443

# 反向代理

使用反向代理的目的是隐藏C2，虽然加了CDN，但是直接请求到server还是有点不安稳，nmap的一些扫描脚本可以直接扫描出来，所以还是要加一个反向代理，这样类似腾讯云、阿里云的风控也能绕过了。

## caddy

使用简单、快速配置，地址https://github.com/caddyserver/caddy

安装完成后，在/etc/caddy文件夹下有一个Caddyfile文件，这个是默认的配置文件，我们编辑一下：

```json
[域名] {
	tls /root/tools/Server/[证书文件].pem /root/tools/Server/[密钥].key
	reverse_proxy /js/jquery-3.* https://127.0.0.1:8443 {  # 端口可以自己设置转发的端口，uri需要与c2 profile中的一致
	# 把对/js/jquery-3.*的请求转发到本地的8443端口
		transport http {
			tls
			tls_insecure_skip_verify
		}
		header_up X-Forwarded-For {http.request.header.X-Forwarded-For}
	}
	header /* {
		Server "Caddy" "Tengine"
	}
}
```

修改完成后，在`/etc/caddy`路径下启动caddy：

```shell
caddy run
```

也可以指定配置文件：

```shell
caddy run --config /etc/caddy/Caddyfile
```

启动成功后，反代配置完成。

![image-20240227111422251](https://raw.githubusercontent.com/AlexsanderShaw/BlogImages/main/img/2023/202402271114431.png)

## nginx

nginx的配置与caddy基本一样，也是将本地的443端口流量转发到本地的8443端口并匹配路径为`/js/jquery-3.*`：

```nginx
http {
        server {
            listen 443 ssl;
            server_name [域名];

            ssl_certificate /root/tools/Server/[证书文件].pem;
            ssl_certificate_key /root/tools/Server/[密钥].key;

            location ~* /js/jquery-3. {
                if ($host != "[域名]") {
                return 403;
                }
                if ($http_user_agent != "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/98.0.4758.102 Safari/537.36") {
		return 403;
                }
		proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
                proxy_pass  https://127.0.0.1:8443;
            }
        }
}
```

需要注意的是，这里配置了UA，否则返回403。

## iptables

因为设置了端口转发，443->8443，所以需要设置一下iptabes，把对8443端口的访问限制在本机：

```shell
iptables -A INPUT -s 127.0.0.1 -p tcp --dport 8443 -j ACCEPT
iptables -A INPUT -p tcp --dport 8443 -j DROP
```

只允许本机访问8443:

![image-20240227111545168](https://raw.githubusercontent.com/AlexsanderShaw/BlogImages/main/img/2023/202402271115343.png)

# 上线效果

上述工作都完成后，CS可以成功上线，并且通信加密，nmap也扫描不出来。

![image-20240227111655010](https://raw.githubusercontent.com/AlexsanderShaw/BlogImages/main/img/2023/202402271116219.png)

# 补充

## 1. 端口限制

如果是国内的VPS，对于常见的80、8080、443、8443端口可能无法直接使用，所以需要使用一些非常见的端口。

而且免费版本的Cloud Flare对能使用的端口有限制：

- http：80、8080、8880、2052、2082、2086、2095
- https：443、2053、2083、2087、2096、8443

所以如果80、8080、443、8443用不了，就可以用2052，2087这种端口。

## 2. http上线

以上针对的是https的beacon，http的话在DNS中加一个二级域名并使用该二级域名上线即可。不用额外再弄一个profile，因为http的beacon只看域名。 在http的raw payload中我们可以验证这一点：

![Image](https://raw.githubusercontent.com/AlexsanderShaw/BlogImages/main/img/2023/202402271530670.png)

对比https的raw payload，它用上了我们之前配置的所有内容：

![Image](https://raw.githubusercontent.com/AlexsanderShaw/BlogImages/main/img/2023/202402271530837.png)

## 3. CF不支持域前置

Cloudflare目前已经不支持域前置，所以上面的操作只能隐藏真实的ip，但是无法隐藏C2使用的域名，会在流量的Host字段中显示出来。AWS 的CloudFront目前也已经不再支持。

有一种类似于Domain Fronting的方法。就是使用一个同样接入了CloudFlare，与目标域名指向相同IP但没有被墙的域名作为SNI。前提是必须要有而且知道这个域名。

# 域前置Domain Fronting

https://evi1cg.me/archives/Domain_Fronting.html

https://www.bamsoftware.com/papers/fronting/






