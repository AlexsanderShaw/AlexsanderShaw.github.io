# 

# JWT认证和攻击界面简单总结



# JWT认证和攻击界面简单总结

## JWT简述

Json web token (JWT), 是为了在网络应用环境间传递声明而执行的一种基于JSON的开放标准（(RFC 7519).该token被设计为紧凑且安全的，特别适用于分布式站点的单点登录（SSO）场景。JWT的声明一般被用来在身份提供者和服务提供者间传递被认证的用户身份信息，以便于从资源服务器获取资源，也可以增加一些额外的其它业务逻辑所必须的声明信息，该token也可直接被用于认证，也可被加密。

### JWT认证和session认证的区别

#### 1. session认证

http协议是一种无状态的协议，即其对事务处理没有记忆能力，不对请求和响应之间的通信状态进行保存。如果用户向应用提供了用户名和密码来进行用户认证，那么在进行下一次请求时，需要再次进行用户认证。因为使用http协议并不能明确是哪个用户发送的请求。

为了实现应用可以识别出发出请求的用户，需要在server上存储一份用户登录的信息，这份登录信息会在server响应时传递给client，告诉其保存为cookie，以便下次请求时发送给应用。这样，就可以识别出发出请求的用户。以上即为传统的基于session的认证。

##### Cookie的传递过程

1. 浏览器向URL发送请求
2. server生成response
3. 在响应头中加入`Set-Cookie`字段，值为要设置的Cookie
4. 浏览器接受到response
5. 浏览器在响应头中搜索`Set-Cookie`字段，并将值保存在内存或硬盘中
6. 当下一次向该server发送http请求时，将server设置的Cookie附加在http请求的字段`Cookie`中
7. server收到请求，发现头部有`Cookie`字段，则明确已处理过该用户的请求
8. 过期的Cookie会被删除

##### 基于Cookie—Session的验证过程

1. 用户输入登录信息
2. server验证信息是否正确，如果正确就为该用户创建一个Session，并把Session存入数据库
3. server向client返回带有sessionID的Cookie
4. client接收到server返回的响应，发现头部有`Set-Cookie`字段，将Cookie进行保存
5. 后续client的请求都会附带该Cookie，server将sessionID与数据库中的做匹配，如果一直则处理该请求
6. 用户登出，Session会在client和server都被销毁

##### Cookie-Session机制的缺陷

1. 跨域问题，Cookie属于同源策略限制的内容之一
2. Session保存在server，容易遭受DoS攻击
3. 扩展性低，多台server较难实现Session共享
4. 安全性低，attacker可以利用本地Cookie进行欺骗和CSRF攻击

#### 2. JWT认证

基于Token的鉴权机制也是无状态的，但它不徐奥server存储用户的认证信息或会话信息。

##### JWT组成

JWT由3部分组成：`header`、`payload`、`signature`，每个部分中间使用`.`进行分隔，其中，`header`和`payload`使用Base64URL进行编码，即：
`base64UrlEncode(header).base64UrlEncode(payload).signature`

`header`部分是一个JSON对象，用来描述JWT的元数据：

```json
{
  "typ": "JWT",   //  表示对象是一个 JWT
  "alg": "HS256"  //  表示使用哪种 Hash 算法来创建签名，这里是 HMAC-SHA256
}
```

`payload`部分也是一个JSON对象，存储实际需要传递的数据，其内容可以是[官方定义的7个字段](https://en.wikipedia.org/wiki/JSON_Web_Token#Standard_fields)，也可以是自定义的私有字段：

```json
{
  "sub": "title",
  "iat": 1605688497,
  "exp": 9999999999,
  "name": "V4ler1an"
}
```

**JWT默认不进行加密，所以该部分不要存放关键信息。**

`signature`是对前2部分的签名，防止数据被篡改。这里需要传入一个key作为加密的私钥：

```
key = "secret"
data = base64urlEncode(header) + "." + base64urlEncode(payload);
signature = HMAC-SHA256(key，data);
```

一个样例JWT如下：

![](https://cdn.jsdelivr.net/gh/AlexsanderShaw/BlogImages@main/img/CVE-2020-16899/JWT_example.png)

##### JWT认证流程

1. 用户使用账号和密码发出post请求
2. server使用私钥创建一个JWT，并返回给浏览器
3. 浏览器将该JWT串放在请求头的`Authorization`中:
   `Authorization: Bearer <token>`,
   发送给server
4. server对JWT进行验证
5. 验证通过后返回相应的资源给浏览器
6. 用户登出，client删除token，server不做处理

##### JWT缺陷

1. 默认不加密
2. 只验证来源可靠性，并不对数据进行保护，也不会防止未授权访问。只要获取到token，任意用户都可以通过验证。为减少盗用，JWT的有效期应该设置尽可能短
3. Token过期问题，因为server不保存Session状态，所以无法在使用过程中废止或更改权限。即JWT一旦签发，到期前会始终有效。

##### JWT攻击界面

1. 爆破私钥key。如果signature的加密私钥key为已知，理论上来说可以通过爆破获得，且已有爆破工具可以直接使用
2. 修改算法，
   1. 将非对称加密算法修改为对称加密算法。HS256使用私密密钥对每条消息进行签名和验证，这也是JWT默认使用的算法，RS256使用私钥对消息进行签名，并使用公钥进行验证。可以将算法RS256更改为HS256，后端代码会使用公钥作为私密密钥，然后使用HS256验证签名。即想办法获取到RS256的公钥，然后修改算法为HS256，然后使用RSA公钥对数据签名，后端代码使用RSA公钥+HS256算法签名，从而实现绕过。
   2. 修改算法为none，即将header中的alg字段修改为none。这种方式只适合一些低版本的JWT库。当设置为none时表示没有签名算法，后端不会进行签名校验，此时去掉JWT的signature数据，然后直接提交给服务端即可。

3. 修改KID参数。`kid`是`header`中的一个可选参数，全称`key ID`，用于指定加密算法的密钥：

   ```json
    {
        "alg" : "HS256",
        "typ" : "jwt",
        "kid" : "/home/jwt/.ssh/pem"
    }
   ```

    该参数可以由用户输入。常见的有以下几种攻击方式：
    - 任意文件读取

        `kid`参数用于读取密钥文件，但系统并不知道用户想要读取的是否是密钥文件。所以，如果没有对参数进行过滤，那么攻击折可以读取到系统的任意文件。

        ```json
        {
            "alg" : "HS256",
            "typ" : "jwt",
            "kid" : "/etc/passwd"
        }
        ```

    - SQL注入

        `kid`也可以从数据库中提取数据，此时有可能造成SQL攻击，通过构造SQL语句来获取数据或绕过signature的验证。

        ```json
        {
            "alg" : "HS256",
            "typ" : "jwt",
            "kid" : "key111111' || union select 'secretkey' -- "
        }
        ```

    - 命令注入

        利用条件苛刻。ruby语言需要使用`open`函数读取密钥文件，可以命令注入。
        `"/path/to/key_file|whoami"`
        如果是php语言，则需要使用`exec`或`system`函数读取密钥文件，可能性较小。

4. 信息泄露。由于JWT的初衷并不是保证传输数据的机密性，所以payload是直接使用`base64url`编码的。如果在payload中携带了敏感信息，可以直接进行`base64url`解码，从而读取到payload中的关键信息。


