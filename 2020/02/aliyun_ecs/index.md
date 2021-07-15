# Aliyun ECS 搭建手记


# Aliyun ECS 搭建手记

**简单记录一下阿里云服务器的搭建过程，包括最后使用本地ssh进行连接。**

## 一、服务器选择

这个因人而异，看个人。有账号就行，记住实例的登陆密码和远程登录密码（6位）。实例的登陆密码在进行本地ssh登陆的时候需要使用，远程登录密码在使用阿里云的在线shell的时候使用。

## 二、阿里云服务器（Linux）的几种连接方式简介

### 1. 通过Workench进行连接

配置比较复杂，不建议新手直接使用这种方法进行远程连接管理。但是功能比较强大。

详细配置过程建议参考官方文档：[Workbench配置手册](https://help.aliyun.com/document_detail/147650.html?spm=a2c4g.11186623.6.670.267a1be5NPf9NU)



### 2. 通过VNC进行连接

该连接方式主要是在实例管理页面开启远程管理界面，shell开启在浏览器页面中。

详细配置过程建议参考官方文档：[VNC连接配置手册](https://help.aliyun.com/document_detail/25433.html?spm=a2c4g.11186623.6.671.49a776f3WJvliW)



### 3. 通过SSH密钥对进行连接

这种方式是我使用的方式，详细说一下步骤，简单实用。几个步骤就可以获取shell连接。

1. 前提条件

   - 已创建密钥对并下载.pem私钥文件
   - 为实例绑定密钥
   - 为实例所在的安全组添加安全组规则，放行对相应端口的访问

2. 通过命令进行配置

   1. 找到.pem私钥文件在本地机上的存储路径，例如~/.ssh/ecs.pem。这里我一般都直接放在了`~/.ssh`路径下

   2. 修改私钥文件属性：

      ```shell
      chmod 400 XXXXXX.pem
      ```

   3. 进行实例连接：

      ```shell
      ssh -i ~/.ssh/XXXXX.pem root@实例ip
      ```

3. 通过config文件进行配置

   1. 打开 `~/.ssh`下的config文件，如果没有的话就自己创建一个，文件内容如下：

      ```shell
      # alias
      Host alias  #主机别名
      HostName ip   #实例的公网IP地址
      Port 22     #这里可以使用其他的端口，但是要注意在安全组中修改端口的出入规则
      User root    #使用root用户进行登录
      IdentityFile XXXXX.pem    #指定私钥文件
      ```

   2. 重启ssh或terminal

   3. 进行连接

      ```shell
      ssh alias
      ```

      

### 4. 通过用户名密码验证连接

该方式主要是使用设置的实例登录密码进行连接

1. 输入ssh

   ```shell
   ssh root@实例ip
   ```

2. 输入登录密码即可

### 5. 通过移动设备进行连接

一般需要使用特定的app进行连接。

详细配置过程建议参考官方文档：[移动设备连接配置手册](https://help.aliyun.com/document_detail/58642.html?spm=a2c4g.11186623.2.24.17056732bTnQWh#concept-bln-hhz-wdb)

## 三、总结

Aliyun官方的文档很详细了，强烈建议如果中间出现什么问题，优先参考官方文档。

