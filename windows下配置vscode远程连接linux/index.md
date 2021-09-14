# Windows下VSCode远程连接Linux


## 1. Windows环境配置

确认安装了openssh

Windows10下检查是否已经安装OpenSSH的方法：
快捷键`Win + X`，选择`Windows PoweShell（管理员）`，输入以下指令：
`Get-WindowsCapability -Online | ? Name -like 'OpenSSH*'`

## 2. VSCode基本配置

1. 安装扩展Remote-SSH

   在应用商店中安装扩展“Remote-SSH”：

   ![image-20210914111439708](https://cdn.jsdelivr.net/gh/AlexsanderShaw/BlogImages@main/img/vuln/shebei20210914111439.png)

2. 配置基本config

   ![image-20210914111544787](https://cdn.jsdelivr.net/gh/AlexsanderShaw/BlogImages@main/img/vuln/shebei20210914111544.png)

   ![image-20210914111602740](https://cdn.jsdelivr.net/gh/AlexsanderShaw/BlogImages@main/img/vuln/shebei20210914111602.png)

3. 在扩展设置中开启terminal显示

![image-20210914111717965](https://cdn.jsdelivr.net/gh/AlexsanderShaw/BlogImages@main/img/vuln/shebei20210914111717.png)

红框处打上钩选中。

## 3. 权限更改

更改`C:/Users/v4ler1an/.ssh`的文件夹权限：

“属性” -> “安全” -> “高级” -> 禁用继承，然后重新添加用户权限。

## 4. 无需密码自动登录

1. server端`/etc/ssh/sshd_config`配置文件开启了`PubkeyAuthentication`；

2. Windows本地生成密钥：

   ```shell
   ssh-keygen -t rsa -c "email@email.com"
   ```

   生成的密钥保存在`C:/Users/xxx/.ssh`文件夹下

3. 将`id_rsa.pub`公钥内容复制到server的`/home/xxx/.ssh/authorized_keys`文件中；

4. 重启server上的sshd服务，重新连接，即可实现无需密码远程连接
