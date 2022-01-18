# 

# Ubuntu 20.04 网络ens33消失问题解决


# Ubuntu 20.04 网络ens33消失问题解决

## Ubuntu 20.04 突然丢失网卡驱动

### 1. 问题描述

Ubuntu 20.04 LTS版本，在进行一次suspend操作后，发现网卡驱动丢失。执行`ifconfig`命令未发现正常的`eth0`或`ens33`网卡，但是执行`ifconfig -a`可以发现`ens33`网卡存在，但是没有正常IP。

桌面右上角没有网络连接的图标，在设置中也没有网络设置相关内容。

### 2. 解决

#### 1. 临时解决办法

执行如下命令：

```shell
sudo dhclient ens33
sudo ifconfig ens33
```

#### 2. 稳定解决办法

清理原有的网络配置相关选项，重启网络。Ubuntu 20.04使用了NetworkManager`的网络服务管理程序。执行如下命令：

```shell
service NetworkManager stop      # 停止当前网络服务
sudo rm /var/lib/NetworkManager/NetworkManager.state	# 建议在删除该状态文件前先进行备份
service NetworkManager start     # 启动网络服务
```

经过以上步骤后，网络可恢复正常。

### 3. 最后的最后

重置虚拟网络配置器。这是最后的办法，实在无法确定网络问题原因时再使用。



