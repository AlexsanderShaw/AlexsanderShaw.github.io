# Hadoop--初学到漏洞(二)--环境搭建--本机模式


# Hadoop--初学到漏洞(二)--环境搭建--本机模式

## 前言

有条件的买一组服务器做集群，没有条件的配置高性能机器搭建虚拟机。此处以虚拟机进行搭建集群（多个Linux主机）。

第一次首先进行本机模式的Hadoop搭建。

## 一、虚拟机

1. centos7, 创建新用户，具有root权限。

2. 在/opt目录下创建两个文件夹，分别为modules和software

   ```shell
   sudo mkdir modules
   sudo mkdir software
   ```

## 二、JAVA环境配置

centos7自带java环境，但自带的openjdk没有增加对java监控命令jps的支持，两种解决方案：卸载原有的openjdk进行再重装或者通过yum安装jdk开发插件。此处我们采用第一种解决方案：

1. 下载Oracle版本JDK，jdk-7u67-linux-x64.tar.gz，并解压，然后配置好环境变量：

   ```shell
   tar -zxvf jdk-7u67-linux-x64.tar.gz -C /opt/modules
   
   export JAVA_HOME=/usr/local/jdk1.7.0_67
   export PATH=$JAVA_HOME/bin:$PATH
   ```

   对java环境进行验证：

   ![java](https://i.imgur.com/Dp4opSd.png)

   **（务必确保java环境正确，java版本可以自行尝试，此处我使用了一个较老的版本）**

## 三、Hadoop环境配置

   1. 下载Apache Hadoop，到官网下载即可，此处使用的是Hadoop-2.10.0（建议使用Binary，因为刚开始可能不熟悉源码编译）：

   ![hadoop-install-1](https://i.imgur.com/0TjXzvp.png)

   

   进入，然后选择一个链接点击下载，也可以直接使用wget下载：

   ![hadoop-install-2](https://i.imgur.com/TXINhgh.png)

   下载后的文件建议放在/opt/modules下面一份，然后解压到/usr/local/路径下。

3. 在.bashrc文件中配置Hadoop的环境变量：

    ```shell
   export HADOOP_HOME=/usr/local/hadoop-2.10.0 
   ```

3. 尝试运行：`hadoop version`

   如果不报错，说明安装没有问题，可以跳过进入下面的验证，如果此处报错：

![hadoop-install-error1](https://i.imgur.com/gJcwMz3.png)

​	运行其他的hadoop jar之类的命令也提示此问题，说明环境变量配置存在问题，可以尝试采用以下解决方式：

​	在.bashrc中添加如下内容：

```shell
export HADOOP_HOME=/usr/local/hadoop-2.10.0  #hadoop的环境变量，前面已经设置过
export HADOOP_INSTALL=$HADOOP_HOME
export HADOOP_MAPRED_HOME=$HADOOP_HOME
export HADOOP_COMMON_HOME=$HADOOP_HOME
export HADOOP_HDFS_HOME=$HADOOP_HOME
export YARN_HOME=$HADOOP_HOME
export HADOOP_COMMON_LIB_NATIVE_DIR=$HADOOP_HOME/lib/native
export PATH=$PATH:$HADOOP_HOME/sbin:$HADOOP_HOME/bin
export HADOOP_CONF_DIR=$HADOOP_HOME
export HADOOP_PREFIX=$HADOOP_HOME
export HADOOP_LIBEXEC_DIR=$HADOOP_HOME/libexec
export JAVA_LIBRARY_PATH=$HADOOP_HOME/lib/native:$JAVA_LIBRARY_PATH
export HADOOP_CONF_DIR=$HADOOP_PREFIX/etc/hadoop
```

​	然后进行 `source ~/.bashrc`，此时再运行`hadoop version`进行验证：

![hadoop-install-error2](https://i.imgur.com/4ZvjxBz.png)

## 四、环境验证

**验证一个简单的Hadoop示例。** 

Hadoop安装提供了以下示例MapReduce jar文件，它提供了MapReduce的基本功能，可用于计算，如Pi值，文件列表中的字数等。

1. 新建目录：`mkdir /tmp/input`

2. 拷贝几个txt文件：`cp $HADOOP_HOME/*.txt input `

3. 检查待测文件：

   ```shell
   ls -l input
   
   #输出
   total 124 
   -rw-r--r-- 1 root root 106210  Mar 5 22:54 LICENSE.txt 
   -rw-r--r-- 1 root root   15841 Mar 5 22:54 NOTICE.txt
   -rw-r--r-- 1 root root  1366	 Mar 5 22:54 README.txt 
   ```

4. 运行命令进行每个可用文件的字数统计：

   ```shell
   hadoop jar $HADOOP_HOME/share/hadoop/mapreduce/hadoop-mapreduce-examples-2.10.0.jar  wordcount input output 
   ```

5. 输出保存在output / part-r00000文件中，可以使用以下命令检查：

   ```shell
   cat output/*
   ```

   检查结果如下所示：

   ![hadoop-install-3](https://i.imgur.com/jmyt5rj.png)

   

   因为检查文件不同可能结果不同，可以正常统计文件的字数即可。

## 五、总结

本机模式的安装配置相对简单，遇到错误网上搜一下基本都可以解决，需要根据自身配置进行不同的修改。后续将进行伪分布式和分布式环境的配置。

 

 

 

 

 

 

 







