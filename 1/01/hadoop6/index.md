# 

# Hadoop--初学到漏洞(六)--分布式环境搭建

# Hadoop--初学到漏洞(六)--分布式环境搭建
## 服务器功能规划

| zy1              | zy2              | zy3               |
| ---------------- | ---------------- | ----------------- |
| NameNode         | ResourceManage   |                   |
| DataNode         | DataNode         | DataNode          |
| NodeManager      | NodeManager      | NodeManager       |
| HistoryServer    |                  | SecondaryNameNode |
| ip：10.251.0.144 | ip：10.251.0.150 | ip：10.251.0.151  |



## 一、解压Hadoop目录

```shell
wget http://mirrors.tuna.tsinghua.edu.cn/apache/hadoop/common/hadoop-2.8.5/hadoop-2.8.5.tar.gz
tar -zxvf hadoop-2.8.5.tar.gz -C /opt/bigdata
mv hadoop-2.8.5 hadoop
```

在伪分布式安装时，已经配置了hadoop的环境变量，无需再重复配置了。验证：

```shell
echo $HADOOP_HOME
```

##  二、配置 hadoop-env.sh、mapred-env.sh  yarn-env.sh JAVA_HOME参数

比如修改hadoop-env.sh：

```shell
vim  ${HADOOP_HOME}/etc/hadoop/hadoop-env.sh
```

修改JAVA_HOME参数为：

```shell
export JAVA_HOME=/usr/lib/jvm/java
```

## 三、各主要配置文件配置

### 1. 配置core-site.xml

```shell
vim ${HADOOP_HOME}/etc/hadoop/core-site.xml
```

添加内容如下：

```xml
<configuration>
    <property>
       <name>fs.defaultFS</name>
       <value>hdfs://zy1:9000</value>
    </property>
    <property>
       <name>hadoop.tmp.dir</name>
      <value>/opt/bigdata/data/hadoop</value>
    </property>
    <property>
       <name>dfs.namenode.name.dir</name>
       <value>file://${hadoop.tmp.dir}/dfs/name</value>
    </property>
    <property>
       <name>dfs.datanode.data.dir</name>
       <value>file://${hadoop.tmp.dir}/dfs/data</value>
    </property>
</configuration>
```

- fs.defaultFS为NameNode的地址。
- hadoop.tmp.dir：为hadoop临时目录的地址，默认情况下，NameNode和DataNode的数据文件都会存在这个目录下的对应子目录下（但是上面我们通过dfs.datanode.data.dir，和dfs.namenode.data.dir指定了）。应该保证此目录是存在的，如果不存在，先创建；
- dfs.namenode.name.dir：指定目录来供namenode存储永久性的文件系统元数据（如果指定多个路径，使用","隔开）。这些元数据文件会同时备份在所有指定的目录上，通常情况下，通过配置dfs.namenode.data.dir可以将namenode元数据写到一两个本地磁盘和一个远程磁盘（例如NFS挂载目录）之中。这样的话，即使本地磁盘发生故障，甚至整个namenode发生故障，都可以恢复数据文件并重新构成新的namenode（辅助namenode只是定期保存namenode的检查点，不维护namenode的最新备份）；
- dfs.datanode.data.dir：可以设定datanode存储数据块的目录列表，上面提到dfs.namenode.name.dir描述一系列目录，其目的是为了支持namenode进行冗余备份。虽然dfs.datanode.data.dir也描述了一系列目录，但是其目的是使datanode循环的在各个目录中写数据。因此，为了提高性能，最好分别为各个本地磁盘指定一个存储目录，这样一来，数据块跨磁盘分布，针对不同的数据块的读操作可以并发执行，从而提高读取速度。

```shell
mkdir /opt/bigdata/data/hadoop
```

### 2.  配置hdfs-site.xml

```shell
vim ${HADOOP_HOME}/etc/hadoop/hdfs-site.xml
```

添加以下内容：

```xml
<configuration>
 <property>
   <name>dfs.namenode.secondary.http-address</name>
   <value>zy3:50090</value>
 </property>
 <property>
       <name>dfs.replication</name>
       <value>2</value>
  </property>
  <property>
        <name>dfs.client.use.datanode.hostname</name>
        <value>true</value>
    </property>
  <property>
        <name>dfs.datanode.use.datanode.hostname</name>
        <value>true</value>
    </property>
</configuration>
```

- dfs.namenode.secondary.http-address：是指定secondaryNameNode的http访问地址和端口号，因为在规划中，我们将zy3规划为SecondaryNameNode服务器。所以这里设置为：zy3:50090。

- dfs.replication配置的是HDFS存储时的备份数量，这里设置为2；
- fs.client.use.datanode.hostname：是否客户端应该使用DN的HostName，在连接DN时，默认是使用IP；（必须设置为true）
- dfs.datanode.use.datanode.hostname：是否DN应该使用HostName连接其它DN，在数据传输时。默认是是IP。（必须设置为true）

### 3. 配置masters、slaves

```shell
cd hadoop
vim etc/hadoop/masters
vim etc/hadoop/slaves
```

masters修改为：zy1

slavers：zy2

​			  zy3

masters文件是指定HDFS的主节点，zy1特有；slaves文件是指定HDFS上有哪些DataNode节点。

### 4. 配置mapred-site.xml

复制mapred-site.xml.template配置模板文件生成mapred-site.xml：

```shell
cp etc/hadoop/mapred-site.xml.template etc/hadoop/mapred-site.xml
```

添加配置：

```shell
vim etc/hadoop/mapred-site.xml
```

修改内容如下：

```xml
<configuration>
    <property>
        <name>mapreduce.framework.name</name>
        <value>yarn</value>
    </property>
    <property>
        <name>mapreduce.jobhistory.address</name>
        <value>zy1:10020</value>
    </property>
    <property>
        <name>mapreduce.jobhistory.webapp.address</name>
        <value>zy1:19888</value>
    </property>
</configuration>
```

- mapreduce.framework.name设置mapreduce任务运行在yarn上；
- mapreduce.jobhistory.address是设置mapreduce的历史服务器安装在zy1机器上；
- mapreduce.jobhistory.webapp.address是设置历史服务器的web页面地址和端口号。

### 5. 配置yarn-site.xml

```shell
vim etc/hadoop/yarn-site.xml
```

添加内容如下：

```xml
<configuration>
    <property>
        <name>yarn.nodemanager.aux-services</name>
        <value>mapreduce_shuffle</value>
    </property>
    <property>
        <name>yarn.resourcemanager.hostname</name>
        <value>zy2</value>
    </property>
    <property>
        <name>yarn.log-aggregation-enable</name>
        <value>true</value>
    </property>
    <property>
        <name>yarn.log-aggregation.retain-seconds</name>
        <value>106800</value>
    </property>
</configuration>     
```

- yarn.nodemanager.aux-services配置了yarn的默认混洗方式，选择为mapreduce的默认混洗算法；
- yarn.resourcemanager.hostname指定了Resourcemanager运行在zy2节点上；
- `yarn.log-aggregation-enable`是配置是否启用日志聚集功能；
- `yarn.log-aggregation.retain-seconds`是配置聚集的日志在HDFS上最多保存多长时间；

## 四、设置SSH无密码登录及文件分发

### 1. SSH无密码登录配置

Hadoop集群中的各个机器间会相互地通过SSH访问，所以要配置各个机器间的SSH为无密码登录的。

在zy1上生成公钥：

```shell
ssh-keygen -t rsa
```

在当前用户的Home目录下的`.ssh`目录中会生成公钥文件`（id_rsa.pub）`和私钥文件`（id_rsa）`。

 分发公钥：

```sh
ssh-copy-id zy1
ssh-copy-id zy2
ssh-copy-id zy3
```

设置zy2、zy3到其他机器的无密钥登录：同样的在zy2、zy3上生成公钥和私钥后，将公钥分发到三台机器上。

### 2. 分发Hadoop文件

通过Scp分发：

```shell
cd /opt/bigdata
scp -r /opt/bigdata/hadoop/ zy2:/opt/bigdata
scp -r /opt/bigdata/hadoop/ zy3:/opt/bigdata
```

在每个节点下执行：

```shell
mkdir /opt/bigdata/data/hadoop
```

## 五、格式化和启动运行

### 1. 格式NameNode

在使用hadoop之前，全新的HDFS安装需要进行格式化。通过创建存储目录和初始化版本的namenode持久数据结构，格式化将创建一个空的文件系统。

在NameNode机器上(节点zy1)执行格式化：

```shell
hdfs namenode -format
```

**注意：如果需要重新格式化NameNode，需要先将原来NameNode和DataNode下的文件全部删除，不然会报错，NameNode和DataNode所在目录是在core-site.xml中hadoop.tmp.dir、dfs.namenode.name.dir、dfs.datanode.data.dir属性配置的。**

每次格式化，默认创建一个集群ID，并写入NameNode的VERSION文件中（VERSION文件所在目录为dfs/name/current ）。

此时并没有将集群ID写入DataNode的VERSION之中，由于namenode管理所有的文件系统的元数据，datanode可以动态加入或离开集群，**所以初始的格式化过程不涉及datanode**。

只有在启动HDFS时，才会将ID写入DataNode的VERSION之中。如果我们重新格式化HDFS，重新格式化时，默认会生成一个新的集群ID，如果不删除原来的数据目录，会导致namenode中的VERSION文件中是新的集群ID,而DataNode中是旧的集群ID，不一致时会报错。

### 2. 启动HDFS

在zy1节点运行以下命令：

```shell
start-dfs.sh
```

### 3. 启动YARN

```shell
start-yarn.sh
```

在zy2上启动ResourceManager：

```shell
yarn-daemon.sh start resourcemanager
```

### 4. 启动日志服务器

规划为在zy1服务器上运行MapReduce日志服务，所以要在zy1上启动：

```shell
mr-jobhistory-daemon.sh start historyserver
```

### 5. 查看HDFS Web页面

hdfs的Web客户端端口号是50070，通过[http://**zy1**:50070/](http://106.15.74.155:50070/)可以查看。

### 6. 查看YARN Web 页面

YARN的Web客户端端口号是8088，由于ResourceManager设置在zy2节点上，因此通过http://zy2:8088/查看当前执行的job。

### 7. hadoop配置信息

Hadoop更多端口相关的配置参考：[hadoop端口号配置信息](https://blog.csdn.net/qq_27231343/article/details/51470216)、[ResourceManager相关配置参数](https://blog.csdn.net/xiaoshunzi111/article/details/50617357)。

更多Hadoop的参数配置可以惨开：[hadoop 参数配置](https://my.oschina.net/U74F1zkKW/blog/471338#OSC_h3_6)。

### 8. 关闭hadoop

在各个节点下运行如下命令：

```shell
cd /opt/bigdata/hadoop
sbin/stop-all.sh 
```

### 9. 重新格式化和启动

在每个节点运行如下命令：

```shell
cd /opt/bigdata/hadoop
sbin/stop-all.sh
rm -rf  logs/*
rm -rf ../data/hadoop/*
```

在namenode节点(zy1)运行：

```shell
hdfs namenode -format
```

然后在每个节点运行相应启动hadoop的命令。

## 六、错误排查

如果hadoop启动出现出错，查看日志，日志位于hadoop安装路径下的logs目录下。



## 七、参考文章

https://blog.csdn.net/hliq5399/article/details/78193113
https://www.cnblogs.com/zyly/p/11209286.html#_label4_16
https://blog.csdn.net/bqw18744018044/article/details/79103931
https://blog.csdn.net/henrrywan/article/details/86432912?depth_1-utm_source=distribute.pc_relevant.none-task&utm_source=distribute.pc_relevant.none-task
https://hadoop.apache.org/docs/

