# Hadoop--初学到漏洞(五)--HDFS


# Hadoop--初学到漏洞(五)--HDFS

## 一、架构

HDFS遵循主从架构。

![hdfs-architecture](https://atts.w3cschool.cn/attachments/image/20190627/1561603936683523.png)

- **Block数据块;**
  1. 基本存储单位，一般大小为64M（配置大的块主要是因为：1）减少搜寻时间，一般硬盘传输速率比寻道时间要快，大的块可以减少寻道时间；2）减少管理块的数据开销，每个块都需要在NameNode上有对应的记录；3）对数据块进行读写，减少建立网络的连接成本）
  2. 一个大文件会被拆分成一个个的块，然后存储于不同的机器。如果一个文件少于Block大小，那么实际占用的空间为其文件的大小
  3. 基本的读写单位，类似于磁盘的页，每次都是读写一个块
  4. 每个块都会被复制到多台机器，默认复制3份
- **NameNode**
  1. 存储文件的metadata，运行时所有数据都保存到内存，整个HDFS可存储的文件数受限于NameNode的内存大小
  2. 一个Block在NameNode中对应一条记录（一般一个block占用150字节），如果是大量的小文件，会消耗大量内存。同时map task的数量是由splits来决定的，所以用MapReduce处理大量的小文件时，就会产生过多的map task，线程管理开销将会增加作业时间。处理大量小文件的速度远远小于处理同等大小的大文件的速度。因此Hadoop建议存储大文件
  3. 数据会定时保存到本地磁盘，但不保存block的位置信息，而是由DataNode注册时上报和运行时维护（NameNode中与DataNode相关的信息并不保存到NameNode的文件系统中，而是NameNode每次重启后，动态重建）
  4. NameNode失效则整个HDFS都失效了，所以要保证NameNode的可用性
- **Secondary NameNode**
  1. 定时与NameNode进行同步（定期合并文件系统镜像和编辑日志，然后把合并后的传给NameNode，替换其镜像，并清空编辑日志，类似于CheckPoint机制），但NameNode失效后仍需要手工将其设置成主机
- **DataNode**
  1. 保存具体的block数据
  2. 负责数据的读写操作和复制操作
  3. DataNode启动时会向NameNode报告当前存储的数据块信息，后续也会定时报告修改信息
  4. DataNode之间会进行通信，复制数据块，保证数据的冗余性

## 二、写文件


![img](https://atts.w3cschool.cn/attachments/image/wk/hadoop/hdfs-write.png)

1.客户端将文件写入本地磁盘的HDFS Client文件中

2.当临时文件大小达到一个block大小时，HDFS client通知NameNode，申请写入文件

3.NameNode在HDFS的文件系统中创建一个文件，并把该block id和要写入的DataNode的列表返回给客户端

4.客户端收到这些信息后，将临时文件写入DataNodes

- 4.1 客户端将文件内容写入第一个DataNode（一般以4kb为单位进行传输）
- 4.2 第一个DataNode接收后，将数据写入本地磁盘，同时也传输给第二个DataNode
- 4.3 依此类推到最后一个DataNode，数据在DataNode之间是通过pipeline的方式进行复制的
- 4.4 后面的DataNode接收完数据后，都会发送一个确认给前一个DataNode，最终第一个DataNode返回确认给客户端
- 4.5 当客户端接收到整个block的确认后，会向NameNode发送一个最终的确认信息
- 4.6 如果写入某个DataNode失败，数据会继续写入其他的DataNode。然后NameNode会找另外一个好的DataNode继续复制，以保证冗余性
- 4.7 每个block都会有一个校验码，并存放到独立的文件中，以便读的时候来验证其完整性

5.文件写完后（客户端关闭），NameNode提交文件（这时文件才可见，如果提交前，NameNode垮掉，那文件也就丢失了。fsync：只保证数据的信息写到NameNode上，但并不保证数据已经被写到DataNode中）

**Rack aware（机架感知）**

通过配置文件指定机架名和DNS的对应关系

假设复制参数是3，在写入文件时，会在本地的机架保存一份数据，然后在另外一个机架内保存两份数据（同机架内的传输速度快，从而提高性能）

整个HDFS的集群，最好是负载平衡的，这样才能尽量利用集群的优势。



## 三、读文件

![img](https://atts.w3cschool.cn/attachments/image/wk/hadoop/hdfs-read.png)

1. 客户端向NameNode发送读取请求
2. NameNode返回文件的所有block和这些block所在的DataNodes（包括复制节点）
3. 客户端直接从DataNode中读取数据，如果该DataNode读取失败（DataNode失效或校验码不对），则从复制节点中读取（如果读取的数据就在本机，则直接读取，否则通过网络读取）

## 四、可靠性

1. DataNode可以失效

   DataNode会定时发送心跳到NameNode。如果一段时间内NameNode没有收到DataNode的心跳消息，则认为其失效。此时NameNode就会将该节点的数据（从该节点的复制节点中获取）复制到另外的DataNode中

2. 数据可以毁坏

   无论是写入时还是硬盘本身的问题，只要数据有问题（读取时通过校验码来检测），都可以通过其他的复制节点读取，同时还会再复制一份到健康的节点中

3. NameNode不可靠

## 五、命令工具

fsck: 检查文件的完整性

start-balancer.sh: 重新平衡HDFS

hdfs dfs -copyFromLocal 从本地磁盘复制文件到HDFS

