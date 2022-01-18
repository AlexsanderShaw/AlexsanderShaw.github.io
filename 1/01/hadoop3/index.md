# 

# Hadoop--初学到漏洞(三)--MapReduce

# Hadoop--初学到漏洞(三)--MapReduce



## 一、简介

MapReduce是一种分布式计算方式，指定一个Map函数，把一组键值对映射成一组新的键值对，指定并发的Reduce（归约）函数，用来保证所有映射的键值对中的每一个共享相同的键组。

其Pattern图如下：

![mapreduce-pattern](https://i.imgur.com/XsyOHH7.png)

map: (K1, V1) → list(K2, V2)  combine: (K2, list(V2)) → list(K2, V2)  reduce: (K2, list(V2)) → list(K3, V3)

Map输出格式和Reduce输入格式一定是相同的。

## 二、流程

### 1. 基本流程

MapReduce主要是先读取文件数据，然后进行Map处理，接着Reduce处理，最后把处理结果写到文件中。流程图如下：

![mapreduce-process-overview](https://i.imgur.com/aU6lOol.png)

### 2. 详细流程

处理的详细流程如下：

![mapreduce-process](https://i.imgur.com/3cvQmf9.png)



### 3. 多节点下的流程

多节点的流程如下：

![mapreduce-process-cluster](https://i.imgur.com/bog3axD.png)

### 4. 数据角度流程处理

数据流的处理过程如下：

![mapreduce-data-process](https://i.imgur.com/aGxXqKZ.png)

1. Record reader

记录阅读器会翻译由输入格式生成的**记录**，记录阅读器用于将数据解析给记录，并不分析记录自身。它将数据以键值对的形式传输给mapper。通常键是位置信息，值是构成记录的数据存储块。

2. Map

在映射器中用户提供的代码称为中间对。键决定了数据分类的依据，而值决定了处理器中的分析信息.本书的设计模式将会展示大量细节来解释特定键值如何选择。

3. Shuffle and Sort

ruduce任务以随机和排序步骤开始。此步骤写入输出文件并下载到本地计算机。这些数据采用键进行排序以把等价密钥组合到一起。

4. Reduce

reducer采用分组数据作为输入。该功能传递键和此键相关值的迭代器。可以采用多种方式来汇总、过滤或者合并数据。当ruduce功能完成，就会发送0个或多个键值对。

5. 输出格式

输出格式会转换最终的键值对并写入文件。默认情况下键和值以tab分割，各记录以换行符分割。因此可以自定义更多输出格式，最终数据会写入HDFS。

## 三、分阶段过程详细分析

### 1. Hadoop读取数据

通过InputFormat决定读取的数据的类型（可以是文件或数据库等），然后拆分成InputSplit，每个InputSplit对应一个Map处理，RecordReader读取InputSplit内容给到Map。

1. 功能

   - 验证作业输入的正确性，如格式等
   - 将输入文件切割成逻辑分片（InputSplit），一个InputSplit分配给一个独立的Map任务
   - 提供ReocrdReader实现，读取InputSplit中的“K-V”对给Mapper使用

2. 方法

   - **List getSplits():** 获取由输入文件计算出输入分片(InputSplit)，解决数据或文件分割成片问题

   - **RecordReader createRecordReader():** 创建RecordReader，从InputSplit中读取数据，解决读取分片中数据问题

   ![mapreduce-inputformat](https://i.imgur.com/OEurCJF.png)

   - **TextInputFormat:** 输入文件中的每一行就是一个记录，Key是这一行的byte offset，而value是这一行的内容

   - **KeyValueTextInputFormat:** 输入文件中每一行就是一个记录，第一个分隔符字符切分每行。在分隔符字符之前的内容为Key，在之后的为Value。分隔符变量通过key.value.separator.in.input.line变量设置，默认为(\t)字符。

   - **NLineInputFormat:** 与TextInputFormat一样，但每个数据块必须保证有且只有Ｎ行，mapred.line.input.format.linespermap属性，默认为１

   - **SequenceFileInputFormat:** 一个用来读取字符流数据的InputFormat，<key,value>为用户自定义的。字符流数据是Hadoop自定义的压缩的二进制数据格式。它用来优化从一个MapReduce任务的输出到另一个MapReduce任务的输入之间的数据传输过程。</key,value>

   - **InputSplit：**代表一个个逻辑分片，并没有真正存储数据，只是提供了一个如何将数据分片的方法

     Split内有Location信息，利于数据局部化。一个InputSplit给一个单独的Map处理

     ```java
public abstract class InputSplit {
           /**
       * 获取Split的大小，支持根据size对InputSplit排序.
            */
           public abstract long getLength() throws IOException, InterruptedException;
     
           /**
            * 获取存储该分片的数据所在的节点位置.
            */
           public abstract String[] getLocations() throws IOException, InterruptedException;
     }
     ```
     
   - **RecordReader：**将InputSplit拆分成一个个<key,value>对给Map处理，也是实际的文件读取分隔对象</key,value>

### 2. 问题

1. 大量小文件如何处理

   CombineFileInputFormat可以将若干个Split打包成一个，目的是避免过多的Map任务（因为Split的数目决定了Map的数目，大量的Mapper Task创建销毁开销将是巨大的）

2. 怎么计算split的

   通常一个split就是一个block（FileInputFormat仅仅拆分比block大的文件），这样做的好处是使得Map可以在存储有当前数据的节点上运行本地的任务，而不需要通过网络进行跨节点的任务调度

   通过mapred.min.split.size， mapred.max.split.size，block.size来控制拆分的大小

   如果mapred.min.split.size大于block size，则会将两个block合成到一个split，这样有部分block数据需要通过网络读取

   如果mapred.max.split.size小于block size，则会将一个block拆成多个split，增加了Map任务数（Map对split进行计算并且上报结果，关闭当前计算打开新的split均需要耗费资源）

   先获取文件在HDFS上的路径和Block信息，然后根据splitSize对文件进行切分（ splitSize = computeSplitSize(blockSize, minSize, maxSize) ），默认splitSize 就等于blockSize的默认值（64m）

```java
public List<InputSplit> getSplits(JobContext job) throws IOException {
    // 首先计算分片的最大和最小值。这两个值将会用来计算分片的大小
    long minSize = Math.max(getFormatMinSplitSize(), getMinSplitSize(job));
    long maxSize = getMaxSplitSize(job);

    // generate splits
    List<InputSplit> splits = new ArrayList<InputSplit>();
    List<FileStatus> files = listStatus(job);
    for (FileStatus file: files) {
        Path path = file.getPath();
        long length = file.getLen();
        if (length != 0) {
              FileSystem fs = path.getFileSystem(job.getConfiguration());
            // 获取该文件所有的block信息列表[hostname, offset, length]
              BlockLocation[] blkLocations = fs.getFileBlockLocations(file, 0, length);
            // 判断文件是否可分割，通常是可分割的，但如果文件是压缩的，将不可分割
              if (isSplitable(job, path)) {
                long blockSize = file.getBlockSize();
                // 计算分片大小
                // 即 Math.max(minSize, Math.min(maxSize, blockSize));
                long splitSize = computeSplitSize(blockSize, minSize, maxSize);

                long bytesRemaining = length;
                // 循环分片。
                // 当剩余数据与分片大小比值大于Split_Slop时，继续分片， 小于等于时，停止分片
                while (((double) bytesRemaining)/splitSize > SPLIT_SLOP) {
                      int blkIndex = getBlockIndex(blkLocations, length-bytesRemaining);
                      splits.add(makeSplit(path, length-bytesRemaining, splitSize, blkLocations[blkIndex].getHosts()));
                      bytesRemaining -= splitSize;
                }
                // 处理余下的数据
                if (bytesRemaining != 0) {
                    splits.add(makeSplit(path, length-bytesRemaining, bytesRemaining, blkLocations[blkLocations.length-1].getHosts()));
                }
            } else {
                // 不可split，整块返回
                splits.add(makeSplit(path, 0, length, blkLocations[0].getHosts()));
            }
        } else {
            // 对于长度为0的文件，创建空Hosts列表，返回
            splits.add(makeSplit(path, 0, length, new String[0]));
        }
    }

    // 设置输入文件数量
    job.getConfiguration().setLong(NUM_INPUT_FILES, files.size());
    LOG.debug("Total # of splits: " + splits.size());
    return splits;
}
```

3. 分片间的数据如何处理

   split是根据文件大小分割的，而一般处理是根据分隔符进行分割的，这样势必存在一条记录横跨两个split

![img](https://atts.w3cschool.cn/attachments/image/wk/hadoop/mapreduce-split.png)

​	解决办法是只要不是第一个split，都会远程读取一条记录。不是第一个split的都忽略到第一条记录

```java
public class LineRecordReader extends RecordReader<LongWritable, Text> {
    private CompressionCodecFactory compressionCodecs = null;
    private long start;
    private long pos;
    private long end;
    private LineReader in;
    private int maxLineLength;
    private LongWritable key = null;
    private Text value = null;

    // initialize函数即对LineRecordReader的一个初始化
    // 主要是计算分片的始末位置，打开输入流以供读取K-V对，处理分片经过压缩的情况等
    public void initialize(InputSplit genericSplit, TaskAttemptContext context) throws IOException {
        FileSplit split = (FileSplit) genericSplit;
        Configuration job = context.getConfiguration();
        this.maxLineLength = job.getInt("mapred.linerecordreader.maxlength", Integer.MAX_VALUE);
        start = split.getStart();
        end = start + split.getLength();
        final Path file = split.getPath();
        compressionCodecs = new CompressionCodecFactory(job);
        final CompressionCodec codec = compressionCodecs.getCodec(file);

        // 打开文件，并定位到分片读取的起始位置
        FileSystem fs = file.getFileSystem(job);
        FSDataInputStream fileIn = fs.open(split.getPath());

        boolean skipFirstLine = false;
        if (codec != null) {
            // 文件是压缩文件的话，直接打开文件
            in = new LineReader(codec.createInputStream(fileIn), job);
            end = Long.MAX_VALUE;
        } else {
            // 只要不是第一个split，则忽略本split的第一行数据
            if (start != 0) {
                skipFirstLine = true;
                --start;
                // 定位到偏移位置，下次读取就会从偏移位置开始
                fileIn.seek(start);
            }
            in = new LineReader(fileIn, job);
        }

        if (skipFirstLine) {
            // 忽略第一行数据，重新定位start
            start += in.readLine(new Text(), 0, (int) Math.min((long) Integer.MAX_VALUE, end - start));
        }
        this.pos = start;
    }

    public boolean nextKeyValue() throws IOException {
        if (key == null) {
            key = new LongWritable();
        }
        key.set(pos);// key即为偏移量
        if (value == null) {
            value = new Text();
        }
        int newSize = 0;
        while (pos < end) {
            newSize = in.readLine(value, maxLineLength,    Math.max((int) Math.min(Integer.MAX_VALUE, end - pos), maxLineLength));
            // 读取的数据长度为0，则说明已读完
            if (newSize == 0) {
                break;
            }
            pos += newSize;
            // 读取的数据长度小于最大行长度，也说明已读取完毕
            if (newSize < maxLineLength) {
                break;
            }
            // 执行到此处，说明该行数据没读完，继续读入
        }
        if (newSize == 0) {
            key = null;
            value = null;
            return false;
        } else {
            return true;
        }
    }
}
```

### 3. Mapper

主要是读取InputSplit的每一个Key,Value对并进行处理：

```java
public class Mapper<KEYIN, VALUEIN, KEYOUT, VALUEOUT> {
    /**
     * 预处理，仅在map task启动时运行一次
     */
    protected void setup(Context context) throws  IOException, InterruptedException {
    }

    /**
     * 对于InputSplit中的每一对<key, value>都会运行一次
     */
    @SuppressWarnings("unchecked")
    protected void map(KEYIN key, VALUEIN value, Context context) throws IOException, InterruptedException {
        context.write((KEYOUT) key, (VALUEOUT) value);
    }

    /**
     * 扫尾工作，比如关闭流等
     */
    protected void cleanup(Context context) throws IOException, InterruptedException {
    }

    /**
     * map task的驱动器
     */
    public void run(Context context) throws IOException, InterruptedException {
        setup(context);
        while (context.nextKeyValue()) {
            map(context.getCurrentKey(), context.getCurrentValue(), context);
        }
        cleanup(context);
    }
}

public class MapContext<KEYIN, VALUEIN, KEYOUT, VALUEOUT> extends TaskInputOutputContext<KEYIN, VALUEIN, KEYOUT, VALUEOUT> {
    private RecordReader<KEYIN, VALUEIN> reader;
    private InputSplit split;

    /**
     * Get the input split for this map.
     */
    public InputSplit getInputSplit() {
        return split;
    }

    @Override
    public KEYIN getCurrentKey() throws IOException, InterruptedException {
        return reader.getCurrentKey();
    }

    @Override
    public VALUEIN getCurrentValue() throws IOException, InterruptedException {
        return reader.getCurrentValue();
    }

    @Override
    public boolean nextKeyValue() throws IOException, InterruptedException {
        return reader.nextKeyValue();
    }
}
```



### 4.Shuffle

对Map的结果进行排序并传输到Reduce进行处理 Map的结果并不是直接存放到硬盘,而是利用缓存做一些预排序处理 Map会调用Combiner，压缩，按key进行分区、排序等，尽量减少结果的大小 每个Map完成后都会通知Task，然后Reduce就可以进行处理

![img](https://atts.w3cschool.cn/attachments/image/wk/hadoop/mapreduce-process.png)

1. Map端

   当Map程序开始产生结果的时候，并不是直接写到文件的，而是利用缓存做一些排序方面的预处理操作

   每个Map任务都有一个循环内存缓冲区（默认100MB），当缓存的内容达到80%时，后台线程开始将内容写到文件，此时Map任务可以继续输出结果，但如果缓冲区满了，Map任务则需要等待

   写文件使用round-robin方式。在写入文件之前，先将数据按照Reduce进行分区。对于每一个分区，都会在内存中根据key进行排序，如果配置了Combiner，则排序后执行Combiner（Combine之后可以减少写入文件和传输的数据）

   每次结果达到缓冲区的阀值时，都会创建一个文件，在Map结束时，可能会产生大量的文件。在Map完成前，会将这些文件进行合并和排序。如果文件的数量超过3个，则合并后会再次运行Combiner（1、2个文件就没有必要了）

   如果配置了压缩，则最终写入的文件会先进行压缩，这样可以减少写入和传输的数据

   一旦Map完成，则通知任务管理器，此时Reduce就可以开始复制结果数据

2. Reduce端

   Map的结果文件都存放到运行Map任务的机器的本地硬盘中

   如果Map的结果很少，则直接放到内存，否则写入文件中

   同时后台线程将这些文件进行合并和排序到一个更大的文件中（如果文件是压缩的，则需要先解压）

   当所有的Map结果都被复制和合并后，就会调用Reduce方法

   Reduce结果会写入到HDFS中

3. 调优

   一般的原则是给shuffle分配尽可能多的内存，但前提是要保证Map、Reduce任务有足够的内存

   对于Map，主要就是避免把文件写入磁盘，例如使用Combiner，增大io.sort.mb的值

   对于Reduce，主要是把Map的结果尽可能地保存到内存中，同样也是要避免把中间结果写入磁盘。默认情况下，所有的内存都是分配给Reduce方法的，如果Reduce方法不怎么消耗内存，可以mapred.inmem.merge.threshold设成0，mapred.job.reduce.input.buffer.percent设成1.0

   在任务监控中可通过Spilled records counter来监控写入磁盘的数，但这个值是包括map和reduce的

   对于IO方面，可以Map的结果可以使用压缩，同时增大buffer size（io.file.buffer.size，默认4kb）

4. 配置

|                  属性                   |    默认值    |                             描述                             |
| :-------------------------------------: | :----------: | :----------------------------------------------------------: |
|               io.sort.mb                |     100      |              映射输出分类时所使用缓冲区的大小.               |
|         io.sort.record.percent          |     0.05     | 剩余空间用于映射输出自身记录.在1.X发布后去除此属性.随机代码用于使用映射所有内存并记录信息. |
|          io.sort.spill.percent          |     0.80     |        针对映射输出内存缓冲和记录索引的阈值使用比例.         |
|             io.sort.factor              |      10      | 文件分类时合并流的最大数量。此属性也用于reduce。通常把数字设为100. |
|       min.num.spills.for.combine        |      3       |                组合运行所需最小溢出文件数目.                 |
|       mapred.compress.map.output        |    false     |                        压缩映射输出.                         |
|   mapred.map.output.compression.codec   | DefaultCodec |                 映射输出所需的压缩解编码器.                  |
|      mapred.reduce.parallel.copies      |      5       |             用于向reducer传送映射输出的线程数目.             |
|       mapred.reduce.copy.backoff        |     300      | 时间的最大数量，以秒为单位，这段时间内若reducer失败则会反复尝试传输 |
|             io.sort.factor              |      10      |                组合运行所需最大溢出文件数目.                 |
| mapred.job.shuffle.input.buffer.percent |     0.70     |           随机复制阶段映射输出缓冲器的堆栈大小比例           |
|    mapred.job.shuffle.merge.percent     |     0.66     | 用于启动合并输出进程和磁盘传输的映射输出缓冲器的阀值使用比例 |
|      mapred.inmem.merge.threshold       |     1000     | 用于启动合并输出和磁盘传输进程的映射输出的阀值数目。小于等于0意味着没有门槛，而溢出行为由 mapred.job.shuffle.merge.percent单独管理. |
| mapred.job.reduce.input.buffer.percent  |     0.0      | 用于减少内存映射输出的堆栈大小比例，内存中映射大小不得超出此值。若reducer需要较少内存则可以提高该值. |

### 5. 编程

1. 处理
   1. select：直接分析输入数据，取出需要的字段数据即可
   2. where: 也是对输入数据处理的过程中进行处理，判断是否需要该数据
   3. aggregation:min, max, sum
   4. group by: 通过Reducer实现
   5. sort
   6. join: map join, reduce join

2. Third-Party Libraries

```shell
# 第一种
export LIBJARS=$MYLIB/commons-lang-2.3.jar, hadoop jar prohadoop-0.0.1-SNAPSHOT.jar org.aspress.prohadoop.c3. WordCountUsingToolRunner -libjars $LIBJARS

#第二种
hadoop jar prohadoop-0.0.1-SNAPSHOT-jar-with-dependencies.jar org.aspress.prohadoop.c3. WordCountUsingToolRunner The dependent libraries are now included inside the application JAR file
```

一般还是第一种的好，指定依赖可以利用Public Cache，如果是包含依赖，则每次都需要拷贝。

## 四、参考文献

[w3 school](https://www.w3cschool.cn/hadoop/g94s1p36.html)

[MapReduce Design Patterns](http://book.douban.com/subject/11229683/)





