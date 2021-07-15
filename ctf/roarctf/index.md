# RoarCTF Misc Davinci-Cipher writeup


# RoarCTF MISC Davinci_Cipher

    这道题实在是可惜，第一天磕了半天没出来。第二天灵光乍现，但是晚了一分钟，比赛结束了。。。唉。。后来看官方的wp，思路步骤全是一样的。。。心痛。。

## 初步分析
题目给了两个附件，一个txt，一个流量包。打开txt看一下：
```
U+1F643U+1F4B5U+1F33FU+1F3A4U+1F6AAU+1F30FU+1F40EU+1F94BU+1F6ABU+1F606U+1F383U+1F993U+2709U+1F33FU+1F4C2U+2603U+1F449U+1F6E9U+2705U+1F385U+2328U+1F30FU+1F6E9U+1F6A8U+1F923U+1F4A7U+1F383U+1F34DU+1F601U+2139U+1F4C2U+1F6ABU+1F463U+1F600U+1F463U+1F643U+1F3A4U+2328U+1F601U+1F923U+1F3A4U+1F579U+1F451U+1F6AAU+1F374U+1F579U+1F607U+1F374U+1F40EU+2705U+2709U+1F30FU+23E9U+1F40DU+1F6A8U+2600U+1F607U+1F3F9U+1F441U+1F463U+2709U+1F30AU+1F6A8U+2716
```

很明显是unicode码，这里首先就想到了可能会用到代码点去进行转换（也就是这个第一印象给自己带偏了）。  
txt文件没有其他信息了，直接开流量包吧：

![](/img/ctf/roarctf/misc/流量包初步分析.png)

首先注意到流量中有一个图片，直接导出特定包，然后把图片提取出来：

![](/img/ctf/roarctf/misc/烟雾弹.png)

然后开始各种蹂躏这个图，然并卵，没有任何有价值的信息。思路不对，而且没有发现图片和txt的丝毫关联。

## 进一步分析
回到流量包，继续磕，发现了另外一个猫腻：存在USB协议流量  
- 分析USB流量  
发现了一个Wacom PTH-660的设备。果断google，是一个数位板。之前遇到过一个类似的ctf题目，大概猜测是通过数位板进行绘画，然后在流量中体现。
- 分析数位板流量  
USB流量的数据段是Leftover Capture Data，发现的数位板的src为1.9.1，frame长度为54。直接筛选可能的有效流量：(usb.src == "1.9.1")&&(frame.len == 54)并导出筛选出后的分组usb.pcapng。
- 分析数据段  
USB协议可以从[USB协议](https://www.usb.org/sites/default/files/documents/hut1_12v2.pdf)了解详细的过程，而且其中包含了对数位板的介绍。这里主要看一下与这道题目相关的数位板：

![](/img/ctf/roarctf/misc/数位板.png)

需要对该数位板的数据格式做一个分析：x，y坐标以小端存储。结合之前在流量包中看到的数据，我们可以猜测到坐标存储的位置。红框为坐标高位bit，同一时间内变 化小于绿框(低位bit)变化率，橙框变化猜测为压力值，笔离开画板时压力变为0。

![](/img/ctf/roarctf/misc/数位板数据.png)

## 脚本
```
# coding:utf-8
import sys
import os
import numpy as np
import matplotlib.pyplot as plt
mousePositionX = 0
mousePositionY = 0
X = [] Y = []
DataFileName = "test.txt"
data = []
def main():
    global mousePositionX
    global mousePositionY
    # check argv
    if len(sys.argv) == 1:
         print "Usage : "
        print "        python UsbDigitizerHacker.py data.pcap [Conditions used
to sort]"
        print "Tips : "
        print "        To use this python2 script , you must install the
numpy,matplotlib first."
        print "        You can use `sudo pip install matplotlib numpy` to
install it"
exit(1)
    # get argv
    pcapFilePath = sys.argv[1]
    print pcapFilePath
    # get data of pcap
    if len(sys.argv)==2:
        command = "tshark -r '%s' -T fields -e usb.capdata > %s" % (
            pcapFilePath, DataFileName)
        print command
        os.system(command)
    if len(sys.argv)==3:
        Conditions=sys.argv[2]
        command = "tshark -r '%s' -T fields -e usb.capdata -Y '%s' > %s" % (
            pcapFilePath,Conditions, DataFileName)
        print command
        os.system(command)
    with open(DataFileName, "rb") as f:
        flag=1
for line in f:
if line[24:26] != "00": 
                print line
                data.append(line[0:-1])
for line in data:
        x0=int(line[6:8],16)
        x1=int(line[9:11],16)
        x=x0+x1*256
        y0=int(line[15:17],16)
        y1=int(line[18:20],16)
        y=y0+y1*256
        X.append(x)
        Y.append(-y)
    #draw
    fig = plt.figure()
    ax1 = fig.add_subplot(111)
    ax1.set_title('[%s]' % (pcapFilePath))
    ax1.scatter(X, Y, c='r', marker='o')
    plt.savefig("out.png")
    plt.show()
    #clean temp data
    os.system("rm ./%s" % (DataFileName))
if __name__ == "__main__":
    main()

```

这里可以得到图如下所示：

![](/img/ctf/roarctf/misc/key.png)

哦！flag！我直接提交，然而。。。错误。  
到此为止，我花了半天的时间去搞完这些操作，最后也得到一个高度仿真的flag。然而提示我错误？思路中断，，  


第二天，早上醒来，突然想到flag.txt还没有用过！打开，直接复制去UTF-8解码（其实有点气急败坏了），发现不对。至此，比赛结束。然后，我发现这是emoji！！！！！去解码，key用上面那个图中的字符串：

![](/img/ctf/roarctf/misc/转码.png)

![](/img/ctf/roarctf/misc/flag.png)

然而，时间已经过去了，，，比赛结束了。
