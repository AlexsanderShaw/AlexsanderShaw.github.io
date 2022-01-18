# Linux平台下的CTF Pwn环境搭建



# Linux平台下的CTF Pwn环境搭建

## 前言
**最近遇到很多人想玩CTF，咨询环境问题。为了更好地将研究重心放在技术本身，这里简单整理一下个人的Pwn环境的搭建过程，仅供参考。**

## 一、操作系统选择

因为是Pwn环境，涉及到Windows平台的比较少，所以一般使用Linux或者MacOS。我个人是一套Linux的虚拟环境搭配MacOS的物理环境，基本能适应所有的Pwn环境要求。

**物理环境：MBP 2015**  
**虚拟环境：Ubuntu 18.04** 

***需要注意，Linux的版本太高很多插件容易出问题，所以不建议使用最新版本的Linux系统，最稳定的不是太老旧的就可以。此外，环境因人而异，没有模板，不是固定的，按需分配。***

## 二、必备一般软件

1. vim：个人必备，强烈建议学习一点vim的相关知识，可以提高效率，避免安装过多的编辑器或者IDE
2. git：必备，很多高效的插件都是放在GitHub上的
3. python：必备，建议python3，毕竟python2已经不支持了
4. pip：必备，有一些插件需要使用pip进行安装
5. 一款编辑器：这个看个人需求，vscode、sublime text等，个人喜欢就好。如果有条件的话，可以设置一下配置，当作一个简单的开发IDE使用，毕竟Pwn环境中开发的代码不会很多。

以上各软件根据官方文档自行安装即可。

## 三、Pwn常用软件

***涉及到的各种软件的安装，均以Ubuntu平台为例***
1. **pwntools**  

    一个ctf框架和漏洞利用开发库，用python开发,必备神器，作用不多解释。  
    安装方法：
    ```
    $ apt-get install python python-pip python-dev libssl-dev libffi-dev build-essential
    $ pip install -U setuptools
    $ pip install --upgrade pip
    $ pip install --upgrade pwntools

    ```
    个人使用的是python2版本，需要注意一下。pwntools现在支持python3了，这里给出GitHub地址，有需要的可以参考其readme进行安装python3的pwntools。  
    [支持python3的pwntools](https://github.com/arthaud/python3-pwntools)  

    安装完成后，打开python测试, 执行`from pwn import *`不会报错即可。  
    （备注：在mac平台下不要使用pip安装，你会怀疑人生的，使用homebrew安装）

2. **gdb**

    动态调试软件，必备。  
    安装方法：
    ```
    apt-get install gdb

3. **peda/pwngdb/gef**

    这是常见的gdb的三个插件，配合gdb使用可以提升调试效率。  
    安装pwndbg：
    ```
    git clone https://github.com/pwndbg/pwndbg

    cd pwndbg

    ./setup.sh
    ```

    安装peda：
    ```
    git clone https://github.com/longld/peda.git~/peda

    echo "source ~/peda/peda.py" >> ~/.gdbinit
    ```

    安装gef：
    ```
    wget -q -O- https://github.com/hugsy/gef/raw/master/scripts/gef.sh| sh
    wget -q -O ~/.gdbinit-gef.py https://github.com/hugsy/gef/raw/master/gef.py
    echo source ~/.gdbinit-gef.py >> ~/.gdbinit

    ```

    因为在同一时刻只能使用一种插件，而且在解决不同类型的题目时使用不同的插件，因此需要配置三种插件的快捷切换。

    首先，gdb使用哪种插件是在.gdbinit文件（一般在root目录下）中使用source进行控制的，我们可以在使用插件时注释掉其他的source命令，即可单独使用某一插件。但是每次都编辑该文件实在是麻烦，因此可以使用脚本进行选择。
    ```
    #!/bin/bash
    function Mode_change {
        name=$1
        gdbinitfile=~/.gdbinit    #这个路径按照你的实际情况修改
        # gdbinitfile=/root/Desktop/mode
        
        peda="source ~/peda/peda.py"   #这个路径按照你的实际情况修改
        gef="source ~/.gdbinit-gef.py"   #这个路径按照你的实际情况修改
        pwndbg="source /opt/pwndbg/gdbinit.py"   #这个路径按照你的实际情况修改
    
        sign=$(cat $gdbinitfile | grep -n "#this place is controled by user's shell")     
            #此处上面的查找内容要和你自己的保持一致
    
        pattern=":#this place is controled by user's shell"
        number=${sign%$pattern}
        location=$[number+2]
    
        parameter_add=${location}i
        parameter_del=${location}d
    
        message="TEST"
    
        if [ $name -eq "1" ];then
            sed -i "$parameter_del" $gdbinitfile
            sed -i "$parameter_add $peda" $gdbinitfile
            echo -e "Please enjoy the peda!\n"
        elif [ $name -eq "2" ];then
            sed -i "$parameter_del" $gdbinitfile
            sed -i "$parameter_add $gef" $gdbinitfile
            echo -e "Please enjoy the gef!\n"
        else
            sed -i "$parameter_del" $gdbinitfile
            sed -i "$parameter_add $pwndbg" $gdbinitfile
            echo -e "Please enjoy the pwndbg!\n"
        fi
    }

    echo -e "Please choose one mode of GDB?\n1.peda    2.gef    3.pwndbg"
    
    read -p "Input your choice:" num
    
    if [ $num -eq "1" ];then
        Mode_change $num
    elif [ $num -eq "2" ];then
        Mode_change $num
    elif [ $num -eq "3" ];then
        Mode_change $num
    else
        echo -e "Error!\nPleasse input right number!"
    fi
    
    gdb $1 $2 $3 $4 $5 $6 $7 $8 $9
    ```

    现在我们把这个shell脚本放到一个环境变量指向的路径里面，查看一下自己的路径，shell脚本放进去
    ```
    echo $PATH
    ```
    我放在了/usr/local/sbin目录下，这样就可以执行 gdb.sh，输入对应插件的数字就可以选择使用哪个插件，无需手动更改.gdbinit文件。

    实在不会可以参考这位师傅的教程：[自动选择gdb插件](https://www.jianshu.com/p/94a71af2022a)

4. **32位程序支持**

    必备，装它。
    ```
    apt-get install libc6-dev-i386
    ```

5. **qemu**
    
    这是arm的pwn环境，前期可以不安装，但是终究是逃不过的，建议一步到位。
    安装qemu：
    ```
    sudo apt-get install qemu

    sudo apt-get install qemu-system qemu-user-static binfmt-support
    ```
    安装依赖库：
    ```
    sudo apt-get install -y gcc-arm-linux-gnueabi

    sudo apt-get install qemu libncurses5-dev gcc-arm-linux-gnueabi build-essential gdb-arm-none-eabi synaptic gcc-aarch64-linux-gnu eclipse-cdt git
    ```

6. **LibcSearcher**

    泄露libc库中函数的偏移的库，建议安装，可以节省时间，提高效率。
    安装LibcSearcher：

    ```
    sudo pip install capstone
    git clone https://github.com/lieanu/LibcSearcher.git
    cd LibcSearcher
    python setup.py develop
    ```

7. **ROPgadget和one_gadget**

    ROPgadget是用来找gadget的，one_gadget用来寻找libc库中的execve('/bin/sh', NULL, NULL)可以一个gadget就可以getshell，建议安装。

    安装ROPgadget：
    ```
    # 先安装Capstone,它是一个轻量级的多平台架构支持的反汇编架构。
    sudo apt-get install python-capstone


    然后，下载好ROPgadget解压进入文件夹中
    python setup.py install
    ```
    安装one_gadget：
    ```
    sudo apt install ruby
    gem install one_gadget
    ```
8. **IDA**
    
    静态调试必备，不多解释。这里建议安装52上的版本：
    [52上的IDA](https://www.52pojie.cn/thread-675251-1-1.html)


## 四、总结

整理这篇文章的目的是希望在玩Pwn的时候可以不用花太多时间在环境上，搭配好一套环境一直用就好了，根据具体情况再进行补充。还是那句话，重心还是要放在技术本身上。


