# Mac下的多版本Python管理实践


# Mac平台下多版本Python的管理实践

## 前言
**Mac系统自带一个Python2，但是在实际生产时现在越来越多使用Python3。如果直接在系统上添加一个Python3，非常不方便进行管理。在进行开发时，也需要进行相关配置才能明确使用的Python版本。经过多方式、多软件尝试，最终找到一种方便的Python版本管理方式。**

## 一、环境说明
首先系统自带一个Python2，然后使用HomeBrew安装了一个Python3。为了不影响系统的Python2的，需要再个人安装一个Python2和Python3。

## 二、Anaconda3
### 1. 选择理由
起初尝试过Pyenv，感觉还是比较麻烦，放弃了。尝试了目前网络上能找到的所有的版本管理方式，最终选择了Anaconda进行管理。
### 2. 安装
#### 1. HomeBrew安装
不使用图形化管理界面，可以直接使用HomeBrew进行安装。
1. Terminal输入：
    ```
    # 查看anaconda的位置
    brew search anaconda
    ```
    ![](https://i.imgur.com/rppYPsI.png)

2. 进行安装：
    ```
    brew install anaconda

以brew cask的方式开始进行安装，先下载文件，然后进行输入本机密码就可以开始进行安装。

3. 安装完成后的环境配置：
    ```
    #使用bash
    echo 'export PATH=/usr/local/anaconda3/bin:$PATH' >> ~/.bash_profile
    source ~/.bash_profile  

    #使用zsh
    echo 'export PATH=/usr/local/anaconda3/bin:$PATH' >> ~/.zshrc
    source ~/.zshrc

4. 检查：
    ```
    conda --vesion
    ```
    ![](https://i.imgur.com/uN33WGh.png)

安装完成。

#### 2. 官网安装
官网地址：[Anaconda3](https://www.anaconda.com/distribution/#macos)

可以下载图形安装包，也可以下载命令行安装文件。如果是第一次使用建议先安装图形安装包，这样你可以清楚地看到每个python环境里安装了哪些包。熟悉了操作之后换成命令行即可。  
##### 1. 图形化安装
图形安装完成后的主界面：

![](https://i.imgur.com/fHPn90j.png)

进入到`Environments`选项中可以查看已安装的相关环境的详细信息：

![](https://i.imgur.com/VLvdZPS.png)

这里anaconda3自带的环境名称为base，基于Python3，该环境中安装了Python常用的各种包，如果不是定制性有极强烈要求，可以使用该环境，能满足常见的各种开发要求，无需再自行配置开发环境。

##### 2. 命令行安装
1. 命令行安装方式是打开终端，执行下面的命令：

    Python2.7：
    ```
    $ bash ~/Downloads/Anaconda3-5.3.1-MacOSX-x86_64.sh //python2版本
    ```
    Python3.7：
    ```
    $ bash ~/Downloads/Anaconda3-5.3.1-MacOSX-x86_64.sh //python3版本
    ```

    后面路径为安装文件的目录。

2. 提示`“In order to continue the installation process, please review the license agreement.”`，点击“Enter”查看“许可证协议”；滚动屏幕到最下方，输入”yes"表示同意协议，安装继续。

3. 提示`“Press Enter to confirm the location, Press CTRL-C to cancel the installation or specify an alternate installation directory.”`,如果接受默认安装路径，则显示“PREFIX=/home//anaconda<2 or 3>”并且继续安装。安装过程大约几分钟。建议直接使用默认安装路径。

4. 提示`“Do you wish the installer to prepend the Anaconda install location to PATH in your /home//.bash_profile ?”`，是否自动添加环境变量到.bash_profile文件中，输入“yes"，自动添加；输入”no"，则需要自行手动添加。如果你使用的是zsh，需要在.zshrc文件中自行添加环境变量。

5. 提示`”Thank you for installing Anaconda!”`,安装完成。

6. source一下或重启终端使新加的环境变量生效
    ```
    source ~/.bash_profile
    # source ~/.zshrc

### 3. 卸载
    ```
    conda install anaconda-clean
    anaconda-clean   #清除个人配置
    rm -r /Users/XXXX/.anaconda_backup/...     #删除备份，路径可能不同
    rm -rf /anaconda3
    vi ~/.bash_profile #删除环境变量
    # vi ~/.zshrc  zsh用户执行这一条
    rm -rf ~/.condarc ~/.conda ~/.continuum #删除可能存在的隐藏文件
    ```
## 三、方案使用

1. 不做任何设置的前提下，安装完anaconda后，会设置为自动启动anaconda环境，默认为base环境。对于是否设置自动启动anaconda环境可以使用如下命令进行更改：
    ```
    # 取消自动启动
    conda config auto_activate_base false

    # 设置自动启动
    conda condif auto_activate_base true


2. anaconda常用的命令

    ```
    #查看conda版本
    conda --version

    #更新conda版本
    conda update conda

    #查看安装了哪些依赖库
    conda list

    #创建新的python环境
    conda create --name myenv

    #创建特定python版本的环境
    conda create -n myenv python=3.7

    #创建新环境并指定包含的库
    conda create -n myenv scipy

    #创建新环境病指定特定版本的库
    conda create -n myenv scipy=0.15.0

    #复制环境
    conda create --name myclone --clone myenv

    #查看是不是复制成功了
    conda info --envs

    #激活、进入某个环境
    source activate myenv

    #退出环境
    source deactivate

    #删除环境
    conda remove --name myenv --all

    #查看当前的环境列表
    conda info --envs 
    conda env list

    #查看某个环境下安装的库
    conda list -n myenv

    #查找包
    conda search XXX

    #安装包
    conda install XXX

    #更新包
    conda update XXX

    #删除包
    conda remove XXX

    #安装到指定环境
    conda install -n myenv XXX

    ```

## 四、总结
Anaconda是我目前为止觉得最简单的Python管理实践方式，也可能是我对其他的了解不够深入。话说回来，适合自己的才是最好的，你觉得呢？
