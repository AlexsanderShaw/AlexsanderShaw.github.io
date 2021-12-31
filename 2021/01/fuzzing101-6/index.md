# Fuzzing 101 -- 6


本文是Fuzzing101系列第六篇，fuzz的对象为 GIMP 。

<!--more-->

## 1. Basic Info

| Target  | CVES to find  | Time estimated | Main topics                    |
| ------- | ------------- | -------------- | ------------------------------ |
| GIMP | CVE-2016-4994 | 7hous          | persistent mode |

> CVE-2016-4994: Use-After-Free vulneratibily.

## 2. Learning Target

1. 使用 fuzz 的 persistent mode
2. 对 interactive/GUI 应用程序进行fuzz

## 3. Fuzzing

### 1. Workflow

1. 找到一种修改 GIMP 源码以启用 AFL++ 的 persistent mode 的有效的方法
2. 创建一个 XCF 的语料库
3. 对 XCF 文件格式创建 dictionary
4. 开始fuzz，直到出现crash
5. 使用造成crash的poc重现crash
6. 修复漏洞

### 2. Solution

#### 1. Download and build target

首先创建待 fuzz 的 GIMP 环境，进行编译待用。

这里首先要安装 GEGL 0.2(Generic Graphics Library)，使用源码编译：

```shell
# install  dependencies
sudo apt install build-essential libatk1.0-dev libfontconfig1-dev libcairo2-dev libgudev-1.0-0 libdbus-1-dev libdbus-glib-1-dev libexif-dev libxfixes-dev libgtk2.0-dev python2.7-dev libpango1.0-dev libglib2.0-dev zlib1g-dev intltool libbabl-dev

# download and uncompress
wget https://download.gimp.org/pub/gegl/0.2/gegl-0.2.2.tar.bz2
tar xvf gegl-0.2.0.tar.bz2 && cd gegl-0.2.2

# modify the source code
sed -i 's/CODEC_CAP_TRUNCATED/AV_CODEC_CAP_TRUNCATED/g' ./operations/external/ff-load.c
sed -i 's/CODEC_FLAG_TRUNCATED/AV_CODEC_FLAG_TRUNCATED/g' ./operations/external/ff-load.c

# build and install
./configure --enable-debug --disable-glibtest  --without-vala --without-cairo --without-pango --without-pangocairo --without-gdk-pixbuf --without-lensfun --without-libjpeg --without-libpng --without-librsvg --without-openexr --without-sdl --without-libopenraw --without-jasper --without-graphviz --without-lua --without-libavformat --without-libv4l --without-libspiro --without-exiv2 --without-umfpack
make -j$(nproc)
sudo make install
```

然后，下载 GIMP 2.8.16，并进行编译安装：

```shell
# download 
cd ..
wget https://mirror.klaus-uwe.me/gimp/pub/gimp/v2.8/gimp-2.8.16.tar.bz2
tar xvf gimp-2.8.16.tar.bz2 && cd gimp-2.8.16/

# build and install
CC=afl-clang-lto CXX=afl-clang-lto++ PKG_CONFIG_PATH=$PKG_CONFIG_PATH:$HOME/Desktop/Fuzz/training/fuzzing_gimp/gegl-0.2.2/ CFLAGS="-fsanitize=address" CXXFLAGS="-fsanitize=address" LDFLAGS="-fsanitize=address" ./configure --disable-gtktest --disable-glibtest --disable-alsatest --disable-nls --without-libtiff --without-libjpeg --without-bzip2 --without-gs --without-libpng --without-libmng --without-libexif --without-aa --without-libxpm --without-webkit --without-librsvg --without-print --without-poppler --without-cairo-pdf --without-gvfs --without-libcurl --without-wmf --without-libjasper --without-alsa --without-gudev --disable-python --enable-gimp-console --without-mac-twain --without-script-fu --without-gudev --without-dbus --disable-mp --without-linux-input --without-xvfb-run --with-gif-compression=none --without-xmc --with-shm=none --enable-debug  --prefix="$HOME/Desktop/Fuzz/training/fuzzing_gimp/gimp-2.8.16/install"
make -j$(nproc)
make install
```

#### 2. persistent mode

为了使用 AFL++ 的 persistent mode，我们需要对源码进行一定的修改：

第一种方案是修改 `app.c` 文件：

![img](https://cdn.jsdelivr.net/gh/AlexsanderShaw/BlogImages@main/img/vuln/shebei20211122162014.png)

第二种方案是修改 `xcf_load_invoker` 函数：

![img](https://cdn.jsdelivr.net/gh/AlexsanderShaw/BlogImages@main/img/vuln/shebei20211122162108.png)

这里我们直接采用第二种方案进行 patch。`gimp-2.8.16/app/xcf/xcf.c` 修改前内容如下：

![image-20211122165817591](https://cdn.jsdelivr.net/gh/AlexsanderShaw/BlogImages@main/img/vuln/shebei20211122165817.png)

补丁内容如下：

```c
--- ../xcf.c	2014-08-20 08:27:58.000000000 -0700
+++ ./app/xcf/xcf.c	2021-10-11 13:02:42.800831192 -0700
@@ -277,6 +277,10 @@
 
   filename = g_value_get_string (&args->values[1]);
 
+#ifdef __AFL_COMPILER
+  while(__AFL_LOOP(10000)){
+#endif
+
   info.fp = g_fopen (filename, "rb");
 
   if (info.fp)
@@ -366,6 +370,12 @@
   if (success)
     gimp_value_set_image (&return_vals->values[1], image);
 
+#ifdef __AFL_COMPILER
+  }
+#endif
+
+  exit(0);
+
   gimp_unset_busy (gimp);
 
   return return_vals;
```

使用上面的补丁修改 `gimp-2.8.16/app/xcf/xcf.c` 文件：

```shell
patch gimp-2.8.16/app/xcf/xcf.c -i persistent.patch
```

pacth 后的文件内容如下：


![image-20211122171326947](https://cdn.jsdelivr.net/gh/AlexsanderShaw/BlogImages@main/img/vuln/shebei20211122171327.png)

这样就可以实现 AFL++ 的 persistent mode。

#### 3. Seed corpus creation

这里直接使用 SampleInput.xcf 做简单的语料样例。

#### 4. Custom dictionary

这里直接使用AFL++提供的 xcf 的 dict 。

#### 4. Fuzzing

执行 `afl-fuzz` ，采用并行方式进行fuzz:

```shell
ASAN_OPTIONS=detect_leaks=0,abort_on_error=1,symbolize=0 afl-fuzz -i './afl_in' -o './afl_out' -D -t 100 -- ./gimp-2.8.16/app/gimp-console-2.8 --verbose -d -f @@
```

![image-20211102144945349](https://cdn.jsdelivr.net/gh/AlexsanderShaw/BlogImages@main/img/vuln/shebei20211102144945.png)

### 3. Crashes

## 4. Triage

## 5. Fix

官方的修复地址：

- https://gitlab.gnome.org/GNOME/gimp/-/commit/6d804bf9ae77bc86a0a97f9b944a129844df9395

后续将对该漏洞进行深入分析和补丁分析，待完善。

