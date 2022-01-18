# SMB 协议简单总结


# SMB协议简单总结


##	SMB协议

### 一. Client和Server的连接过程
1. client和server首先建立NetBIOS session
2. clent和server确定使用的smb协议的dialect（定义了特定协议版本的消息包集）
3. client登录到server
4. client连接server上的一个share
5. client在share中打开文件
6. client开始读取文件

client和server首先要建立全双工的TCP连接，然后client建立并发送一个NetBIOS session请求包。
如果请求包格式化正确，server返回一个包含着确认session建立成功的消息包。然后，client
开始想server发送第一个smb协议数据包。

### 二. SMB协议涉及到的数据包分析

Packet1. SMB_COM_NEGOTIATE

    Direction:C->S
    Description:client想server发送smb dialect的确认信息，server返回一个包含着dialects
    的字符串的数据包。

Packet2. SMB_COM_NEGOTIATE

    Direction:S->C
    Description:server相应client的请求，确定将在session中使用的smb dialect。server返回
    的数据包中还包括一个8字节的随机字符串，该字符串将在系一部中用于在登录过程中对客户端
    进行身份验证。

Packet3. SMB_COM_SESSION_SETUP_ANDX

    Direction:C->S
    Description:该数据包包含着有关client功能的信息，因此即使server实现了share-level
    security model，也必须要发送该数据包。

Packet4. SMB_COM_SESSION_SETUP_ANDX

    Direction:S->C
    Description:如果server接受了challenge/response，则返回给client的数据包中将包含
    一个有效的UID。如果不接受，则在数据包中返回error code，并拒绝访问。


Packet5. SMB_COM_TREE_CONNECT_ANDX

    Direction：C->S
    Description:client对share发起访问，该数据包中包含UNC格式的绝对共享路径。

Packet6. SMB_COM_TREE_CONNECT_ANDX

    Direction:S->C
    Description:如果server授予了client访问权限，则server返回与该数据包中的share对应的
    16位的TID。如果share不存在或者client没有足够的权限，则server返回error code并拒绝访问。

Packet7. SMB_COM_OPEN_ANDX

    Direction:C->S
    Description:client请求server代表自己在share中打开文件，该数据包中包含要打开的文件的名称。

Packet8. SMB_COM_OPEN_ANDX

    Direction:S->C
    Description:如果授予了对文件的访问权限，则server返回请求文件的ID；如果文件不存在或者
    用户没有足够的权限访问该文件，则返回error code并拒绝client的访问。


Packet9. SMB_COM_READ_ANDX

    Direction:C->S
    Description:client请求server代替自己读取文件中的数据并返回给自己。打开文件时client
    获取的文件ID包含在该数据包中，以便识别server应该从哪个打开的文件中读取数据。

Packet10. SMB_COM_READ_ANDX

    Direction:S->C
    Description：server返回client请求的文件数据。由于已授予对server，share和文件的访问
    权限，一般不会出现问题。但是在某些特殊情况下会发生错误，例如在打开文件和从文件中读取数据
    这两步之间，对share的访问权限遭到了更改，就会发生错误。

## 三. SMB Message结构

    SMB Message包括一个固定长度的header（32字节）、一个可变长度的Parameter block（最大
    为64kb）、一个可变长度的Data block。


1. **The SMB Message Header**

        32字节的固定长度。

        SMB_Header
        {
          UCHAR  Protocol[4];
          UCHAR  Command;
          SMB_ERROR Status;
          UCHAR  Flags;
          USHORT Flags2;
          USHORT PIDHigh;
          UCHAR  SecurityFeatures[8];
          USHORT Reserved;
          USHORT TID;
          USHORT PIDLow;
          USHORT UID;
          USHORT MID;
        }


       简单说一下比较重要的部分：

    1. **Protocol**:(4 字节)需要包含"\xff","S","M","B"
    2. **Flags2**:保留位必须设置为0，且需要重点关注SMB_FLAGS2_DFS字段，如果该位被设置为1，则任何的文件路径名都应该在DFS中进行处理（这也是很多漏洞触发点，因为对于文件路径规范化处理函数，有漏洞）
    3. **SecuritySignature** (8 bytes): 如果已协商SMB签名，则此字段必须包含一个8字节的加密消息签名，可用于检测消息是否在传输过程中被修改。 消息签名的使用与无连接传输是互斥的。


2. **Parameter Block**
      在CIFS方言中，SMB_Parameters.Words数组可以包含任意结构。 SMB_Parameters.Words结构的格式是针对每个命令消息单独定义的。 Words数组的大小仍然被测量为字节对的计数。其结构如下所示：

        SMB_Parameters
        {
        UCHAR  WordCount;
        USHORT Words[WordCount] (variable);
        }

      **Words (variable)**: The message-specific parameters structure. The size of this field MUST be (2 x WordCount) bytes. If WordCount is 0x00, this field is not included.


3. **Data Block**

        结构与Parameter Block相似：

        SMB_Data
        {
          USHORT ByteCount;
          UCHAR  Bytes[ByteCount] (variable);
        }


4. **Batched Message(AndX Messages)**

        主要是为了在一个message中发送多个request或者response command，而只需要一个smb header即可。

        In AndX Messages, only one SMB Header (section 2.2.3.1) is sent. The header is then followed by zero or more Parameter and Data block pairs, each corresponding to an additional command request/response. There is no limit on the number of block pairs in a message specifically, only on the total message size. *The total size of a Batched Message MUST NOT exceed the negotiated MaxBufferSize.* AndX Messages contain a construct, conceptually similar to a linked-list, that is used to connect the batched block pairs. The resulting list is referred to as an AndX Chain.

        其结构如下：
        AndX
        {
          UCHAR  AndXCommand;
          UCHAR  AndXReserved;
          USHORT AndXOffset;
        }


    **AndXOffset (2 bytes)**: The offset in bytes, relative to the start of the SMB Header, of the next Parameter block in the AndX Message. This offset is independent of any other size parameters or offsets within the command. This offset can point to a location past the end of the current block pair.

    **The AndX construct is located at the start of the Parameter block of an AndX command request/response.**



## 四. SMB COMMANDS

    由于commands数量较多，此处给出微软官方的命令解释地址。
    [Microsoft Docs]: <https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-cifs/5cd5747f-fe0b-40a6-89d0-d67f751f8232>



​        


