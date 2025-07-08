---
title: pwnable--flag--(reverse)
updated: 2022-09-06 08:11:18Z
created: 2022-04-12 14:21:34Z
---

### PS:xxd十六进制编辑器–kali

* * *

```
Papa brought me a packed present! let's open it.

Download : http://pwnable.kr/bin/flag

This is reversing task. all you need is binary
```

**下载文件并检查：**

```sh
┌──(root💀kali)-[~/Desktop/pwnable]
└─# checksec flag 
[*] '/root/Desktop/pwnable/flag'
    Arch:     amd64-64-little
    RELRO:    No RELRO
    Stack:    No canary found
    NX:       NX disabled
    PIE:      No PIE (0x400000)
    RWX:      Has RWX segments
    Packer:   Packed with UPX
                                                                                                                                                                      
┌──(root💀kali)-[~/Desktop/pwnable]
└─# file flag              
flag: ELF 64-bit LSB executable, x86-64, version 1 (GNU/Linux), statically linked, no section header
```

**运行一下flag**

```
┌──(root💀kali)-[~/Desktop/pwnable]
└─# ./flag 
I will malloc() and strcpy the flag there. take it.
```

**用IDA打开，发现参数非常少，怀疑加壳，使用工具检测：**

```shell
└─# xxd flag|tail                                                                                                                                                 1 ⨯
00051d20: 77c4 8a1d b0f1 d302 6973 b0a0 c023 8d6d  w.......is...#.m
00051d30: 616b 424e 9948 2c86 8ec3 0232 2a45 db17  akBN.H,....2*E..
00051d40: 0981 0be3 b91f 2656 2211 c349 4608 1fb8  ......&V"..IF...
00051d50: 3b9d c5c0 e820 1e5f 5f00 01a2 30b0 9943  ;.... .__...0..C
00051d60: e968 58b1 f464 65e3 b58b 137a 54de 7375  .hX..de....zT.su
00051d70: 6022 5d52 d7e5 00bb c625 8581 116d 4992  `"]R.....%...mI.
00051d80: 9041 9f00 a092 24ff 0000 0000 5550 5821  .A....$.....UPX!
00051d90: 0000 0000 5550 5821 0d16 0807 19cc 204a  ....UPX!...... J
00051da0: dbd8 21c5 3145 0100 5e70 0000 217c 0d00  ..!.1E..^p..!|..
00051db0: 4919 0089 bc00 0000                      I.......
```

发现是UPX加壳，在linux下使用 `upx -d flag` 脱壳，然后使用IDA打开

<img src="https://cdn.jsdelivr.net/gh/DarkLord-W/CloudImages@main/images/ee86bb80ab597e956ad0a23c8b524869.png" alt="ee86bb80ab597e956ad0a23c8b524869.png" width="1056" height="521" class="jop-noMdConv">

**双击flag跳转至下图，得到flag**

<img src="https://cdn.jsdelivr.net/gh/DarkLord-W/CloudImages@main/images/4a8e2574afe63ed666996c8f2306b19a.png" alt="4a8e2574afe63ed666996c8f2306b19a.png" width="993" height="571" class="jop-noMdConv">