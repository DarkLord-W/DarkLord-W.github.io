**启动靶机，使用给出的glzjin/123456进行ssh连接：**

```c
└─$ ssh glzjin@a12ecd55-07fe-466e-8736-5c4eb02c3ba6.node5.buuoj.cn -p 25751
glzjin@a12ecd55-07fe-466e-8736-5c4eb02c3ba6.node5.buuoj.cn's password: 
Last login: Wed Oct 15 09:19:21 2025 from 192.168.122.15
$ whoami
glzjin
$ ls
$ pwd
/home/glzjin
$ cd /
$ ls
bd_build  boot  etc   flag.txt  lib    media  opt   root  sbin  sys  usr
bin       dev   flag  home      lib64  mnt    proc  run   srv   tmp  var
$ cat flag.txt
flag{glzjin_wants_a_girl_friend}
$ cat /flag
flag{8440e710-5b30-4cd3-a860-4c6b0081e427}
$ 
```
