
# What is this?

This repository contains a port of 
[libressl](https://github.com/libressl-portable/openbsd), 
[wattcp32](http://www.watt-32.net/), and 
[wget](https://savannah.gnu.org/projects/wget/)
to [FreeDOS](http://freedos.org) 
using the OpenWatcom compiler.

The code is divided into a source and development tree.
To build SSL applications, only the __usr__ directory is
required. The __usr__ directory contains all the header
and library files. In addition, it contains prebuilt
binaries such as __wget__.

```
|-- src
|   |-- bin
|   |   `-- wget
|   `-- lib
|       |-- libbsd
|       |-- libcrypt
|       |-- libssl
|       |-- libtls
|       `-- wattcp32
`-- usr
    |-- bin
    |-- include
    |   |-- arpa
    |   |-- net
    |   |-- netinet
    |   |-- netinet6
    |   |-- openssl
    |   |-- protocol
    |   |-- rpc
    |   |-- rpcsvc
    |   |-- sys
    |   `-- w32-fake
    `-- lib
```
# FreeDOS Networking 

Running networking software such as __wget__ requires a
packet driver to be loaded.

For example, to load RTL8139 driver you would
enter the following command:

```
C:\NETWORK\RTSPKT 0x60
```

If your using QEMU, you would add the following flags:

``` 
-net nic,model=rtl8139 -net user
```

The complete command might look something like the following:

```
qemu-system-x86_64 -boot order=c -m 1G -drive file=fdos.raw,cache=none,format=raw -net nic,model=rtl8139 -net user -rtc base=localtime -vga std -show-cursor
```

## Packet Drivers

Georg Potthast packet [drivers](http://www.georgpotthast.de/sioux/packet.htm) for DOS.

Crynwr Software [drivers](www.crynwr.com/).
