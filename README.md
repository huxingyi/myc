Overview
=========================
Async mysql connector, in pure c.

How MyC Works
================
MyC implemented a parser of tiny subset of Mysql Client/Server Protocol 4.1 to support simple sql interface.
The tiny subset can conclude as the following states.
```
Handshake -> Login -> Select Database -> Execute SQL -> Fetch Result
```
MyC only contains two source files:
```
MyC/include/myc.h
MyC/src/myc.c
```
You can not use MyC directly without implementing the underlying network layer, because it is just a protocol parser.

However, there is a fully functional example included in this repository, which use the popular async network library - libuv as the supporting network layer for MyC:
```
examples/uvmyc/include/uvmyc.h
examples/uvmyc/src/uvmyc.c
```
If you want implement your own network layer, you should manage the tcp connection with Mysql server, and when there is something come from server, just call `mycRead` to handle it, and you should check `mycWantWriteSize` to see if MyC has something want to be send to Mysql server, and you should take care of the whole send logic to delivery the data pointed by `mycWantWriteData`, after finish the delivery on the tcp layer, you should call `mycFinishWrite` to let MyC know it.
