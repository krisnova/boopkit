# Remote

This is a tool that can be used to trigger the eBPF probe on the remote end.

### TCP Retransmission 

The eBPF probe is triggered when the kernel will retransmit a `SYNACK` packet. 

By default, most modern programming languages will attempt to complete the TCP handshake at all costs.
We can leverage `SYN` flooding tactics, and design a malformed [TCP handshake](https://www.ietf.org/rfc/rfc793.txt) library that will cause the kernel to retransmit a `SYNACK` packet. 

When this occurs on the remote end, the eBPF probe is fired and the deep packet inspection, and ultimately the backdoor execution begins.

``` 
  Client (remote)                          Server (eBPF Probe)
===================                        ===================   

  +------------+                            +------------+
  |    SYN     |       --> [ SYN ] -->      |  SYN + ACK |
  +------------+                            +------------+
  
  +------------+                           +-------------+
  |  Malformed |   <- [ SYN, ACK (0) ] <-  |  Kernel TCP | [ ]
  |  Library   |   <- [ SYN, ACK (1) ] <-  |  Retransmit | [ retry 1 ] 
  +------------+                           +-------------+               
  
```

The eBPF probe on the server side uses `tracepoint/tcp/tcp_retransmit_synack` to trigger when a retransmission occurs.
This is where the backdoor firing process begins. 
This process can be triggered remotely over any TCP server connection (authenticated or not) by using the malformed client library.

#### Research in proc(5) (procfs, proc)

The kernel holds a maximum number of retries on the server side, which can be pulled from memory, and set using the proc filesystem.

```bash 
cat /proc/sys/net/ipv4/tcp_synack_retries
echo 5 > /proc/sys/net/ipv4/tcp_synack_retries
```


### Future Considerations

 - TCP Handshake encapsulation (RCE with TCP retransmission)
 - Deep packet content filtering. EG: Trigger on packet contents



