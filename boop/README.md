# Boopkit Boop

Remote trigger program for boopkit.

```
================================================================

    ██████╗  ██████╗  ██████╗ ██████╗ ██╗  ██╗██╗████████╗
    ██╔══██╗██╔═══██╗██╔═══██╗██╔══██╗██║ ██╔╝██║╚══██╔══╝
    ██████╔╝██║   ██║██║   ██║██████╔╝█████╔╝ ██║   ██║   
    ██╔══██╗██║   ██║██║   ██║██╔═══╝ ██╔═██╗ ██║   ██║   
    ██████╔╝╚██████╔╝╚██████╔╝██║     ██║  ██╗██║   ██║   
    ╚═════╝  ╚═════╝  ╚═════╝ ╚═╝     ╚═╝  ╚═╝╚═╝   ╚═╝   
    Author: Kris Nóva <kris@nivenly.com> Version 1.2.0
    
    IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE 
    LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, 
    EXEMPLARY, OR CONSEQUENTIAL DAMAGES.    

    DO NOT ATTEMPT TO USE THE TOOLS TO VIOLATE THE LAW.
    THE AUTHOR IS NOT RESPONSIBLE FOR ANY ILLEGAL ACTION.
    MISUSE OF THE SOFTWARE, INFORMATION, OR SOURCE CODE
    MAY RESULT IN CRIMINAL CHARGES.
    
    Use at your own risk.

================================================================

Boopkit. (Client program)
Linux rootkit and backdoor. Built using eBPF.

Usage: 
boopkit-boop [options]

Options:
-lhost             Local  (src) address   : 127.0.0.1.
-lport             Local  (src) port      : 3535
-rhost             Remote (dst) address   : 127.0.0.1.
-rport             Remote (dst) port      : 22
-9, halt/kill      Halt or kill the boopkit malware on a server.
-q, quiet          Disable output.
-c, execute        Remote command to exec : ls -la
-p, payload-only   Boop with only SYN. No reverse conn.
-h, help           Print help and usage.
```

