Use `utun` interface to connect with darwin kernel, and implement wrappers with Hyper/Tower or whchever is necessary and add support.
Inspired by clouflare's boringtun[see https://github.com/cloudflare/boringtun/blob/master/boringtun/src/device/tun_darwin.rs] 

Probable steps (need to be reviewed) 
1. create a utun interface
2. read raw packets / requests
3. encrypt requests with hashd session keys (internally generated)
4. write packets from userspace back to kernel to be routed internally

Im not too sure about the specifics of implementation, this is HIGHLY HIGHLY EXPERIMENTAL, proceed with caution ☠️
