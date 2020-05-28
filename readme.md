# NFSpionage



### Description
NFSpionage is a tool designed to work in tandem during a Man-In-The-Middle attack to hijack and spoof an active, intercepted Network File System (NFS) connections.

#### Features
- Full CRUD functionality on remote filesystem 
- TCP and UDP packet forwarding
- Packet processing and forging (via scapy)
- IP Spoofing
- Text based client for basic filesystem interaction
- Socket based API for sharing credentials with other applications



### Requirements
- libpcap
- libdnet
- tcpdump
- scapy and the following contrib packages:
    - nfs
    - mount
    - portmapper
    - rpc



### Usage
Run NFSpionage with the following command:<br>
`python nfspionage.py -s NFS_SERVER_IP`<br>

At that point, you can use any NFS client to interact through NFSpionage. To use the text client included in this repository, run the following command:<br>
`python text_client.py -s NFS_SERVER_IP -m MOUNT_PATH`

#### MITM Tool
NFSpionage **should** work with virtual any external MITM tool or software, however, <a href="https://www.bettercap.org/">Bettercap</a> has provided the most consistent and reliable results.


### Contact
