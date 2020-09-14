# NFSpionage

## Description
NFSpionage is a tool designed to work in tandem during a Man-In-The-Middle attack to hijack and spoof an active, intercepted Network File System (NFS) connections.

![](./logo.png)

#### Features
- Full CRUD functionality for remote NFS 
- TCP and UDP packet forwarding
- Packet processing and forging (via scapy)
- Client IP address spoofing (** in progress **)
- Text based client for basic filesystem interaction
- Socket based API for sharing credentials with other programs
<br>
<br>


## Requirements
- Python 3
- Python packages: `pip install -r requirements.txt`
- libdnet
- tcpdump
<br>
<br>

## Usage
Run NFSpionage with the following command:<br>
`python nfspionage.py -s NFS_SERVER_IP`<br>

At that point, you can use most any NFS client to interact through NFSpionage or just use NFS through the filesystem on the MITM machine like normal.<br>

To use the text client included in this repository, run the following command:<br>
`python text_client.py -s NFS_SERVER_IP -m MOUNT_PATH`
<br>
<br>

#### MITM Attack
NFSpionage is designed work with virtually any external MITM/ARP spoof/ARP Poisoning tool _i.e.,_ <a href="https://www.bettercap.org/">Bettercap</a>.<br>

For simplicity's sake there is a simple script, arp_spoof.py, that performs a basic ARP poisoning attack on the LAN.
<br>
<br>

## Contact
This project was created by Daniel Nazarian with the help of <a href="https://t.co/CRtZOgqCKn?amp=1">Dr. Joseph Wilson</a>

If you'd like to contribute or have any questions, feel free to reach out to me at <a href="mailto:danielnazarian@outlook.com">DanielNazarian@outlook.com</a> or visit <a href="https://DanielNazarian.com">DanielNazarian.com</a> for more about me and other projects I'm working on.
