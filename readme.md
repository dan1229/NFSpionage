# NFSpionage

![](./logo.png)

## Description
NFSpionage is a tool designed to work in tandem during a Man-In-The-Middle attack to hijack and spoof an active, intercepted Network File System (NFS) connections.

#### Features
- Full CRUD functionality for remote NFS 
- TCP and UDP packet forwarding
- Packet processing and forging (via scapy)
- IP Spoofing
- Text based client for basic filesystem interaction
- Socket based API for sharing credentials with other applications
<br>
<br>


## Requirements
- Python >= 3.7
- Python packages: `pip install -r requirements.txt`
- libdnet
- tcpdump
<br>


## Usage
Run NFSpionage with the following command:<br>
`python nfspionage.py -s NFS_SERVER_IP`<br>

At that point, you can use most any NFS client to interact through NFSpionage. To use the text client included in this repository, run the following command:<br>
`python text_client.py -s NFS_SERVER_IP -m MOUNT_PATH`

#### MITM Tool
NFSpionage **should** work with virtual any external MITM tool or software _i.e.,_ <a href="https://www.bettercap.org/">Bettercap</a>.
<br>
<br>

## Contact
If you'd like to contribute or have any questions, feel free to reach out to me at <a href="mailto:danielnazarian@outlook.com">DanielNazarian@outlook.com</a> or visit <a href="https://DanielNazarian.com">DanielNazarian.com</a> for more. 