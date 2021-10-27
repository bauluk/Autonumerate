# Autonumerate
This script will automate some early stages of enumeration. It starts with four simultaneous nmap scans. These are the top 1000 of TCP/UDP, and all ports. This should allow the user to get started quickly with earlier results. Next, it will check the results for HTTP, SMB, and NFS ports. The program will then run dirb and nikto for HTTP, enum4linux and smbclient for SMB, and nmap's NFS scripts. Results will be stored in the "scans" folder.

## Usage
```
python3 autonumerate.py -t <domain/ip_address> [options]

Options:
-h, --help	 Show this menu.
-t, --target	 The destination address to run this script against.
```
