import sys
import os
import getopt
import threading
import subprocess
from datetime import datetime

known_tcp_ports = []
known_udp_ports = []
known_http_ports = []
known_nfs_ports = []
enum4linux_scanned = False
smbclient_scanned = False

nmap_pn_warning_shown = False
null_write = open(os.devnull, 'w')

class TextColors:
    RED = '\33[91m'
    GREEN = '\33[92m'
    YELLOW = '\33[93m'
    BLUE = '\33[94m'
    END = '\33[0m'

def nmapHostIsDown(filepath):
    # check if we got a response, if not try adding '-Pn'
    if '0 hosts up' in open(filepath, 'r').read().replace('\n', ' '):
        global nmap_pn_warning_shown
        if nmap_pn_warning_shown is False:
            print(currentTimeYellow() + ' nmap is indicating that the host is down. Retrying with -Pn...')
            nmap_pn_warning_shown = True
        return True
    else:
        return False


# TCP/UDP SCANS
def nmapTCPScanTop1000(target):
    print(currentTimeBlue() + ' Running top 1000 TCP scan...')
    filepath = target + '/scans/nmap-tcp-top-1000.txt'

    subprocess.run('sudo nmap -sS -A --top-ports 1000 ' + target + ' -oN ' + filepath, shell=True, stdout=null_write, stderr=null_write)
    if nmapHostIsDown(filepath):
        subprocess.run('sudo nmap -sS -A --top-ports 1000 ' + target + ' -Pn -oN ' + filepath, shell=True, stdout=null_write, stderr=null_write)

    print(currentTimeGreen() + ' Top 1000 TCP scan has finished.')
    serviceCheck(target, filepath, 'TCP')

def nmapUDPScanTop1000(target):
    print(currentTimeBlue() + ' Running top 1000 UDP scan...')
    filepath = target + '/scans/nmap-udp-top-1000.txt'

    subprocess.run('sudo nmap -sU --max-retries 3 --top-ports 1000 ' + target + ' -oN ' + filepath, shell=True, stdout=null_write, stderr=null_write)
    if nmapHostIsDown(filepath):
        subprocess.run('sudo nmap -sU --max-retries 3 --top-ports 1000 ' + target + ' -Pn -oN ' + filepath, shell=True, stdout=null_write, stderr=null_write)

    print(currentTimeGreen() + ' Top 1000 UDP scan has finished.')
    serviceCheck(target, filepath, 'UDP')

def nmapTCPScanAll(target):
    print(currentTimeBlue() + ' Running full TCP scan...')
    filepath = target + '/scans/nmap-tcp-all.txt'

    subprocess.run('sudo nmap -sS -A -p- ' + target + ' -oN ' + filepath, shell=True, stdout=null_write, stderr=null_write)
    if nmapHostIsDown(filepath):
        subprocess.run('sudo nmap -sS -A -p- ' + target + ' -Pn -oN ' + filepath, shell=True, stdout=null_write, stderr=null_write)

    print(currentTimeGreen() + ' Full TCP scan has finished.')
    serviceCheck(target, filepath, 'TCP')
    vulnerabilityScan(target, 'TCP')

def nmapUDPScanAll(target):
    print(currentTimeBlue() + ' Running full UDP scan...')
    filepath = target + '/scans/nmap-udp-all.txt'
    subprocess.run('sudo nmap -sU -p- --max-retries 3 ' + target + ' -oN ' + filepath, shell=True, stdout=null_write, stderr=null_write)
    if nmapHostIsDown(filepath):
        subprocess.run('sudo nmap -sU -p- --max-retries 3 ' + target + ' -Pn -oN ' + filepath, shell=True, stdout=null_write, stderr=null_write)

    print(currentTimeGreen() + ' Full UDP scan has finished.')
    serviceCheck(target, filepath, 'UDP')
    vulnerabilityScan(target, 'UDP')

def vulnerabilityScan(target, protocol):
    # create nmap port format (i.e. 22,80,139)
    if protocol == 'TCP':
        ports = str(known_tcp_ports)[1:-1].replace(' ', '')
    elif protocol == 'UDP':
        ports = str(known_udp_ports)[1:-1].replace(' ', '')
    
    if ports == '':
        print(currentTimeYellow() + ' No ' + protocol + ' ports were found.')
        return

    print(currentTimeBlue() + ' Running ' + protocol + ' vulnerability scan...')
    filepath = target + '/scans/nmap-' + protocol.lower() + '-vuln.txt'
    subprocess.run('sudo nmap --script vuln -p ' + ports + ' ' + target + ' -oN ' + filepath, shell=True, stdout=null_write, stderr=null_write)
    if nmapHostIsDown(filepath):
        subprocess.run('sudo nmap --script vuln -p ' + ports + ' ' + target + ' -Pn -oN ' + filepath, shell=True, stdout=null_write, stderr=null_write)

    print(currentTimeGreen() + ' ' + protocol + ' vulnerability scan has finished.')


# HTTP SCANS
def dirbScan(target, port):
    print(currentTimeBlue() + ' Running dirb scan of port ' + port + '...')
    subprocess.run('dirb http://' + target + ':' + port + ' -r -o ' + target + '/scans/dirb-port-' + port + '.txt', shell=True, stdout=null_write, stderr=null_write)
    print(currentTimeGreen() + ' dirb scan of port ' + port + ' has finished.')

def niktoScan(target, port):
    print(currentTimeBlue() + ' Running nikto scan of port ' + port + '...')
    subprocess.run('nikto --host=http://' + target + ':' + port + ' -o ' + target + '/scans/nikto-port-' + port + '.txt', shell=True, stdout=null_write, stderr=null_write)
    print(currentTimeGreen() + ' nikto scan of port ' + port + ' has finished.')

# SMB/NFS SCANS

def enum4LinuxScan(target):
    print(currentTimeBlue() + ' Running enum4linux scan...')
    subprocess.run('enum4linux -a ' + target + ' > ' + target + '/scans/enum4linux.txt', shell=True, stdout=null_write, stderr=null_write)
    print(currentTimeGreen() + ' enum4linux scan has finished.')

# need to find way to automatically press enter on go
def smbClientScan(target):
    print(currentTimeBlue() + ' Running smbclient scan...')
    subprocess.run('smbclient -L ' + target + ' -N > ' + target + '/scans/smbclient.txt', shell=True, stdout=null_write, stderr=null_write)
    print(currentTimeGreen() + ' smbclient scan has finished.')

def nfsScan(target, port):
    print(currentTimeBlue() + ' Running nfs scan...')
    filepath = target + '/scans/nmap-nfs-port-' + port + '.txt'
    subprocess.run('nmap -sV -p ' + port + ' --script=nfs* ' + target + ' -oN ' + filepath, shell=True, stdout=null_write, stderr=null_write)
    print(currentTimeGreen() + ' nfs scan has finished.')


##########

def serviceCheck(target, filepath, protocol):
    global known_tcp_ports
    global known_udp_ports
    f = open(filepath, 'r')
    lines = f.readlines()
    for i in range(0, len(lines)):
        line_items = lines[i].split()
        try:
            port = line_items[0]
            if '/' not in port:
                continue # not nmap port format, skip to next iteration

            port = port.split('/')[0] # remove slash and network protocol type to extract number
            if port.isdigit() is False:
                continue # not a port number, skip to next iteration

            if (protocol == 'TCP') and (port not in known_tcp_ports):
                known_tcp_ports.append(port)
            elif (protocol == 'UDP') and (port not in known_udp_ports):
                known_udp_ports.append(port)
            
            global known_http_ports
            if ('http' in lines[i].lower()) and (port not in known_http_ports):
                known_http_ports.append(port) # prevent scanning multiple times
                t1 = threading.Thread(target=dirbScan, args=(target,port), daemon=True)
                t2 = threading.Thread(target=niktoScan, args=(target,port), daemon=True)
                t1.start()
                t2.start()
                t1.join()
                t2.join()

            global known_nfs_ports
            if ('rpcbind' in lines[i].lower()) and (port not in known_nfs_ports):
                known_nfs_ports.append(port) # prevent scanning multiple times
                t3 = threading.Thread(target=nfsScan, args=(target,port), daemon=True)
                t3.start()
                t3.join()

            global enum4linux_scanned
            global smbclient_scanned
            smb_keywords = ['smb', 'microsoft-ds']
            for j in range(0, len(smb_keywords)):
                if (smb_keywords[j] in lines[i].lower()) and (enum4linux_scanned is False):
                    enum4linux_scanned = True
                    smbclient_scanned = True
                    t4 = threading.Thread(target=enum4LinuxScan, args=(target,), daemon=True)
                    t5 = threading.Thread(target=smbClientScan, args=(target,), daemon=True)
                    t4.start()
                    t5.start()
                    t4.join()
                    t5.join()
                    break

        except: # may be triggered due to false port declaration
            pass

def currentTimeGreen():
    return TextColors.GREEN + '[' + datetime.now().strftime('%H:%M:%S') + ']' + TextColors.END

def currentTimeYellow():
    return TextColors.YELLOW + '[' + datetime.now().strftime('%H:%M:%S') + ']' + TextColors.END

def currentTimeBlue():
    return TextColors.BLUE + '[' + datetime.now().strftime('%H:%M:%S') + ']' + TextColors.END

def main():
    options, arguments = getopt.getopt(sys.argv[1:], 'ht:', ['help', 'target='])
    target = None
    for opt, arg in options:
        if opt in ('-h', '--help'):
            print('Name: Autonumerate v0.1')
            description = 'Description: This script will automate some early stages of enumeration. It starts with four simultaneous nmap scans. These are the top 1000 of TCP/UDP, and all ports. This should allow the user to get started quickly with earlier results.'
            description += ' Next, it will check the results for HTTP, SMB, and NFS ports. The program will then run dirb and nikto for HTTP, enum4linux and smbclient for SMB, and nmap\'s NFS scripts.'
            description += ' Results will be stored in the "scans" folder.\n'
            print(description)
            print('Warning: Tampering with scan files while this program is running will break the output. You can view them, but do not edit or save said files until completion.\n')
            print('Usage: python3 autonumerate.py -t <domain/ip_address> [options]\n')
            print('Options:')
            print('-h, --help\t Show this menu.')
            print('-t, --target\t The destination address to run this script against.\n')
        elif opt in ('-t', '--target'):
            target = arg
    
    if target is None:
        print('You must provide a target. For help, use "-h".')
        return

    # create directories
    os.makedirs(target, exist_ok=True)
    os.makedirs(target + '/exploits/', exist_ok=True)
    os.makedirs(target + '/files/', exist_ok=True)
    os.makedirs(target + '/reports/', exist_ok=True)
    os.makedirs(target + '/scans/', exist_ok=True)

    # create files
    f = open(target + '/reports/notes.txt' , 'w')
    f.write('Hostname: \nIP: \nOS: \n')
    f.close()

    t1 = threading.Thread(target=nmapTCPScanTop1000, args=(target,), daemon=True)
    t2 = threading.Thread(target=nmapUDPScanTop1000, args=(target,), daemon=True)
    t3 = threading.Thread(target=nmapTCPScanAll, args=(target,), daemon=True)
    t4 = threading.Thread(target=nmapUDPScanAll, args=(target,), daemon=True)

    t1.start()
    t2.start()
    t3.start()
    t4.start()

    t1.join()
    t2.join()
    t3.join()
    t4.join()

main()
