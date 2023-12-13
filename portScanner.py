import os
import socket
import time
import sys
from queue import Queue
from datetime import datetime
import requests
import urllib3
import nmap3
import nmap

#ping scan using for ip's availability.
#port scanning using nmap3 library.
#login check using requests library.
#It detects the open http or https ports of the IPs that you can give as a single or a range, 
# and searches for the password string in them with the request module.
#output.txt file for results.
#execution time for all process.
#port scanning time for only port scanning process.
#login check time for only login check process.
#total checked ports for only port scanning process.

#Terminal Cleaning
def clear():
    os.system('cls' if os.name == 'nt' else 'clear')
clear()

#*Disabled SSL warnings*
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

#Found Ports Array
ipPorts = []

#Global Variables
start_time = time.time()
up_ips = []
mode_num=0
portScanningTime = 0

def print_banner():
    print("\nSelect your scan type : ")
    print("[+] Select 1 for scanning one IP")
    print("[+] Select 2 for scanning for ip range")
    print("[+] Select 3 for scanning from file")
    print("[+] Select 4 for exit \n")

print_banner()

def print_scan_options():
    print("\nSelect your scan mode : ")
    print("[+] Select 1 for scanning top 1024 ports")
    print("[+] Select 2 for scanning all ports")
    print("[+] Select 3 for scanning custom ports")
    print("[+] Select 4 for exit \n")

input_mode = int(input("[+] Select any option: "))
print()

#----Port finder block----- 
def ips(start, end):
    import socket, struct
    start = struct.unpack('>I', socket.inet_aton(start))[0]
    end = struct.unpack('>I', socket.inet_aton(end))[0]
    return [socket.inet_ntoa(struct.pack('>I', i)) for i in range(start, end)]

def scan_ports(host, mode):
    nmap = nmap3.Nmap()
    version_result = None

    if (mode==0):
        print_scan_options()
        mode = int(input("[+] Select any option: "))
        print()

        global mode_num
        mode_num = mode
    
    print("-"*50)
    print(f"Target IP: {host}")
    print("Scanning started at:" + str(datetime.now()))
    print("-"*50)

    global portScanStart
    portScanStart = time.time() #for calculating portScan time

    try:
        if mode == 1:
            timeout_seconds = 20
            version_result = nmap.nmap_version_detection(host, '--top-ports=1024', timeout=timeout_seconds)
        elif mode == 2:
            timeout_seconds = 140
            version_result = nmap.nmap_version_detection(host, '-p-', timeout=timeout_seconds)
        elif mode == 3:
            timeout_seconds = 140
            customPortStart = int(input("[+] Enter starting port number: "))
            customPortEnd = int(input("[+] Enter ending port number: "))
            version_result = nmap.nmap_version_detection(host, f'-p {customPortStart}-{customPortEnd+1}', timeout=timeout_seconds)
    except:
        print("Port scanning timed out. Check the target host's availability.")

    def check_and_print_ports(host, service_name):
        for i in range(len(version_result[host]['ports'])):
            if 'service' in version_result[host]['ports'][i]:
                if version_result[host]['ports'][i]['service']['name'] == service_name and (version_result[host]['ports'][i]['state'] != 'filtered' or version_result[host]['ports'][i]['state'] != 'closed'):
                    print("{}://{}:{} is open".format(version_result[host]['ports'][i]['service']['name'], host, version_result[host]['ports'][i]['portid']))
                    ipPorts.append("{}://{}:{}".format(version_result[host]['ports'][i]['service']['name'], host, version_result[host]['ports'][i]['portid']))
    
    if version_result is not None:
        check_and_print_ports(host, 'http')
        check_and_print_ports(host, 'https')
    
    global portScanningTime
    portScanningTime = round( (time.time() - portScanStart), 2 )

#ping scan for ip range 
def ping_scan(ip_range, mode):
    nm = nmap.PortScanner()
    hosts_to_scan = ' '.join(ip_range)

    nm.scan(hosts=hosts_to_scan, arguments='-sn')

    for host in nm.all_hosts():
        if nm[host].state() == 'up':
            print(f"Host: {host} is UP")
            up_ips.append(host)

if input_mode==1:
    host = socket.gethostbyname(input("Enter Your ip/domain: "))
    scan_ports(host,mode_num)

elif input_mode==2:
    print("Do you want to PING scan? 1-YES 2-NO\n")
    ping_choice = int(input("Enter your choice : "))
    print("Example format = 192.168.1.10-192.168.1.15")
    host = input("Enter your ip range: ")
    ip_addresses=host.split('-')
    ip_range=ips(ip_addresses[0],ip_addresses[1])

    if ping_choice == 1:
        ping_scan(ip_range, mode_num)
        if up_ips:
            for i in up_ips:
                scan_ports(i,mode_num)
                
    elif ping_choice == 2:
        for i in ip_range:
            scan_ports(i,mode_num)
        scan_ports(ip_addresses[1],mode_num)

elif input_mode==3:
    file = str(input("File name = "))
    with open (file,'r') as dosya:
        for host in dosya.read().splitlines():
            scan_ports(host,mode_num)

else:
    sys.exit()
#----End of Port finder block----


#----Login Check Block----
total_ports = len(ipPorts)
def check_login_page(ipPorts):
    global loginCheckStart
    loginCheckStart = time.time() #for calculate loginCheck time 
    
    output_file = open('output.txt', 'w', encoding='utf-8')

    #calculaate for each url
    for ipPort in ipPorts:
        try:
            response = requests.get(ipPort, verify=False, timeout=20)  #SSL verifying verify=False
            #html response code
            if response.status_code == 200:
                html_content = response.text
                print(html_content)
                #only if there is 'password' in source code for now! 
                if "password" in html_content.lower():
                    output_file.write(f"{ipPort} = The relevant page is the login page.\n")
                    print("-"*50)
                    print("{} = LOGIN PAGE".format(ipPort))
                else:
                    output_file.write(f"{ipPort} = The relevant page is not the login page.\n")
                    print("-"*50)
                    print("{} = NOT LOGIN PAGE".format(ipPort))
            else:
                output_file.write(f"{ipPort} = The request failed. Error Code : {response.status_code}\n")
                print("-"*50)
                print(f"{ipPort} = The request failed. Error code:", response.status_code)

        except requests.exceptions.Timeout:
            output_file.write(f"{ipPort} = There was a TIMEOUT error on the relevant page.\n")
            print("-"*50)
            print ("{} = TIMEOUT".format(ipPort))

        except requests.exceptions.ConnectionError as e:
            output_file.write(f"{ipPort} = There was a CONNECTION ERROR on the relevant page. : {e}\n")
            print("-"*50)
            print ("{} = CONNECTION ERROR : {}".format(ipPort, e))

        except urllib3.exceptions.ProtocolError as e:
            output_file.write(f"{ipPort} = There was a PROTOCOL ERROR occurred while sending the request : {e}\n")
            print("-"*50)
            print ("{} = PROTOCOL ERROR : {}".format(ipPort, e))

    output_file.close()
#----End of Login Check Block----

def prints_times():
    loginCheckTime = round( (time.time() - loginCheckStart), 2 )
    executionTime = round( (time.time() - start_time), 2 )
    print("-"*50)
    print("\nTotal Checked Ports : {}".format(total_ports))
    print("Port Scanning Time : {} seconds.".format(portScanningTime))
    print("Login Check Time : {} seconds.".format(loginCheckTime))
    print("Total Execution : {} seconds.\n".format(executionTime))
    
    output_file = open('output.txt', 'a', encoding='utf-8')
    output_file.write(f"Total Checked Ports : {total_ports}\n")
    output_file.write(f"Port Scanning Time : {portScanningTime}\n")
    output_file.write(f"Login Check Time : {loginCheckTime}\n")
    output_file.write(f"Execution Time : {executionTime}\n")
    output_file.close()


check_login_page(ipPorts)
prints_times()