import os
from dotenv import load_dotenv
import ipinfo
import dpkt
import datetime
from dpkt.utils import mac_to_str, inet_to_str

destinationIPAddresses = set()
destinationIPAddressesFiltered = set()
stock_destinationIPAddresses = set()
stock_destinationIPAddressesFiltered = set()
vanced_destinationIPAddresses = set()
vanced_destinationIPAddressesFiltered = set()
commonIPAddresses = set()
uncommonIPAddresses = set()

def main(): 
    handler = setupIPinfo()
    ip_address = "216.239.36.21"
    details = probeIPaddress(handler, ip_address)
    # ask which pcap(s) to open
    print("Please select a group of packet captures to open:")
    print("1. Stock Youtube App")
    print("2. Vanced Youtube App")
    print("3. Both")
    print("4. Specify Packet")
    print("5. Exit")
    choice = input("Enter the number of your choice: ")
    if choice == "1":
        openAllPcapsInDir("PacketCaptures/Stock")
        removePrivateIPs(destinationIPAddresses, destinationIPAddressesFiltered)
        printSetDetails(destinationIPAddresses, destinationIPAddressesFiltered)
        printDetailsForSet(destinationIPAddressesFiltered, handler)
    elif choice == "2":
        openAllPcapsInDir("PacketCaptures/Vanced")
        removePrivateIPs(destinationIPAddresses, destinationIPAddressesFiltered)
        printSetDetails(destinationIPAddresses, destinationIPAddressesFiltered)
        printDetailsForSet(destinationIPAddressesFiltered, handler)
    elif choice == "3":
        openAllPcaps()
        removePrivateIPs(stock_destinationIPAddresses, stock_destinationIPAddressesFiltered)
        removePrivateIPs(vanced_destinationIPAddresses, vanced_destinationIPAddressesFiltered)
        findCommonAndUncommonIPs(stock_destinationIPAddressesFiltered, vanced_destinationIPAddressesFiltered)
        printCommonAndUncommonIPs()
        printUncommonIPDetails(handler)
    elif choice == "4":
        openSpecificPcap(input("Enter the name of the pcap file (including directory): "))
        removePrivateIPs(destinationIPAddresses, destinationIPAddressesFiltered)
        printSetDetails(destinationIPAddresses, destinationIPAddressesFiltered)
        printDetailsForSet(destinationIPAddressesFiltered, handler)
    elif choice == "5" or choice == "exit" or choice == "q":
        print("Exiting program.")
        return
    else:
        print("Invalid choice. Exiting program.")
        return

def setupIPinfo():
    access_token = getAccessToken()
    handler = ipinfo.getHandler(access_token)
    return handler

def getAccessToken(): # Get the access token from the environment variables. If it doesn't exist, use the free plan.
    load_dotenv()
    access = os.environ['API_KEY']
    if access == None:
        print("No environment variable found, utilizing free plan for IPinfo API.")
        access = ""
    return access

# Get all the details for a given IP address, we'll sort out what we want to print later
def probeIPaddress(handler, ip_address):
    details = handler.getDetails(ip_address)
    return details

def printDetails(details):
    try:
        print("IP Address: " + details.ip)
    except:
        print("IP Address: N/A")
    try:
        print("Hostname: " + details.hostname)
    except:
        print("Hostname: N/A")
    try:
        print("City: " + details.city)
    except:
        print("City: N/A")
    try:
        print("Region: " + details.region)
    except:
        print("Region: N/A")
    try:
        print("Country: " + details.country)
    except:
        print("Country: N/A")
    try:
        print("Organization: " + details.org)
    except:
        print("Organization: N/A")
    print("--------------------")

def printDetailsForSet(setToPrint, handler):
    print("Would you like to print details for each packet?")
    choice = input("Enter 'y' for yes, 'n' for no: ")
    if choice == "n":
        return
    for ip in setToPrint:
        printDetails(probeIPaddress(handler, ip))

def printSetDetails(unfilteredSet, filteredSet):
    print("Packets in unfiltered set: " + str(len(unfilteredSet)))
    print("Packets in filtered set: " + str(len(filteredSet)))
    print("Unique IP addresses in filtered set: " + str(len(filteredSet)))

def printCommonAndUncommonIPs():
    print("Shared IP Addresses: " + str(len(commonIPAddresses)))
    print("Non-Shared IP Addresses: " + str(len(uncommonIPAddresses)))

def printUncommonIPDetails(handler):
    print("Would you like to print details for packets with non-shared IP addresses?")
    choice = input("Enter 'y' for yes, 'n' for no: ")
    if choice == "n":
        return
    nonCDNIPs = set()
    for ip in uncommonIPAddresses:
        details = probeIPaddress(handler, ip)
        printDetails(details)
        # check if organization contains "Google" or "Cloudfare" and add to set
        if "Google" not in details.org and "Cloudflare" not in details.org:
            nonCDNIPs.add(ip)
        if len(nonCDNIPs) > 0:
            print("Non-CDN IP Addresses: " + str(len(nonCDNIPs)))
            print("Unique Non-CDN IP Addresses: " + str(len(nonCDNIPs)))
            for ip in nonCDNIPs:
                printDetails(probeIPaddress(handler, ip))
        else: # Majority of the time, the addresses went to 1e100.net which is a domain name for google servers (usually CDNs)
            print("No non-CDN/1e100.net addresses found.")


# Packet Capture Parsing
def parsePcap(pcap_file, setToAddTo=destinationIPAddresses):
    with open(pcap_file, 'rb') as f:
        pcap = dpkt.pcap.Reader(f)
        for timeStamp, packet_data in pcap: # for each packet in the pcap file, grab the ip packet and add the destination IP to the set
            ipv4_packet = dpkt.ip.IP(packet_data)
            src_ip = inet_to_str(ipv4_packet.src)
            dst_ip = inet_to_str(ipv4_packet.dst)
            setToAddTo.add(dst_ip) # add destination IP's to a set (no duplicates this way)

def openExamplePcap(): # Used for testing purposes
    pcap_file = "PacketCaptures/Stock/PCAPdroid_25_Apr_11_55_45.pcap"
    parsePcap(pcap_file)

def openSpecificPcap(pcapNameandDir):
    pcap_file = pcapNameandDir
    parsePcap(pcap_file)

def openAllPcapsInDir(dir):
    for pcap_file in os.listdir(dir):
        parsePcap(os.path.join(dir, pcap_file))

# Open all packet captures in the Stock and Vanced directories
def openAllPcaps():
    stock_dir = "PacketCaptures/Stock"
    vanced_dir = "PacketCaptures/Vanced"
    for pcap_file in os.listdir(stock_dir):
        parsePcap(os.path.join(stock_dir, pcap_file), stock_destinationIPAddresses)
    for pcap_file in os.listdir(vanced_dir):
        parsePcap(os.path.join(vanced_dir, pcap_file), vanced_destinationIPAddresses)

# Packet Capture Filtering
# Remove the private IP addresses from the set (192.168.x.x, 10.x.x.x, 172.16.x.x)
def removePrivateIPs(setToFilter, setFiltered):
    for ip in setToFilter: 
        if not ip.startswith("192.168.") and not ip.startswith("10.") and not ip.startswith("172.16."):
            setFiltered.add(ip)

# Find the shared and non-shared IP addresses between two sets
def findCommonAndUncommonIPs(set1, set2):
    for ip in set1:
        if ip in set2:
            commonIPAddresses.add(ip)
        else:
            uncommonIPAddresses.add(ip)

if __name__=="__main__": 
    main() 