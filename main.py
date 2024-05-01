import os
from dotenv import load_dotenv
import ipinfo
import dpkt
import datetime
from dpkt.utils import mac_to_str, inet_to_str

def main(): 
    handler = setupIPinfo()
    ip_address = "216.239.36.21"
    details = probeIPaddress(handler, ip_address)
    #print(details.all)

def setupIPinfo():
    access_token = getAccessToken()
    handler = ipinfo.getHandler(access_token)
    openExamplePcap()
    return handler

def probeIPaddress(handler, ip_address):
    details = handler.getDetails(ip_address)
    return details

def getAccessToken():
    load_dotenv()
    access = os.environ['API_KEY']
    if access == None:
        print("No environment variable found, utilizing free plan.")
        access = ""
    return access

def parsePcap(pcap_file):
    with open(pcap_file, 'rb') as f:
        pcap = dpkt.pcap.Reader(f)
        for ts, buf in pcap:
            eth = dpkt.ethernet.Ethernet(buf)
            ip = eth.data
            src_ip = inet_to_str(ip.src)
            dst_ip = inet_to_str(ip.dst)
            print("Source IP: " + src_ip)
            print("Destination IP: " + dst_ip)
            print("")

def openExamplePcap():
    pcap_file = "PacketCapture/Example.pcap"
    parsePcap(pcap_file)


if __name__=="__main__": 
    main() 