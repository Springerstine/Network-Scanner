#Network Scanner
#Zachary Springer
#01/04/22

import scapy.all as scapy
import argparse

def get_arguments():
    parser = argparse.ArgumentParser()
    #User inputs vars when program is writen in cmd line
    parser.add_argument("-t", "--itarget", dest="target", help="Target IP address to scan, use ##.#.#.#/# to scan a range of IPs. Use --help for more information.")
    (options) = parser.parse_args()
    #Checks for valid inputs
    if not options.target:
        #Error handler: Interface
        parser.error("[-] Please specify a valid ip, use --help for more information.")
    return options 

def scan(ip):
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast/arp_request
    answered_list= scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]
    clients_list = []

    
    for element in answered_list: 
        client_dict = {"ip": element[1].psrc, "mac": element[1].hwsrc}
    for element in answered_list:
        clients_list.append(client_dict)
        print(element[1].psrc + "\t\t" + element[1].hwsrc)

    return clients_list


def print_result(result_list):
    print("IP \t\tMAC Address\n----------------------------------------------------------------")
    for client in result_list:
        print(client["ip"] + client["mac"])

options = get_arguments()
scan_result = scan(options.target)
print_result(scan_result)