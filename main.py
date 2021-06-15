from scapy.all import *
pkt = sniff(count=20)
ip_addresses = []
local_Ip = "192.168.11.102" #run ipconfig to find out
for p in pkt:
    if "UDP" in p and p["IP"].dst == local_Ip:
        #print(p["IP"].src)
        ip = p["IP"].src
        ip_addresses.append(ip)

victim_ip = max(ip_addresses, key=ip_addresses.count)

def ipInfo(addr=''):
    from urllib.request import urlopen
    from json import load
    if addr == '':
        url = 'https://ipinfo.io/json'
    else:
        url = 'https://ipinfo.io/' + addr + '/json'
    res = urlopen(url)
    #response from url(if res==None then check connection)
    data = load(res)
    #will load the json response into data
    for attr in data.keys():
        #will print the data line by line
        print(attr,' '*13+'\t->\t',data[attr])
ipInfo(victim_ip)