#!/usr/bin/env python3
import netsnmp
from tabulate import tabulate

def snmp_get (iid,request):
    ipNetToMedia = netsnmp.Varbind(request+'{0}'.format(iid))
    netsnmp.snmpget(ipNetToMedia, DestHost="192.168.30.137", Version=2, Community="public")
    if request == 'IP-MIB::ipNetToMediaType.':
        if int(ipNetToMedia.val.decode("utf-8")) == 3:
            return "dynamic"
        elif int(ipNetToMedia.val.decode("utf-8")) == 1:
            return "other"
        elif int(ipNetToMedia.val.decode("utf-8")) == 2:
            return "invalid"
        elif int(ipNetToMedia.val.decode("utf-8")) == 4:
            return "static"
    elif(request == 'IP-MIB::ipNetToMediaPhysAddress.'):
            mac = ipNetToMedia.val
            mac = str(mac.hex())
            mac = ':'.join(mac[i:i+2] for i in range(0,12,2))
            return mac

    else:
        return ipNetToMedia.val

def get_arp_table():
    arp_table = {}
    # descriptions
    ipNetToMediaIfIndex = netsnmp.VarList(netsnmp.Varbind(".1.3.6.1.2.1.4.22.1.1"))
    netsnmp.snmpwalk(ipNetToMediaIfIndex, DestHost="192.168.30.137", Version=2, Community="public")
    for member in ipNetToMediaIfIndex:
 #       print((member.val).hex())    # 005056ea3d36
 #       print(member.iid)    # 2.192.168.44.254 
 #       print(member.tag)   # ipNetToMediaPhysAddress
 #       print(member.type)    #  OCTETSTR

        if int(member.val) == 1:
            interface = "FastEthernet0/0"
        elif int(member.val) == 2:
            interface = "FastEthernet0/1"
        elif int(member.val) == 4:
            interface = "Null0"
        
        a = {"iid": member.iid, "index": interface}
        a["mac"] = (snmp_get (member.iid,'IP-MIB::ipNetToMediaPhysAddress.'))
        a["IP"] =  snmp_get (member.iid,'IP-MIB::ipNetToMediaNetAddress.')
        a["MediaType"] = snmp_get (member.iid,'IP-MIB::ipNetToMediaType.')
        arp_table[a ["iid"]] = a    
        a = {}
    # status
    return arp_table


result = get_arp_table ()
device_list = []
i=0
for item in result:
    i+=1
    device_list.append([i,result[item]["IP"],result[item]["mac"],result[item]["MediaType"],result[item]["index"]])

# We use tabulate module here to print a nice table format. You should use "pip" tool to install in your local machine
# For the simplicity we just copy the source code in working directory without  installing it.
# Not showing id to user, it's just a hex string
print (tabulate(device_list, headers=['number','Address','Hardware Addr','MediaType','Interface'],tablefmt="rst"))
