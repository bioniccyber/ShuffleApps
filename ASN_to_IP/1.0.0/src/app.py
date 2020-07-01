import socket
import time
import ipaddress
import json
import asyncio

from walkoff_app_sdk.app_base import AppBase

class IP_to_ASN(AppBase):
    """
    An example of a Walkoff App.
    Inherit from the AppBase class to have Redis, logging, and console logging set up behind the scenes.
    """
    __version__ = "1.0.0"
    app_name = "IP to ASN"  # this needs to match "name" in api.yaml for WALKOFF to work

    def __init__(self, redis, logger, console_logger=None):
        """
        Each app should have this __init__ to set up Redis and logging.
        :param redis:
        :param logger:
        :param console_logger:
        """
        super().__init__(redis, logger, console_logger)


    def netcat(self,hostname, port, content):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((hostname, port))
        s.sendall(content)
        time.sleep(0.5)
        s.shutdown(socket.SHUT_WR)
        res = []
        while True:
            data = s.recv(1024)
            if (not data):
                break
            res.append(data.decode())
        s.close()
        return ("".join(res))

    async def IP_to_ASN(self,ips):
        # Team Cymru IP to ASN Mapping through 'netcat' (bulk use - few thousand per bulk use to minimize overall load as noted by the team cymru doc page).
        # Set output filename to include date+time


        valid_list=[]
        error_list=["Errors"]
        content="begin\nverbose\n"+ips+"\nend"
        # Place output into list
        tc_output_list = self.netcat("whois.cymru.com", 43, content.encode()).splitlines()
        # Skip first line of netcat output which is the following: 'Bulk mode; whois.cymru.com [2020-05-13 21:08:56 +0000]'
        for tc_record in tc_output_list[1:]:
            # Format of Output: ASN, IP, CIDR, CC, Registry, Allocated, AS Name
            tc_record = " ".join(tc_record.split()).replace(' | ','#~#')
            # Verify there's an expected amount of columns (6).
            counted_columns = tc_record.count("#~#")
            if counted_columns == 6:
                asn = tc_record.split('#~#')[0]
                ip = tc_record.split('#~#')[1]
                cidr = tc_record.split('#~#')[2]
                cc = tc_record.split('#~#')[3]
                registry = tc_record.split('#~#')[4]
                allocated = tc_record.split('#~#')[5]
                as_name = tc_record.split('#~#')[6]

                # Requested to convert CIDR into IP Range - from '68.22.187.0/24' to the following format: '68.22.187.0#~#24#~#68.22.187.255'
                cidr_tail = cidr.split('/')[1]
                cidr = ipaddress.ip_network(cidr)
                cidr = '%s#~#%s#~#%s' % (cidr[0], cidr_tail, cidr[-1])

                # Test prints
                '''
                print ("ASN: " + asn)
                print ("IP: " + ip)
                print ("CIDR: " + cidr)
                print ("CC: " + cc)
                print ("Registry: " + registry)
                print ("Allocated: " + allocated)
                print ("AS Name: " + as_name)
                print ('%s#~#%s#~#%s#~#%s#~#%s#~#%s#~#%s' % (asn, ip, cidr, cc, registry, allocated, as_name) + '\n')
                '''
                #Append to Output

                valid_list.append('%s#~#%s#~#%s#~#%s#~#%s#~#%s#~#%s' % (asn, ip, cidr, cc, registry, allocated, as_name) + '\n')
            else:
                # If there's for some reason an unexpected number of columns (greater/lower than 6), the above parser would be inaccurate and need to analyze the given IP's output and update the script accordingly.
                error_list.append(tc_record)
        return ("".join(valid_list) if len(error_list)==1 else "".join(valid_list)+"\n".join(error_list))

if __name__ == "__main__":
    asyncio.run(IP_to_ASN.run(), debug=True)
