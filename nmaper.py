import nmap
import ipgetter

print ipgetter.myip()

nm = nmap.PortScanner()
nm.scan(ipgetter.myip(),arguments='')
print nm.command_line()

for host in nm.all_hosts():
    print nm[host]

    print('----------------------------------------------------')
    print('Host : %s (%s)' % (host, nm[host].hostname()))
    print('State : %s' % nm[host].state())
    for proto in nm[host].all_protocols():
        print('----------')
        lport = nm[host][proto].keys()
        lport.sort()
        for port in lport:
            try:
                print port
                a = nm[host][proto][port]['state']
                print ('port : %s\tstate : %s' % (port,a))
            except: pass