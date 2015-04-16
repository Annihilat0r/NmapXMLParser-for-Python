import xml.dom.minidom


def analyse_nmap_xml_scan(nmap_xml_output=None):

    scan_result = {}

    try:
        dom = xml.dom.minidom.parseString(nmap_xml_output)
    except xml.parsers.expat.ExpatError:
        print('error when trying parse xml file')

    scan_result['parameters'] = dom.getElementsByTagName('nmaprun')[0].getAttributeNode('args').value
    scan_result['host'] = dom.getElementsByTagName('host')[0].getElementsByTagName('address')[0].getAttributeNode('addr').value
    scan_result['hostinfo'] = {}

    for dport in dom.getElementsByTagName('host')[0].getElementsByTagName('port'):
        port = int(dport.getAttributeNode('portid').value)
        state = dport.getElementsByTagName('state')[0].getAttributeNode('state').value
        reason = dport.getElementsByTagName('state')[0].getAttributeNode('reason').value
        name, product, version, extrainfo, conf, cpe = '', '', '', '', '', ''
        for dname in dport.getElementsByTagName('service'):
            name = dname.getAttributeNode('name').value
            if dname.hasAttribute('product'):
                product = dname.getAttributeNode('product').value
            if dname.hasAttribute('version'):
                version = dname.getAttributeNode('version').value
            if dname.hasAttribute('extrainfo'):
                extrainfo = dname.getAttributeNode('extrainfo').value
            if dname.hasAttribute('conf'):
                conf = dname.getAttributeNode('conf').value
            for dcpe in dname.getElementsByTagName('cpe'):
                cpe = dcpe.firstChild.data
        # store everything about ports
        scan_result['hostinfo'][port] = {'state': state,
                                         'reason': reason,
                                         'name': name,
                                         'product': product,
                                         'version': version,
                                         'extrainfo': extrainfo,
                                         'conf': conf,
                                         'cpe': cpe}
    return scan_result


result = analyse_nmap_xml_scan(open('scan.xml').read())

print 'Host:', result['host']
print 'Scan parameters:', result['parameters']
print 'Open ports:', result['hostinfo'].keys()
for port in result['hostinfo'].keys():
    print '---', str(port), '---', str(result['hostinfo'][port])
