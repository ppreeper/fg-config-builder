#!/usr/bin/env python3
import json
import ipaddress
import argparse


def netmaker(address, netmask):
    ip = "%s/%s" % (address, netmask)
    ipnet = ipaddress.ip_network(ip, strict=False)
    net = ipnet.with_netmask.split('/')
    return net


def systemglobal(network, location):
    globalconfig = "config system global\n"
    glbl = network['global']
    for k in glbl:
        globalconfig += "set %s %s\n" % (k, glbl[k])
    globalconfig += "set hostname \"gw%s\"\n" % (str(location).lower())
    globalconfig += "end\n"
    return globalconfig


def systemadmin(network):
    adminconfig = "config system admin\n"
    adminconfig += "edit \"admin\"\n"
    adminconfig += "set password %s\n" % (network['admin']['password'])
    adminconfig += "end\n"
    return adminconfig


def systemsettings(network):
    config = "config system settings\n"
    config += "set v4-ecmp-mode weight-based\n"
    config += "set sip-helper disable\n"
    config += "set sip-nat-trace disable\n"
    config += "set allow-subnet-overlap enable\n"
    config += "set default-voip-alg-mode kernel-helper-based\n"
    config += "end\n"
    return config


def systeminterfaceenum(interface, netgw, portlist):
    for l in netgw['wan']:
        if l['port'] == interface and l['type'] == 'physical':
            portlist.append(
                {
                    "port": l['port'],
                    "name": l['name'],
                    "access": l['access'],
                    "type": l['type'],
                    "mode": l['mode'],
                    "address": l['address'],
                    "netmask": l['netmask'],
                    "weight": l['weight']
                }
            )
    for l in netgw['internal']:
        if l['port'] == interface and l['type'] == 'physical':
            portlist.append(
                {
                    "port": l['port'],
                    "name": l['name'],
                    "access": l['access'],
                    "type": l['type'],
                    "address": l['address'],
                    "netmask": l['netmask']
                }
            )
    for l in netgw['internal']:
        if l['port'] == interface and l['type'] == 'switch':
            portlist.append(
                {
                    "port": l['port'],
                    "name": l['name'],
                    "access": l['access'],
                    "type": l['type'],
                    "address": l['address'],
                    "netmask": l['netmask']
                }
            )
    for l in netgw['internal']:
        if l['port'] == interface and l['type'] == 'vlan':
            portlist.append(
                {
                    "port": l['port'],
                    "name": l['name'],
                    "access": l['access'],
                    "type": l['type'],
                    "address": l['address'],
                    "netmask": l['netmask'],
                    "vlanid": l['vlanid']
                }
            )
    return portlist


def systemswitchinterface(network, location):
    switchconfig = ""
    try:
        sw = network['locations'][location]['switch']
    except:
        pass
    else:
        switchconfig = "config system switch-interface\n"
        netgw = network['locations'][location]
        sw = netgw['switch']
        for s in range(len(sw)):
            switchconfig += "edit \"%s\"\n" % (sw[s]['name'])
            members = ""
            for m in range(len(sw[s]['members'])):
                members += "\"%s\" " % (sw[s]['members'][m])
            switchconfig += "set member %s\n" % (members)
            switchconfig += "next\n"
        switchconfig += "end\n"
    return switchconfig


def systeminterface(network, location):
    interfaceconfig = "config system interface\n"
    netgw = network['locations'][location]
    intf = netgw['interfaces']
    portlist = []
    for i in range(intf['mgmt']):
        intfNum = "mgmt%s" % (i + 1)
        portlist = systeminterfaceenum(intfNum, netgw, portlist)
    for i in range(intf['wan']):
        intfNum = "wan%s" % (i + 1)
        portlist = systeminterfaceenum(intfNum, netgw, portlist)
    for i in range(intf['dmz']):
        intfNum = "dmz"
        portlist = systeminterfaceenum(intfNum, netgw, portlist)
    for i in range(intf['internal']):
        if netgw['version'] == '4':
            intfNum = "internal"
            portlist = systeminterfaceenum(intfNum, netgw, portlist)
        elif netgw['version'] == '5':
            intfNum = "lan"
            portlist = systeminterfaceenum(intfNum, netgw, portlist)
    for i in range(intf['port']):
        intfNum = "port%s" % (i + 1)
        portlist = systeminterfaceenum(intfNum, netgw, portlist)
    for p in range(len(portlist)):
        if portlist[p]['type'] == 'vlan':
            interfaceconfig += "edit \"%s\"\n" % (portlist[p]['name'])
            interfaceconfig += "set ip %s %s\n" % (
                portlist[p]['address'], portlist[p]['netmask'])
            access = ""
            for a in range(len(portlist[p]['access'])):
                access += "%s " % portlist[p]['access'][a]
            interfaceconfig += "set allowaccess %s\n" % (access)
            interfaceconfig += "set interface \"%s\"\n" % (portlist[p]['port'])
            interfaceconfig += "set vlanid %s\n" % (portlist[p]['vlanid'])
        else:
            interfaceconfig += "edit \"%s\"\n" % (portlist[p]['port'])
            try:
                if portlist[p]['mode'] == 'dhcp':
                    interfaceconfig += "set mode %s\n" % (portlist[p]['mode'])
                else:
                    interfaceconfig += "set mode static\n"
                    interfaceconfig += "set ip %s %s\n" \
                        % (portlist[p]['address'], portlist[p]['netmask'])
            except:
                interfaceconfig += "set ip %s %s\n" \
                    % (portlist[p]['address'], portlist[p]['netmask'])
            interfaceconfig += "set distance 10\n"
            try:
                if portlist[p]['weight']:
                    interfaceconfig += "set weight %s\n" \
                        % (portlist[p]['weight'])
            except:
                pass
            access = ""
            for a in range(len(portlist[p]['access'])):
                access += "%s " % portlist[p]['access'][a]
            interfaceconfig += "set allowaccess %s\n" % (access)
            interfaceconfig += "set alias \"%s\"\n" % (portlist[p]['name'])
        interfaceconfig += "next\n"
    try:
        sw = network['locations'][location]['switch']
    except:
        pass
    else:
        intifs = netgw['internal']
        for s in range(len(sw)):
            for i in range(len(intifs)):
                if intifs[i]['name'] == sw[s]['name']:
                    interfaceconfig += "edit \"%s\"\n" % (intifs[i]['name'])
                    interfaceconfig += "set ip %s %s\n" % (
                        intifs[i]['address'], intifs[i]['netmask'])
                    interfaceconfig += "set distance 10\n"
                    access = ""
                    for a in range(len(intifs[i]['access'])):
                        access += "%s " % intifs[i]['access'][a]
                    interfaceconfig += "set allowaccess %s\n" % (access)
                    interfaceconfig += "set type %s\n" % (intifs[i]['type'])
                    interfaceconfig += "next\n"
                if intifs[i]['type'] == 'vlan':
                    interfaceconfig += "edit \"%s\"\n" % (intifs[i]['name'])
                    interfaceconfig += "set ip %s %s\n" % (
                        intifs[i]['address'], intifs[i]['netmask'])
                    interfaceconfig += "set distance 10\n"
                    access = ""
                    for a in range(len(intifs[i]['access'])):
                        access += "%s " % intifs[i]['access'][a]
                    interfaceconfig += "set allowaccess %s\n" % (access)
                    interfaceconfig += "set interface \"%s\"\n" % (intifs[i][
                                                                   'port'])
                    interfaceconfig += "set vlanid %s\n" % (
                        intifs[i]['vlanid'])
                    interfaceconfig += "next\n"

    interfaceconfig += "end\n"
    return interfaceconfig


def systemdhcpserver(network, location):
    dhcpconfig = "config system dhcp server\n"
    netgw = network['locations'][location]
    dhcp = netgw['dhcp']
    for i in range(len(dhcp)):
        address = ""
        netmask = ""
        for p in range(len(netgw['internal'])):
            if netgw['internal'][p]['port'] == dhcp[i]['port']:
                if netgw['internal'][p]['type'] == dhcp[i]['type']:
                    address = netgw['internal'][p]['address']
                    netmask = netgw['internal'][p]['netmask']
        dhcpconfig += "edit %s\n" % (i + 1)
        dhcpconfig += "set lease-time %s\n" % (dhcp[i]['leasetime'])
        dhcpconfig += "set domain \"%s\"\n" % (dhcp[i]['domain'])
        dhcpconfig += "set default-gateway %s\n" % (address)
        dhcpconfig += "set netmask %s\n" % (netmask)
        dhcpconfig += "set interface \"%s\"\n" % (dhcp[i]['port'])
        for d in range(len(dhcp[i]['dns'])):
            dhcpconfig += "dns-server%s %s\n" % (d + 1, dhcp[i]['dns'][d])
        dhcpconfig += "config ip-range\n"
        for d in range(len(dhcp[i]['iprange'])):
            dhcpconfig += "edit %s\n" % (d + 1)
            ip = "%s/%s" % (address, netmask)
            ipnet = ipaddress.ip_network(ip, strict=False)
            ipaddr = ipaddress.IPv4Address(ipnet.network_address)
            ipsplit = str(dhcp[i]['iprange'][d][0]).split(".")
            ipraw = 0
            ipexp = 0
            for o in range(len(ipsplit), 0, -1):
                ipraw += int(ipsplit[o - 1]) * (256 ** ipexp)
                ipexp += 1
            startip = ipaddr + int(ipraw)
            ipsplit = str(dhcp[i]['iprange'][d][1]).split(".")
            ipraw = 0
            ipexp = 0
            for o in range(len(ipsplit), 0, -1):
                ipraw += int(ipsplit[o - 1]) * (256 ** ipexp)
                ipexp += 1
            endip = ipaddr + int(ipraw)
            dhcpconfig += "set start-ip %s\n" % (startip)
            dhcpconfig += "set end-ip %s\n" % (endip)
            dhcpconfig += "next\n"
        dhcpconfig += "end\n"
        dhcpconfig += "next\n"
    dhcpconfig += "end\n"
    return dhcpconfig


def vpnipsec(network, location, hub=False):
    ipsec = network['ipsec']
    phase1 = ipsec['phase1']
    phase2 = ipsec['phase2']
    srcgw = network['locations'][location]
    dstgw = network['locations'][ipsec['hub']]
    srcwan = srcgw['wan']
    dstwan = dstgw['wan']

    locations = network['locations']
    branchlist = sorted(locations.keys())
    del branchlist[branchlist.index(ipsec['hub'])]

    vpnconfig = "config vpn ipsec phase1-interface\n"
    if hub is False:
        for s in range(len(srcwan)):
            for h in range(len(dstwan)):
                if dstwan[h]['vpn'] == 'True':
                    if srcwan[s]['vpn'] == 'True':
                        vpnconfig += "edit \"%s%s-%s%s-P1\"\n" \
                            % (srcgw['name'], s + 1, dstgw['name'], h + 1)
                        vpnconfig += "set interface \"%s\"\n" \
                            % (srcwan[s]['port'])
                        vpnconfig += "set keylife %s\n" % (phase1['keylife'])
                        proposal = ""
                        for p in range(len(phase1['proposal'])):
                            proposal += "%s " % (phase1['proposal'][p])
                        vpnconfig += "set proposal %s\n" % (proposal)
                        dhgrp = ""
                        for d in range(len(phase1['dhgrp'])):
                            dhgrp += "%s " % (phase1['dhgrp'][d])
                        vpnconfig += "set dhgrp %s\n" % (dhgrp)
                        vpnconfig += "set remote-gw %s\n" \
                            % (dstwan[h]['extaddress'])
                        vpnconfig += "set psksecret %s\n" \
                            % (phase1['psk'])
                        vpnconfig += "next\n"
    else:
        for s in range(len(srcwan)):
            for h in range(len(branchlist)):
                dstgw = network['locations'][branchlist[h]]
                dstwan = network['locations'][branchlist[h]]['wan']
                for w in range(len(dstwan)):
                    if dstwan[w]['vpn'] == 'True':
                        if srcwan[s]['vpn'] == 'True':
                            vpnconfig += "edit \"%s%s-%s%s-P1\"\n" \
                                % (srcgw['name'], s + 1,
                                   dstgw['name'], w + 1)
                            vpnconfig += "set interface \"%s\"\n" \
                                % (srcwan[s]['port'])
                            vpnconfig += "set keylife %s\n" \
                                % (phase1['keylife'])
                            proposal = ""
                            for p in range(len(phase1['proposal'])):
                                proposal += "%s " % (phase1['proposal'][p])
                            vpnconfig += "set proposal %s\n" % (proposal)
                            dhgrp = ""
                            for d in range(len(phase1['dhgrp'])):
                                dhgrp += "%s " % (phase1['dhgrp'][d])
                            vpnconfig += "set dhgrp %s\n" % (dhgrp)
                            vpnconfig += "set remote-gw %s\n" \
                                % (dstwan[w]['extaddress'])
                            vpnconfig += "set psksecret %s\n" % (phase1['psk'])
                            vpnconfig += "next\n"
    vpnconfig += "end\n\n"

    vpnconfig += "config vpn ipsec phase2-interface\n"
    if hub is False:
        for s in range(len(srcwan)):
            for h in range(len(dstwan)):
                if dstwan[h]['vpn'] == 'True':
                    if srcwan[s]['vpn'] == 'True':
                        vpnconfig += "edit \"%s%s-%s%s-P2\"\n" \
                            % (srcgw['name'], s + 1, dstgw['name'], h + 1)
                        vpnconfig += "set phase1name \"%s%s-%s%s-P1\"\n" \
                            % (srcgw['name'], s + 1, dstgw['name'], h + 1)
                        proposal = ""
                        for p in range(len(phase2['proposal'])):
                            proposal += "%s " % (phase2['proposal'][p])
                        vpnconfig += "set proposal %s\n" % (proposal)
                        dhgrp = ""
                        for d in range(len(phase2['dhgrp'])):
                            dhgrp += "%s " % (phase2['dhgrp'][d])
                        vpnconfig += "set dhgrp %s\n" % (dhgrp)
                        vpnconfig += "set keepalive %s\n" \
                            % (phase2['keepalive'])
                        vpnconfig += "set auto-negotiate %s\n" \
                            % (phase2['auto-negotiate'])
                        vpnconfig += "set keylifeseconds %s\n" \
                            % (phase2['keylifeseconds'])
                        vpnconfig += "next\n"
    else:
        for s in range(len(srcwan)):
            for h in range(len(branchlist)):
                dstgw = network['locations'][branchlist[h]]
                dstwan = network['locations'][branchlist[h]]['wan']
                for w in range(len(dstwan)):
                    if dstwan[w]['vpn'] == 'True':
                        if srcwan[s]['vpn'] == 'True':
                            vpnconfig += "edit \"%s%s-%s%s-P2\"\n" \
                                % (srcgw['name'], s + 1,
                                   dstgw['name'], w + 1)
                            vpnconfig += "set phase1name \"%s%s-%s%s-P1\"\n" \
                                % (srcgw['name'], s + 1,
                                   dstgw['name'], w + 1)
                            proposal = ""
                            for p in range(len(phase2['proposal'])):
                                proposal += "%s " % (phase2['proposal'][p])
                            vpnconfig += "set proposal %s\n" % (proposal)
                            dhgrp = ""
                            for d in range(len(phase2['dhgrp'])):
                                dhgrp += "%s " % (phase2['dhgrp'][d])
                            vpnconfig += "set dhgrp %s\n" % (dhgrp)
                            vpnconfig += "set keepalive %s\n" \
                                % (phase2['keepalive'])
                            vpnconfig += "set auto-negotiate %s\n" \
                                % (phase2['auto-negotiate'])
                            vpnconfig += "set keylifeseconds %s\n" \
                                % (phase2['keylifeseconds'])
                            vpnconfig += "next\n"
    vpnconfig += "end\n"
    return vpnconfig


def systemzone(network, location, hub=False):
    srcgw = network['locations'][location]
    dstgw = network['locations'][network['ipsec']['hub']]
    srcwan = srcgw['wan']
    dstwan = dstgw['wan']
    locations = network['locations']
    branchlist = sorted(locations.keys())
    del branchlist[branchlist.index(network['ipsec']['hub'])]

    phase1interfaces = ""
    if hub is False:
        for s in range(len(srcwan)):
            for h in range(len(dstwan)):
                if dstwan[h]['vpn'] == 'True':
                    if srcwan[s]['vpn'] == 'True':
                        phase1interfaces += "\"%s%s-%s%s-P1\" " \
                            % (srcgw['name'], s + 1, dstgw['name'], h + 1)
    else:
        for s in range(len(srcwan)):
            for h in range(len(branchlist)):
                dstgw = network['locations'][branchlist[h]]
                dstwan = network['locations'][branchlist[h]]['wan']
                for w in range(len(dstwan)):
                    if dstwan[w]['vpn'] == 'True':
                        if srcwan[s]['vpn'] == 'True':
                            phase1interfaces += "\"%s%s-%s%s-P1\" " \
                                % (srcgw['name'], s + 1, dstgw['name'], w + 1)

    srcgw = network['locations'][location]
    zone = srcgw['zone']

    zoneconfig = "config system zone\n"
    for z in range(len(zone)):
        zoneconfig += "edit \"%s\"\n" % (zone[z]['name'])
        zoneconfig += "set intrazone allow\n"
        zoneconfig += "set interface %s\n" % (phase1interfaces)
        zoneconfig += "next\n"
    zoneconfig += "end\n"
    return zoneconfig


def setvpnweight(network, location, hub=False):
    srcgw = network['locations'][location]
    dstgw = network['locations'][network['ipsec']['hub']]
    srcwan = srcgw['wan']
    dstwan = dstgw['wan']
    locations = network['locations']
    branchlist = sorted(locations.keys())
    del branchlist[branchlist.index(network['ipsec']['hub'])]

    vpnweight = "config system interface\n"

    if hub is False:
        for s in range(len(srcwan)):
            for h in range(len(dstwan)):
                if dstwan[h]['vpn'] == 'True':
                    vpnweight += "edit \"%s%s-%s%s-P1\"\n" % (
                        srcgw['name'], s + 1, dstgw['name'], h + 1)
                    vpnweight += "set distance 20\n"
                    vpnweight += "set weight 20\n"
                    vpnweight += "next\n"
    vpnweight += "end\n"
    return vpnweight


def firewalladdress(network, location):
    addressconfig = "config firewall address\n"
    locations = network['locations']
    routes = network['routes']
    keylist = sorted(routes.keys())
    for l in keylist:
        addressconfig += "edit \"%s\"\n" % l
        addressconfig += "set subnet %s %s\n" % (routes[l][0], routes[l][1])
        addressconfig += "next\n"
    keylist = sorted(network['locations'].keys())
    for l in keylist:
        for i in locations[l]['internal']:
            if location == l:
                addressconfig += "edit \"%s\"\n" % i['name']
                net = netmaker(i['address'], i['netmask'])
                addressconfig += "set subnet %s %s\n" % (net[0], net[1])
                if i['type'] == 'vlan':
                    addressconfig += "set associated-interface \"%s\"\n" \
                        % (i['name'])
                else:
                    addressconfig += "set associated-interface \"%s\"\n" \
                        % (i['port'])
                addressconfig += "next\n"
        try:
            locations[l]['address']
        except:
            pass
        # else:
        #     for i in locations[l]['address']:
        #         addressconfig += "edit \"%s\"\n" % i['name']
        #         addressconfig += "set type %s\n" % i['type']
        #         addressconfig += "set start-ip %s\n" % i['iprange'][0]
        #         addressconfig += "set end-ip %s\n" % i['iprange'][1]
        #         addressconfig += "next\n"
    addressconfig += "end\n"
    return addressconfig


def firewalladdrgrp(network, location):
    netlist = ""
    locations = network['locations']
    routes = network['routes']
    keylist = sorted(routes.keys())
    for l in keylist:
        netlist += "\"%s\" " % l

    # keylist = sorted(locations.keys())
    # for l in keylist:
    #     for i in locations[l]['internal']:
    #         if location != l:
    #             netlist += "\"%s\" " % (i['name'])
    #     try:
    #         locations[l]['address']
    #     except KeyError:
    #         pass
    #     else:
    #         for i in locations[l]['address']:
    #             if location != l:
    #                 netlist += "\"%s\" " % (i['name'])
    addrgrpconfig = "config firewall addrgrp\n"
    addrgrps = network['firewall']['addrgrp']
    for a in addrgrps:
        addrgrpconfig += "edit \"%s\"\n" % (a['name'])
        addrgrpconfig += "set member %s\n" % (netlist)
        addrgrpconfig += "next\n"
    addrgrpconfig += "end\n"
    return addrgrpconfig


def firewallpolicy(network, location):
    srcgw = network['locations'][location]
    srcwan = srcgw['wan']
    srcver = srcgw['version']
    srcint = srcgw['internal']

    policyconfig = "config firewall policy\n"
    policynum = 1
    for i in range(len(srcint)):
        for w in range(len(srcwan)):
            policyconfig += "edit %s\n" % (policynum)
            policyconfig += "set srcintf \"%s\"\n" % (srcint[i]['port'])
            policyconfig += "set srcaddr \"%s\"\n" % (srcint[i]['name'])
            policyconfig += "set dstintf \"%s\"\n" % (srcwan[w]['port'])
            policyconfig += "set dstaddr \"%s\"\n" % ("all")
            policyconfig += "set action accept\n"
            policyconfig += "set schedule \"always\"\n"
            if srcver == "4":
                policyconfig += "set service \"ANY\"\n"
            elif srcver == "5":
                policyconfig += "set service \"ALL\"\n"
            policyconfig += "set nat enable\n"
            policyconfig += "next\n"
            policynum += 1
    if len(srcint) >= 2:
        for i in range(len(srcint)):
            for w in range(len(srcint)):
                if srcint[i]['name'] != srcint[w]['name']:
                    policyconfig += "edit %s\n" % (policynum)
                    if srcint[i]['type'] == 'vlan':
                        policyconfig += "set srcintf \"%s\"\n" \
                                        % (srcint[i]['name'])
                    else:
                        policyconfig += "set srcintf \"%s\"\n" \
                                        % (srcint[i]['port'])
                    policyconfig += "set srcaddr \"%s\"\n" % (
                        srcint[i]['name'])
                    if srcint[w]['type'] == 'vlan':
                        policyconfig += "set dstintf \"%s\"\n" \
                                        % (srcint[w]['name'])
                    else:
                        policyconfig += "set dstintf \"%s\"\n" \
                                        % (srcint[w]['port'])
                    policyconfig += "set dstaddr \"%s\"\n" % (
                        srcint[w]['name'])
                    policyconfig += "set action accept\n"
                    policyconfig += "set schedule \"always\"\n"
                    if srcver == "4":
                        policyconfig += "set service \"ANY\"\n"
                    elif srcver == "5":
                        policyconfig += "set service \"ALL\"\n"
                    policyconfig += "next\n"
                    policynum += 1
    for i in range(len(srcint)):
        for z in range(len(srcgw['zone'])):
            for a in range(len(network['firewall']['addrgrp'])):
                policyconfig += "edit %s\n" % (policynum)
                if srcint[i]['type'] == 'vlan':
                    policyconfig += "set srcintf \"%s\"\n" % (
                        srcint[i]['name'])
                else:
                    policyconfig += "set srcintf \"%s\"\n" % (
                        srcint[i]['port'])
                policyconfig += "set srcaddr \"%s\"\n" % (srcint[i]['name'])
                policyconfig += "set dstintf \"%s\"\n" \
                                % (srcgw['zone'][z]['name'])
                policyconfig += "set dstaddr \"%s\"\n" \
                                % (network['firewall']['addrgrp'][a]['name'])
                policyconfig += "set action accept\n"
                policyconfig += "set schedule \"always\"\n"
                if srcver == "4":
                    policyconfig += "set service \"ANY\"\n"
                elif srcver == "5":
                    policyconfig += "set service \"ALL\"\n"
                policyconfig += "next\n"
                policynum += 1
    for i in range(len(srcint)):
        for z in range(len(srcgw['zone'])):
            for a in range(len(network['firewall']['addrgrp'])):
                policyconfig += "edit %s\n" % (policynum)
                policyconfig += "set srcintf \"%s\"\n" \
                    % (srcgw['zone'][z]['name'])
                policyconfig += "set srcaddr \"%s\"\n" \
                    % (network['firewall']['addrgrp'][a]['name'])
                if srcint[i]['type'] == 'vlan':
                    policyconfig += "set dstintf \"%s\"\n" % (
                        srcint[i]['name'])
                else:
                    policyconfig += "set dstintf \"%s\"\n" % (
                        srcint[i]['port'])
                policyconfig += "set dstaddr \"%s\"\n" % (srcint[i]['name'])
                policyconfig += "set action accept\n"
                policyconfig += "set schedule \"always\"\n"
                if srcver == "4":
                    policyconfig += "set service \"ANY\"\n"
                elif srcver == "5":
                    policyconfig += "set service \"ALL\"\n"
                policyconfig += "next\n"
                policynum += 1
    policyconfig += "end\n"
    return policyconfig


def netlistgen(locations, keylist, location):
    nets = []
    for l in keylist:
        for i in locations[l]['internal']:
            if location != l:
                net = netmaker(i['address'], i['netmask'])
                nets.append([i['name'], net[0], net[1]])
        try:
            locations[l]['address']
        except:
            pass
        else:
            for i in locations[l]['address']:
                if location != l:
                    net = netmaker(i['iprange'][0], "255.255.255.0")
                    nets.append([i['name'], net[0], net[1]])
    nets = sorted(nets)
    return nets


def routestatic(network, location, hub=False):
    srcgw = network['locations'][location]
    dstgw = network['locations'][network['ipsec']['hub']]
    srcwan = srcgw['wan']
    dstwan = dstgw['wan']

    locations = network['locations']
    branchlist = sorted(locations.keys())
    del branchlist[branchlist.index(network['ipsec']['hub'])]

    #keylist = sorted(locations.keys())
    #nets = netlistgen(locations, keylist, location)
    brlist = []
    for b in branchlist:
        br = "%s" % (network['locations'][b]['branch'])
        if srcgw['branch'] == "True" and br == 'True':
            brlist.append(b)
    brnets = netlistgen(locations, brlist, location)
    routes = network['routes']
    routelist = sorted(routes.keys())

    staticconfig = "config router static\n"
    routenum = 1
    for s in range(len(srcwan)):
        if srcwan[s]['mode'] == 'static':
            staticconfig += "edit %s\n" % (routenum)
            staticconfig += "set comment \"%s\"\n" % (srcwan[s]['name'])
            staticconfig += "set device \"%s\"\n" % (srcwan[s]['port'])
            staticconfig += "set distance 10\n"
            staticconfig += "set priority 5\n"
            if srcwan[s]['mode'] == 'static':
                staticconfig += "set gateway \"%s\"\n" % (srcwan[s]['gateway'])
            staticconfig += "next\n"
            routenum += 1

    if hub is False:
        for n in range(len(routelist)):
            for s in range(len(srcwan)):
                for d in range(len(dstwan)):
                    if dstwan[d]['vpn'] == 'True':
                        if srcwan[s]['vpn'] == 'True':
                            staticconfig += "edit %s\n" % (routenum)
                            staticconfig += "set comment \"%s %s-%s\"\n" % (
                                routelist[n], s + 1, d + 1)
                            staticconfig += "set device \"%s%s-%s%s-P1\"\n" % (
                                srcgw['name'], s + 1, dstgw['name'], d + 1)
                            staticconfig += "set dst %s %s\n" % (
                                routes[routelist[n]][0],
                                routes[routelist[n]][1])
                            staticconfig += "set priority {}1\n".format(s + 1)
                            staticconfig += "next\n"
                            routenum += 1
        # for n in range(len(brnets)):
        #     for s in range(len(srcwan)):
        #         for d in range(len(dstwan)):
        #             if dstwan[d]['vpn'] == 'True':
        #                 if srcwan[s]['vpn'] == 'True':
        #                     print(routenum)
        #                     staticconfig += "edit %s\n" % (routenum)
        #                     staticconfig += "set comment \"%s %s-%s\"\n" \
        #                         % (brnets[n][0], s + 1, d + 1)
        #                     staticconfig += "set device \"%s%s-%s%s-P1\"\n" \
        #                         % (srcgw['name'], s + 1,
        #                            dstgw['name'], d + 1)
        #                     staticconfig += "set dst %s %s\n" \
        #                         % (brnets[n][1], brnets[n][2])
        #                     dgCur = "%s%s" % (dstgw['name'], d + 1)
        #                     dgRef = "%s%s" % (dstgw['name'], "1")
        #                     if dgCur == dgRef:
        #                         staticconfig += "set priority 10\n"
        #                     else:
        #                         staticconfig += "set priority 20\n"
        #                     # staticconfig +=
        #                     #        "set priority %s%s\n" % (d + 1, s + 1)
        #                     staticconfig += "next\n"
        #                     routenum += 1
    else:
        for b in range(len(branchlist)):
            dstgw = network['locations'][branchlist[b]]
            for i in range(len(dstgw['internal'])):
                for s in range(len(srcwan)):
                    for d in range(len(dstgw['wan'])):
                        if dstwan[d]['vpn'] == 'True':
                            if srcwan[s]['vpn'] == 'True':
                                net = netmaker(dstgw['internal'][i]['address'],
                                               dstgw['internal'][i]['netmask'])
                                staticconfig += "edit %s\n" % (routenum)
                                staticconfig += "set comment \"%s %s-%s\"\n" \
                                    % (dstgw['internal'][i]['name'],
                                       s + 1, d + 1)
                                staticconfig += "set device \"%s%s-%s%s-P1\"\n"\
                                    % (srcgw['name'], s + 1,
                                       dstgw['name'], d + 1)
                                staticconfig += "set dst %s %s\n" \
                                    % (net[0], net[1])
                                #dgCur = "%s%s" % (dstgw['name'], d + 1)
                                #dgRef = "%s%s" % (dstgw['name'], "1")
                                # if dgCur == dgRef:
                                #staticconfig += "set priority 10\n"
                                # else:
                                #staticconfig += "set priority 20\n"
                                staticconfig += "set priority %s%s\n" \
                                    % (s + 1, d + 1)
                                staticconfig += "next\n"
                                routenum += 1
    staticconfig += "end\n"
    return staticconfig


def main():
    network = json.load(open('netvpn.json'))
    hub = network['ipsec']['hub']
    locations = network['locations']

    parser = argparse.ArgumentParser()
    parser.add_argument("--branch")
    parser.add_argument("--hub", action="store_true")
    args = parser.parse_args()

    if vars(args)['branch'] is not None and vars(args)['hub'] is True:
        print(("Cannot specify --branch and --hub at the same time."
               + "\nUse --branch for branch config. \nUse --hub for hub config."))
    elif vars(args)['hub'] is True:
        location = hub
        f = open(location + '.txt', 'w')
        f.write(systemglobal(network, location) + "\n")
        f.write(systemadmin(network) + "\n")
        f.write(systemsettings(network) + "\n")
        f.write(systemswitchinterface(network, location) + "\n")
        f.write(systeminterface(network, location) + "\n")
        f.write(systemdhcpserver(network, location) + "\n")
        f.write(vpnipsec(network, location, hub=True) + "\n")
        f.write(systemzone(network, location, hub=True) + "\n")
        f.write(setvpnweight(network, location, hub=True) + "\n")
        f.write(firewalladdress(network, location) + "\n")
        f.write(firewalladdrgrp(network, location) + "\n")
        f.write(firewallpolicy(network, location) + "\n")
        f.write(routestatic(network, location, hub=True) + "\n")
        f.close()
    elif vars(args)['branch'] is not None:
        location = str(vars(args)['branch']).upper()
        keylist = sorted(locations.keys())
        try:
            keylist.index(location)
        except:
            print("Location Not Found")
        else:
            if location != network['ipsec']['hub']:
                f = open(location + '.txt', 'w')
                f.write(systemglobal(network, location) + "\n")
                f.write(systemadmin(network) + "\n")
                f.write(systemsettings(network) + "\n")
                f.write(systemswitchinterface(network, location) + "\n")
                f.write(systeminterface(network, location) + "\n")
                f.write(systemdhcpserver(network, location) + "\n")
                f.write(vpnipsec(network, location) + "\n")
                f.write(systemzone(network, location) + "\n")
                f.write(setvpnweight(network, location) + "\n")
                f.write(firewalladdress(network, location) + "\n")
                f.write(firewalladdrgrp(network, location) + "\n")
                f.write(firewallpolicy(network, location) + "\n")
                f.write(routestatic(network, location) + "\n")
                f.close()
            else:
                print("Location is the Hub, Please use the --hub option")


if __name__ == "__main__":
    main()
