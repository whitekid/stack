#!/bin/bash
python stack2.py cleanup && \
apt-get -y purge nova-common && \
apt-get -y autoremove 
killall -9 dnsmasq kvm
rm -rf /var/lib/nova
rm -rf /var/lock/nova
rm -rf /var/log/nova
rm -rf /var/log/openvswitch

for table in filter nat mangle raw security ; do
	iptables -t $table -F
	iptables -t $table -X
done

for chain in INPUT FORWARD OUTPUT ; do
	iptables -P $chain ACCEPT
done
