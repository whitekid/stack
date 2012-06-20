Prepare machine
===============
all in one
----------
network:
 setup eth0 for management traffic
 setup eth1 for vm traffic

check you machine supports HVM with
$ egrep '(vmx|svm)' /proc/cpuinfo

HDD:
 /dev/sda for your OS
 /dev/sdb for nova-volume

separte compute
---------------
Control node:
network:
 setup eth0 for management traffic
 setup eth1 for vm traffic

HDD:
 /dev/sda for your OS
 /dev/sdb for nova-volume

Compute node:
check you machine supports HVM with
$ egrep '(vmx|svm)' /proc/cpuinfo

network:
 setup eth0 for management traffic
 setup eth1 for vm traffic

separete compute and network
----------------------------
Control node:
network:
 setup eth0 for management traffic
 setup eth1 for vm traffic

HDD:
 /dev/sda for your OS
 /dev/sdb for nova-volume

Compute node:
check you machine supports HVM with
$ egrep '(vmx|svm)' /proc/cpuinfo

network:
 setup eth0 for management traffic
 setup eth1 for vm traffic

Network node:
network:
 setup eth0 for management traffic
 setup eth1 for vm traffic

Configuration
=============
$ cp stack2.conf.sample stack2.conf
$ vi stack2.conf
 - edit roles your machines mac addr, and roles
 - edit network.control_ip as your control ip
 - edit volume.dev as your block device to use nova-volume


Installation
============
Just run stack2.py. It install packages and setup as your configured role.

$ python stack2.py

If you want clean up installation

$ python stack2.py setup
$ apt-get purge -y nova-common && apt-get -y autoremove
$ iptables -F && iptables -F -t nat

