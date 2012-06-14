#!/usr/bin/python
# -*- coding: utf8 -*-
"""
OpenStack Installer stack2

Overview
========

Design
======

Physical Machine
----------------
OpenStack을 설치하기 위해서 데스크탑에 VMWare Workstation을 설치하고 가상머신 2대를 설치하여 각각 control node, compute node로 사용한다.

- Host OS: Ubutu 12.04 64bit desktop
- VMWare Network Setup
  * vmnet2: 10.200.1.0/24 for management network
  * vmnet3: 10.200.2.0/24 for private network

- openstack-control:
  * 설치할 구성 요소: database, dashboard, nova(except compute), glance, swift(not done)
  * Memory: 1G
  * HDD: 500G x 2 (하나는 OS, 나머지 하나는 nova-volume에서 사용함)
  * Network:
    * vmnet2/ eth0/ 10.200.1.10 : 관리용
    * vmnet3/ eth1/ <none>      : nova-network이 사용할 것으로 br100에 private networ의 gateway가 자동으로 설정될 것

- openstack-node:
  * enable "Virtualize intel VT-x/EPT or AMD-V/RVI" option
  * 설치할 구성 요소: nova-compute
  * Memory: 4G
  * HDD: 500G (그냥 우선 대충 충분히 많게)
  * Network:
    * vmnet2/ eth0/ 10.200.1.20 : 관리용
    * vmnet3/ eth1/ <none>      : nova-network이 사용할 것으로 br100에 private networ의 gateway가 자동으로 설정될 것
    * create bridge br100 with eth1

Virtual Environment
-------------------
 * hypervisor: kvm(OpenStack의 기본 hypervisor)

미리 설정할 것
-------------
VMWare는 기본적으로 vmnet이 promiscuous 모드로 동작하지 않도록 되있다. 아래처럼 promiscuous

$ sudo chgrp `whoami` /dev/vmnet*
$ sudo chmod g+rw `whoami` /dev/vmnet*

NAT 설정
$ sudo sysctl net.ipv4.ip_forward=0
$ sudo iptables -A POSTROUTING -t nat -j MASQUERADE

TODO
======
 * 생성된 인스턴스에서 외부로 트래픽이 나가지 않는 문제
   - nova-network이 설치된 호스트까지 traffic이 나가는 것은 확인
   - 아마도 nova-network에서 iptables에서 수정해야 할 것 같음

* keypair로 접속하도록 설정하기

Troubleshooting
===============

nova-compute에서 instance를 만들는데 에러가 나는 경우
-----------------------------------------------------
/var/log/nova/nova-compute.log에 "Instance already created" 와 같은 에러가 나면
nova-scheduler에서 사용하는 amqp(rabbitmq)의 캐쉬 문제일 가능성이 있다. 재시작하고 다시 시도한다.
"""
import os, sys
import subprocess
import json
import time
import inspect

class Config:
	# 모든 암호는 아래로 설정된다.
	passwd = 'choe'
	region = 'region0'
	private_net = '10.200.2.0/24'
	private_net_size = 254	# ip address의 갯수
	private_gw = '10.200.2.1'
	private_dns1 = '168.126.63.1'
	private_dhcp_start = '10.200.2.10'
	bridge = 'br100'
	bridge_iface = 'eth1'

	def __init__(self):
		import ConfigParser

		self._config = ConfigParser.SafeConfigParser()
		self._config.read(os.path.dirname(sys.argv[0]) + '/stack2.conf')

	def get(self, section, key):
		return self._config.get(section, key)


def get_ip(iface = None):
	if iface == None: iface = 'eth0'
	return subprocess.check_output("ifconfig %s | grep 'inet addr' | cut -d: -f 2 | awk '{print $1}'" % iface, shell=True).strip()

def get_mac(iface = None):
	if iface == None: iface = 'eth0'
	return subprocess.check_output("ifconfig %s | grep HWaddr | awk '{print $5}'" % iface, shell=True).strip()

def get_hostname():
	return subprocess.check_output('hostname').strip()


def shell(command):
	print command
	return subprocess.check_call(command, shell=True)

def try_shell(command):
	try:
		return shell(command)
	except:
		return 999

def output(command):
	print command
	try:
		return subprocess.check_output(command, shell=True)
	except:
		return ''
	
def pkg_installed(pkg):
	try:
		return output("dpkg -l  | grep '%s ' | grep -c ^ii" % pkg).strip() == '1'
	except:
		return False

def pkg_remove(pkg):
	return shell("apt-get purge -y %s" % pkg)

def pkg_install(pkg):
	os.environ['DEBIAN_FRONTEND'] = 'noninteractive'
	try:
		shell("apt-get install -q -y %s" % pkg)
	finally:
		del os.environ['DEBIAN_FRONTEND']

class Installer(object):
	role = None

	def run(self):
		self._setup()
		self._run()
		self._teardown()

	def setup(self): self._setup()

	def _setup(self): pass
	def _run(self): pass
	def _teardown(self): pass


	class File:
		def __init__(self, parent, filename):
			self.parent = parent
			self.filename = filename

		def replace(self, orig, rep):
			shell("sed -i 's/%s/%s/g' %s" % (orig, rep, self.filename))
			return self

		def append(self, line):
			open(self.filename, 'a+').write(line + '\n')
			return self

	def replace(self, filename, org, rep):
		self.file(filename).replace(org, rep)

	def append(self, filename, app):
		self.file(filename).append(app)

	def file(self, filename):
		return self.File(self, filename)


class Runner:
	def __init__(self, context):
		self._installer = []
		self._context = context

	def append(self, installer):
		installer.context = self._context
		self._installer.append(installer)
		return self

	def run(self, what_to_run=None):
		for installer in self._installer:
			if what_to_run == 'setup':
				installer.setup()
			else:
				installer.run()

class OsInstaller(Installer):
	role = 'os'

	def _setup(self):
		pkg_remove('ntp')

	def _run(self):
		pkg_install('ntp')


class DatabaseInstaller(Installer):
	role = 'db'

	def _setup(self):
		pkg_remove('mysql-common')
		shell('rm -rf /var/lib/mysql')
		
	def _run(self):
		shell("'mysql-server-5.5 mysql-server/root_password password %s' | debconf-set-selections" % self.context.passwd)
		shell("'mysql-server-5.5 mysql-server/root_password_again password %s' | debconf-set-selections" % self.context.passwd)

		pkg_install('mysql-server')
		pkg_install('python-mysqldb')

		shell("sed -i 's/127.0.0.1/0.0.0.0/g' /etc/mysql/my.cnf")
		shell("service mysql restart")

		shell("""mysql -uroot -e "SET PASSWORD=PASSWORD('%s')" """ % self.context.passwd)
		self.create_db('nova', 'nova')
		self.create_db('glance', 'glance')
		self.create_db('keystone', 'keystone')

	def create_db(self, dbname, user):
		passwd = self.context.passwd
		hostname = get_hostname()

		shell("""mysql -uroot -p%(passwd)s -e "create database %(dbname)s;" """ % locals())
		shell("""mysql -uroot -p%(passwd)s -e "grant all on %(dbname)s.* to %(user)s identified by '%(passwd)s';" """ % locals())
		shell("""mysql -uroot -p%(passwd)s -e "grant all on %(dbname)s.* to %(user)s@localhost identified by '%(passwd)s';" """ % locals())
		shell("""mysql -uroot -p%(passwd)s -e "grant all on %(dbname)s.* to %(user)s@'%(hostname)s' identified by '%(passwd)s';" """ % locals())

class KeystoneInstaller(Installer):
	role = 'keystone'

	def _setup(self):
		pkg_remove("keystone")
		shell('rm -rf /var/lib/keystone')

		try: del os.environ['SERVICE_ENDPOINT']
		except: pass
		try: del os.environ['SERVICE_TOKEN']
		except: pass

	def _run(self):
		pkg_install("keystone")
		self.replace('/etc/keystone/keystone.conf', 'admin_token = ADMIN', 'admin_token = %s' % self.context.passwd)
		self.replace('/etc/keystone/keystone.conf',
			r'connection = sqlite:\/\/\/\/var\/lib\/keystone\/keystone.db', 
			r'connection = mysql:\/\/keystone:%s@localhost\/keystone' % self.context.passwd)
		shell('restart keystone')
		shell('keystone-manage db_sync')

		os.environ['SERVICE_ENDPOINT'] = 'http://localhost:35357/v2.0'
		os.environ['SERVICE_TOKEN'] = self.context.passwd

		shell('keystone tenant-create --name admin --description "Default Tenant"')
		shell('keystone tenant-create --name service --description "Service Tenant"')

		# TODO: tenant_id가 없어도 별 상관 없는 듯..
		shell('keystone user-create --name admin --pass %s' % self.context.passwd)
		shell('keystone user-create --name nova --pass %s' % self.context.passwd)
		shell('keystone user-create --name glance --pass %s' % self.context.passwd)
		shell('keystone user-create --name swift --pass %s' % self.context.passwd)

		shell('keystone role-create --name admin')
		shell('keystone role-create --name member')

		# http://docs.openstack.org/essex/openstack-compute/starter/content/Adding_Roles_to_Users-d1e465.html
		# TODO: 뭔가... 어떤 user가 어떤 tenant의 어떤 role을 가져야하는지 명확하지 않음...
		shell('keystone user-role-add --user %s --role %s --tenant_id=%s' % (self.get_user_id('admin'), self.get_role_id('admin'), self.get_tenant_id('admin')))
		shell('keystone user-role-add --user %s --role %s --tenant_id=%s' % (self.get_user_id('admin'), self.get_role_id('member'), self.get_tenant_id('admin')))
		shell('keystone user-role-add --user %s --role %s --tenant_id=%s' % (self.get_user_id('nova'), self.get_role_id('admin'), self.get_tenant_id('service')))
		shell('keystone user-role-add --user %s --role %s --tenant_id=%s' % (self.get_user_id('glance'), self.get_role_id('admin'), self.get_tenant_id('service')))
		shell('keystone user-role-add --user %s --role %s --tenant_id=%s' % (self.get_user_id('swift'), self.get_role_id('admin'), self.get_tenant_id('service')))

		shell('keystone user-role-add --user %s --role %s --tenant_id=%s' % (self.get_user_id('swift'), self.get_role_id('member'), self.get_tenant_id('admin')))

		# create service
		shell("keystone service-create --name nova --type compute --description 'OpenStack Compute Service'")
		shell("keystone service-create --name volume --type volume --description 'OpenStack Volume Service'")
		shell("keystone service-create --name glance --type image --description 'OpenStack Image Service'")
		shell("keystone service-create --name swift --type object-store --description 'OpenStack Storage Service'")
		shell("keystone service-create --name keystone --type identity --description 'OpenStack Identity Service'")
		shell("keystone service-create --name ec2 --type ec2 --description 'EC2 Service'")

		# endpoints
		# TODO: 여기 $(tenant_id)s가 다른 곳에서는 %(tenant_id)s인데.. 이거 python 문법 아닌가?
		def endpoint_create(service_name, publicurl, adminurl, internalurl):
			region = self.context.region
			service_id = self.get_service_id(service_name)
			publicurl = publicurl % {'ip': self.context.get('network', 'control_ip')}
			adminurl = adminurl % {'ip': self.context.get('network', 'control_ip')}
			internalurl = internalurl % {'ip': self.context.get('network', 'control_ip')}

			shell(
				"keystone endpoint-create --region %(region)s --service_id %(service_id)s "
				"--publicurl '%(publicurl)s' --adminurl '%(adminurl)s' --internalurl '%(internalurl)s'" % locals())

		endpoint_create('nova', 'http://%(ip)s:8774/v2/%%(tenant_id)s', 'http://%(ip)s:8774/v2/%%(tenant_id)s', 'http://%(ip)s:8774/v2/%%(tenant_id)s')
		endpoint_create('volume', 'http://%(ip)s:8776/v1/%%(tenant_id)s', 'http://%(ip)s:8776/v1/%%(tenant_id)s', 'http://%(ip)s:8776/v1/%%(tenant_id)s')
		endpoint_create('glance', 'http://%(ip)s:9292/v1', 'http://%(ip)s:9292/v1', 'http://%(ip)s:9292/v1')
		endpoint_create('swift', 'http://%(ip)s:8080/v1/AUTH_%%(tenant_id)s', 'http://%(ip)s:8080/v1', 'http://%(ip)s:8080/v1/AUTH_%%(tenant_id)s')
		endpoint_create('keystone', 'http://%(ip)s:5000/v2.0', 'http://%(ip)s:35357/v2.0', 'http://%(ip)s:5000/v2.0')
		endpoint_create('ec2', 'http://%(ip)s:8773/services/Cloud',  'http://%(ip)s:8773/services/Admin', 'http://%(ip)s:8773/services/Cloud')

	def get_user_id(self, name): return self.get_keystone_id('user', name)
	def get_role_id(self, name): return self.get_keystone_id('role', name)
	def get_tenant_id(self, name): return self.get_keystone_id('tenant', name)
	def get_service_id(self, name): return self.get_keystone_id('service', name)

	def get_keystone_id(self, service, name):
		return output("keystone %s-list | grep ' %s ' | awk '{print $2}'" % (service, name)).strip()
	

class GlanceInstaller(Installer):
	role = 'glance'

	def _setup(self):
		pkg_remove('glance-common')
		shell('rm -rf /var/lib/glance*')

		#del os.environ['SERVICE_TOKEN']
		#del os.environ['OS_TENANT_NAME']
		#del os.environ['OS_USERNAME']
		#del os.environ['OS_PASSWORD']
		#del os.environ['OS_AUTH_URL']
		#del os.environ['SERVICE_ENDPOINT']

	def _run(self):
		pkg_install('glance')
		self.file('/etc/glance/glance-api-paste.ini').replace(
			'%SERVICE_TENANT_NAME%', 'service').replace(
			'%SERVICE_USER%', 'glance').replace(
			'%SERVICE_PASSWORD%', self.context.passwd).replace(
			'pipeline = versionnegotiation context apiv1app', 'pipeline = versionnegotiation autotoken context apiv1app')	#  TODO: 이 항목 없음..

		self.file('/etc/glance/glance-registry-paste.ini').replace(
			'%SERVICE_TENANT_NAME%', 'service').replace(
			'%SERVICE_USER%', 'glance').replace(
			'%SERVICE_PASSWORD%', self.context.passwd).replace(
			'pipeline = context registryapp', 'pipeline = authtoken auth-context context registryapp')	# TODO: 이 항목 없음...

		self.file('/etc/glance/glance-registry.conf').replace(
			r'connection = sqlite:\/\/\/\/var\/lib\/glance\/glance.sqlite', 
			r'connection = mysql:\/\/glance:%s@localhost\/glance' % self.context.passwd)
		self.file('/etc/glance/glance-registry.conf').append('').append(
			'[paste_deploy]').append(
			'flavor = keystone')

		self.file('/etc/glance/glance-api.conf').append('').append(
			'[paste_deploy]').append(
			'flavor = keystone')

		shell('glance-manage version_control 0')
		shell('glance-manage db_sync')

		shell('restart glance-api')
		shell('restart glance-registry')
		time.sleep(0.5)	#  완전히 startup하기까지 조금 기다려야...

		os.environ['SERVICE_TOKEN'] = self.context.passwd
		os.environ['OS_TENANT_NAME'] = 'admin'
		os.environ['OS_USERNAME'] = 'admin'
		os.environ['OS_PASSWORD'] = self.context.passwd
		os.environ['OS_AUTH_URL'] = "http://localhost:5000/v2.0/"
		os.environ['SERVICE_ENDPOINT'] = 'http://localhost:35357/v2.0'

		shell('glance index')
		#shell('glance --os_username=admin --os_password=choe --os_tenant=admin --os_auth_url=http://localhost:5000/v2.0 index')


class NovaBaseInstaller(Installer):
	def _setup_nova_config(self):
		f = self.file('/etc/nova/nova.conf')
		#f.append('--dhcpbridge_flagfile=/etc/nova/nova.conf')
		#f.append('--dhcpbridge=/usr/bin/nova-dhcpbridge')
		#f.append('--logdir=/var/log/nova')
		#f.append('--state_path=/var/lib/nova')
		#f.append('--lock_path=/run/lock/nova')
		f.append('--allow_admin_api=true')
		f.append('--use_deprecated_auth=false')
		f.append('--auth_strategy=keystone')
		f.append('--scheduler_driver=nova.scheduler.simple.SimpleScheduler')
		f.append('--s3_host=%s' % self.context.get('network', 'control_ip'))
		f.append('--ec2_host=%s' % self.context.get('network', 'control_ip'))
		f.append('--rabbit_host=%s' % self.context.get('network', 'control_ip'))
		f.append('--cc_host=%s' % self.context.get('network', 'control_ip'))
		f.append('--nova_url=http://%s:8774/v1.1/' % self.context.get('network', 'control_ip'))
		f.append('--routing_source_ip=%s' % self.context.get('network', 'control_ip'))
		f.append('--glance_api_servers=%s:9292' % self.context.get('network', 'control_ip'))
		f.append('--image_service=nova.image.glance.GlanceImageService')
		f.append('--iscsi_ip_prefix=192.168.4')
		f.append('--sql_connection=mysql://nova:%s@%s/nova' % (self.context.passwd, self.context.get('network', 'control_ip')))
		f.append('--ec2_url=http://%s:8773/services/Cloud' % self.context.get('network', 'control_ip'))
		f.append('--keystone_ec2_url=http://%s:5000/v2.0/ec2tokens' % self.context.get('network', 'control_ip'))
		f.append('--api_paste_config=/etc/nova/api-paste.ini')
		f.append('--libvirt_type=kvm')
		#f.append('--libvirt_use_virtio_for_bridges=true')
		f.append('--start_guests_on_host_boot=true')
		f.append('--resume_guests_state_on_host_boot=true')
		# vnc specific configuration
		f.append('--novnc_enabled=true')
		f.append('--novncproxy_base_url=http://%s:6080/vnc_auto.html' % self.context.get('network', 'control_ip'))
		f.append('--vncserver_proxyclient_address=%s' % self.context.get('network', 'control_ip'))
		f.append('--vncserver_listen=%s' % get_ip('eth0'))
		# network specific settings
		f.append('--network_manager=nova.network.manager.FlatDHCPManager')
		f.append('--public_interface=eth0')
		f.append('--flat_interface=%s' % self.context.get('network', 'bridge_iface'))
		f.append('--flat_network_bridge=%s' % self.context.get('network', 'bridge'))
		f.append('--fixed_range=%s' % self.context.private_net)
		#f.append('--floating_range=10.200.3.0/24')		# TODO: public ip range인데 아직은 고려하지 않음
		f.append('--network_size=%s' % self.context.private_net_size)				# TODO: hmm...
		f.append('--flat_network_dhcp_start=%s' % self.context.private_dhcp_start)	# TODO: hmm...
		f.append('--flat_injected=False')
		#f.append('--force_dhcp_release')
		#f.append('--iscsi_helper=tgtadm')
		#f.append('--connection_type=libvirt')
		#f.append('--root_helper=sudo nova-rootwrap')
		#f.append('--verbose')

		shell('chown -R nova:nova /etc/nova')
		shell('chmod 644 /etc/nova/nova.conf')


class NovaControllerInstaller(NovaBaseInstaller):
	"""controller installation"""
	role = 'controller'

	def _setup(self):
		pkg_remove('nova-common')
		# volume depends
		pkg_remove('tgt')
		pkg_remove('apache2.2-common')
		pkg_remove('memcached')
		try_shell('service memcached restart')	# openstack-dashboard에서 사용하는데.. 캐쉬 문제로 에러가 발생하는 경우가 있음
		try_shell('service rabbitmq-server restart')
		try_shell('killall -9 dnsmasq')
		try_shell('killall -9 kvm')
		pkg_remove('dnsmasq-base')
		pkg_remove('openstack-dashboard')

		try_shell('service tgt stop')

		try_shell('vgremove -f nova-volumes')
		shell('pvremove -ff -y %s' % self.context.get('volume', 'dev'))
		shell('rm -rf /var/lib/nova')

		shell('sysctl net.ipv4.ip_forward=0')

	
	def _run(self):
		pkg_install('nova-api nova-cert nova-doc nova-network nova-objectstore nova-scheduler nova-volume rabbitmq-server novnc nova-consoleauth')

		self._setup_nova_config()

		# nova-volumes 이름을 가진 lvm volume group이 있어야한다.
		shell('pvcreate %s' % self.context.get('volume', 'dev'))
		shell('vgcreate nova-volumes %s' % self.context.get('volume', 'dev'))

		shell('chown -R nova:nova /etc/nova')
		shell('chmod 644 /etc/nova/nova.conf')

		self.file('/etc/nova/api-paste.ini').replace(
			'%SERVICE_TENANT_NAME%', 'service').replace(
			'%SERVICE_USER%', 'nova').replace(
			'%SERVICE_PASSWORD%', self.context.passwd)

		shell('nova-manage db sync')

		# TODO: 여기 정확한 아키텍처 파악 필요
		# dnsmasq가 아래처럼 동작하고 있다>
		# /usr/sbin/dnsmasq --strict-order --bind-interfaces --conf-file= --domain=novalocal --pid-file=/var/lib/nova/networks/nova-br100.pid --listen-address=10.200.2.1 --except-interface=lo --dhcp-range=10.200.2.2,static,120s --dhcp-lease-max=32 --dhcp-hostsfile=/var/lib/nova/networks/nova-br100.conf --dhcp-script=/usr/bin/nova-dhcpbridge --leasefile-ro
		# TODO: private : label
		# TODO: 소스를 보자 https://github.com/openstack/nova/blob/master/bin/nova-manage
		# TODO: DHCP Server가 10.200.2.1로 들어가고 있음. compute-nod의 /var/lib/nova/instances/instance-00000002/libvirt.xml 를 확인...
		#shell('nova-manage network create private --fixed_range_v4=%s --num_networks=1 --bridge=%s --bridge_interface=%s --network_size=%s --dns1 %s --gateway %s' %
		#	(self.context.private_net, self.context.bridge, self.context.bridge_iface, self.context.private_net_size, self.context.private_dns1, self.context.private_gw))
		shell(
			'nova-manage network create private --fixed_range_v4=%s --num_networks=1 '
			'--bridge=%s --bridge_interface=%s --network_size=%s' %
			(self.context.private_net, self.context.get('network', 'bridge'),
			 self.context.get('network', 'bridge_iface'), self.context.private_net_size))

		# 이전과 비슷
		#export OS_TENANT_NAME=admin
		#export OS_USERNAME=admin
		#export OS_PASSWORD=admin
		#export OS_AUTH_URL="http://localhost:5000/v2.0/"

		shell("service tgt restart")
		shell("service nova-network restart")
		shell("service nova-api restart")
		shell("service nova-objectstore restart")
		shell("service nova-scheduler restart")
		shell("service nova-volume restart")
		shell("service nova-consoleauth restart")

		pkg_install('openstack-dashboard')
		shell('service apache2 restart')

		shell('sysctl net.ipv4.ip_forward=1')


class NovaComputeInstaller(NovaBaseInstaller):
	role = 'compute'

	def _setup(self):
		if output("egrep -c '(vmx|svm)' /proc/cpuinfo").strip() == '0':
			raise Exception, 'CPU hardware virtualization not enabled'

		# compute depends
		pkg_remove('nova-compute qemu-common libvirt0 open-iscsi')
		if output('brctl show | grep -c %s' % self.context.get('network', 'bridge')).strip() == '0':
			shell('brctl addbr %s' % self.context.get('network', 'bridge'))
			shell('brctl addif %s %s' % (self.context.get('network', 'bridge'), self.context.get('network', 'bridge_iface')))

	def _run(self):
		# nova-compute의 depens
		# cgroup-lite cpu-checker dmidecode ebtables kpartx kvm kvm-ipxe libaio1 libapparmor1 libasound2 libasyncns0 libavahi-client3 libavahi-common-data libavahi-common3 libcaca0
		# libflac8 libjson0 libnspr4 libnss3 libnuma1 libogg0 libpulse0 librados2 librbd1 libsdl1.2debian libsndfile1 libvirt-bin libvirt0 libvorbis0a libvorbisenc2 libxenstore3.0
		# libxml2-utils libyajl1 msr-tools nova-compute-kvm open-iscsi open-iscsi-utils python-libvirt qemu-common qemu-kvm qemu-utils seabios vgabios

		pkg_install('nova-compute')
		pkg_install('python-mysqldb')
		shell('kvm-ok')
		pkg_remove('dmidecode')	# 이 패키지가 설치되면 kvm이 서비스가 정상작동하지 않음, 아마 ubuntu vm의 문제일 듯..
		shell('service libvirt-bin restart')

		pkg_install('ntp')

		self._setup_nova_config()

		shell('service open-iscsi restart')
		shell('service nova-compute restart')
		shell('nova-manage service list')


class SwiftInstaller(Installer):
	role = 'swift'

	def _setup(self):
		pkg_remove('swift swift-proxy swift-account swift-container swift-object')
		pkg_remove('xfsprogs')

		self.dev = self.context.get('swift', 'dev')
		self.mount = self.context.get('swift', 'mount')
		try_shell('umount %s' % self.mount)
	
	def _run(self):
		pkg_install('swift swift-proxy swift-account swift-container swift-object')
		pkg_install('xfsprogs')
		pkg_install('curl python-pastedeploy')

		mount_opt = ''
		if not self.dev.startswith('/dev/'):
			shell('truncate --size=%s %s' % (self.context.get('swift', 'loopback_size'), self.dev))
			mount_opt = '-o loop'

		shell('mkfs.xfs -f %s' % self.dev)
		shell('mkdir -p %s' % self.context.get('swift', 'mount'))
		# /dev/sdb3 /mnt/swift_backend xfs noatime,nodiratime,nobarrier,logbufs=8 0 0

		shell('mount %s %s %s' % (mount_opt, self.dev, self.mount))
		for i in range(1,5):
			shell('mkdir %s/node%s' % (self.mount, i))
			shell('chown -R swift.swift %s/node%s' % (self.mount, i))

class PrepareImageInstaller(Installer):
	role = 'prepare-image'

	def _run(self):
		# Create glance image
		#
		# 
		# $ wget http://ftp.daum.net/ubuntu-releases/12.04/ubuntu-12.04-server-amd64.iso
		# $ kvm-img create -f qcow2 server.qcow2 5G
		# $ sudo kvm -m 256 -cdrom ubuntu-12.04-server-amd64.iso -drive file=server.qcow2,if=virtio,index=0 -boot d -net nic -net user -nographic  -vnc :0
		# install ubuntu sever using gvncviewr <ip>:0
		# this installed image placed at http://192.168.100.108/isos/server.qcow2
		# $ glance --os_username=admin --os_password=choe --os_tenant=admin --os_auth_url=http://10.200.1.10:5000/v2.0 add name="Ubuntu 12.04 Server 64" is_public=true container_format=ovf disk_format=qcow2 < server.qcow2
		image = 'ubuntu-12.04.qcow2'
		if not os.path.exists(image):
			shell('wget -O %s http://192.168.100.108/isos/server.qcow2' % image)

		shell('glance --os_username=admin --os_password=choe --os_tenant=admin '
			  '--os_auth_url=http://10.200.1.10:5000/v2.0 add name="Ubuntu 12.04 Server 64" '
			  'is_public=true container_format=ovf disk_format=qcow2 < %s' % image)


class PrepareInstanceInstaller(Installer):
	role = 'prepare-instance'

	def _setup(self):
		try_shell('nova-manage flavor delete --name choe.test.small')
		try_shell('killall kvm')

	def _nova_cmd(self):
		return \
			'nova --os_username admin --os_password %s --os_tenant_name admin ' \
			'--os_auth_url=http://%s:35357/v2.0' % (self.context.passwd, self.context.get('network', 'control_ip'))

	def _nova(self, *args): return shell('%s %s' % (self._nova_cmd(), ' '.join(args)))

	def _run(self):
		# 테스트용 가상머신 생성
		flavor = 9999
		shell('nova-manage flavor create --name choe.test.small --memory=512 --cpu=1 --root_gb=5 --ephemeral_gb=100 --flavor %s' % flavor)
		shell('nova-manage service list')

		def get_image(): return output("%s image-list| grep ACTIVE | awk '{print $2}'" % (self._nova_cmd())).strip()

		self._nova('image-list')
		try: self._nova('keypair-delete test')
		except: pass
		self._nova('keypair-add test > test.pem')
		self._nova('boot --flavor %s --image %s test' % (flavor, get_image()))
		self._nova('list')

def get_classes(module):
	for name, obj in inspect.getmembers(module):
		if inspect.isclass(obj):
			yield name, obj

	
def main():
	if os.getuid() != 0: raise Exception, 'root required'

	config = Config()

	# build installer
	klasses = { }
	for name, klass in get_classes(sys.modules[__name__]):
		if issubclass(klass, Installer):
			if klass.role: klasses[klass.role] = klass

	# build runner
	runner = Runner(config)
	for role in config.get('roles', get_mac().replace(':','')).split(', '):
		try:
			runner.append(klasses[role]())
		except IndexError, e:
			raise Exception, 'Undefined role: %s' % role
		
	if len(sys.argv) == 2: what_to_run = sys.argv[1]
	else: what_to_run = None

	runner.run(what_to_run)


main()

# vim: aw ai nu
