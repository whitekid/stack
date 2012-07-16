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
  * vmnet3: 10.200.2.0/24 for guest network

- openstack-control:
  * 설치할 구성 요소: database, dashboard, nova(without compute, network), glance, swift(not done)
  * Memory: 1G
  * HDD:
  	/dev/sda(500G) used by OS
	/dev/sdb(500G) used as volume service. see volume.dev configuration

  * Network:
    * vmnet2/ eth0/ 10.200.1.10 : 관리용, see network.control_ip configuration
    * vmnet3/ eth1/ <none>      : nova-network이 사용할 것으로 br100에 guest network의 gateway가 자동으로 설정될 것

- openstack-node:
  * enable "Virtualize intel VT-x/EPT or AMD-V/RVI" option
  * 설치할 구성 요소: nova-compute
  * Memory: 4G
  * HDD: 500G (그냥 우선 대충 충분히 많게)
  * Network:
    * vmnet2/ eth0/ 10.200.1.20 : 관리용
    * vmnet3/ eth1/ <none>
    * create bridge br100 with eth1

- openstack-network
 * packages: nova-network
 * Memory: 1G
 * HDD: as you want
 * Network:
    * vmnet2/ eth0/ 10.200.1.9 : 관리용 IP, currently we have no public traffic network. so VM traffice are SNATed by this IP.
    * vmnet3/ eth1/ <none>      : nova-network이 사용할 것으로 br100에 guest network의 gateway ip로 자동으로 설정될 것
    * create bridge br100 with eth1

Virtual Environment
-------------------
 * hypervisor: kvm(OpenStack의 기본 hypervisor)

미리 설정할 것
-------------
VMWare는 기본적으로 vmnet이 promiscuous 모드로 동작하지 않도록 되있다. 아래처럼 promiscuous로 설정
see http://kb.vmware.com/selfservice/microsites/search.do?language=en_US&cmd=displayKC&externalId=287

$ sudo chgrp `whoami` /dev/vmnet*
$ sudo chmod g+rw `whoami` /dev/vmnet*

NAT 설정
$ sudo sysctl net.ipv4.ip_forward=1
$ sudo iptables -A POSTROUTING -t nat -j MASQUERADE

Configuration
=============
First you must edit stack2.conf file

see carefully below items
 * roles
 * control_ip

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
nova-scheduler에서 사용하는 amqp(rtgt tgtabbitmq)의 캐쉬 문제일 가능성이 있다. 재시작하고 다시 시도한다.

dashboard를 접속하는데 Internal Server Error
--------------------------------------------
이것은 django의 문제로, 로그에 보면 cross site scriptig을 차단하는 라이브러리 오류라고 나온다.
django를 재설치하면 해결된다.
$ apt-get purge -y python-django && apt-get install -y openstack-dashboard
"""
import os, sys
import subprocess
import json
import time
import inspect
import ConfigParser

class Config:
	def __init__(self):
		self._config = ConfigParser.SafeConfigParser()
		self._config.read(os.path.join(os.path.dirname(sys.argv[0]), 'stack2.conf'))

	def _get(self, section, key):
		return self._config.get(section, key)

	def __getitem__(self, key):
		return self.get(key)

	def get(self, key, default=None):
		key, value = key.split('.')
		return self._get(key, value)

def get_ip(iface = None):
	if iface == None: iface = 'eth0'
	return subprocess.check_output("ifconfig %s | grep 'inet addr' | cut -d: -f 2 | awk '{print $1}'" % iface, shell=True).strip()

def get_mac(iface = None):
	if iface == None: iface = 'eth0'
	return subprocess.check_output("ifconfig %s | grep HWaddr | awk '{print $5}'" % iface, shell=True).strip().replace(':','')

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

	def setup(self):
		self._cleanup()
		self._setup()

	def cleanup(self):
		self._cleanup()

	def _cleanup(self):
		pass

	def _setup(self): pass

	class File:
		def __init__(self, parent, filename):
			self.parent = parent
			self.filename = filename

		def __enter__(self): return self
		def __exit__(self, type, value, traceback): pass

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

	def _get_with_quantum(self): return bool(self.context['network.with_quantum'].lower() == 'true')
	with_quantum = property(_get_with_quantum)


class Runner:
	def __init__(self, context):
		self._installer = []
		self._context = context

	def append(self, installer):
		installer.context = self._context
		self._installer.append(installer)
		return self

	def setup(self, what_to_run=None):
		if not what_to_run: what_to_run = 'setup'

		for installer in self._installer:
			func = getattr(installer, what_to_run)
			func()
			#if what_to_run == 'cleanup':
				#installer.cleanup()
			#else:
				#installer.setup()

class OsInstaller(Installer):
	role = 'os'

	def _cleanup(self):
		pkg_remove('ntp')

	def _setup(self):
		pkg_install('ntp')


class DatabaseInstaller(Installer):
	role = 'db'

	def _cleanup(self):
		pkg_remove('mysql-common')
		shell('rm -rf /var/lib/mysql')
		
	def _setup(self):
		shell("'mysql-server-5.5 mysql-server/root_password password %s' | debconf-set-selections" % self.context['global.passwd'])
		shell("'mysql-server-5.5 mysql-server/root_password_again password %s' | debconf-set-selections" % self.context['global.passwd'])

		pkg_install('mysql-server')
		pkg_install('python-mysqldb')

		shell("sed -i 's/127.0.0.1/0.0.0.0/g' /etc/mysql/my.cnf")
		shell("service mysql restart")

		shell("""mysql -uroot -e "SET PASSWORD=PASSWORD('%s')" """ % self.context['global.passwd'])
		self.create_db('nova', 'nova')
		self.create_db('glance', 'glance')
		self.create_db('keystone', 'keystone')
		if self.with_quantum: self.create_db('ovs_quantum', 'ovs_quantum')

	def create_db(self, dbname, user):
		passwd = self.context['global.passwd']
		hostname = get_hostname()

		shell("""mysql -uroot -p%(passwd)s -e "create database %(dbname)s;" """ % locals())
		shell("""mysql -uroot -p%(passwd)s -e "grant all on %(dbname)s.* to %(user)s identified by '%(passwd)s';" """ % locals())
		shell("""mysql -uroot -p%(passwd)s -e "grant all on %(dbname)s.* to %(user)s@localhost identified by '%(passwd)s';" """ % locals())
		shell("""mysql -uroot -p%(passwd)s -e "grant all on %(dbname)s.* to %(user)s@'%(hostname)s' identified by '%(passwd)s';" """ % locals())

class KeystoneInstaller(Installer):
	role = 'keystone'

	def _cleanup(self):
		pkg_remove("keystone")
		shell('rm -rf /var/lib/keystone')

		try: del os.environ['SERVICE_ENDPOINT']
		except: pass
		try: del os.environ['SERVICE_TOKEN']
		except: pass

	def _setup(self):
		pkg_install("keystone")
		self.replace('/etc/keystone/keystone.conf', 'admin_token = ADMIN', 'admin_token = %s' % self.context['global.passwd'])
		self.replace('/etc/keystone/keystone.conf',
			r'connection = sqlite:\/\/\/\/var\/lib\/keystone\/keystone.db', 
			r'connection = mysql:\/\/keystone:%s@localhost\/keystone' % self.context['global.passwd'])
		shell('restart keystone')
		shell('keystone-manage db_sync')

		os.environ['SERVICE_ENDPOINT'] = 'http://localhost:35357/v2.0'
		os.environ['SERVICE_TOKEN'] = self.context['global.passwd']

		shell('keystone tenant-create --name admin --description "Default Tenant"')
		shell('keystone tenant-create --name service --description "Service Tenant"')
		# create additional tenants
		for tenant in self.context['global.tenants'].split(', '):
			if tenant: shell('keystone tenant-create --name %s --description "Tenant %s"' % (tenant, tenant))

		# TODO: tenant_id가 없어도 별 상관 없는 듯..
		shell('keystone user-create --name admin --pass %s' % self.context['global.passwd'])
		shell('keystone user-create --name nova --pass %s' % self.context['global.passwd'])
		shell('keystone user-create --name glance --pass %s' % self.context['global.passwd'])
		shell('keystone user-create --name swift --pass %s' % self.context['global.passwd'])

		shell('keystone role-create --name admin')
		shell('keystone role-create --name member')

		# http://docs.openstack.org/essex/openstack-compute/starter/content/Adding_Roles_to_Users-d1e465.html
		# TODO: 뭔가... 어떤 user가 어떤 tenant의 어떤 role을 가져야하는지 명확하지 않음...
		shell('keystone user-role-add --user %s --role %s --tenant_id=%s' % (self.get_user_id('admin'), self.get_role_id('admin'), self.get_tenant_id('admin')))
		shell('keystone user-role-add --user %s --role %s --tenant_id=%s' % (self.get_user_id('admin'), self.get_role_id('member'), self.get_tenant_id('admin')))
		shell('keystone user-role-add --user %s --role %s --tenant_id=%s' % (self.get_user_id('nova'), self.get_role_id('admin'), self.get_tenant_id('service')))
		shell('keystone user-role-add --user %s --role %s --tenant_id=%s' % (self.get_user_id('glance'), self.get_role_id('admin'), self.get_tenant_id('service')))
		shell('keystone user-role-add --user %s --role %s --tenant_id=%s' % (self.get_user_id('swift'), self.get_role_id('admin'), self.get_tenant_id('service')))


		#def role_add(user, role, tenant):
		#	shell('keystone user-role-add --user %s --role %s --tenant_id=%s' %
		#		(self.get_user_id(user), self.get_role_id(role), self.get_tenant_id(tenant)))
		#
		#role_add('admin', 'admin', 'admin')
		#role_add('admin', 'member', 'admin')
		#role_add('nova', 'admin', 'service')
		#role_add('glance', 'admin', 'service')
		#role_add('swift', 'admin', 'service')
		#role_add('swift', 'member', 'admin')

		# create additional users
		for user in self.context['global.users'].split(', '):
			if user: shell('keystone user-create --name %s --pass %s' % (user, self.context['global.passwd']))

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
			region = self.context['global.region']
			service_id = self.get_service_id(service_name)
			publicurl = publicurl % {'ip': self.context['network.control_ip']}
			adminurl = adminurl % {'ip': self.context['network.control_ip']}
			internalurl = internalurl % {'ip': self.context['network.control_ip']}

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

	def _cleanup(self):
		pkg_remove('glance-common')
		shell('rm -rf /var/lib/glance*')
		shell('rm -rf /var/log/glance*')

		#del os.environ['SERVICE_TOKEN']
		#del os.environ['OS_TENANT_NAME']
		#del os.environ['OS_USERNAME']
		#del os.environ['OS_PASSWORD']
		#del os.environ['OS_AUTH_URL']
		#del os.environ['SERVICE_ENDPOINT']

	def _setup(self):
		pkg_install('glance')
		self.file('/etc/glance/glance-api-paste.ini').replace(
			'%SERVICE_TENANT_NAME%', 'service').replace(
			'%SERVICE_USER%', 'glance').replace(
			'%SERVICE_PASSWORD%', self.context['global.passwd']).replace(
			'pipeline = versionnegotiation context apiv1app', 'pipeline = versionnegotiation autotoken context apiv1app')	#  TODO: 이 항목 없음..

		self.file('/etc/glance/glance-registry-paste.ini').replace(
			'%SERVICE_TENANT_NAME%', 'service').replace(
			'%SERVICE_USER%', 'glance').replace(
			'%SERVICE_PASSWORD%', self.context['global.passwd']).replace(
			'pipeline = context registryapp', 'pipeline = authtoken auth-context context registryapp')	# TODO: 이 항목 없음...

		self.file('/etc/glance/glance-registry.conf').replace(
			r'connection = sqlite:\/\/\/\/var\/lib\/glance\/glance.sqlite', 
			r'connection = mysql:\/\/glance:%s@localhost\/glance' % self.context['global.passwd'])
		self.file('/etc/glance/glance-registry.conf').append('').append(
			'[paste_deploy]').append(
			'flavor = keystone')

		self.file('/etc/glance/glance-api.conf').append('').append(
			'[paste_deploy]').append(
			'flavor = keystone')

		shell('glance-manage version_control 0')
		shell('glance-manage db_sync')

		shell('service glance-api restart')
		shell('service glance-registry restart')
		time.sleep(0.5)	#  완전히 startup하기까지 조금 기다려야...

		os.environ['SERVICE_TOKEN'] = self.context['global.passwd']
		os.environ['OS_TENANT_NAME'] = 'admin'
		os.environ['OS_USERNAME'] = 'admin'
		os.environ['OS_PASSWORD'] = self.context['global.passwd']
		os.environ['OS_AUTH_URL'] = "http://%s:5000/v2.0/" % self.context['network.control_ip']
		os.environ['SERVICE_ENDPOINT'] = 'http://%s:35357/v2.0' % self.context['network.control_ip']

		shell('glance index')
		#shell('glance --os_username=admin --os_password=choe --os_tenant=admin --os_auth_url=http://localhost:5000/v2.0 index')


class NovaBaseInstaller(Installer):
	def _nova_config(self):
		class NovaConfig:
			config = '/etc/nova/nova.conf'

			def __init__(self):
				self.items = []
				if not os.path.exists(self.config): return

				f = file(self.config, 'r+')

				for x in f.readlines():
					if not x: continue
					v = x.lstrip('-').strip().split('=')
					if len(v) == 1: v.append('')
					self.items.append([v[0],v[1]])
				
			def __enter__(self): return self
			def __exit__(self, type, value, traceback): pass

			def __del__(self):
				f = file(self.config, 'w')
				for k, v in self.items:
					if v: f.write('--%s=%s\n' % (k, v))
					else: f.write('--%s\n' % k)

			def __setitem__(self, key, value):
				keys = [x[0] for x in self.items]
				try:
					self.items[keys.index(key)][1] = value
				except ValueError:
					self.items.append([key,value])

		with NovaConfig() as n:
			#n['dhcpbridge_flagfile'] = '/etc/nova/nova.conf')
			#n['dhcpbridge'] = '/usr/bin/nova-dhcpbridge')
			#n['logdir'] = '/var/log/nova')
			#n['state_path'] = '/var/lib/nova')
			#n['lock_path'] = '/run/lock/nova')
			n['allow_admin_api'] = 'true'
			n['use_deprecated_auth'] = 'false'
			n['auth_strategy'] = 'keystone'
			n['scheduler_driver'] = 'nova.scheduler.simple.SimpleScheduler'
			n['s3_host'] = self.context['network.control_ip']
			n['ec2_host'] = self.context['network.control_ip']
			n['rabbit_host'] = self.context['network.control_ip']
			n['cc_host'] = self.context['network.control_ip']
			n['nova_url'] = 'http://%s:8774/v1.1/' % self.context['network.control_ip']
			# vm traffic이 외부로 나가는데 SNAT을 수행해서 나간다. SNAT을 수행할 IP를 지정한다.
			# 따라서 여기의 ip는 public traffic을 전달할 ip address
			n['routing_source_ip'] = '%s' % get_ip(self.context['network.public_interface'])
			n['glance_api_servers'] = '%s:9292' % self.context['network.control_ip']
			n['image_service'] = 'nova.image.glance.GlanceImageService'
			n['iscsi_ip_prefix'] = '192.168.4'
			n['sql_connection'] = 'mysql://nova:%s@%s/nova' % (self.context['global.passwd'], self.context['network.control_ip'])
			n['ec2_url'] = 'http://%s:8773/services/Cloud' % self.context['network.control_ip']
			n['keystone_ec2_url'] = 'http://%s:5000/v2.0/ec2tokens' % self.context['network.control_ip']
			n['api_paste_config'] = '/etc/nova/api-paste.ini'
			n['libvirt_type'] = 'kvm'
			#f.append('--libvirt_use_virtio_for_bridges'] = 'true')
			n['start_guests_on_host_boot'] = 'true'
			n['resume_guests_state_on_host_boot'] = 'true'
			# vnc specific configuration
			n['novnc_enabled'] = 'true'
			n['novncproxy_base_url'] = 'http://%s:6080/vnc_auto.html' % self.context['network.control_ip']
			n['vncserver_proxyclient_address'] = self.context['network.control_ip']
			n['vncserver_listen'] = get_ip('eth0')
			# network specific settings
			if self.with_quantum:
				n['network_manager'] = 'nova.network.quantum.manager.QuantumManager'
			else:
				n['network_manager'] = 'nova.network.manager.FlatDHCPManager'
			n['public_interface'] = self.context['network.public_interface']
			n['flat_interface'] = self.context['network.bridge_iface']
			n['flat_network_bridge'] = self.context['network.bridge']
			try:
				network_type = self.network_context('network_type')
				n['multi_host'] = network_type == 'multi_host' and 'True' or 'False'
				n['fixed_range'] = self.network_context('fixed_cidr')
				n['network_size'] = self.network_context('fixed_size')
				n['flat_network_dhcp_start'] = self.network_context('fixed_dhcp_start')
				if network_type == 'physical_gateway':
					n['dnsmasq_config_file'] = '/etc/dnsmasq-nova.conf'
					self.file('/etc/dnsmasq-nova.conf').append(
						'dhcp-option=option:router,%s' % self.network_context('gw'))
			except ConfigParser.NoOptionError:
				pass

			if self.with_quantum:
				if self.role in ('network', 'compute'):
					if self.role == 'network':
						n['linuxnet_interface_driver'] = 'nova.network.linux_net.LinuxOVSInterfaceDriver'
						n['linuxnet_ovs_integration_bridge'] = self.context['network.bridge']
						n['quantum_connection_host'] = self.context['network.control_ip']
						#n['quantum_connection_port'] = 9393
						n['quantum_use_dhcp'] = True
					if self.role == 'compute':
						n['libvirt_ovs_bridge'] = self.context['network.bridge']
						n['libvirt_vif_type'] = 'ethernet'
						n['libvirt_vif_driver'] = 'nova.virt.libvirt.vif.LibvirtOpenVswitchDriver'

			n['auto_assign_floating_ip'] = self.context['network.auto_assign_floating_ip']
			#n['floating_range'] = '10.200.3.0/24'		# TODO: public ip range인데 아직은 고려하지 않음
			n['flat_injected'] = 'False'
			#n['force_dhcp_release'
			#n['iscsi_helper'] = 'tgtadm'
			#n['connection_type'] = 'libvirt'
			#n['root_helper'] = 'sudo nova-rootwrap'
			n['verbose'] = ''
			n['send_arp_for_ha'] = 'True'

		shell('chown -R nova:nova /etc/nova')
		shell('chmod 644 /etc/nova/nova.conf')

	def get_network_section(self):
		host_alias = self.context['hosts.%s' % get_mac()]
		return self.context['network.%s' % host_alias]
	network_section = property(get_network_section)

	def network_context(self, key):
		print self.network_section, key
		return self.context['%s.%s' % (self.network_section, key)]

	def _cleanup_bridge(self):
		# LinuxBridge인 경우는 nova-network이 자동으로 만들고 관리하지만 OVS는 하지 않아서 직접 해야한다
		bridge = self.context['network.bridge']

		if self.with_quantum:
			if output(r'ovs-vsctl list-br | grep -c %s' % bridge).strip() == '1':
				shell(r'ovs-vsctl del-br %s' % bridge)

		else:
			if output('brctl show | grep -c %s' % bridge).strip() == '1':
				shell('ifconfig %s down' % bridge)
				shell('brctl delbr %s' % bridge)

	def _setup_bridge(self):
		bridge = self.context['network.bridge']

		if self.with_quantum:
			shell('ovs-vsctl add-br %s' % bridge)
			shell('ovs-vsctl add-port %s %s' % (bridge, self.context['network.bridge_iface']))

		else:
			shell('brctl addbr %s' % bridge)
			shell('brctl addif %s %s' % (bridge, self.context['network.bridge_iface']))

		shell('ifconfig %s up' % bridge)

	def _setup_quantum_plugin(self):
		with self.file('/etc/quantum/plugins/openvswitch/ovs_quantum_plugin.ini') as f:
			f.replace(
				'sql_connection = sqlite:\/\/',
				'sql_connection = mysql:\/\/ovs_quantum:%s@%s:3306\/ovs_quantum' % (self.context['global.passwd'], self.context['network.control_ip']))
			f.replace('integration-bridge = br-int', 'integration-bridge = %s' % self.context['network.bridge'])


class NovaControllerInstaller(NovaBaseInstaller):
	"""controller installation"""
	role = 'controller'

	def _cleanup(self):
		pkg_remove('nova-common')
		pkg_remove('novnc')
		pkg_remove('rabbitmq-server')
		# volume depends
		pkg_remove('tgt')
		pkg_remove('apache2.2-common')
		pkg_remove('memcached')
		if self.with_quantum:
			pkg_remove('openvswitch-datapath-dkms python-quantum python-quantumclient quantum-server')

		try_shell('service memcached restart')	# openstack-dashboard에서 사용하는데.. 캐쉬 문제로 에러가 발생하는 경우가 있음
		try_shell('service rabbitmq-server restart')
		try_shell('killall -9 dnsmasq')
		try_shell('killall -9 kvm')
		try_shell('killall -9 epmd')
		try_shell('killall -9 beam')
		pkg_remove('dnsmasq-base')
		pkg_remove('python-django-horizon openstack-dashboard')

		try_shell('service tgt stop')

		try_shell('vgremove -f nova-volumes')
		shell('pvremove -ff -y %s' % self.context['volume.dev'])
		shell('rm -rf /var/lib/nova')

	
	def _setup(self):
		pkg_install('nova-api nova-cert nova-doc nova-objectstore nova-scheduler nova-volume rabbitmq-server novnc nova-consoleauth')
		if self.with_quantum: pkg_install('quantum-server quantum-plugin-openvswitch')

		self._nova_config()

		# nova-volumes 이름을 가진 lvm volume group이 있어야한다.
		shell('pvcreate %s' % self.context['volume.dev'])
		shell('vgcreate nova-volumes %s' % self.context['volume.dev'])

		shell('chown -R nova:nova /etc/nova')
		shell('chmod 644 /etc/nova/nova.conf')

		self.file('/etc/nova/api-paste.ini').replace(
			'%SERVICE_TENANT_NAME%', 'service').replace(
			'%SERVICE_USER%', 'nova').replace(
			'%SERVICE_PASSWORD%', self.context['global.passwd'])

		if self.with_quantum:
			with self.file('/etc/quantum/plugins.ini') as f:
				f.replace(
					'provider = quantum.plugins.sample.SamplePlugin.FakePlugin',
					'provider = quantum.plugins.openvswitch.ovs_quantum_plugin.OVSQuantumPlugin')

			self._setup_quantum_plugin()

			shell('service quantum-server restart')

		shell('nova-manage db sync')

		# 이전과 비슷
		#export OS_TENANT_NAME=admin
		#export OS_USERNAME=admin
		#export OS_PASSWORD=admin
		#export OS_AUTH_URL="http://localhost:5000/v2.0/"

		shell("service tgt restart")
		shell("service rabbitmq-server restart")
		shell("service nova-api restart")
		shell("service nova-objectstore restart")
		shell("service nova-scheduler restart")
		shell("service nova-volume restart")
		shell("service nova-consoleauth restart")

		pkg_install('openstack-dashboard')
		shell('service apache2 restart')

		# flavor
		try_shell('nova-manage flavor delete --name choe.test.small')

		#shell('nova-manage flavor create --name choe.test.small --memory=256 --cpu=1 --root_gb=5 --ephemeral_gb=10 --flavor 9999')
		shell('nova-manage flavor create --name choe.test.small --memory=256 --cpu=1 --root_gb=5 --ephemeral_gb=10 --flavor 9999')
		shell('nova-manage service list')

		shell('nova secgroup-add-rule default icmp -1 -1 0.0.0.0/0')
		shell('nova secgroup-add-rule default tcp 22 22 0.0.0.0/0')


class NovaNetworkInstaller(NovaBaseInstaller):
	"""Install only nova-network packages
	do not manupulate network settings"""
	role = 'network'

	def _cleanup(self):
		self._cleanup_bridge()

		pkg_remove('nova-network')
		try_shell('rm /etc/dnsmasq-nova.conf')
		if self.with_quantum:
			pkg_remove('openvswitch-datapath-dkms openvswitch-common')
			try_shell('rm -rf /etc/openvswitch')
	
		try_shell('killall dnsmasq')
		try_shell('ifconfig %s 0.0.0.0' % self.context['network.bridge'])
		shell('sysctl net.ipv4.ip_forward=0')
		shell('iptables -F')
		shell('iptables -F -t nat')

	def _setup(self):
		pkg_install('nova-network')
		if self.with_quantum: pkg_install('quantum-plugin-openvswitch')
		self._nova_config()

		try_shell('rm /var/lock/nova/nova-iptables.lock')
		if self.with_quantum:
			shell("service openvswitch-switch restart")
			self._setup_quantum_plugin()

		self._setup_bridge()

		shell("service nova-network restart")
		shell('sysctl net.ipv4.ip_forward=1')


class NovaNetworkCreateInstaller(NovaBaseInstaller):
	""""Network Node Installer
	network node network pre setings
	    - eth1 must be configured with no ip addr assigned
	    - bridge br100 will be created by nova-network
	    - net.ipv4.ip_forward=1
	"""
	role = 'create-network'

	def _cleanup(self):
		super(NovaNetworkCreateInstaller, self)._cleanup()

		try_shell("nova-manage network list | tail -n +2 | awk '{print $9}' | xargs -L1 nova-manage network delete --uuid ")
		if self.context['network.floating_cidr']:
			try_shell('nova-manage floating delete %s' % self.context['network.floating_cidr'])

	def _setup(self):
		super(NovaNetworkCreateInstaller, self)._setup()

		# options
		# http://docs.openstack.org/essex/openstack-compute/admin/content/configuring-vlan-networking.html
		# nova-manage network create <label> [options]
		# --fixed_range_v4	10.200.2.0/24
		# --num_networks	1
		#	10.200.2.0/24로 주어지고 num_networks를 3으로 지정하면
		#	다음처럼 3개의 네트웍이 만들어 진다.
		#	10.200.2.0/24,10.200.2.0/24, 10.200.2.0/24
		# --network_size	주어진 CIDR의 IP 갯수
		# --bridge
		# --bridge_interface
		# --multi_host=[T|F]	multihost 모드 사용
		# TODO: DNS를 지정해도 VM에서는 nova-network의 노드로 잡힌다.
		# TODO: Gateway를 지정해도 VM에서는 nova-network가 지정된다. 단 physical_gateway 옵션을 제외하고
		# --dns1, --dns2	DNS 지정
		# --gateway		Not confirmed
		# --gateway_v6		Not confirmed
		# --project_id=<id>	tenant ID 지정
		network_type = self.network_context('network_type')
		multi_host = network_type == 'multi_host' and 'T' or 'F'
		if network_type == 'physical_gateway':
			dns_option = []
			for i, dns in enumerate(self.network_context('dns').split(', ')[:1]):
				dns_option.append("--dns%d=%s" % (i + 1, dns))
			dns_option = ' '.join(dns_option)
		else:
			dns_option = ''

		shell(
			"nova-manage network create %s --fixed_range_v4='%s' --num_networks=%s "
			"--bridge=%s --bridge_interface=%s --network_size=%s --multi_host=%s %s" %
			(self.network_context('name'), self.network_context('fixed_cidr'),
			 self.network_context('num_networks'), self.context['network.bridge'],
			 self.context['network.bridge_iface'], self.network_context('fixed_size'),
			 multi_host, dns_option)
		)

		# floating IPs
		if self.context['network.floating_cidr']:
			shell('nova-manage floating create %s' % self.context['network.floating_cidr'])


class NovaComputeInstaller(NovaBaseInstaller):
	role = 'compute'

	def _cleanup(self):
		if output("egrep -c '(vmx|svm)' /proc/cpuinfo").strip() == '0':
			raise Exception, 'CPU hardware virtualization not enabled'

		self._cleanup_bridge()

		# compute depends
		pkg_remove('nova-compute qemu-common libvirt0 open-iscsi')
		if self.with_quantum:
			pkg_remove('openvswitch-datapath-dkms openvswitch-common')
			try_shell("kill -9 `ps ax | grep quantum-openvswitch-agent | grep -v grep | awk '{print $1}'`")

		shell('rm -rf /var/lib/nova/instances/*')


	def _setup(self):
		pkg_install('ntp')

		pkg_install('nova-compute')
		pkg_install('python-mysqldb')
		shell('kvm-ok')
		pkg_remove('dmidecode')	# 이 패키지가 설치되면 kvm이 서비스가 정상작동하지 않음, 아마 ubuntu vm의 문제일 듯..

		self._nova_config()
		if self.with_quantum:
			pkg_install('quantum-plugin-openvswitch quantum-plugin-openvswitch-agent')
			self._setup_quantum_plugin()

			self.file('/etc/libvirt/qemu.conf').append("""cgroup_device_acl = [
    "/dev/null", "/dev/full", "/dev/zero",
    "/dev/random", "/dev/urandom",
    "/dev/ptmx", "/dev/kvm", "/dev/kqemu",
    "/dev/rtc", "/dev/hpet", "/dev/net/tun",
]""")

		shell('service libvirt-bin restart')
		if self.with_quantum:
			shell('service openvswitch-switch restart')
		shell('service open-iscsi restart')
		shell('service nova-compute restart')
		shell('nova-manage service list')

		self._setup_bridge()

		if self.with_quantum:
			shell('quantum-openvswitch-agent /etc/quantum/plugins/openvswitch/ovs_quantum_plugin.ini &')


class SwiftInstaller(Installer):
	role = 'swift'

	def _cleanup(self):
		pkg_remove('swift swift-proxy swift-account swift-container swift-object')
		pkg_remove('xfsprogs')

		self.dev = self.context['swift.dev']
		self.mount = self.context['swift.mount']
		try_shell('umount %s' % self.mount)
	
	def _setup(self):
		pkg_install('swift swift-proxy swift-account swift-container swift-object')
		pkg_install('xfsprogs')
		pkg_install('curl python-pastedeploy')

		mount_opt = ''
		if not self.dev.startswith('/dev/'):
			shell('truncate --size=%s %s' % (self.context['swift.loopback_size'], self.dev))
			mount_opt = '-o loop'

		shell('mkfs.xfs -f %s' % self.dev)
		shell('mkdir -p %s' % self.context['swift.mount'])
		# /dev/sdb3 /mnt/swift_backend xfs noatime,nodiratime,nobarrier,logbufs=8 0 0

		shell('mount %s %s %s' % (mount_opt, self.dev, self.mount))
		for i in range(1,5):
			shell('mkdir %s/node%s' % (self.mount, i))
			shell('chown -R swift.swift %s/node%s' % (self.mount, i))

class PrepareImageInstaller(Installer):
	"""VM을 시작하기 위한 이미지 만들어 등록하기
	TODO
	* Ubuntu의 경우 cloud-init라는 패키지를 클라우드 인스턴스 초기화 및 keypair 업데이트 용으로 제공하고 있으며
	  그 것을 이용해서 초기 이미지 만드는 것을 적용해야겠음
	"""
	role = 'prepare-image'

	def _setup(self):
		# Create glance image
		# 
		def glance_register(url, name):
			filename = os.path.basename(url)
			if not os.path.exists(filename):
				shell('wget -O %s %s' % (filename, url))

			shell('glance --os_username=admin --os_password=choe --os_tenant=admin '
				  '--os_auth_url=http://%s:5000/v2.0 add name="%s" '
				  'is_public=true container_format=ovf disk_format=qcow2 < %s' % (self.context['network.control_ip'], name, filename))

		# Custom Cloud Image
		# $ wget http://ftp.daum.net/ubuntu-releases/12.04/ubuntu-12.04-server-amd64.iso
		# $ kvm-img create -f qcow2 server.qcow2 5G
		# $ sudo kvm -m 256 -cdrom ubuntu-12.04-server-amd64.iso -drive file=server.qcow2,if=virtio,index=0 -boot d -net nic -net user -nographic  -vnc :0
		# install ubuntu sever using gvncviewr <ip>:0
		# this installed image placed at http://192.168.100.108/isos/server.qcow2
		# $ glance --os_username=admin --os_password=choe --os_tenant=admin --os_auth_url=http://10.200.1.10:5000/v2.0 add name="Ubuntu 12.04 Server 64" is_public=true container_format=ovf disk_format=qcow2 < server.qcow2
		glance_register('http://192.168.100.108/isos/server.qcow2', 'Ubuntu 12.04 Server 64bit')

		# Ubuntu Cloud Image
		# http://uec-images.ubuntu.com/precise/current/precise-server-cloudimg-amd64-disk1.img
		# see http://docs.openstack.org/essex/openstack-compute/admin/content/starting-images.html
		#glance_register('http://uec-images.ubuntu.com/precise/current/precise-server-cloudimg-amd64-disk1.img', 'Ubuntu CloudImage 12.04 Server 64bit')


class CreateSampleInstanceInstaller(Installer):
	role = 'create-sample-instance'

	def _nova_cmd(self):
		return \
			'nova --os_username admin --os_password %s --os_tenant_name admin ' \
			'--os_auth_url=http://%s:35357/v2.0' % (self.context['global.passwd'], self.context['network.control_ip'])

	def _nova(self, *args): return shell('%s %s' % (self._nova_cmd(), ' '.join(args)))

	def _setup(self):
		# 테스트용 가상머신 생성
		def get_image(): return output("%s image-list | grep ACTIVE | head -1 | awk '{print $2}'" % (self._nova_cmd())).strip()

		self._nova('image-list')
		try: self._nova('keypair-delete test')
		except: pass
		self._nova('keypair-add test > test.pem')
		self._nova('boot --flavor 9999 --image %s test' % get_image())
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
	runner.append(OsInstaller())
	for role in config['roles.%s' % config['hosts.%s' % get_mac()]].split(', '):
		try:
			runner.append(klasses[role]())
		except IndexError, e:
			raise Exception, 'Undefined role: %s' % role
		
	what_to_run = None
	if len(sys.argv) == 2: what_to_run = sys.argv[1]

	runner.setup(what_to_run)


main()

# vim: aw ai nu
