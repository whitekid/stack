#!/usr/bin/python
# -*- coding: utf8 -*-
import os, sys
import subprocess
import json
import time

def get_ip(iface = None):
	if iface == None: iface = 'eth0'
	return subprocess.check_output("ifconfig %s | grep 'inet addr' | cut -d: -f 2 | awk '{print $1}'" % iface, shell=True).strip()

def get_mac(iface = None):
	if iface == None: iface = 'eth0'
	return subprocess.check_output("ifconfig %s | grep HWaddr | awk '{print $5}'" % iface, shell=True).strip()

class Context:
	passwd = 'choe'
	region = 'region0'
	volume_dev = '/dev/sdb'
	guest_net = '10.200.2.0/27'
	guest_gw = '100.200.2.2'
	bridge = 'br100'
	bridge_iface = 'eth1'
	control_ip = '10.200.1.10'

	def __init__(self):
		self.hostname = subprocess.check_output('hostname').strip()

	def get_ip(self, iface = None): return get_ip(iface)
	def get_mac(self, iface = None): return get_mac(iface)

class Installer:
	def run(self):
		self._setup()
		self._run()
		self._teardown()

	def _setup(self): pass
	def _run(self): pass
	def _teardown(self): pass

	def shell(self, command):
		return subprocess.check_call(command, shell=True)

	def output(self, command):
		return subprocess.check_output(command, shell=True)
		

	def pkg_installed(self, pkg):
		try:
			return self.output("dpkg -l  | grep '%s ' | grep -c ^ii" % pkg) == '1'
		except:
			return False

	def pkg_remove(self, pkg):
		self.shell("apt-get purge -y %s" % pkg)

	def pkg_install(self, pkg):
		self.shell("apt-get install -y %s" % pkg)

	class File:
		def __init__(self, parent, filename):
			self.parent = parent
			self.filename = filename

		def replace(self, orig, rep):
			self.parent.shell("sed -i 's/%s/%s/g' %s" % (orig, rep, self.filename))
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

	def run(self):
		for installer in self._installer:
			installer.run()

class OsInstaller(Installer):
	def _run(self):
		"ntp setup"

class DatabaseInstaller(Installer):
	def _setup(self):
		if self.pkg_installed('mysql-server'):
			self.pkg_remove('mysql-server')
		self.pkg_install('mysql-server')

		try: self.shell("service mysql stop")
		except: pass
		self.shell("sed -i 's/127.0.0.1/0.0.0.0/g' /etc/mysql/my.cnf")
		self.shell("rm -rf /var/lib/mysql")
		self.shell("mysql_install_db")
		self.shell("service mysql start")

	def _run(self):
		self.shell("""mysql -uroot -e "SET PASSWORD=PASSWORD('%s')" """ % self.context.passwd)
		self.create_db('nova', 'nova')
		self.create_db('glance', 'glance')
		self.create_db('keystone', 'keystone')

	def create_db(self, dbname, user):
		passwd = self.context.passwd
		hostname = self.context.hostname

		self.shell("""mysql -uroot -p%(passwd)s -e "create database %(dbname)s;" """ % locals())
		self.shell("""mysql -uroot -p%(passwd)s -e "grant all on %(dbname)s.* to %(user)s identified by '%(passwd)s';" """ % locals())
		self.shell("""mysql -uroot -p%(passwd)s -e "grant all on %(dbname)s.* to %(user)s@localhost identified by '%(passwd)s';" """ % locals())
		self.shell("""mysql -uroot -p%(passwd)s -e "grant all on %(dbname)s.* to %(user)s@'%(hostname)s' identified by '%(passwd)s';" """ % locals())

class KeystoneInstaller(Installer):
	def _setup(self):
		self.pkg_remove("keystone")
		self.shell('rm -rf /var/lib/keystone')
		self.pkg_install("keystone")

		try: del os.environ['SERVICE_ENDPOINT']
		except: pass
		try: del os.environ['SERVICE_TOKEN']
		except: pass

	def _run(self):
		self.replace('/etc/keystone/keystone.conf', 'admin_token = ADMIN', 'admin_token = %s' % self.context.passwd)
		self.replace('/etc/keystone/keystone.conf',
			r'connection = sqlite:\/\/\/\/var\/lib\/keystone\/keystone.db', 
			r'connection = mysql:\/\/keystone:%s@localhost\/keystone' % self.context.passwd)
		self.shell('restart keystone')
		self.shell('keystone-manage db_sync')

		os.environ['SERVICE_ENDPOINT'] = 'http://localhost:35357/v2.0'
		os.environ['SERVICE_TOKEN'] = self.context.passwd

		self.shell('keystone tenant-create --name admin --description "Default Tenant"')
		self.shell('keystone tenant-create --name service --description "Service Tenant"')

		# TODO: tenant_id가 없어도 별 상관 없는 듯..
		self.shell('keystone user-create --name admin --pass %s' % self.context.passwd)
		self.shell('keystone user-create --name nova --pass %s' % self.context.passwd)
		self.shell('keystone user-create --name glance --pass %s' % self.context.passwd)
		self.shell('keystone user-create --name swift --pass %s' % self.context.passwd)

		self.shell('keystone role-create --name admin')
		self.shell('keystone role-create --name member')

		# http://docs.openstack.org/essex/openstack-compute/starter/content/Adding_Roles_to_Users-d1e465.html
		# TODO: 뭔가... 어떤 user가 어떤 tenant의 어떤 role을 가져야하는지 명확하지 않음...
		self.shell('keystone user-role-add --user %s --role %s --tenant_id=%s' % (self.get_user_id('admin'), self.get_role_id('admin'), self.get_tenant_id('admin')))
		self.shell('keystone user-role-add --user %s --role %s --tenant_id=%s' % (self.get_user_id('admin'), self.get_role_id('member'), self.get_tenant_id('admin')))
		self.shell('keystone user-role-add --user %s --role %s --tenant_id=%s' % (self.get_user_id('nova'), self.get_role_id('admin'), self.get_tenant_id('service')))
		self.shell('keystone user-role-add --user %s --role %s --tenant_id=%s' % (self.get_user_id('glance'), self.get_role_id('admin'), self.get_tenant_id('service')))
		self.shell('keystone user-role-add --user %s --role %s --tenant_id=%s' % (self.get_user_id('swift'), self.get_role_id('admin'), self.get_tenant_id('service')))

		self.shell('keystone user-role-add --user %s --role %s --tenant_id=%s' % (self.get_user_id('swift'), self.get_role_id('member'), self.get_tenant_id('admin')))

		# create servic3
		self.shell("keystone service-create --name nova --type compute --description 'OpenStack Compute Service'")
		self.shell("keystone service-create --name volume --type volume --description 'OpenStack Volume Service'")
		self.shell("keystone service-create --name glance --type image --description 'OpenStack Image Service'")
		self.shell("keystone service-create --name swift --type object-store --description 'OpenStack Storage Service'")
		self.shell("keystone service-create --name keystone --type identity --description 'OpenStack Identity Service'")
		self.shell("keystone service-create --name ec2 --type ec2 --description 'EC2 Service'")

		# endpoints
		# TODO: 여기 $(tenant_id)s가 다른 곳에서는 %(tenant_id)s인데.. 이거 python 문법 아닌가?
		def endpoint_create(service_name, publicurl, adminurl, internalurl):
			region = self.context.region
			service_id = self.get_service_id(service_name)
			publicurl = publicurl % {'ip': self.context.get_ip('eth0')}
			adminurl = adminurl % {'ip': self.context.get_ip('eth0')}
			internalurl = internalurl % {'ip': self.context.get_ip('eth0')}

			self.shell(
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
		return self.output("keystone %s-list | grep ' %s ' | awk '{print $2}'" % (service, name)).strip()
	

class GlanceInstaller(Installer):
	def _setup(self):
		self.pkg_remove('glance glance-registry glance-api')
		self.pkg_install('glance')

		#del os.environ['SERVICE_TOKEN']
		#del os.environ['OS_TENANT_NAME']
		#del os.environ['OS_USERNAME']
		#del os.environ['OS_PASSWORD']
		#del os.environ['OS_AUTH_URL']
		#del os.environ['SERVICE_ENDPOINT']

	def _run(self):
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

		self.shell('glance-manage version_control 0')
		self.shell('glance-manage db_sync')

		self.shell('restart glance-api')
		self.shell('restart glance-registry')
		time.sleep(0.5)	#  완전히 startup하기까지 조금 기다려야...

		os.environ['SERVICE_TOKEN'] = self.context.passwd
		os.environ['OS_TENANT_NAME'] = 'admin'
		os.environ['OS_USERNAME'] = 'admin'
		os.environ['OS_PASSWORD'] = self.context.passwd
		os.environ['OS_AUTH_URL'] = "http://localhost:5000/v2.0/"
		os.environ['SERVICE_ENDPOINT'] = 'http://localhost:35357/v2.0'

		self.shell('glance index')
		#self.shell('glance --os_username=admin --os_password=choe --os_tenant=admin --os_auth_url=http://localhost:5000/v2.0 index')

class NovaInstaller(Installer):
	def _setup(self):
		self.pkg_remove('nova-common nova-compute-kvm libvirt-bin')
		self.pkg_remove('openstack-dashboard')

		try: self.shell('service tgt stop')
		except: pass

		try: self.shell('vgremove -f nova-volumes')
		except: pass
		self.shell('pvremove -ff -y %s' % self.context.volume_dev)

	
	def _run(self):
		self.pkg_install('nova-api nova-cert nova-doc nova-network nova-objectstore nova-scheduler nova-volume rabbitmq-server novnc nova-consoleauth')
		#self.pkg_install('nova-compute')

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
		f.append('--s3_host=%s' % self.context.get_ip('eth0'))
		f.append('--ec2_host=%s' % self.context.get_ip('eth0'))
		f.append('--rabbit_host=%s' % self.context.get_ip('eth0'))
		f.append('--cc_host=%s' % self.context.get_ip('eth0'))
		f.append('--nova_url=http://%s:8774/v1.1/' % self.context.get_ip('eth0'))
		f.append('--routing_source_ip=%s' % self.context.get_ip('eth0'))
		f.append('--glance_api_servers=%s:9292' % self.context.get_ip('eth0'))
		f.append('--image_service=nova.image.glance.GlanceImageService')
		f.append('--iscsi_ip_prefix=192.168.4')
		f.append('--sql_connection=mysql://nova:%s@%s/nova' % (self.context.passwd, self.context.get_ip('eth0')))
		f.append('--ec2_url=http://%s:8773/services/Cloud' % self.context.get_ip('eth0'))
		f.append('--keystone_ec2_url=http://%s:5000/v2.0/ec2tokens' % self.context.get_ip('eth0'))
		f.append('--api_paste_config=/etc/nova/api-paste.ini')
		f.append('--libvirt_type=kvm')
		#f.append('--libvirt_use_virtio_for_bridges=true')
		f.append('--start_guests_on_host_boot=true')
		f.append('--resume_guests_state_on_host_boot=true')
		# vnc specific configuration
		f.append('--novnc_enabled=true')
		f.append('--novncproxy_base_url=http://%s:6080/vnc_auto.html' % self.context.get_ip('eth0'))
		f.append('--vncserver_proxyclient_address=%s' % self.context.get_ip('eth0'))
		f.append('--vncserver_listen=%s' % self.context.get_ip('eth0'))
		# network specific settings
		f.append('--network_manager=nova.network.manager.FlatDHCPManager')
		f.append('--public_interface=eth0')
		f.append('--flat_interface=eth1')
		f.append('--flat_network_bridge=br100')
		f.append('--fixed_range=192.168.4.1/27')		# TODO: hmm...
		f.append('--floating_range=10.10.10.2/27')		# TODO: hmm...
		f.append('--network_size=32')				# TODO: hmm...
		f.append('--flat_network_dhcp_start=192.168.4.33')	# TODO: hmm...
		f.append('--flat_injected=False')
		#f.append('--force_dhcp_release')
		#f.append('--iscsi_helper=tgtadm')
		#f.append('--connection_type=libvirt')
		#f.append('--root_helper=sudo nova-rootwrap')
		#f.append('--verbose')

		# nova-volumes 이름을 가진 lvm volume group이 있어야한다.
		self.shell('pvcreate %s' % self.context.volume_dev)
		self.shell('vgcreate nova-volumes %s' % self.context.volume_dev)

		self.shell('chown -R nova:nova /etc/nova')
		self.shell('chmod 644 /etc/nova/nova.conf')

		self.file('/etc/nova/api-paste.ini').replace(
			'%SERVICE_TENANT_NAME%', 'service').replace(
			'%SERVICE_USER%', 'nova').replace(
			'%SERVICE_PASSWORD%', self.context.passwd)

		self.shell('nova-manage db sync')

		# TODO: 여기 정확한 아키텍처 파악 필요
		self.shell('nova-manage network create private --fixed_range_v4=%s --num_networks=1 --bridge=%s --bridge_interface=%s --network_size=32' %
			(self.context.guest_net, self.context.bridge, self.context.bridge_iface))

		# 이전과 비슷
		#export OS_TENANT_NAME=admin
		#export OS_USERNAME=admin
		#export OS_PASSWORD=admin
		#export OS_AUTH_URL="http://localhost:5000/v2.0/"

		self.shell("service libvirt-bin restart && service nova-network restart && service nova-api restart && service nova-objectstore restart && service nova-scheduler restart && service nova-volume restart && service nova-consoleauth restart")
		#self.shell('service nova-compute restart')

		self.pkg_install('openstack-dashboard')
		self.shell('service apache2 restart')


class NovaNodeInstaller(Installer):
	"""Nova Computing Node
	Assumtions:
		- eth0: management network
		- eth1: guest network
	"""
	def _setup(self):
		if not self.pkg_installed('ntp'): self.pkg_remove('ntp')
		if not self.pkg_installed('nova-common'): self.pkg_remove('nova-common')
		self.shell('kvm-ok')

	def _run_compute(self):
		self.pkg_install('nova-compute')

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
		f.append('--s3_host=%s' % self.context.control_ip)
		f.append('--ec2_host=%s' % self.context.control_ip)
		f.append('--rabbit_host=%s' % self.context.control_ip)
		f.append('--cc_host=%s' % self.context.control_ip)
		f.append('--nova_url=http://%s:8774/v1.1/' % self.context.control_ip)
		f.append('--routing_source_ip=%s' % self.context.guest_gw)	# guest router
		f.append('--glance_api_servers=%s:9292' % self.context.control_ip)
		f.append('--image_service=nova.image.glance.GlanceImageService')
		f.append('--iscsi_ip_prefix=10.200.1')
		f.append('--sql_connection=mysql://nova:%s@%s/nova' % (self.context.passwd, self.context.control_ip))
		f.append('--ec2_url=http://%s:8773/services/Cloud' % self.context.control_ip)
		f.append('--keystone_ec2_url=http://%s:5000/v2.0/ec2tokens' % self.context.control_ip)
		f.append('--api_paste_config=/etc/nova/api-paste.ini')
		f.append('--libvirt_type=kvm')
		#f.append('--libvirt_use_virtio_for_bridges=true')
		f.append('--start_guests_on_host_boot=true')
		f.append('--resume_guests_state_on_host_boot=true')
		# vnc specific configuration
		f.append('--novnc_enabled=true')
		f.append('--novncproxy_base_url=http://%s:6080/vnc_auto.html' % self.context.control_ip)
		f.append('--vncserver_proxyclient_address=%s' % self.context.control_ip)
		f.append('--vncserver_listen=%s' % self.context.control_ip)
		# network specific settings
		f.append('--network_manager=nova.network.manager.FlatDHCPManager')
		f.append('--public_interface=eth0')
		f.append('--flat_interface=eth1')
		f.append('--flat_network_bridge=br100')
		f.append('--fixed_range=192.168.4.1/27')		# TODO: hmm...
		f.append('--floating_range=10.10.10.2/27')		# TODO: hmm...
		f.append('--network_size=32')				# TODO: hmm...
		f.append('--flat_network_dhcp_start=192.168.4.33')	# TODO: hmm...
		f.append('--flat_injected=False')
		#f.append('--force_dhcp_release')
		#f.append('--iscsi_helper=tgtadm')
		#f.append('--connection_type=libvirt')
		#f.append('--root_helper=sudo nova-rootwrap')
		#f.append('--verbose')

		self.shell('chown -R nova:nova /etc/nova')
		self.shell('chmod 644 /etc/nova/nova.conf')

		self.file('/etc/nova/api-paste.ini').replace(
			'%SERVICE_TENANT_NAME%', 'service').replace(
			'%SERVICE_USER%', 'nova').replace(
			'%SERVICE_PASSWORD%', self.context.passwd)

		self.shell('service nova-compute restart')
		self.shell('nova-manage service list')

	def _run(self):
		self.pkg_install('ntp')
		self._run_compute()


class SwiftInstaller(Installer):
	def _setup(self):
		self.pkg_remove('swift swift-proxy swift-account swift-container swift-object')
		self.pkg_remove('xfsprogs')
	
	def _run(self):
		self.pkg_install('swift swift-proxy swift-account swift-container swift-object')
		self.pkg_install('xfsprogs python-pastedeploy')

		# TODO: swift는 나중에 처리한다..

def main():
	if os.getuid() != 0: raise Exception, 'root required'

	runner = Runner(Context())

	mac = get_mac()
	if mac == '00:0c:29:6a:64:33':
		# controller
		runner.append(OsInstaller())
		runner.append(DatabaseInstaller())
		runner.append(KeystoneInstaller())
		runner.append(GlanceInstaller())
		runner.append(NovaInstaller())
		runner.append(SwiftInstaller())
	elif mac == '00:0c:29:d5:16:5f':
		runner.append(NovaNodeInstaller())
	else:
		raise Exception, 'Unknown mac %s' % mac

	runner.run()


main()
