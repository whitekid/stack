#!/bin/bash
cmd=$1
if [ -z $cmd ]; then
	cmd='create'
fi

vm_count=2
use_quantum=`grep -c QuantumManager /etc/nova/nova.conf`

create_vm() {
	flavor=9999
	image=`nova image-list | grep ACTIVE | awk '{print $2}'`
	network=`nova-manage network list | tail -n +2 | head -1 | awk '{print $9}'`

	for i in `seq 1 $vm_count` ; do
		name="test${i}"
		if [ `nova list | grep -c " $name "` == '0' ]; then
			# ovs의 경우는 net-id가 반듯이 있어야함.
			# net-id를 지정하면 생성되는 호스트가 해당 네트웍에 속해야함.. network_host로 설정?
			#nova boot --flavor ${flavor} --image ${image} --nic net-id="${network}" $name
			nic=""
			if [ $use_quantum = '1' ]; then
				nic="--nic net-id=${network}"
			fi

			nova boot --flavor ${flavor} --image ${image} $nic $name
		fi
	done
}

delete_vm() {
	status=$1
	if [ -z $status ]; then
		status=test
	fi

	nova list | grep $status | awk '{print $2}' | xargs -L1 nova delete
}

ping_vm() {
	nova list | grep ACTIVE | awk '{print $8}' | cut -d = -f 2 | xargs -L1 ping -c 2
}

usage() {
	echo $2
	exit
}

case $cmd in
	create)
		create_vm
		;;

	delete)
		delete_vm $2
		;;

	ping)
		ping_vm
		;;
		
	clear-net)
		nova-manage network list | tail -n +2 | awk '{print $9}' | xargs -L1 nova-manage network delete --uuid
		nova-manage network list
		;;

	create-net)
		opt=""
		if [ $use_quantum = '1' ]; then
			opt="--bridge=br100 --bridge_interface=eth1"
		fi
		nova-manage network create private --fixed_range_v4=192.168.200.0/24 --num_networks=1 --network_size=256 $opt
		nova-manage network list
		;;

	*)
		usage
		;;
esac
