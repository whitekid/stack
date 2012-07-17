#!/bin/sh
cmd='restart'

for service in keystone glance-api glance-registry nova-cert nova-api nova-objectstor nova-scheduler nova-volume nova-consoleaut quantum-server ; do
	service $service $cmd
done
