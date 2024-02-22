MAKEFLAGS += --no-print-directory

-include /tmp/if.inc

SERVER1_DEV = eth2
SERVER2_DEV = eth3
CLIENT_DEV = eth4

SERVER1_V6PREFIX=2010:db8:0:1
SERVER2_V6PREFIX=2110:db8:0:1

SERVER1_V6PREFIXLEN=64
SERVER2_V6PREFIXLEN=64

SERVER1_V6ADDR=$(SERVER1_V6PREFIX)::1
SERVER2_V6ADDR=$(SERVER2_V6PREFIX)::1

SERVER1_V6LLAD=$(SERVER1_V6PREFIX)::1
SERVER2_V6LLAD=$(SERVER2_V6PREFIX)::1

.PHONY: help

help:
	@echo 'make start_StatefullDhcp'
	@echo 'make start_StatelessDhcp'
	@echo 'make start_StatelessRdnss'
	@echo 'make start_StatelessRdnss_StatefullDHCP'
	@echo 'make start_StatelessRdnssX2'
	@echo 'make status_loop'
	@echo 'make status'
	@echo 'make dump'

log:
	journalctl -xe
dump:
	sudo radvdump

## ------------------------------------------------------------------------- main targets

## - - - - - - - - - - - - - - 
start_StatefullDhcp:
	make update_if
	make _start_StatefullDhcp

_start_StatefullDhcp:
	make reset_configfile

#DHCPv6 v6 address and DNS address
	make DEVICE=$(SERVER1_DEV) PREFIX=$(SERVER1_V6PREFIX) PREFIXLEN=$(SERVER1_V6PREFIXLEN) conf_radvd_statefullDhcp
	make DEVICE=$(SERVER1_DEV) PREFIX=$(SERVER1_V6PREFIX) PREFIXLEN=$(SERVER1_V6PREFIXLEN) NAMESERVER=$(SERVER1_V6ADDR) conf_dhcpd6_statefull
	make DEVICE=$(SERVER1_DEV) conf_dhcpd4
	make DEVICE=$(SERVER1_DEV) OPTIONS="" conf_dhcpd_default

	make v6_start_radvd
	make v6_start_dhcpd
	make v4_start_dhcpd

## - - - - - - - - - - - - - - 
start_StatelessDhcp:
	make update_if
	make _start_StatelessDhcp

_start_StatelessDhcp:
	make reset_configfile

#Slacc v6 address + DHCPv6 DNS server address
	make DEVICE=$(SERVER1_DEV) PREFIX=$(SERVER1_V6PREFIX) PREFIXLEN=$(SERVER1_V6PREFIXLEN) conf_radvd_slacc_statelessDhcp
	make DEVICE=$(SERVER1_DEV) PREFIX=$(SERVER1_V6PREFIX) PREFIXLEN=$(SERVER1_V6PREFIXLEN) NAMESERVER=$(SERVER1_V6ADDR) conf_dhcpd6_stateless
	make DEVICE=$(SERVER1_DEV) conf_dhcpd4
	make DEVICE=$(SERVER1_DEV) OPTIONS="" conf_dhcpd_default

	make v6_start_radvd
	make v6_start_dhcpd
	make v4_start_dhcpd

## - - - - - - - - - - - - - - 
start_StatelessRdnss:
	make update_if
	make _start_StatelessRdnss

_start_StatelessRdnss:
	make reset_configfile

#Slacc v6 address / RDNSS DNS server address
	make DEVICE=$(SERVER1_DEV) PREFIX=$(SERVER1_V6PREFIX) PREFIXLEN=$(SERVER1_V6PREFIXLEN) RDNSSADDR=$(SERVER1_V6LLAD) conf_radvd_slacc_rdnss
	make DEVICE=$(SERVER1_DEV) conf_dhcpd4
	make DEVICE=$(SERVER1_DEV) OPTIONS="" conf_dhcpd_default

	make v6_start_radvd
	make v6_stop_dhcpd
	make v4_start_dhcpd

## - - - - - - - - - - - - - - 
start_StatelessRdnss_StatefullDHCP:
	make update_if
	make _start_StatelessRdnss_StatefullDHCP

_start_StatelessRdnss_StatefullDHCP:
	make reset_configfile

#DHCPv6 v6 address and DNS address
	make DEVICE=$(SERVER1_DEV) PREFIX=$(SERVER1_V6PREFIX) PREFIXLEN=$(SERVER1_V6PREFIXLEN) conf_radvd_statefullDhcp
	make DEVICE=$(SERVER1_DEV) PREFIX=$(SERVER1_V6PREFIX) PREFIXLEN=$(SERVER1_V6PREFIXLEN) NAMESERVER=$(SERVER1_V6ADDR) conf_dhcpd6_statefull

#Slacc v6 address / RDNSS DNS server address
	make DEVICE=$(SERVER2_DEV) PREFIX=$(SERVER2_V6PREFIX) PREFIXLEN=$(SERVER2_V6PREFIXLEN) RDNSSADDR=$(SERVER2_V6LLAD) conf_radvd_slacc_rdnss

	make DEVICE=$(SERVER1_DEV) conf_dhcpd4
	make DEVICE=$(SERVER1_DEV) OPTIONS="" conf_dhcpd_default

	make v6_start_radvd
	make v6_stop_dhcpd
	make v4_start_dhcpd

## - - - - - - - - - - - - - - 
start_StatelessRdnssX2:
	make update_if
	make _start_StatelessRdnssX2

_start_StatelessRdnssX2:
	make reset_configfile

#Slacc v6 address / RDNSS DNS server address
	make DEVICE=$(SERVER1_DEV) PREFIX=$(SERVER1_V6PREFIX) PREFIXLEN=$(SERVER1_V6PREFIXLEN) RDNSSADDR=$(SERVER1_V6LLAD) conf_radvd_slacc_rdnss
	make DEVICE=$(SERVER2_DEV) PREFIX=$(SERVER2_V6PREFIX) PREFIXLEN=$(SERVER2_V6PREFIXLEN) RDNSSADDR=$(SERVER2_V6LLAD) conf_radvd_slacc_rdnss_slave
	make DEVICE=$(SERVER1_DEV) conf_dhcpd4
	make DEVICE=$(SERVER1_DEV) OPTIONS="" conf_dhcpd_default

	make v6_start_radvd
	make v6_stop_dhcpd
	make v4_start_dhcpd

## -------------------------------------------------------------------------
status_loop:
	while true ; do \
		make status; \
		sleep 5; \
	done

status:
	-cat status.txt
	@echo ------------------------------------------ address
	-ifconfig $(SERVER1_DEV)
	@echo ------------------------------------------ flags
	@sudo sysctl net.ipv6.conf.$(SERVER1_DEV).disable_ipv6
	@sudo sysctl net.ipv6.conf.$(SERVER1_DEV).accept_ra
	@sudo sysctl net.ipv6.conf.$(SERVER1_DEV).addr_gen_mode
	@echo ------------------------------------------ process
	-@if [ -f /var/run/radvd.pid ] ; then \
		ps axuw | grep radvd | grep -v grep; \
	fi
	-@if [ -f /var/run/dhcpd6.pid ] ; then \
		ps axuw | grep dhcpd | grep -v grep; \
	fi
	-@if [ -f /var/run/dhclient6.pid ] ; then \
		ps axuw | grep dhclient | grep -v grep; \
	fi
	@echo ------------------------------------------ routing
	route -A inet6 | grep -v `hostname`
	@echo ------------------------------------------ resolv.conf
	-cat /etc/resolv.conf


## ------------------------------------------------------------------------- sub targets
update_if:
#	-@if [ ! -f /tmp/if.inc ] ; then \
#		make __update_if; \
#	fi
#__update_if:
	make DEVICE=$(SERVER1_DEV) v6_disable_ra
	make DEVICE=$(SERVER2_DEV) v6_disable_ra

	make ADDRESS=$(SERVER1_V6ADDR)/$(SERVER1_V6PREFIXLEN) DEVICE=$(SERVER1_DEV) v6_set_address
	make ADDRESS=$(SERVER2_V6ADDR)/$(SERVER2_V6PREFIXLEN) DEVICE=$(SERVER2_DEV) v6_set_address

	@echo -n '' > /tmp/if.inc
	@echo -n 'SERVER1_V6LLAD=' >> /tmp/if.inc
	@ifconfig $(SERVER1_DEV) | grep fe80 | awk '{print $$2}' >> /tmp/if.inc
	@echo -n 'SERVER2_V6LLAD=' >> /tmp/if.inc
	@ifconfig $(SERVER2_DEV) | grep fe80 | awk '{print $$2}' >> /tmp/if.inc

## -------------------------------------------------------------------------
reset_configfile:
	sudo rm -f /etc/radvd.conf
	sudo rm -f /etc/dhcp/dhcpd6.conf
	sudo rm -f /etc/dhcp/dhcpd.conf
	sudo rm -f /etc/default/isc-dhcp-server

conf_radvd_slacc_rdnss:
	sudo sh -c "cat radvd.conf.slacc_rdnss \
	| sed -e 's/@@IFNAME@@/$(DEVICE)/g' \
	| sed -e 's/@@PREFIX_ADDR@@/$(PREFIX)::0\\/$(PREFIXLEN)/' \
	| sed -e 's/@@RDNSS_ADDR@@/$(RDNSSADDR)/' \
	>> /etc/radvd.conf"
conf_radvd_slacc_rdnss_slave:
	sudo sh -c "cat radvd.conf.slacc_rdnss \
	| sed -e 's/@@IFNAME@@/$(DEVICE)/g' \
	| sed -e 's/@@PREFIX_ADDR@@/$(PREFIX)::0\\/$(PREFIXLEN)/' \
	| sed -e 's/@@RDNSS_ADDR@@/$(RDNSSADDR)/' \
	| sed -e 's/AdvRouterAddr on;/AdvRouterAddr off;/' \
	>> /etc/radvd.conf"
conf_radvd_slacc_statelessDhcp:
	sudo sh -c "cat radvd.conf.slacc_stateless \
	| sed -e 's/@@IFNAME@@/$(DEVICE)/g' \
	| sed -e 's/@@PREFIX_ADDR@@/$(PREFIX)::0\\/$(PREFIXLEN)/' \
	>> /etc/radvd.conf"
conf_radvd_statefullDhcp:
	sudo sh -c "cat radvd.conf.statefull \
	| sed -e 's/@@IFNAME@@/$(DEVICE)/g' \
	| sed -e 's/@@PREFIX_ADDR@@/$(PREFIX)::0\\/$(PREFIXLEN)/' \
	>> /etc/radvd.conf"
conf_dhcpd6_stateless:
	sudo sh -c "cat dhcpd6.conf.stateless \
	| sed -e 's/@@IFNAME@@/$(DEVICE)/' \
	| sed -e 's/@@PREFIX@@/$(PREFIX)/g' \
	| sed -e 's/@@PREFIXLEN@@/$(PREFIXLEN)/' \
	| sed -e 's/@@NAMESERVER@@/$(NAMESERVER)/' \
	> /etc/dhcp/dhcpd6.conf"
conf_dhcpd6_statefull:
	sudo sh -c "cat dhcpd6.conf.statefull \
	| sed -e 's/@@IFNAME@@/$(DEVICE)/' \
	| sed -e 's/@@PREFIX@@/$(PREFIX)/g' \
	| sed -e 's/@@PREFIXLEN@@/$(PREFIXLEN)/' \
	| sed -e 's/@@NAMESERVER@@/$(NAMESERVER)/' \
	> /etc/dhcp/dhcpd6.conf"
conf_dhcpd4:
	sudo sh -c "cat dhcpd.conf.v4 \
	> /etc/dhcp/dhcpd.conf"

conf_dhcpd_default:
	sudo sh -c "cat isc-dhcp-server.default \
	| sed -e 's/@@IFNAME@@/$(DEVICE)/' \
	| sed -e 's/@@OPTIONS@@/$(OPTIONS)/' \
	> /etc/default/isc-dhcp-server"


## ------------------------- DHCPD (DHCP Server)
v6_stop_dhcpd:
	-@if [ -f /var/run/dhcpd6.pid ] ; then \
		sudo kill -9 `cat /var/run/dhcpd6.pid`; \
		sudo rm -f /var/run/dhcpd6.pid; \
	fi
v6_start_dhcpd:
	-@if [ -f /var/run/udhcpd.pid ] ; then \
		sudo kill -9 `cat /var/run/udhcpd.pid`; \
		sudo rm -f /var/run/udhcpd.pid; \
	fi
	-@if [ -f /var/run/dhcpd6.pid ] ; then \
		sudo kill -9 `cat /var/run/dhcpd6.pid`; \
		sudo rm -f /var/run/dhcpd6.pid; \
	fi
	sudo /usr/sbin/dhcpd -6 -q -cf /etc/dhcp/dhcpd6.conf $(SERVER1_DEV)


v4_stop_dhcpd:
	-@if [ -f /var/run/dhcpd.pid ] ; then \
		sudo kill -9 `cat /var/run/dhcpd.pid`; \
		sudo rm -f /var/run/dhcpd.pid; \
	fi
v4_start_dhcpd:
	-@if [ -f /var/run/udhcpd.pid ] ; then \
		sudo kill -9 `cat /var/run/udhcpd.pid`; \
		sudo rm -f /var/run/udhcpd.pid; \
	fi
	-@if [ -f /var/run/dhcpd.pid ] ; then \
		sudo kill -9 `cat /var/run/dhcpd.pid`; \
		sudo rm -f /var/run/dhcpd.pid; \
	fi
	sudo /usr/sbin/dhcpd -4 -q -cf /etc/dhcp/dhcpd.conf $(SERVER1_DEV)


# ## ------------------------- DHCP Client target
# client_stop:
# 	make stop_NetworkManager
# 	make v6_stop_dhcpc
# 	make v6_disable
# 
# 	@echo ------------------------------------------ $@ > status.txt
# 	@make status_loop
# 
# client_start_manual:
# 	make stop_NetworkManager
# 	make v6_stop_dhcpc
# 	make DEVICE=eth0 v6_disable
# 
# 	make v6_disable_ra
# 	make DEVICE=eth0 v6_enable
# 	make v6_disable_ra # あとから設定しないと止まらない？
# 	make v6_enable_local
# 	make ADDRESS=2030:db8:0:1::100/64 DEVICE=eth0 v6_set_address
# 
# 	@echo ------------------------------------------ $@ > status.txt
# 	@echo manual v6address 2030:db8:0:1::/64 >> status.txt
# 	@make status_loop
# 
# client_start_auto:
# 	make stop_NetworkManager
# 	make v6_stop_dhcpc
# 	make DEVICE=eth0 v6_disable
# 
# 	make DEVICE=eth0 v6_enable
# 	make v6_enable_ra
# 	make v6_enable_local
# #	sleep 1
# 
# #	make ADDRESS=2014:db8:0:1::100/64 DEVICE=eth0 v6_set_address
# 	make CONFFILE=dhclient.conf.auto DEVICE=eth0 v6_start_dhcpc
# 
# 	@echo ------------------------------------------ $@ > status.txt
# 	@echo auto v6address >> status.txt
# 	@make status_loop
# 
# client_start_disable:
# 	make stop_NetworkManager
# 	make v6_stop_dhcpc
# 	make DEVICE=eth0 v6_disable
# 
# 	@echo ------------------------------------------ $@ > status.txt
# 	@echo disable v6address >> status.txt
# 	@make status_loop
# 

# ## ------------------------- DHCP Server target
# stop:
# 	make v6_stop_dhcpd
# 	make v6_stop_radvd
# 	make DEVICE=eth0 v6_disable_ra
# 	make DEVICE=eth0 v6_disable
# 
# 	@echo ------------------------------------------ $@ > status.txt
# 	@echo linked local only >> status.txt
# 	@make status
# 
# start_slacc_rdnss:
# 	make DEVICE=eth0 v6_stop_dhcpd
# 	make DEVICE=eth0 v6_stop_radvd
# 	make DEVICE=eth0 v6_disable
# #	sleep 1
# 	make DEVICE=eth0 v6_disable_ra
# 	make DEVICE=eth0 v6_enable
# 	make DEVICE=eth0 v6_enable_router
# 	make DEVICE=eth0 v6_enable_local
# 
# 	make ADDRESS=2012:db8:0:1::100/64 DEVICE=eth0 v6_set_address
# ##	make ADDRESS=2013:db8:0:1::100/64 DEVICE=eth0 v6_del_address
# ##	make ADDRESS=2014:db8:0:1::100/64 DEVICE=eth0 v6_del_address
# ##	make ADDRESS=2015:db8:0:1::100/64 DEVICE=eth0 v6_del_address
# 
# 	make ADDRESS=3012:db8:0:1::100/64 DEVICE=eth2 v6_set_address
# ##	make ADDRESS=3013:db8:0:1::100/64 DEVICE=eth2 v6_del_address
# ##	make ADDRESS=3014:db8:0:1::100/64 DEVICE=eth2 v6_del_address
# ##	make ADDRESS=3015:db8:0:1::100/64 DEVICE=eth2 v6_del_address
# 
# 	make CONFFILE=radvd.conf.slacc_rdnss v6_start_radvd
# 
# 	@echo ------------------------------------------ $@ > status.txt
# 	@echo linked local >> status.txt
# 	@echo stateless 2012:a250:6269:600::/64 >> status.txt
# 	@echo DNS 2012:db8::1 2012:db8::2 >> status.txt
# 	@make status
# 
# start_slacc_stateless:
# 	make DEVICE=eth0 v6_stop_dhcpd
# 	make DEVICE=eth0 v6_stop_radvd
# 	make DEVICE=eth0 v6_disable
# #	sleep 1
# 	make DEVICE=eth0 v6_disable_ra
# 	make DEVICE=eth0 v6_enable
# 	make DEVICE=eth0 v6_enable_router
# 	make DEVICE=eth0 v6_enable_local
# 
# ##	make ADDRESS=2012:db8:0:1::100/64 DEVICE=eth0 v6_del_address
# 	make ADDRESS=2013:db8:0:1::100/64 DEVICE=eth0 v6_set_address
# ##	make ADDRESS=2014:db8:0:1::100/64 DEVICE=eth0 v6_del_address
# 	make ADDRESS=2015:db8:0:1::100/64 DEVICE=eth0 v6_set_address
# 
# ##	make ADDRESS=3012:db8:0:1::100/64 DEVICE=eth2 v6_del_address
# 	make ADDRESS=3013:db8:0:1::100/64 DEVICE=eth2 v6_set_address
# ##	make ADDRESS=3014:db8:0:1::100/64 DEVICE=eth2 v6_del_address
# 	make ADDRESS=3015:db8:0:1::100/64 DEVICE=eth2 v6_set_address
# 
# 	make CONFFILE6=dhcpd6.conf.stateless v6_start_dhcpd
# 	make CONFFILE=radvd.conf.slacc_stateless v6_start_radvd
# 
# 	@echo ------------------------------------------ $@ > status.txt
# 	@echo linked local >> status.txt
# 	@echo stateless 2013:db8:0:1::/64 >> status.txt
# 	@make status
# 
# start_slacc_statefull:
# 	make DEVICE=eth0 v6_stop_dhcpd
# 	make DEVICE=eth0 v6_stop_radvd
# 	make DEVICE=eth0 v6_disable
# #	sleep 1
# 	make DEVICE=eth0 v6_disable_ra
# 	make DEVICE=eth0 v6_enable
# 	make DEVICE=eth0 v6_enable_router
# 	make DEVICE=eth0 v6_enable_local
# 
# #	make ADDRESS=2012:db8:0:1::100/64 DEVICE=eth0 v6_del_address
# #	make ADDRESS=2013:db8:0:1::100/64 DEVICE=eth0 v6_del_address
# 	make ADDRESS=2014:db8:0:1::100/64 DEVICE=eth0 v6_set_address
# 	make ADDRESS=2015:db8:0:1::100/64 DEVICE=eth0 v6_set_address
# 
# #	make ADDRESS=3012:db8:0:1::100/64 DEVICE=eth2 v6_del_address
# #	make ADDRESS=3013:db8:0:1::100/64 DEVICE=eth2 v6_del_address
# 	make ADDRESS=3014:db8:0:1::100/64 DEVICE=eth2 v6_set_address
# 	make ADDRESS=3015:db8:0:1::100/64 DEVICE=eth2 v6_set_address
# 
# 	make CONFFILE6=dhcpd6.conf.statefull v6_start_dhcpd
# 	make CONFFILE=radvd.conf.slacc_statefull v6_start_radvd
# 
# 	@echo ------------------------------------------ $@ > status.txt
# 	@echo linked local >> status.txt
# 	@echo stateless 2014:db8:0:1::/64 >> status.txt
# 	@echo statefull 2015:db8:0:1::129-254/64 >> status.txt
# 	@echo DNS fec0:0:0:1::1 >> status.txt
# 	@make status
# 
# start_statefull:
# 	make DEVICE=eth0 v6_stop_dhcpd
# 	make DEVICE=eth0 v6_stop_radvd
# 	make DEVICE=eth0 v6_disable
# #	sleep 1
# 	make DEVICE=eth0 v6_disable_ra
# 	make DEVICE=eth0 v6_enable
# 	make DEVICE=eth0 v6_enable_router
# 	make DEVICE=eth0 v6_enable_local
# 
# #	make ADDRESS=2012:db8:0:1::100/64 DEVICE=eth0 v6_del_address
# #	make ADDRESS=2013:db8:0:1::100/64 DEVICE=eth0 v6_del_address
# 	make ADDRESS=2014:db8:0:1::100/64 DEVICE=eth0 v6_set_address
# 	make ADDRESS=2015:db8:0:1::100/64 DEVICE=eth0 v6_set_address
# 
# #	make ADDRESS=3012:db8:0:1::100/64 DEVICE=eth2 v6_del_address
# #	make ADDRESS=3013:db8:0:1::100/64 DEVICE=eth2 v6_del_address
# 	make ADDRESS=3014:db8:0:1::100/64 DEVICE=eth2 v6_set_address
# 	make ADDRESS=3015:db8:0:1::100/64 DEVICE=eth2 v6_set_address
# 
# 	make CONFFILE6=dhcpd6.conf.statefull v6_start_dhcpd
# 	make CONFFILE=radvd.conf.statefull v6_start_radvd
# 
# 	@echo ------------------------------------------ $@ > status.txt
# 	@echo linked local >> status.txt
# 	@echo statefull 2015:db8:0:1::129-254/64 >> status.txt
# 	@echo DNS fec0:0:0:1::1 >> status.txt
# 	@make status
# 
## ------------------------- IPV6 enable/disable
v6_enable:
	@sudo sysctl -w net.ipv6.conf.$(DEVICE).disable_ipv6=0
#	@sudo sysctl -w net.ipv6.conf.all.disable_ipv6=0
#	@sudo sysctl -w net.ipv6.conf.default.disable_ipv6=0
#	@sudo sysctl -w net.ipv6.conf.eth0.disable_ipv6=0
v6_disable:
	@sudo sysctl -w net.ipv6.conf.$(DEVICE).disable_ipv6=1
#	@sudo sysctl -w net.ipv6.conf.all.disable_ipv6=1
#	@sudo sysctl -w net.ipv6.conf.default.disable_ipv6=1
#	@sudo sysctl -w net.ipv6.conf.eth0.disable_ipv6=1

## ------------------------- IPV6 ADDRESS
v6_set_address:
	make DEVICE=$(DEVICE) v6_disable
	make DEVICE=$(DEVICE) v6_enable
	make DEVICE=$(DEVICE) v6_enable_router
	make DEVICE=$(DEVICE) v6_enable_local

#	-sudo ip -6 addr del $(ADDRESS) dev $(DEVICE) 
	sudo ip -6 addr add $(ADDRESS) dev $(DEVICE) 
v6_del_address:
	-sudo ip -6 addr del $(ADDRESS) dev $(DEVICE) 

## ------------------------- IPV6 RA recieve control
v6_enable_ra:
	@sudo sysctl -w net.ipv6.conf.$(DEVICE).accept_ra=1
#	@sudo sysctl -w net.ipv6.conf.all.accept_ra=1
#	@sudo sysctl -w net.ipv6.conf.default.accept_ra=1
#	@sudo sysctl -w net.ipv6.conf.eth0.accept_ra=1

v6_disable_ra:
	@sudo sysctl -w net.ipv6.conf.$(DEVICE).accept_ra=0
#	@sudo sysctl -w net.ipv6.conf.all.accept_ra=0
#	@sudo sysctl -w net.ipv6.conf.default.accept_ra=0
#	@sudo sysctl -w net.ipv6.conf.eth0.accept_ra=0

## ------------------------- IPV6 virtual router control
v6_enable_router:
	@sudo sysctl -w net.ipv6.conf.$(DEVICE).accept_redirects=0
	@sudo sysctl -w net.ipv6.conf.$(DEVICE).forwarding=1

v6_disable_router:
	@sudo sysctl -w net.ipv6.conf.$(DEVICE).accept_redirects=1
	@sudo sysctl -w net.ipv6.conf.$(DEVICE).forwarding=0

## ------------------------- IPV6 RA recieve control
## https://ktaka.blog.ccmp.jp/2020/05/linuxslaac-ipv6.html
v6_enable_local:
	@sudo sysctl -w net.ipv6.conf.$(DEVICE).addr_gen_mode=0	# RFC4291
#	sleep 3
v6_disable_local:
	@sudo sysctl -w net.ipv6.conf.$(DEVICE).addr_gen_mode=1	# disable
v6_enable_local2:
#	echo "::" > /proc/sys/net/ipv6/conf/eth0/stable_secret
	@sudo sysctl -w net.ipv6.conf.$(DEVICE).stable_secret="::"
	@sudo sysctl -w net.ipv6.conf.$(DEVICE).addr_gen_mode=2	# RFC7217, must be set secret_key
#	sleep 3
v6_enable_local3:
	@sudo sysctl -w net.ipv6.conf.$(DEVICE).addr_gen_mode=3	# RFC7217, secret_key set by user or random generate.
#	sleep 3



## ------------------------- RADVD (RA daemon)
v6_stop_radvd:
	-sudo systemctl stop radvd

v6_start_radvd:
	-sudo systemctl stop radvd
##	sudo cp $(CONFFILE) /etc/radvd.conf
	sudo systemctl start radvd

## ------------------------- dhcp client
v6_stop_dhcpc:
	-sudo systemctl stop dhcpcd.service
	-@if [ -f /var/run/dhclient6.pid ] ; then \
		sudo kill -9 `cat /var/run/dhclient6.pid`; \
		sudo rm -f /var/run/dhclient6.pid; \
	fi
	-sudo killall dhclient
v6_start_dhcpc:
	-sudo systemctl stop dhcpcd.service
#	-sudo killall dhclient
	-@if [ -f /var/run/dhclient6.pid ] ; then \
		sudo kill -9 `cat /var/run/dhclient6.pid`; \
		sudo rm -f /var/run/dhclient6.pid; \
	fi

	sudo mkdir -p /tmp/dhclient6
	sudo cp $(CONFFILE) /tmp/dhclient6/dhclient6.conf

# start foreground debug
#	sudo /sbin/dhclient -6 -d eth0
# start background
#	sudo /sbin/dhclient -6 -nw eth0

#	sudo /sbin/dhclient -d -6 -sf /sbin/dhclient-script -cf /tmp/dhclient6/dhclient6.conf -lf /tmp/dhclient6/dhclient6.leases -pf /var/run/dhclient6.pid eth0
	sudo /sbin/dhclient -nw -6 -sf /sbin/dhclient-script -cf /tmp/dhclient6/dhclient6.conf -lf /tmp/dhclient6/dhclient6.leases -pf /var/run/dhclient6.pid eth0

## ------------------------- 
v4_set_addr1:
	-sudo ip -4 addr add 192.168.1.50 dev eth0 
v4_set_addr2:
	-sudo ip -4 addr add 192.168.1.51 dev eth0 

## ------------------------- 
stop_NetworkManager:
	sudo systemctl stop NetworkManager.service

## ------------------------- 
setup:
	sudo apt update
	sudo apt install isc-dhcp-server		# DHCPサーバー
	sudo apt install isc-dhcp-client		# DHCPクライアント
	sudo apt install radvd radvdump			# ルーター通知デーモン
##	sudo apt install zebra				# ルーティングデーモン


### EQ1
#
# > dhclient -nw eth0
#
# Internet Systems Consortium DHCP Client 4.2.3-P2
# Usage: dhclient [-4|-6] [-SNTP1dvrx] [-nw] [-p <port>] [-D LL|LLT]
#                [-s server-addr] [-cf config-file] [-lf lease-file]
#                [-pf pid-file] [--no-pid] [-e VAR=val]
#                [-sf script-file] [interface]

