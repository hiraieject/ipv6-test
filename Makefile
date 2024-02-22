-include /tmp/if.inc

ETH0V6PREFIX=2010:db8:0:1
ETH1V6PREFIX=2110:db8:0:1
#ETH2V6PREFIX=2210:db8:0:1
#ETH3V6PREFIX=2310:db8:0:1
#ETH4V6PREFIX=2410:db8:0:1
#ETH5V6PREFIX=2510:db8:0:1
#ETH6V6PREFIX=2610:db8:0:1
#ETH7V6PREFIX=2710:db8:0:1

ETH0V6PREFIXLEN=64
ETH1V6PREFIXLEN=64
#ETH2V6PREFIXLEN=64
#ETH3V6PREFIXLEN=64
#ETH4V6PREFIXLEN=64
#ETH5V6PREFIXLEN=64
#ETH6V6PREFIXLEN=64
#ETH7V6PREFIXLEN=64

ETH0V6ADDR=$(ETH0V6PREFIX)::1
ETH1V6ADDR=$(ETH1V6PREFIX)::1
#ETH2V6ADDR=$(ETH2V6PREFIX)::1
#ETH3V6ADDR=$(ETH3V6PREFIX)::1
#ETH4V6ADDR=$(ETH4V6PREFIX)::1
#ETH5V6ADDR=$(ETH5V6PREFIX)::1
#ETH6V6ADDR=$(ETH6V6PREFIX)::1
#ETH7V6ADDR=$(ETH7V6PREFIX)::1

ETH0V6LLAD=$(ETH0V6PREFIX)::1
ETH1V6LLAD=$(ETH1V6PREFIX)::1
#ETH2V6LLAD=$(ETH2V6PREFIX)::1
#ETH3V6LLAD=$(ETH3V6PREFIX)::1
#ETH4V6LLAD=$(ETH4V6PREFIX)::1
#ETH5V6LLAD=$(ETH5V6PREFIX)::1
#ETH6V6LLAD=$(ETH6V6PREFIX)::1
#ETH7V6LLAD=$(ETH7V6PREFIX)::1

.PHONY: help

help:
	@echo make start_StatefullDhcp
	@echo make start_StatelessDhcp
	@echo make start_StatelessRdnss
	@echo make start_StatelessRdnss_StatefullDHCP
	@echo make start_StatelessRdnssX2
	@echo make status_loop
	@echo make status
	@echo make
	@echo make dump

log:
	journalctl -xe
dump:
	sudo radvdump

## ------------------------------------------------------------------------- main targets
start_StatefullDhcp:
	make update_if
	make reset_configfile

#DHCPv6 v6 address and DNS address
	make DEVICE=eth0 PREFIX=$(ETH0V6PREFIX) PREFIXLEN=$(ETH0V6PREFIXLEN) conf_radvd_statefullDhcp
	make DEVICE=eth0 PREFIX=$(ETH0V6PREFIX) PREFIXLEN=$(ETH0V6PREFIXLEN) NAMESERVER=$(ETH0V6ADDR) conf_dhcpd6_statefull
	make DEVICE=eth0 conf_dhcpd4
	make DEVICE=eth0 OPTIONS="" conf_dhcpd_default

	make v6_start_radvd
	make v6_start_dhcpd
	make v4_start_dhcpd

start_StatelessDhcp:
	make update_if
	make reset_configfile

#Slacc v6 address + DHCPv6 DNS server address
	make DEVICE=eth0 PREFIX=$(ETH0V6PREFIX) PREFIXLEN=$(ETH0V6PREFIXLEN) conf_radvd_slacc_statelessDhcp
	make DEVICE=eth0 PREFIX=$(ETH0V6PREFIX) PREFIXLEN=$(ETH0V6PREFIXLEN) NAMESERVER=$(ETH0V6ADDR) conf_dhcpd6_stateless
	make DEVICE=eth0 conf_dhcpd4
	make DEVICE=eth0 OPTIONS="" conf_dhcpd_default

	make v6_start_radvd
	make v6_start_dhcpd
	make v4_start_dhcpd

start_StatelessRdnss:
	make update_if
	make reset_configfile

#Slacc v6 address / RDNSS DNS server address
	make DEVICE=eth0 PREFIX=$(ETH0V6PREFIX) PREFIXLEN=$(ETH0V6PREFIXLEN) RDNSSADDR=$(ETH0V6LLAD) conf_radvd_slacc_rdnss
	make DEVICE=eth0 conf_dhcpd4
	make DEVICE=eth0 OPTIONS="" conf_dhcpd_default

	make v6_start_radvd
	make v6_stop_dhcpd
	make v4_start_dhcpd

start_StatelessRdnss_StatefullDHCP:
	make update_if
	make reset_configfile

#DHCPv6 v6 address and DNS address
	make DEVICE=eth0 PREFIX=$(ETH0V6PREFIX) PREFIXLEN=$(ETH0V6PREFIXLEN) conf_radvd_statefullDhcp
	make DEVICE=eth0 PREFIX=$(ETH0V6PREFIX) PREFIXLEN=$(ETH0V6PREFIXLEN) NAMESERVER=$(ETH0V6ADDR) conf_dhcpd6_statefull

#Slacc v6 address / RDNSS DNS server address
	make DEVICE=eth1 PREFIX=$(ETH1V6PREFIX) PREFIXLEN=$(ETH1V6PREFIXLEN) RDNSSADDR=$(ETH1V6LLAD) conf_radvd_slacc_rdnss

	make DEVICE=eth0 conf_dhcpd4
	make DEVICE=eth0 OPTIONS="" conf_dhcpd_default

	make v6_start_radvd
	make v6_stop_dhcpd
	make v4_start_dhcpd

start_StatelessRdnssX2:
	make update_if
	make reset_configfile

#Slacc v6 address / RDNSS DNS server address
	make DEVICE=eth0 PREFIX=$(ETH0V6PREFIX) PREFIXLEN=$(ETH0V6PREFIXLEN) RDNSSADDR=$(ETH0V6LLAD) conf_radvd_slacc_rdnss
	make DEVICE=eth1 PREFIX=$(ETH1V6PREFIX) PREFIXLEN=$(ETH1V6PREFIXLEN) RDNSSADDR=$(ETH1V6LLAD) conf_radvd_slacc_rdnss_slave
	make DEVICE=eth0 conf_dhcpd4
	make DEVICE=eth0 OPTIONS="" conf_dhcpd_default

	make v6_start_radvd
	make v6_stop_dhcpd
	make v4_start_dhcpd

#start_StatelessRdnssX8:
#	make update_if
#	make reset_configfile
#
##Slacc v6 address / RDNSS DNS server address
#	make DEVICE=eth0 PREFIX=$(ETH0V6PREFIX) PREFIXLEN=$(ETH0V6PREFIXLEN) RDNSSADDR=$(ETH0V6LLAD) conf_radvd_slacc_rdnss
#	make DEVICE=eth1 PREFIX=$(ETH1V6PREFIX) PREFIXLEN=$(ETH1V6PREFIXLEN) RDNSSADDR=$(ETH1V6LLAD) conf_radvd_slacc_rdnss
#	make DEVICE=eth2 PREFIX=$(ETH2V6PREFIX) PREFIXLEN=$(ETH2V6PREFIXLEN) RDNSSADDR=$(ETH2V6LLAD) conf_radvd_slacc_rdnss
#	make DEVICE=eth3 PREFIX=$(ETH3V6PREFIX) PREFIXLEN=$(ETH3V6PREFIXLEN) RDNSSADDR=$(ETH3V6LLAD) conf_radvd_slacc_rdnss
#	make DEVICE=eth4 PREFIX=$(ETH4V6PREFIX) PREFIXLEN=$(ETH4V6PREFIXLEN) RDNSSADDR=$(ETH4V6LLAD) conf_radvd_slacc_rdnss
#	make DEVICE=eth5 PREFIX=$(ETH5V6PREFIX) PREFIXLEN=$(ETH5V6PREFIXLEN) RDNSSADDR=$(ETH5V6LLAD) conf_radvd_slacc_rdnss
#	make DEVICE=eth6 PREFIX=$(ETH6V6PREFIX) PREFIXLEN=$(ETH6V6PREFIXLEN) RDNSSADDR=$(ETH6V6LLAD) conf_radvd_slacc_rdnss
#	make DEVICE=eth7 PREFIX=$(ETH7V6PREFIX) PREFIXLEN=$(ETH7V6PREFIXLEN) RDNSSADDR=$(ETH7V6LLAD) conf_radvd_slacc_rdnss
#	make DEVICE=eth0 conf_dhcpd4
#	make DEVICE=eth0 OPTIONS="" conf_dhcpd_default
#
#	make v6_start_radvd
#	make v6_stop_dhcpd
#	make v4_start_dhcpd

## -------------------------------------------------------------------------
status_loop:
	while true ; do \
		make status; \
		sleep 5; \
	done

status:
	-cat status.txt
	@echo ------------------------------------------ address
	-ifconfig eth0
	@echo ------------------------------------------ flags
	@sudo sysctl net.ipv6.conf.eth0.disable_ipv6
	@sudo sysctl net.ipv6.conf.eth0.accept_ra
	@sudo sysctl net.ipv6.conf.eth0.addr_gen_mode
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
	-@if [ ! -f /tmp/if.inc ] ; then \
		make __update_if; \
	fi
__update_if:
	make DEVICE=eth0 v6_disable_ra
#	make DEVICE=eth1 v6_disable_ra
#	make DEVICE=eth2 v6_disable_ra
#	make DEVICE=eth3 v6_disable_ra
#	make DEVICE=eth4 v6_disable_ra
#	make DEVICE=eth5 v6_disable_ra
#	make DEVICE=eth6 v6_disable_ra
#	make DEVICE=eth7 v6_disable_ra

	make ADDRESS=$(ETH0V6ADDR)/$(ETH0V6PREFIXLEN) DEVICE=eth0 v6_set_address
#	make ADDRESS=$(ETH1V6ADDR)/$(ETH1V6PREFIXLEN) DEVICE=eth1 v6_set_address
#	make ADDRESS=$(ETH2V6ADDR)/$(ETH2V6PREFIXLEN) DEVICE=eth2 v6_set_address
#	make ADDRESS=$(ETH3V6ADDR)/$(ETH3V6PREFIXLEN) DEVICE=eth3 v6_set_address
#	make ADDRESS=$(ETH4V6ADDR)/$(ETH4V6PREFIXLEN) DEVICE=eth4 v6_set_address
#	make ADDRESS=$(ETH5V6ADDR)/$(ETH5V6PREFIXLEN) DEVICE=eth5 v6_set_address
#	make ADDRESS=$(ETH6V6ADDR)/$(ETH6V6PREFIXLEN) DEVICE=eth6 v6_set_address
#	make ADDRESS=$(ETH7V6ADDR)/$(ETH7V6PREFIXLEN) DEVICE=eth7 v6_set_address

	@echo -n '' > /tmp/if.inc
	@echo -n 'ETH0V6LLAD=' >> /tmp/if.inc
	@ifconfig eth0 | grep fe80 | awk '{print $$2}' >> /tmp/if.inc
	@echo -n 'ETH1V6LLAD=' >> /tmp/if.inc
	@ifconfig eth1 | grep fe80 | awk '{print $$2}' >> /tmp/if.inc
	@echo -n 'ETH2V6LLAD=' >> /tmp/if.inc
	@ifconfig eth2 | grep fe80 | awk '{print $$2}' >> /tmp/if.inc
	@echo -n 'ETH3V6LLAD=' >> /tmp/if.inc
	@ifconfig eth3 | grep fe80 | awk '{print $$2}' >> /tmp/if.inc
#	@echo -n 'ETH4V6LLAD=' >> /tmp/if.inc
#	@ifconfig eth4 | grep fe80 | awk '{print $$2}' >> /tmp/if.inc
#	@echo -n 'ETH5V6LLAD=' >> /tmp/if.inc
#	@ifconfig eth5 | grep fe80 | awk '{print $$2}' >> /tmp/if.inc
#	@echo -n 'ETH6V6LLAD=' >> /tmp/if.inc
#	@ifconfig eth6 | grep fe80 | awk '{print $$2}' >> /tmp/if.inc
#	@echo -n 'ETH7V6LLAD=' >> /tmp/if.inc
#	@ifconfig eth7 | grep fe80 | awk '{print $$2}' >> /tmp/if.inc

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
	sudo /usr/sbin/dhcpd -6 -q -cf /etc/dhcp/dhcpd6.conf eth0


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
	sudo /usr/sbin/dhcpd -4 -q -cf /etc/dhcp/dhcpd.conf eth0


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

