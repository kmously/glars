#!/bin/bash

##################################################################################################
##################################################################################################
#                                                               
#
#                            +-----------------------------------------------+
#                            |                                               |
#                            |  +----------------+                           |
#                            |  |                |                           |
#                            |  |  $INTERNAL_IF  |                           |
#                            |  |                |                           |
#                            |  |   +-------+    |                           |
#                            |  |   |       |    |                           |
#                            |  |   | eth0  |    |                           |
#                            |  |   |       |    |                           |
#                            |  |   +-------+    |     +-----------------+   |
#                            |  |       +        |     |                 |   |
#                            |  |   +-------+    |     |                 +-------------->
#                    +---------->   |       |    |     |   $EXTERNAL_IF  |   |          Internet
#       Local Network        |  |   | wlan0 |    |     |                 <--------------+
#                    <----------+   |       |    |     |                 |   |
#                            |  |   +-------+    |     +-----------------+   |
#                            |  |       +        |                           |
#                            |  |   +-------+    |                           |
#                            |  |   |       |    |                           |
#                            |  |   | tap0  |    |                           |
#                            |  |   |       |    |                           |
#                            |  |   +-------+    |                           |
#                            |  |                |                           |
#                            |  |   ...etc.      |                           |
#                            |  |                |                           |
#                            |  +----------------+                           |
#                            |                                               |
#                            +-----------------------------------------------+
#                                                                                              
#                                                                                              
##################################################################################################
##################################################################################################




BOLD=1
GREY="\033[$BOLD;30m"
RED="\033[$BOLD;31m"
GREEN="\033[$BOLD;32m"
YELLOW="\033[$BOLD;33m"
BLUE="\033[$BOLD;34m"
PINK="\033[$BOLD;35m"
CYAN="\033[$BOLD;36m"
WHITE="\033[$BOLD;37m"

# Comment out these 2 vars if you dont want colors in the output
COLOR=$GREEN
COLOREND="\033[0m"

# This is the interface that's connected to the Internet
EXTERNAL_IF=eth1

# This is the interface that is connected to the internal network
# If you are bridging multiple interfaces (wifi, VPN, etc.), then
# use the bridge interface here.
# The bridge must exist BEFORE running this script
INTERNAL_IF=br0

# Define local subnet here
# It is better to avoid common subnets, like 
#
# 192.168.0.0/24
# 192.168.1.0/24
# 192.168.10.0/24
# 192.168.100.0/24
#
# ..to minimize chances of collision when setting up a VPN
LOCAL_SUBNET=192.168.31.0/24


# This is our public (external) IP
# It can be explicitly specified if you know it in advance, or it can be 
# queried, using for example 'ifconfig' or 'ip addr'
PUBLIC_IP=$(ifconfig $EXTERNAL_IF|grep inet.*netmas|sed -e "s/netmask.*//g"|sed -e "s/.*inet.//g"|sed -e "s/ *//g")



# (Optional) Specify text file containing blacklisted IPs
# The file must contain ONLY IP ranges in CIDR notation
#
# e.g. w.x.y.z/24
#
# To ban a single IP, use /32 subnet
#
# One CIDR IP per line, no comments or anything else allowed
# You can use as many as you want, they won't affect iptables rules
# and will be efficiently matched.
#
IP_BLACKLIST_FILE=/etc/glars/blacklist


#
# (Optional) Specify a rules file
#
# Advanced functionality and non-default settings, such as port forwarding,
# and bandwidth control can be specified in $RULES_FILE
# All variables declared above can also be overridden in $RULES_FILE
# The $RULES_FILE must a setup_rules_and_policies() function
# See the example rules files for more information on how to write a $RULES_FILE
#

RULES_FILE=/etc/glars/rules


                                  





































########################################################
#
# You don't need to look at the stuff below,
# unless you want to see how the sausage is made
#
########################################################




































































function clear_all_configurations {
	echo -en "Resetting all configurations (iptables, tc and ipset)..."
	iptables -F -t nat
	iptables -F
	tc qdisc del dev $INTERNAL_IF root
	tc qdisc del dev $EXTERNAL_IF root
	ipset -F
	ipset -X
	echo -e "done"
}


#
# This function must be called once for each of 'upload' and 'download'.
# It must be called after the 'upload|download' matrix has been declared,
# but before any 'upload|download' classify_* functions are called
#
function initialize_bw_classes {
#	$1  'upload' or 'download'

	if [ "$1" = "upload" ] ; then
		# The following syntax means CLASSES is an array () 
		# made up of the expanded expression ${} that is the 
		# set of everything * in the array UPLOAD_CLASSES
		CLASSES=(${UPLOAD_CLASSES[*]})
		CLASSES_SIZE=${#UPLOAD_CLASSES[*]};
		IFACE=$EXTERNAL_IF
		CEIL=$UPLOAD_CEIL
	elif [ "$1" = "download" ]; then
		# The following syntax means CLASSES is an array () 
		# made up of the expanded expression ${} that is the 
		# set of everything * in the array DOWNLOAD_CLASSES
		CLASSES=(${DOWNLOAD_CLASSES[*]})
		CLASSES_SIZE=${#DOWNLOAD_CLASSES[*]};
		IFACE=$INTERNAL_IF
		CEIL=$DOWNLOAD_CEIL
	fi


	tc qdisc add dev $IFACE root handle 1: htb default 10
	tc class add dev $IFACE parent 1: classid 1:1 htb ceil ${CEIL}kbit rate ${CEIL}kbit

	for ((i=0;i<$CLASSES_SIZE;i+=4)); do
		tc class add dev $IFACE parent 1:1 classid ${CLASSES[$i]} htb prio ${CLASSES[$i+1]} rate $[CEIL * ${CLASSES[$i+2]}/100]kbit ceil $[CEIL * ${CLASSES[$i+3]}/100]kbit
		tc qdisc add dev $IFACE parent ${CLASSES[$i]} handle "$i"0 sfq perturb 40
	done

	printf "\t%12s %12s %12s %12s\n" "ID" "Prio" "Min %" "Max %"
	for ((i=0;i<$CLASSES_SIZE;i+=4)); do
		printf "\t$COLOR%12s %12s %12s %12s $COLOREND\n" "${CLASSES[$i]}" "${CLASSES[$i+1]}" "${CLASSES[$i+2]}" "${CLASSES[$i+3]}"
	done
	printf "\n"
}



#
# Enables forwarding and NAT
#
function setup_gateway {
	# Enable forwarding in the kernel
	echo -en "Setting up NAT and packet forwarding..."
	echo 1 > /proc/sys/net/ipv4/ip_forward

	# MASQUERADE traffic leaving out on $EXTERNAL_IF 
	# as well as traffic leaving out on $INTERNAL_IF if it's from 
	# $LOCAL_SUBNET. The second rule is needed so that internal 
	# hosts can connect to internal servers using the public IP
	# e.g. smtp.domain.com:25
	iptables -t nat -A POSTROUTING -o $EXTERNAL_IF -j MASQUERADE
	iptables -t nat -A POSTROUTING -o $INTERNAL_IF -s $LOCAL_SUBNET -j MASQUERADE
	echo -e "done"
}



# Classify download traffic to a particular host on the network
# to control bandwidth usage
function classify_download_by_host {
#	$1 = host or subnet
#	$2 = class
	printf "\t(dest ip)$COLOR  %30s $COLOREND ------> $COLOR $2 $COLOREND\n" "$1"
	iptables -A FORWARD -o $INTERNAL_IF -d $1 -j CLASSIFY --set-class $2
	}


# Classify download traffic from a particular host on the Internet
# to control bandwidth usage
function classify_download_from_host {
#	$1 = host or subnet
#	$2 = class
	printf "\t(source ip)$COLOR  %28s $COLOREND ------> $COLOR $2 $COLOREND\n" "$1"
	iptables -A FORWARD -o $INTERNAL_IF -s $1 -j CLASSIFY --set-class $2
	}



# Classify download traffic from a specific (remote) port
# to control bandwidth usage
function classify_download_from_port {
#	$1 = tcp or udp
#	$2 = port
#	$3 = class
	printf "\t(source port)$COLOR  %26s $COLOREND ------> $COLOR $3 $COLOREND\n" "($1) :$2"
	iptables -A FORWARD -o $INTERNAL_IF -p $1 --sport $2 -j CLASSIFY --set-class $3
	}


# Classify upload traffic from a particular host on the network
# to control bandwidth usage
function classify_upload_from_host {
#	$1 = host or subnet
#	$2 = class
	printf "\t(source ip)$COLOR  %28s $COLOREND ------> $COLOR $2 $COLOREND\n" "$1"
	iptables -A FORWARD -o $EXTERNAL_IF -s $1 -j CLASSIFY --set-class $2
	}


# Classify upload traffic from a specific (local) port
# to control bandwidth usage
function classify_upload_from_port {
#	$1 = tcp or udp
#	$2 = source port
#	$3 = class
	printf "\t(source port)$COLOR  %26s $COLOREND ------> $COLOR $3 $COLOREND\n" "($1) :$2"
	iptables -A FORWARD -o $EXTERNAL_IF -p $1 --sport $2 -j CLASSIFY --set-class $3
	iptables -A FORWARD -o $EXTERNAL_IF -p $1 --sport $2 -j RETURN
	}


# Classifies router-generated (not forwarded) traffic-to-WAN
# It is recommended to keep a minimum bandwidth for this so router is 
# always reachable from WAN-side
function classify_traffic_to_wan {
#	$1 class
	printf "%50s ------> $COLOR $1 $COLOREND\n" "(Router-to-WAN traffic)"
	iptables -A OUTPUT -o $EXTERNAL_IF  -j CLASSIFY --set-class $1
}

# Classifies router-generated (not forwarded) traffic-to-LAN
# It is recommended to keep a minimum bandwidth for this so router is 
# always reachable from LAN-side
function classify_traffic_to_lan {
#	$1 class
	printf "%50s ------> $COLOR $1 $COLOREND\n" "(Router-to-LAN traffic)"
	iptables -A OUTPUT -o $INTERNAL_IF  -j CLASSIFY --set-class $1
}


 
# Forwards a public port to an internal host:port
# Each forwarded port requires two iptables rules:
# 1) for redirecting traffic coming from the outside (on $EXTERNAL_IF) 
#    to internal service
# 2) for redirecting traffic coming from the inside (on $INTERNAL_IF) 
#    to our public (external) IP.
# The second rule is needed so that internal 
# hosts can connect to internal servers using the public IP/domain
# e.g. smtp.domain.com:25
function forward {
#	$1 = tcp or udp
#	$2 = EXTERNAL PORT
#	$3 = INTERNAL DESTINATION (IP:PORT)
        printf "\tforwarding port$COLOR %25s $COLOREND ------> $COLOR %s $COLOREND\n" "($1)  :$2" "$3"
	iptables -t nat -A PREROUTING -p $1 -i $EXTERNAL_IF --dport $2 -j DNAT --to-destination $3
	iptables -t nat -A PREROUTING -i $INTERNAL_IF -s $LOCAL_SUBNET -d $PUBLIC_IP -p $1 --dport $2 -j DNAT --to-destination $3
}



# Duplicate a port on EXTERNAL_IF
function duplicate_port {
#	$1 = tcp or udp
#	$2 = (external) port
#	$3 = port to which $2 should be duplicated
        printf "\tDuplicating (public) port$COLOR %15s $COLOREND ------> $COLOR %s $COLOREND\n" "($1)  :$2" "$3"
	iptables -t nat -A PREROUTING -i $EXTERNAL_IF -p $1 --dport $3 -j REDIRECT --to-port $2
	iptables -t nat -A PREROUTING -i $INTERNAL_IF -p $1 -s $LOCAL_SUBNET --dport $3 -j REDIRECT --to-port $2
}



# Limit number of incoming connections to
# our ports
# This only affects connections to the router itself
# If you want to limit connections on a forwarded port, use
# limit_connections_to_internal_host() or limit_connections_to_internal_port()
function limit_connections_to_public_port {
#	$1 tcp or udp
#	$2 port to ratelimit
#	$3 ratelimit
	printf "\tlimiting (public port)$COLOR %18s $COLOREND ------> $COLOR $3 $COLOREND\n" "($1)  :$2"
	iptables -A INPUT -i $EXTERNAL_IF -m hashlimit -p $1 --dport $2 --hashlimit $3 --hashlimit-mode srcip --hashlimit-name ssh -m state --state new -j ACCEPT
	iptables -A INPUT -i $EXTERNAL_IF -p $1 --dport $2 -m state --state NEW -j DROP
}

# Limit incoming connections to a host on the network
#
# Note: You cannot limit connections to a HOST on the network by doing:
#
# limit_connections_to_port tcp x 1/min
# limit_connections_to_port tcp y 1/min
# ...etc
#
# even if x and y are the only ports that are forwarded to HOST
#
# That is because NAT processing is done before INPUT processing
# In other words, the traffic will be forwarded before the INPUT chain
# is even checked, so the rules will have no effect.
# 
# To limit connections to internal hosts, the limiting must be done
# on the FORWARD chain.
#
function limit_connections_to_internal_host {
#	$1 host to protect
#	$2 ratelimit of allowed connections to host
	printf "\tlimiting (dest host)$COLOR %20s $COLOREND ------> $COLOR $2 $COLOREND\n" "$1"
	iptables -A FORWARD -m hashlimit -p tcp -d $1 ! -s $LOCAL_SUBNET --hashlimit $2 --hashlimit-mode dstip --hashlimit-name "connections_to_host_$1" -m state --state new -j ACCEPT
	iptables -A FORWARD -p tcp -d $1 ! -s $LOCAL_SUBNET -m state --state NEW -j DROP
}

#
# Limit incoming connections to a forwarded port on the network
#
function limit_connections_to_internal_port {
#	$1 tcp or udp
#	$2 port to protect
#	$3 ratelimit of allowed connections to internal port
	printf "\tlimiting (private port)$COLOR %17s $COLOREND ------> $COLOR $3 $COLOREND\n" "($1)  :$2"
	iptables -A FORWARD -m hashlimit -p $1 --dport $2 -d $LOCAL_SUBNET ! -s $LOCAL_SUBNET --hashlimit $3 --hashlimit-mode dstip --hashlimit-name "connections_to_forwarded_port_$1_$2" -m state --state new -j ACCEPT
	iptables -A FORWARD -p $1 --dport $2 -d $LOCAL_SUBNET ! -s $LOCAL_SUBNET -m state --state new -j DROP
}

function setup_blacklist {
	IP_COUNT=0
	# Ignore blacklisted IPs
	if [[ -f "$IP_BLACKLIST_FILE" ]]; then
		echo -en "Setting blacklist from $COLOR $IP_BLACKLIST_FILE $COLOREND..."
		ipset -N banned_ips nethash
		iptables -A INPUT -i $EXTERNAL_IF -m set --match-set banned_ips src -j DROP
		for i in `cat $IP_BLACKLIST_FILE`; do 
			# echo "Blacklisting $i"
			IP_COUNT=$(($IP_COUNT+1))
			ipset -A banned_ips $i
		done;
		echo "done - $IP_COUNT IP subnets blacklisted"
	else
		echo -e "No blacklist file -- skipping blacklist setup"
	fi;
}








function main {
	echo -e \
"
$COLOR
┏━╸╻  ┏━┓┏━┓┏━┓   ╻ ╻╺┓  ┏━┓
┃╺┓┃  ┣━┫┣┳┛┗━┓   ┃┏┛ ┃  ┃┃┃
┗━┛┗━╸╹ ╹╹┗╸┗━┛   ┗┛ ╺┻╸╹┗━┛
$COLOREND
"
	if [[ -f "$RULES_FILE" ]]; then
		source $RULES_FILE
	fi;

	printf "Our public IP address is:$COLOR%20s $COLOREND\n" "$PUBLIC_IP"

	clear_all_configurations;

	setup_gateway;

	setup_blacklist;

	if [[ -f "$RULES_FILE" ]]; then
		setup_rules_and_policies;
	else
		printf "No rules specified\n"
	fi;
}

main;
