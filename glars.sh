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





# $EXTERNAL_IF is the interface that's connected to the Internet
EXTERNAL_IF=eth1



# $INTERNAL_IF is the interface that is connected to the internal network
# If you are bridging multiple interfaces on the LAN side (wifi, VPN, etc.), then
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
# It can be explicitly specified here if it is a static IP, or it can be 
# queried from the $EXTERNAL_IF, using for example 'ifconfig' or 'ip addr'
# if it is a dynamically assigned IP
PUBLIC_IP=$(ifconfig $EXTERNAL_IF|grep inet.*netmas|sed -e "s/netmask.*//g"|sed -e "s/.*inet.//g"|sed -e "s/ *//g")



# (Optional) Specify a rules file
#
# Advanced functionality and settings, such as port forwarding,
# and bandwidth control can be specified in $RULES_FILE
# All variables declared above can also be overridden in $RULES_FILE
# The $RULES_FILE must define a function called setup_rules_and_policies()
# See the example rules files for more information on how to use rules files.
RULES_FILE=/etc/glars/rules



# (Optional) Specify text file containing blacklisted IPs
# The file must contain IP ranges in CIDR notation
#
# e.g. w.x.y.z/24
#
# To ban a single IP, use /32 subnet or don't specify a subnet
#
# One CIDR IP per line
# Empty lines are allowed
# Lines starting with # are ignored
#
# You can use as many IPs/subnets as you want, they won't affect iptables rules
# and will be efficiently matched.
#
IP_BLACKLIST_FILE=/etc/glars/blacklist



# (Optional) Specify text file containing whitelisted IPs
# The file must contain IP ranges in CIDR notation
#
# e.g. w.x.y.z/24
#
# To ban a single IP, use /32 subnet or don't specify a subnet
#
# One CIDR IP per line
# Empty lines are allowed
# Lines starting with # are ignored
#
# You can use as many IPs/subnets as you want, they won't affect iptables rules
# and will be efficiently matched.
#
# The whitelist entries override the blacklist entries
# (so an IP that is both whitelisted and blacklisted is effectively whitelisted)
IP_WHITELIST_FILE=/etc/glars/whitelist



# (Optional) Enable kernel logging
# ('dmesg|grep GLARS' to see logs)
LOG=1



# (Optional) Set COLOR to one of
#
# green pink red blue yellow cyan white
#
# or unset it if you don't want colors in the output
COLOR=random



# (Optional) Set to 1 if you want BOLD in the output
# Set to 0 if you do not want BOLD in the output
# Set to 'random' if you're an extreme person who loves living on the edge
BOLD=random










































































########################################################
#
# You don't need to look beyond here,
# unless you want to see how the sausage is made
#
########################################################


























































































if [ "$BOLD" = "random" ] ; then
	NUM=$(( RANDOM % 2  ))
	case "$NUM" in
	0) BOLD=1
	    ;;
	1) BOLD=0
	    ;;
	esac
fi






RED="\033[$BOLD;31m"
GREEN="\033[$BOLD;32m"
YELLOW="\033[$BOLD;33m"
BLUE="\033[$BOLD;34m"
PINK="\033[$BOLD;35m"
CYAN="\033[$BOLD;36m"
WHITE="\033[$BOLD;37m"

COLOREND="\033[0m"



if [ "$COLOR" = "random" ] ; then
	NUM=$(( RANDOM % 7 ))
	case "$NUM" in
	0)
	COLOR=$WHITE
	    ;;
	1)
	COLOR=$RED
	    ;;
	2)
	COLOR=$GREEN
	    ;;
	3)
	COLOR=$YELLOW
	    ;;
	4)
	COLOR=$BLUE
	    ;;
	5)
	COLOR=$PINK
	    ;;
	6)
	COLOR=$CYAN
	    ;;
	esac
else

	if [ "$COLOR" = "green" ] ; then
		COLOR=$GREEN
	elif [ "$COLOR" = "red" ] ; then
		COLOR=$RED
	elif [ "$COLOR" = "yellow" ] ; then
		COLOR=$YELLOW
	elif [ "$COLOR" = "blue" ] ; then
		COLOR=$BLUE
	elif [ "$COLOR" = "pink" ] ; then
		COLOR=$PINK
	elif [ "$COLOR" = "cyan" ] ; then
		COLOR=$CYAN
	elif [ "$COLOR" = "white" ] ; then
		COLOR=$WHITE
	fi;


fi;







UPLOAD_CLASSES_HAVE_BEEN_INITIALIZED=0
DOWNLOAD_CLASSES_HAVE_BEEN_INITIALIZED=0






function clear_all_configurations {
	echo -en "Resetting all configurations (iptables, tc and ipset)..."
	iptables -F
	iptables -F -t nat
	iptables -X 
	iptables -t nat -X
	ipset -F
	ipset -X
	tc qdisc del dev $INTERNAL_IF root
	tc qdisc del dev $EXTERNAL_IF root
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
		UPLOAD_CLASSES_HAVE_BEEN_INITIALIZED=1
		printf "\n\tUpload ceiling is $COLOR %s $COLOREND kbit/s\n\n" "$CEIL"
	elif [ "$1" = "download" ]; then
		# The following syntax means CLASSES is an array () 
		# made up of the expanded expression ${} that is the 
		# set of everything * in the array DOWNLOAD_CLASSES
		CLASSES=(${DOWNLOAD_CLASSES[*]})
		CLASSES_SIZE=${#DOWNLOAD_CLASSES[*]};
		IFACE=$INTERNAL_IF
		CEIL=$DOWNLOAD_CEIL
		DOWNLOAD_CLASSES_HAVE_BEEN_INITIALIZED=1
		printf "\n\tDownload ceiling is $COLOR %s $COLOREND kbit/s\n\n" "$CEIL"
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







# Classify download traffic by a particular host on the LAN
# to control bandwidth usage
function classify_download_by_host {
#	$1 = host or subnet
#	$2 = class

	if [ $DOWNLOAD_CLASSES_HAVE_BEEN_INITIALIZED == 0 ] ; then
		initialize_bw_classes download
	fi;
	printf "\t(dest ip)$COLOR  %30s $COLOREND ------> $COLOR $2 $COLOREND\n" "$1"
	iptables -A FORWARD -o $INTERNAL_IF -d $1 -j CLASSIFY --set-class $2
}





# Classify download traffic from a particular host on the Internet
# to control bandwidth usage
function classify_download_from_host {
#	$1 = host or subnet
#	$2 = class
	if [ $DOWNLOAD_CLASSES_HAVE_BEEN_INITIALIZED == 0 ] ; then
		initialize_bw_classes download
	fi;
	printf "\t(source ip)$COLOR  %28s $COLOREND ------> $COLOR $2 $COLOREND\n" "$1"
	iptables -A FORWARD -o $INTERNAL_IF -s $1 -j CLASSIFY --set-class $2
}






# Classify download traffic from a specific (remote) port
# to control bandwidth usage
function classify_download_from_port {
#	$1 = tcp or udp
#	$2 = port
#	$3 = class
	if [ $DOWNLOAD_CLASSES_HAVE_BEEN_INITIALIZED == 0 ] ; then
		initialize_bw_classes download
	fi;
	printf "\t(source port)$COLOR  %26s $COLOREND ------> $COLOR $3 $COLOREND\n" "($1) :$2"
	iptables -A FORWARD -o $INTERNAL_IF -p $1 --sport $2 -j CLASSIFY --set-class $3
}





# (UNTESTED)
# Classify upload traffic to a particular host or subnet on the Internet
# to control bandwidth usage
function classify_upload_to_host {
#	$1 = host or subnet
#	$2 = class
	if [ $UPLOAD_CLASSES_HAVE_BEEN_INITIALIZED == 0 ] ; then
		initialize_bw_classes upload
	fi;
	printf "\t(dest ip)$COLOR  %28s $COLOREND ------> $COLOR $2 $COLOREND\n" "$1"
	iptables -A FORWARD -o $EXTERNAL_IF -d $1 -j CLASSIFY --set-class $2
}




# Classify upload traffic from a particular host or subnet on the LAN
# to control bandwidth usage
function classify_upload_from_host {
#	$1 = host or subnet
#	$2 = class
	if [ $UPLOAD_CLASSES_HAVE_BEEN_INITIALIZED == 0 ] ; then
		initialize_bw_classes upload
	fi;
	printf "\t(source ip)$COLOR  %28s $COLOREND ------> $COLOR $2 $COLOREND\n" "$1"
	iptables -A FORWARD -o $EXTERNAL_IF -s $1 -j CLASSIFY --set-class $2
}







# Classify upload traffic from a specific (local) port
# to control bandwidth usage
function classify_upload_from_port {
#	$1 = tcp or udp
#	$2 = source port
#	$3 = class
	if [ $UPLOAD_CLASSES_HAVE_BEEN_INITIALIZED == 0 ] ; then
		initialize_bw_classes upload
	fi;
	printf "\t(source port)$COLOR  %26s $COLOREND ------> $COLOR $3 $COLOREND\n" "($1) :$2"
	iptables -A FORWARD -o $EXTERNAL_IF -p $1 --sport $2 -j CLASSIFY --set-class $3
	# TODO: This RETURN rule looks like a mistake - need to test this whole area better
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
function port_forward {
#	$1 = tcp or udp
#	$2 = EXTERNAL PORT
#	$3 = INTERNAL DESTINATION (IP:PORT)
        printf "\tforwarding port$COLOR %25s $COLOREND ------> $COLOR %s $COLOREND\n" "($1)  :$2" "$3"
	iptables -t nat -A PREROUTING -p $1 -i $EXTERNAL_IF --dport $2 -j DNAT --to-destination $3
	iptables -t nat -A PREROUTING -i $INTERNAL_IF -s $LOCAL_SUBNET -d $PUBLIC_IP -p $1 --dport $2 -j DNAT --to-destination $3
}



# Duplicate a port (on both $EXTERNAL_IF and $INTERNAL_IF)
function port_duplicate {
#	$1 = tcp or udp
#	$2 = (external) port
#	$3 = port to which $2 should be duplicated
        printf "\tDuplicating (public) port$COLOR %15s $COLOREND ------> $COLOR %s $COLOREND\n" "($1)  :$2" "$3"
	iptables -t nat -A PREROUTING -i $EXTERNAL_IF -p $1 --dport $3 -j REDIRECT --to-port $2
	iptables -t nat -A PREROUTING -i $INTERNAL_IF -p $1 -d $LOCAL_SUBNET --dport $3 -j REDIRECT --to-port $2
}



# Deny Internet access to a specific host or subnet
function deny_internet {
#	$1 = host (or subnet) which should be denied Internet access
        printf "\tDenying Internet access to %15s ------> $COLOR %s $COLOREND\n" "" "$1"
	ipset -A denied_internet $1
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
	iptables -A INPUT -i $EXTERNAL_IF -m hashlimit -p $1 --dport $2 --hashlimit $3 --hashlimit-mode srcip,dstport --hashlimit-name "limitport-$2" -m state --state new -j ACCEPT
	if [ $LOG = 1 ] ; then
		iptables -A INPUT -i $EXTERNAL_IF -p $1 --dport $2 -m state --state NEW  -j LOG --log-prefix "GLARS: DropPktToPubPort-$2: "
	fi
	iptables -A INPUT -i $EXTERNAL_IF -p $1 --dport $2 -m state --state NEW -m set ! --match-set whitelisted_ips src -j DROP
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
	iptables -A FORWARD -p tcp -d $1 ! -s $LOCAL_SUBNET -m state --state new -m hashlimit --hashlimit $2 --hashlimit-name $1  -j ACCEPT
	if [ $LOG = 1 ] ; then
		iptables -A FORWARD -p tcp -d $1 ! -s $LOCAL_SUBNET -m state --state NEW -m set ! --match-set whitelisted_ips src -j LOG --log-prefix "GLARS: DropPktToHost: "
	fi;
	iptables -A FORWARD -p tcp -d $1 ! -s $LOCAL_SUBNET -m state --state NEW -m set ! --match-set whitelisted_ips src -j DROP
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
	if [ $LOG = 1 ] ; then
		iptables -A FORWARD -p $1 --dport $2 -d $LOCAL_SUBNET ! -s $LOCAL_SUBNET -m set ! --match-set whitelisted_ips src -m state --state new -j LOG --log-prefix "GLARS: DropPktToFwdPort: "
	fi;
	iptables -A FORWARD -p $1 --dport $2 -d $LOCAL_SUBNET ! -s $LOCAL_SUBNET -m set ! --match-set whitelisted_ips src -m state --state new -j DROP
}

function setup_blacklist_and_whitelist {
	IP_COUNT=0
	if [[ -f "$IP_WHITELIST_FILE" ]]; then
		echo -en "Setting whitelist from $COLOR $IP_WHITELIST_FILE $COLOREND..."
		for i in `cat $IP_WHITELIST_FILE|grep -v "\s*#"`; do
			# echo "Whitelisting $i"
			IP_COUNT=$(($IP_COUNT+1))
			ipset -A whitelisted_ips $i
		done;
		echo "done - $IP_COUNT IP subnets whitelisted "
	else
		echo -e "No whitelist file -- skipping whitelist setup"
	fi;


	IP_COUNT=0
	if [[ -f "$IP_BLACKLIST_FILE" ]]; then
		echo -en "Setting blacklist from $COLOR $IP_BLACKLIST_FILE $COLOREND..."
		for i in `cat $IP_BLACKLIST_FILE|grep -v "\s*#"`; do 
			# echo "Blacklisting $i"
			IP_COUNT=$(($IP_COUNT+1))
			ipset -A blacklisted_ips $i
		done;
		echo "done - $IP_COUNT IP subnets blacklisted"
	else
		echo -e "No blacklist file -- skipping blacklist setup"
	fi;
}









# Opens up access to a port
# on the GLARS router
function port_open {
#	$1 = tcp or udp
#	$2 = EXTERNAL PORT
        printf "\tOpening (public) port   $COLOR %19s $COLOREND\n" "($1)  :$2"
	iptables -A INPUT -p $1 -i $EXTERNAL_IF --dport $2 -j ACCEPT
}











#
# Forwards a port to an internal host and locks it with the specified
# lock sequence.
#
# A connecting host must knock on the ports in the specified order, within
# the specified amount of time, to temporarily open up access to the locked
# port
#
# example:
#
# port_lock_forward 9000 5000,6000,7000 60 192.168.31.5:22
#
# will forward port 9000 to 192.168.31.5:22 and 
# lock it so that it opens up only for hosts 
# that knock on 5000 then 6000 then 7000 within 60 seconds
# 
# The locked port will then remain open for this IP address for 
# <seconds>/<number of ports>. In this example, port 9000 will 
# remain open for 20 seconds after the knock on port 7000
#
# A minimum of one port is needed for the lock sequence, but the sequence can be 
# arbitrarily long.
function port_lock_forward {
#	$1 = tcp or udp
#	$2 = EXTERNAL PORT
#	$3 = array of port numbers
#	$4 = seconds
#	$5 = HOST:PORT to forward port to

	# Without an exemption, local traffic to the locked/forwarded port will be dropped in the general
	# "drop traffic coming from outside" rule unless the local host "knocks" first.
	# The following rule exempts LAN-side traffic from having to go through the knock-tests to get to the locked port.
	# I guess in accordance with the general "trust the LAN-side" approach taken elsewhere
	iptables -t nat -A KNOCKING_FORWARD -i $INTERNAL_IF -p $1 -d $PUBLIC_IP --dport $2 -j DNAT --to-destination $5

	printf "\tLocking & forwarding port $COLOR %14s $COLOREND ------> $COLOR %s %s (%s seconds) $COLOREND\n" "($1)  :$2" "$5" "$3" "$4"
	UNIQUEKEY=$(echo $3 | md5sum|cut -c 1-3)
	LOCK_SEQUENCE=$(echo $3 | sed -e 's/,/ /g')
	COUNT=0
	for i in $LOCK_SEQUENCE; do
		COUNT=$((COUNT+1))

		# If you change GATENAME, be sure to change the other rules that need
		# to find the first gate
		GATENAME="gate_$1_$2_"$UNIQUEKEY"_$COUNT"
		iptables -t nat -N $GATENAME
		# For anything after the first knock, we need to remove the last mark
		if [[ $COUNT -gt 1 ]] ; then
			LASTCOUNT=$((COUNT-1))
			iptables -t nat -A $GATENAME -p $1 -m recent --remove --name auth_$1_$2_"$UNIQUEKEY"_$LASTCOUNT
		fi;
		if [ $LOG = 1 ] ; then
			iptables -t nat -A $GATENAME -p $1 --dport $i -j LOG --log-prefix "GLARS: $GATENAME "
		fi;
		iptables -t nat -A $GATENAME -p $1 --dport $i -m recent --name auth_$1_$2_"$UNIQUEKEY"_$COUNT --set -j ACCEPT
		# For anything after the first knock, we need to redirect traffic to first gate
		if [[ $COUNT -gt 1 ]] ; then
			iptables -t nat -A $GATENAME -j gate_$1_$2_"$UNIQUEKEY"_1
		fi;
	done
	iptables -t nat -N passed_fwd_p_$1_$2_"$UNIQUEKEY"
	if [ $LOG = 1 ] ; then
		iptables -t nat -A passed_fwd_p_$1_$2_"$UNIQUEKEY" -p $1 --dport $2 -j LOG --log-prefix "GLARS: accept_p_$2_$UNIQUEKEY "
	fi;
	iptables -t nat -A passed_fwd_p_$1_$2_"$UNIQUEKEY" -p $1 --dport $2 -j DNAT --to-destination $5
	iptables -t nat -A passed_fwd_p_$1_$2_"$UNIQUEKEY" -j gate_$1_$2_"$UNIQUEKEY"_1


	SECONDS_PER_GATE=$(($4/$COUNT))
	iptables -t nat -A KNOCKING_FORWARD -m recent --rcheck --seconds $SECONDS_PER_GATE --name auth_$1_$2_"$UNIQUEKEY"_$COUNT -j passed_fwd_p_$1_$2_"$UNIQUEKEY"
	for ((i=$COUNT-1; i>0; i--)); do
		NEXTGATE=$((i+1))
		GATENAME=gate_$1_$2_"$UNIQUEKEY"_$NEXTGATE
		iptables -t nat -A KNOCKING_FORWARD -m recent --rcheck --seconds $SECONDS_PER_GATE --name auth_$1_$2_"$UNIQUEKEY"_$i -j $GATENAME
	done;


	# Whitelisted IPs don't have to knock (straight to "passed")
	iptables -t nat -A KNOCKING_FORWARD -m set --match-set whitelisted_ips src -j passed_fwd_p_$1_$2_"$UNIQUEKEY"

	# Everyone else starts at gate 1
	iptables -t nat -A KNOCKING_FORWARD -j gate_$1_$2_"$UNIQUEKEY"_1
}

#
# Locks a port with the specified lock sequence.
#
# A connecting host must knock on the ports in the specified order, within
# the specified amount of time, to temporarily open up access to the locked
# port
#
# example:
#
# port_lock tcp 22 5000,6000,7000 90
#
# ..will lock port 22 (SSH) so that it the port is only accessible to hosts
# who knock on ports 5000, 6000, 7000, in order, within 90 seconds.
#
# At that point, the locked port will remain open for the remote IP address for 
# <seconds>/<number of ports>. In this example, port 22 will 
# remain open for 30 seconds after the knock on port 7000
#
# A minimum of one port is needed for the lock sequence, but the sequence can be 
# arbitrarily long.
#
function port_lock {
#       $1 = tcp or udp
#       $2 = EXTERNAL PORT
#       $3 = array of port numbers
#       $4 = seconds


	printf "\tLocking (public port)$COLOR %19s $COLOREND ------> $COLOR %s (%s seconds) $COLOREND\n" "($1)  :$2" "$3" "$4"
	LOCK_SEQUENCE=$(echo $3 | sed -e 's/,/ /g')
	COUNT=0
	for i in $LOCK_SEQUENCE; do
		COUNT=$((COUNT+1))

		# If you change GATENAME, be sure to change the other rules that need
		# to find the first gate
		GATENAME=gate_$1_$2_$COUNT
		iptables -N $GATENAME
		# For anything after the first knock, we need to remove the last mark
		if [[ $COUNT -gt 1 ]] ; then
			LASTCOUNT=$((COUNT-1))
			iptables -A $GATENAME -p $1 -m recent --remove --name auth_$1_$2_$LASTCOUNT
		fi;
		if [ $LOG = 1 ] ; then
			iptables -A $GATENAME -p $1 --dport $i -j LOG --log-prefix "GLARS: $GATENAME "
		fi;
		iptables -A $GATENAME -p $1 --dport $i -m recent --name auth_$1_$2_$COUNT --set -j ACCEPT
		# For anything after the first knock, we need to redirect traffic to first gate
		if [[ $COUNT -gt 1 ]] ; then
			iptables -A $GATENAME -j gate_$1_$2_1
		fi;
	done
	iptables -N passed_p_$1_$2
	if [ $LOG = 1 ] ; then
		iptables -A passed_p_$1_$2 -p $1 --dport $2 -j LOG --log-prefix "GLARS: accept_p_$2 "
	fi;
	iptables -A passed_p_$1_$2 -p $1 --dport $2 -j ACCEPT
	iptables -A passed_p_$1_$2 -j gate_$1_$2_1


	SECONDS_PER_GATE=$(($4/$COUNT))
	iptables -A KNOCKING -m recent --rcheck --seconds $SECONDS_PER_GATE --name auth_$1_$2_$COUNT -j passed_p_$1_$2
	for ((i=$COUNT-1; i>0; i--)); do
		NEXTGATE=$((i+1))
		GATENAME=gate_$1_$2_$NEXTGATE
		iptables -A KNOCKING -m recent --rcheck --seconds $SECONDS_PER_GATE --name auth_$1_$2_$i -j $GATENAME
	done;

	# Whitelisted IPs don't have to knock (straight to "passed")
	iptables -A KNOCKING -m set --match-set whitelisted_ips src -j passed_p_$1_$2

	# Everyone else starts at gate 1
	iptables -A KNOCKING -j gate_$1_$2_1


}


function finalize_rules_and_policies {
	echo -n "Finalizing rules and policies..."
	iptables -A INPUT -i $EXTERNAL_IF -p icmp -j ACCEPT
	iptables -A INPUT -j KNOCKING
	iptables -A PREROUTING -t nat -j KNOCKING_FORWARD
	iptables -A INPUT -i $EXTERNAL_IF -m set ! --match-set whitelisted_ips src -j DROP
	echo "done"
}


function pre_initialize_rules_and_policies {
	echo -n "Initializing rules and policies..."

	# Create empty chains
	iptables -N KNOCKING
	iptables -t nat -N KNOCKING_FORWARD

	# Create empty sets
        ipset -N blacklisted_ips nethash
        ipset -N whitelisted_ips nethash
	ipset -N denied_internet nethash

	# Add default early rules
	iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT




	if [ $LOG = 1 ] ; then
		iptables -A FORWARD -o $EXTERNAL_IF -m set --match-set denied_internet  src -j LOG --log-prefix "GLARS: RejectDeniedInternet: "
	fi;
	iptables -A FORWARD -o $EXTERNAL_IF -m set --match-set denied_internet src -j REJECT

	if [ $LOG = 1 ] ; then
		iptables -A INPUT -i $EXTERNAL_IF -m conntrack --ctstate NEW -m set --match-set whitelisted_ips src -j LOG --log-prefix "GLARS: AcceptWhitelistInput: "
	fi;
#	iptables -A INPUT -i $EXTERNAL_IF -m set --match-set whitelisted_ips src -j ACCEPT

	if [ $LOG = 1 ] ; then
		iptables -A FORWARD -i $EXTERNAL_IF -m conntrack --ctstate NEW -m set --match-set whitelisted_ips src -j LOG --log-prefix "GLARS: AcceptWhiteklistFwd: "
	fi;
#	iptables -A FORWARD -i $EXTERNAL_IF -m set --match-set whitelisted_ips src -j ACCEPT

	if [ $LOG = 1 ] ; then
		iptables -A INPUT -i $EXTERNAL_IF -m set --match-set blacklisted_ips src -m set ! --match-set whitelisted_ips src -j LOG --log-prefix "GLARS: DropBlacklistInput: "
	fi;
	iptables -A INPUT -i $EXTERNAL_IF -m set --match-set blacklisted_ips src -m set ! --match-set whitelisted_ips src -j DROP

	if [ $LOG = 1 ] ; then
		iptables -A FORWARD -i $EXTERNAL_IF -m set --match-set blacklisted_ips src -m set ! --match-set whitelisted_ips src -j LOG --log-prefix "GLARS: DropBlacklistFwd: "
	fi;
	iptables -A FORWARD -i $EXTERNAL_IF -m set --match-set blacklisted_ips src -m set ! --match-set whitelisted_ips src -j DROP



	echo "done"
}


function main {
	echo -e \
"
$COLOR
┏━╸╻  ┏━┓┏━┓┏━┓   ╻ ╻┏━┓ ┏━┓
┃╺┓┃  ┣━┫┣┳┛┗━┓   ┃┏┛┏━┛ ┃┃┃
┗━┛┗━╸╹ ╹╹┗╸┗━┛   ┗┛ ┗━╸╹┗━┛
$COLOREND
"

	if [[ -f "$RULES_FILE" ]]; then
		source $RULES_FILE
	fi;

	printf "Our public IP address is:$COLOR%20s $COLOREND\n" "$PUBLIC_IP"

	clear_all_configurations;

	setup_gateway;

	pre_initialize_rules_and_policies;

	if [[ -f "$RULES_FILE" ]]; then
		setup_rules_and_policies;
	else
		printf "No rules specified\n"
	fi;

	finalize_rules_and_policies;
	setup_blacklist_and_whitelist;
}

main;
