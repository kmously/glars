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
#                    +---------->       +        |     |                 |   |
#       Local Network        |  |   +-------+    |     |                 +-------------->
#                    <----------+   |       |    |     |   $EXTERNAL_IF  |   |          Internet
#                            |  |   | wlan0 |    |     |                 <--------------+
#                            |  |   |       |    |     |                 |   |
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





##################################################################################################
##################################################################################################
#
#              
#                  ▄▄▄▄▄   ▄▄▄▄        
#                  █   ▀█ █▀   ▀       
#                  █▄▄▄█▀ ▀█▄▄▄    █   
#                  █          ▀█       
#                  █      ▀▄▄▄█▀   █   
#                     
# Font is generated with 
#
# $ toilet --font mono9 text
#
#
#                    ┏━┓┏━┓┏━┓ 
#                    ┣━┛┣━┛┗━┓╹
#                    ╹  ╹  ┗━┛╹
#
# Font is generated with
#
# $ toilet --font future pps
#
#
#
#  +------------------------------------------+
#  |  Diagrams generated using asciiflow.com  |
#  +---------------------+--------------------+
#                        ^
#                        |
#                        |
#                        |
#                        +
#
#
###################################################################################################
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

# Comment out these 2 vars if you dont want colors
COLOR=$YELLOW
COLOREND="\033[0m"

# This is the interface that's connected to the Internet
EXTERNAL_IF=eth1

# This is the interface that is connected to the internal network
# If you are bridging multiple interfaces (wifi, VPN, etc.), then
# use the bridge interface here.
# The bridge must be created BEFORE running this script
INTERNAL_IF=br0

# This is the interface used to limit upload speed of hosts on the network
UPLOAD_IFACE=$EXTERNAL_IF

# This is the interface used to limit download speed of hosts on the network
DOWNLOAD_IFACE=$INTERNAL_IF

# This is our public IP
# You can use a static IP or get the IP from the EXTERNAL_IF
PUBLIC_IP=$(ifconfig $EXTERNAL_IF|grep inet.*netmas|sed -e "s/netmask.*//g"|sed -e "s/.*inet.//g"|sed -e "s/ *//g")

# Define local subnet here
LOCAL_SUBNET=192.168.31.0/24

# Declare host IPs here
# Can also get IPs from /etc/hosts, e.g:
# $(cat /etc/hosts|grep 'foo'|sed -e 's/\s.*//g')
FOO_IP=192.168.31.8
BAR_IP=192.168.31.9

# Specify text file containing blacklisted IPs
# The file must contain ONLY IP ranges in CIDR notation
#
# e.g. w.x.y.z/24
#
# To ban a single IP, use /32 subnet
#
# One CIDR IP per line, no comments or anything else allowed
# You can use as many as you want, they won't affect firewall rules
# and will be efficiently processed.
#
IP_BLACKLIST_FILE=/root/glars_blacklist.txt

 


                                  
##################################################################################################
##################################################################################################
#                                ▄   
#   ▄ ▄▄   ▄▄▄    ▄▄▄    ▄▄▄   ▄▄█▄▄ 
#   █▀  ▀ █▀  █  █   ▀  █▀  █    █   
#   █     █▀▀▀▀   ▀▀▀▄  █▀▀▀▀    █   
#   █     ▀█▄▄▀  ▀▄▄▄▀  ▀█▄▄▀    ▀▄▄ 
#                                   
# ▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀
#                                   

function clear_all_configurations {
	echo -en "Resetting all configurations (iptables, tc and ipset)..."
	iptables -F -t nat
	iptables -F
	tc qdisc del dev $DOWNLOAD_IFACE root
	tc qdisc del dev $UPLOAD_IFACE root
	ipset -F
	ipset -X
	echo -e "done"
}
#
##################################################################################################
##################################################################################################









##################################################################################################
##################################################################################################
#
#                            
#   ▀             ▀      ▄   
# ▄▄▄    ▄ ▄▄   ▄▄▄    ▄▄█▄▄ 
#   █    █▀  █    █      █   
#   █    █   █    █      █   
# ▄▄█▄▄  █   █  ▄▄█▄▄    ▀▄▄ 
#                            
# ▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀
#                            
function initialize {
	echo -e "This is our public IP address:"
	echo -e "\t\t\t\t   $COLOR  $PUBLIC_IP $COLOREND"
}
#
##################################################################################################
##################################################################################################








##################################################################################################
##################################################################################################
#   ▄▄▄▄   ▄▄▄   ▄▄█▄▄   ▄▄▄  ▄     ▄  ▄▄▄   ▄   ▄ 
#  █▀ ▀█  ▀   █    █    █▀  █ ▀▄ ▄ ▄▀ ▀   █  ▀▄ ▄▀ 
#  █   █  ▄▀▀▀█    █    █▀▀▀▀  █▄█▄█  ▄▀▀▀█   █▄█  
#  ▀█▄▀█  ▀▄▄▀█    ▀▄▄  ▀█▄▄▀   █ █   ▀▄▄▀█   ▀█   
#   ▄  █                                      ▄▀   
#    ▀▀                                      ▀▀    
#                  ▄                 
#   ▄▄▄    ▄▄▄   ▄▄█▄▄  ▄   ▄  ▄▄▄▄  
#  █   ▀  █▀  █    █    █   █  █▀ ▀█ 
#   ▀▀▀▄  █▀▀▀▀    █    █   █  █   █ 
#  ▀▄▄▄▀  ▀█▄▄▀    ▀▄▄  ▀▄▄▀█  ██▄█▀ 
#                              █     
#                              ▀     
# ▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀
#
function setup_nat {
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
#
##################################################################################################
##################################################################################################









##################################################################################################
##################################################################################################
#
#                      
#   ▄▄▄▄          ▄▄▄▄ 
#  ▄▀  ▀▄  ▄▄▄   █▀   ▀
#  █    █ █▀ ▀█  ▀█▄▄▄ 
#  █    █ █   █      ▀█
#   █▄▄█▀ ▀█▄█▀  ▀▄▄▄█▀
#      █               
#                      
#    ▄▄▄ 
#   █    
#   ██   
#  █  █▄█
#  ▀█▄▄█▄
#                                                  
#         █                      ▀                 
#   ▄▄▄   █ ▄▄    ▄▄▄   ▄▄▄▄   ▄▄▄    ▄ ▄▄    ▄▄▄▄ 
#  █   ▀  █▀  █  ▀   █  █▀ ▀█    █    █▀  █  █▀ ▀█ 
#   ▀▀▀▄  █   █  ▄▀▀▀█  █   █    █    █   █  █   █ 
#  ▀▄▄▄▀  █   █  ▀▄▄▀█  ██▄█▀  ▄▄█▄▄  █   █  ▀█▄▀█ 
#                       █                     ▄  █ 
#                       ▀                      ▀▀  
# ▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀
#
function classify_download_host {
	#	$1 = host or subnet
	#	$2 = class
		printf "\t$COLOR  %25s $COLOREND\t------>\t     $COLOR $2 $COLOREND\n" "(dest) $1"
		iptables -A FORWARD -o $DOWNLOAD_IFACE -d $1 -j CLASSIFY --set-class $2
		iptables -A FORWARD -o $DOWNLOAD_IFACE -d $1 -j RETURN
	}
function classify_download_port {
	#	$1 = tcp or udp
	#	$2 = port
	#	$3 = class
		printf "\t$COLOR  %25s $COLOREND\t------>\t     $COLOR $3 $COLOREND\n" "(source) $1 :$2"
		iptables -A FORWARD -o $DOWNLOAD_IFACE -p $1 --sport $2 -j CLASSIFY --set-class $3
		iptables -A FORWARD -o $DOWNLOAD_IFACE -p $1 --sport $2 -j RETURN
	}
function classify_upload_host {
	#	$1 = host or subnet
	#	$2 = class
		printf "\t$COLOR  %25s $COLOREND\t------>\t     $COLOR $2 $COLOREND\n" "$1"
		iptables -A FORWARD -o $UPLOAD_IFACE -s $1 -j CLASSIFY --set-class $2
		iptables -A FORWARD -o $UPLOAD_IFACE -s $1 -j RETURN
	}
function classify_upload_port {
	#	$1 = tcp or udp
	#	$2 = source port
	#	$3 = class
		printf "\t$COLOR  %25s $COLOREND\t------>\t     $COLOR $3 $COLOREND\n" "(source) $1 :$2"
		iptables -A FORWARD -o $UPLOAD_IFACE -p $1 --sport $2 -j CLASSIFY --set-class $3
		iptables -A FORWARD -o $UPLOAD_IFACE -p $1 --sport $2 -j RETURN
	}



function setup_bw_limiting {
	echo -e "Setting up bandwidth control"


        # ╺┳┓┏━┓╻ ╻┏┓╻╻  ┏━┓┏━┓╺┳┓
        #  ┃┃┃ ┃┃╻┃┃┗┫┃  ┃ ┃┣━┫ ┃┃
        # ╺┻┛┗━┛┗┻┛╹ ╹┗━╸┗━┛╹ ╹╺┻┛

	CEIL=25000
	tc qdisc add dev $DOWNLOAD_IFACE root handle 1: htb default 10
	tc class add dev $DOWNLOAD_IFACE parent 1: classid 1:1 htb ceil ${CEIL}kbit rate ${CEIL}kbit

	# Let's keep a high priority "sliver" of bandwidth just for us - so we can be reachable at all times
	# Only we will use this class
	tc class add dev $DOWNLOAD_IFACE parent 1:1 classid 1:10 htb prio 0 rate $[CEIL * 2/100]kbit ceil ${CEIL}kbit

	# High priority/low latency traffic should go in here (VoIP..HTTP..SSH..etc.)
	tc class add dev $DOWNLOAD_IFACE parent 1:1 classid 1:11 htb prio 1 rate $[CEIL * 30/100]kbit ceil ${CEIL}kbit

	# Regular traffic for regular hosts goes here
	tc class add dev $DOWNLOAD_IFACE parent 1:1 classid 1:12 htb prio 2 rate $[CEIL * 48/100]kbit ceil ${CEIL}kbit

	# Low priority traffic can go in here 
	tc class add dev $DOWNLOAD_IFACE parent 1:1 classid 1:13 htb prio 3 rate $[CEIL * 20/100]kbit ceil ${CEIL}kbit

	tc qdisc add dev $DOWNLOAD_IFACE parent 1:10 handle 100: sfq perturb 40
	tc qdisc add dev $DOWNLOAD_IFACE parent 1:11 handle 110: sfq perturb 40
	tc qdisc add dev $DOWNLOAD_IFACE parent 1:12 handle 120: sfq perturb 40
	tc qdisc add dev $DOWNLOAD_IFACE parent 1:13 handle 130: sfq perturb 40

	printf "\tDownload: \n"

	# Order matters here - first matching rule wins

	# Let's make web browsing faster and more responsive!
	classify_download_port tcp 80 1:11
	classify_download_port tcp 443 1:11

	# SSH (outgoing) too!
	classify_download_port tcp 22 1:11

	# Traffic to FOO is important
	classify_download_host $FOO_IP 1:11

	# Traffic to BAR is not important
	classify_download_host $BAR_IP 1:13

	# Regular traffic goes to the regular lane
	classify_download_host $LOCAL_SUBNET 1:12


	# ╺━╸╺━╸╺━╸╺━╸╺━╸╺━╸╺━╸╺━╸╺━╸╺━╸╺━╸╺━╸╺━╸╺━╸╺━╸╺━╸╺━╸╺━╸╺━╸╺━╸╺━╸╺━╸╺━╸╺━╸╺━╸╺━╸


	# ╻ ╻┏━┓╻  ┏━┓┏━┓╺┳┓
	# ┃ ┃┣━┛┃  ┃ ┃┣━┫ ┃┃
	# ┗━┛╹  ┗━╸┗━┛╹ ╹╺┻┛
	#                                 

	CEIL=9000
	tc qdisc add dev $UPLOAD_IFACE root handle 1: htb default 10
	tc class add dev $UPLOAD_IFACE parent 1: classid 1:1 htb ceil ${CEIL}kbit rate ${CEIL}kbit

	# Let's keep a high priority "sliver" of bandwidth just for us - so we can be reachable at all times
	# Only we will use this class
	tc class add dev $UPLOAD_IFACE parent 1:1 classid 1:10 htb prio 0 rate $[CEIL * 2/100]kbit ceil ${CEIL}kbit

	# Traffic that needs to be responsive can go in here
	tc class add dev $UPLOAD_IFACE parent 1:1 classid 1:11 htb prio 1 rate $[CEIL * 20/100]kbit ceil ${CEIL}kbit

	# Regular traffic for regular hosts goes here
	tc class add dev $UPLOAD_IFACE parent 1:1 classid 1:12 htb prio 2 rate $[CEIL * 68/100]kbit ceil ${CEIL}kbit

	# Low priority traffic can go in here  (SMTP, etc.)
	tc class add dev $UPLOAD_IFACE parent 1:1 classid 1:13 htb prio 3 rate $[CEIL * 10/100]kbit ceil ${CEIL}kbit

	tc qdisc add dev $UPLOAD_IFACE parent 1:10 handle 100: sfq perturb 40
	tc qdisc add dev $UPLOAD_IFACE parent 1:11 handle 110: sfq perturb 40
	tc qdisc add dev $UPLOAD_IFACE parent 1:12 handle 120: sfq perturb 40
	tc qdisc add dev $UPLOAD_IFACE parent 1:13 handle 130: sfq perturb 40

	printf "\tUpload: \n"

	# Order matters here - first matching rule wins

	# Traffic from FOO is high priority
	classify_upload_host $FOO_IP 1:11

	# Traffic from BAR isn't high priority
	classify_upload_host $BAR_IP 1:13

	# Let's make incoming SSH/SCP sessions fast!
	classify_upload_port tcp 22 1:11

	# Regular traffic goes to the regular lane
	classify_upload_host $LOCAL_SUBNET 1:12

	# ╺━╸╺━╸╺━╸╺━╸╺━╸╺━╸╺━╸╺━╸╺━╸╺━╸╺━╸╺━╸╺━╸╺━╸╺━╸╺━╸╺━╸╺━╸╺━╸╺━╸╺━╸╺━╸╺━╸╺━╸╺━╸╺━╸
}

#
#
##################################################################################################
##################################################################################################





##################################################################################################
##################################################################################################
#                             
#                          ▄   
#   ▄▄▄▄    ▄▄▄    ▄ ▄▄  ▄▄█▄▄ 
#   █▀ ▀█  █▀ ▀█   █▀  ▀   █   
#   █   █  █   █   █       █   
#   ██▄█▀  ▀█▄█▀   █       ▀▄▄ 
#   █                          
#   ▀                          
#                                                                       
#    ▄▀▀                                         █    ▀                 
#  ▄▄█▄▄   ▄▄▄    ▄ ▄▄ ▄     ▄  ▄▄▄    ▄ ▄▄   ▄▄▄█  ▄▄▄    ▄ ▄▄    ▄▄▄▄ 
#    █    █▀ ▀█   █▀  ▀▀▄ ▄ ▄▀ ▀   █   █▀  ▀ █▀ ▀█    █    █▀  █  █▀ ▀█ 
#    █    █   █   █     █▄█▄█  ▄▀▀▀█   █     █   █    █    █   █  █   █ 
#    █    ▀█▄█▀   █      █ █   ▀▄▄▀█   █     ▀█▄██  ▄▄█▄▄  █   █  ▀█▄▀█ 
#                                                                  ▄  █ 
#                                                                   ▀▀  
# 
# ▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀
#
 
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
        printf "\t$COLOR %29s $COLOREND ------>\t $COLOR %18s $COLOREND\n" "($1)  :$2" "$3"
	iptables -t nat -A PREROUTING -p $1 -i $EXTERNAL_IF --dport $2 -j DNAT --to-destination $3
	iptables -t nat -A PREROUTING -i $INTERNAL_IF -s $LOCAL_SUBNET -d $PUBLIC_IP -p $1 --dport $2 -j DNAT --to-destination $3
}


function setup_port_forwarding()
{
	printf "Setting up port forwarding: \n"

	# FOO is hosting an HTTP server
	# so let's forward ports 80 and 443
	forward tcp 80 $FOO_IP:80
	forward tcp 443 $FOO_IP:443

}
#
#
##################################################################################################
##################################################################################################


# Duplicate a port on EXTERNAL_IF
function duplicate_port {
#	$1 = tcp or udp
#	$2 = (external) port
#	$3 = port to which $2 should be duplicated
        printf "\t$COLOR %29s $COLOREND ------>\t $COLOR %8s $COLOREND\n" "($1)  :$2" "$3"
	iptables -t nat -A PREROUTING -i $EXTERNAL_IF -p $1 --dport $3 -j REDIRECT --to-port $2
}

function setup_port_duplication()
{
	printf "Setting up port duplication: \n"

	# Duplicate SSH to port 80 and 443 as those are some of the most commonly unblocked ports
	duplicate_port tcp 22 80
	duplicate_port tcp 22 443
}








##################################################################################################
##################################################################################################
#                                                         
#    ▄▀▀    ▀                                ▀▀█    ▀▀█   
#  ▄▄█▄▄  ▄▄▄     ▄ ▄▄   ▄▄▄  ▄     ▄  ▄▄▄     █      █   
#    █      █     █▀  ▀ █▀  █ ▀▄ ▄ ▄▀ ▀   █    █      █   
#    █      █     █     █▀▀▀▀  █▄█▄█  ▄▀▀▀█    █      █   
#    █    ▄▄█▄▄   █     ▀█▄▄▀   █ █   ▀▄▄▀█    ▀▄▄    ▀▄▄ 
#                                                         
# ▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀
#

function limit_connections_to_port {
#	$1 tcp or udp
#	$2 port to ratelimit
#	$3 ratelimit
	printf "\t $COLOR%28s $COLOREND  ------> $COLOR %5s$3 $COLOREND\n" "(dest) $1 :$2"
	iptables -A INPUT -i $EXTERNAL_IF -m hashlimit -p $1 --dport $2 --hashlimit 4/min --hashlimit-mode srcip --hashlimit-name ssh -m state --state new -j ACCEPT
	iptables -A INPUT -i $EXTERNAL_IF -p tcp --dport $2 -m state --state NEW -j DROP
}

# Limit incoming connections to a host on the network
#
# *** This function doesn't actually work (still TODO) ***
#
# Note: You cannot limit connections to a HOST on the network by doing:
#
# limit_connections_to_port tcp x 1/min
# limit_connections_to_port tcp y 1/min
# ...etc
#
# even if x and y are ports that are forwarded to HOST
#
# That is because NAT processing is done before INPUT processing
# In other words, the traffic will be forwarded before the INPUT chain
# is even checked, so the rules will have no effect.
#
function limit_connections_to_host {
#	$1 host to protect
#	$2 ratelimit of allowed connections to host
	iptables -t filter -A FORWARD -m hashlimit -p tcp -d $1 --hashlimit $2 --hashlimit-mode dstip --hashlimit-name "connections_to_$1" -m state --state new -j ACCEPT
	iptables -t filter -A FORWARD -p tcp -d $1 -m state --state NEW -j DROP
}

function setup_firewall {

	echo -e "Limiting inbound connections to ports:"

	# limit attacks on our SSH (22) port
	limit_connections_to_port tcp 22 4/min


	# limit attacks on our server (TODO: this doesn't work yet) 
	#echo -e "Limiting inbound connections to hosts: "
	#limit_connections_to_host $FOO_IP 30/min


	# Ignore blacklisted IPs
	if [[ -f "$IP_BLACKLIST_FILE" ]]; then
		echo -en "Setting blacklist from $COLOR $IP_BLACKLIST_FILE     $COLOREND..."
		ipset -N banned_ips nethash
		for i in `cat $IP_BLACKLIST_FILE`; do 
			# echo "Banning $i"
			ipset -A banned_ips $i
		done;
		echo " done"
	else
		echo -e "No blacklist file -- skipping blacklist setup"
	fi;

}
#
#
#
##################################################################################################
##################################################################################################






clear_all_configurations;

initialize;

setup_nat;

setup_port_duplication;

setup_port_forwarding;

setup_bw_limiting;

setup_firewall;
