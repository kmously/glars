## ABOUT

GLARS is a single bash script that allows you to turn any Linux box with 2 network interfaces into a powerful but easy-to-use layer 3 router. It uses only the Linux firewall (iptables) and a few basic GNU/Linux applications that usually come by default in most Linux distros.


## HOW TO USE

GLARS assumes your machine has 2 network interfaces. In general, any 2 network interfaces can be used. This includes "bridged" interfaces (which are virtual interfaces that "bridge together" one or more physical or virtual interfaces, such as Ethernet + WiFi, Ethernet + VPN, Ethernet + WiFi + VPN, etc.) or USB-to-Ethernet or USB-to-WiFi interfaces.

In theory, it really doesn't matter which interface goes where. From the point of view of the GLARS router, it's just traffic that is being pushed out of one interface or the other. However, for most common use-cases, one interface will be connected to a "local" (LAN) side, and one will be connected to an external (WAN) side, the latter is usually connected to a cable modem or similar device that connects to ISP (Internet Service Provider) hardware. Home routers will usually have one port labeled "WAN" in a different colour to mark the WAN port from all the other LAN-ports. GLARS calls the WAN interface the **$EXTERNAL_IF** and the LAN interface the **$INTERNAL_IF**


To use GLARS in the default settings, you only need to edit 3 options at the top of the glars.sh script before running it. Those options are:
 - The name of the external interface ($EXTERNAL_IF)
 - The name of the internal interface ($INTERNAL_IF)
 - The IP and subnet of the LAN-side (most home routers default to something like 192.168.0.0/24)


Those are the only required options. If GLARS is run without any further options, it will default to behaviour similar to the behaviour of most newly-installed "regular" home routers. In general, GLARS trusts the LAN-side and distrusts the WAN-side, so make sure that you do not lock yourself out of your GLARS box if you are accessing it from the WAN-side.

GLARS has many optional settings that can control its behaviour, and is expected to gain further functionality in the future. For optional settings, see **OPTIONAL SETTINGS** and for for advanced functionality, you may want to add a "rules" file to control the behaviour of GLARS. See **TECHNICAL DETAILS** for more info.



## FAQ

### Who is GLARS intended for?
Anyone who has a Linux box (either large x86 systems or small ARM devices like Raspberry Pi or Odroid) that they would like to use as a router, but would rather not have to deal directly with low-level tools (iptables, tc, etc.) that are required to so. Anyone fed up with the limited (and insecure) routers available today will likely enjoy the flexibility and power of running a Linux-based router. GLARS makes that easier.




### Can GLARS replace a home router (like Linksys or Netgear)?
Most home routers do several things in addition to "routing". Many home routers today will provide one or more of the the following functionality:
 1) Provide one or more Wi-Fi access points
 2) Provide DHCP functionality (responds to new hosts on the network and tells them the information they need to use the local network or get to the Internet)
 3) Provide DNS functionality (responds to queries for IP addresses of hosts like "www.yahoo.com")
 4) **Provide layer 3 routing** (allows, and controls, the flow of traffic from one network to the other. Usually one network is a "local" network, and the other an "external" network (usually the Internet). This is the definition of "routing".


GLARS is only concerned with (4), "routing". As such, by itself, it will likely be insufficient as a replacement for most people's use-cases. However, in combination with other GNU/Linux software and/or hardware extensions that provide DHCP/DNS/Wi-Fi functionality, the end result can act as very powerful and customizable alternative to any home (or even enterprise-level) routers.  It is also very easy to use a GNU/Linux box running GLARS _in combination_ with common home routers, such that the Wi-Fi/DNS/DHCP is provided by the existing home router, but the actual routing is done by GLARS, thus getting the best of both worlds.

It is unlikely that GLARS will gain DHCP or DNS functionality in the future, however, it may gain the ability to integrate or interact with common existing DHCP/DNS software, in order to help "centralize" all networking settings.



## TECHNICAL DETAILS

GLARS provides an API that facilitates common routing functionality. It is essentially a bunch of helper functions that automate the generation of iptables, ipset and tc rules and can abstract some of the tricky things associated with using them correctly.

GLARS will perform NAT (Network Address Translation) on traffic leaving the WAN interface. This makes it seem like all devices on the LAN-side are a single IP address on the Internet. This is the default behaviour of most home routers. NAT is the primary reason that a distinction needs to be made between $EXTERNAL_IF and $INTERNAL_IF.

From the point of view of the GLARS router, there is no concept of "download" or "upload" - all traffic is coming from one interface and (usually) going into the other. However, to make it easy to conceptualize and control the behaviour of traffic, GLARS defines "download traffic" as traffic coming from $EXTERNAL_IF and leaving on $INTERNAL_IF. Similarly, GLARS defines "upload traffic" as traffic coming from $INTERNAL_IF and leaving on $EXTERNAL_IF. Thus when speaking of controlling "download traffic", we're speaking of controlling how much bandwidth hosts on the LAN-side can use for downloading. When we speak of "upload traffic", we're speaking of the bandwidth that hosts on the LAN-side use for uploading.

In general, GLARS assumes the LAN-side is trustworthy but the WAN-side isn't. Thus, by default, ports are open to the LAN side but closed to WAN-side. LAN-side hosts don't need to "knock" to get to "locked" ports, for example, but WAN-side hosts do. LAN side hosts can reach the WAN-side (Internet) by default unless they are explicitly restricted.

For another example, if you set up your GLARS box to be accessible via SSH, which runs by default on port TCP:22, then by default, your SSH service will be accessible from the LAN-side. To make your SSH service accessible via the WAN-side (usually the Internet), you can add the following rule to your "rules" file:


**`port_open tcp 22`**


## The 'rules' file

The behaviour of the router can be modified and fine-tuned further with the use of a 'rules' file. This is a text file that can be used to provide 3 bash functions for glars to execute: 
 - **`pre_glars`**
   - this hook will be called by GLARS before it does anything. You can put anything you here that needs to happen before all the settings are applied
 - **`setup_rules_and_policies`**
   - this is where the API (see below) can be used
 - **`post_glars`**
   - this hook will be called by GLARS after it is done. You can put anything you here that needs to happen after all the settings are applied


## API

These functions can be used in a "rules" file to specify advanced, non-default settings. They See the rules-template file to see what a minimum rules file looks like, or see the rules-example files for more examples.

To use a rules file with glars, copy the template file somewhere and edit it to suit your needs. Make sure that the GLARS script can find your rules file by specifying its location in $RULES_FILE and make sure it has read permissions to be able to read it.














### port_open <protocol> <number>
Opens port <number> on the specified protocol. This only affects WAN-side traffic, as LAN-side is automatically accessible. Example:

**`port_open tcp 22`**

This will make port 22 accessible to the WAN-side.








### port_forward
Forwards an external port to the specified internal_host:port. For example, if you have an HTTP server on the LAN side with IP address 192.168.0.10, listening to port 80, you can make it accessible from the WAN-side on port 80 with:

**`port_forward tcp 80 192.168.0.10:80`**










### port_lock
Opens port <number> only for hosts that "knock" on the specified <lock sequence> of ports, within the specified <timeout> seconds value. The port will then remain open for <timeout> / < number of ports in lock sequence>. Example:

**`port_lock tcp 22 4000,5000,6000 90`**


This will make port 22 accessible from the WAN side only to IP addresses that "knock" on ports 4000 then 5000 then 6000 within 90 seconds. After knocking on port 6000, the port will remain open for that IP address for 90/3 = 30 seconds before closing again.









### port_lock_forward 
Forwards an external port to the specified internal_host:port, only for hosts that "knock" on the specified <lock sequence> of ports, within the specified <timeout> seconds value. The port will then remain open for <timeout> / < number of ports in lock sequence>. For example, if you have an FTP server on the LAN side with IP address 192.168.0.12, listening to port 21, you can make it accessible from the WAN-side on port 1000, only to those who have successfully knocked on the secret knock sequence, using:

**`port_lock_forward tcp 1000 3000,5000,7000,9000 100 192.168.0.12:21`**


External hosts that knock on ports 3000,5000,7000,9000 within 100 seconds will be able to access the FTP server via external port 1000 for 100/4 = 25 seconds










### port_duplicate
Duplicates a local port. For example, if your GLARS router is running an SSH server that is listening on port 22, you can make it listen for SSH connections on port 11503 using:

**`port_duplicate tcp 22 11503`**








### no_internet
Disallows traffic from an internal host or an internal subnet using REJECT. Local traffic to and from this host/subnet will be unaffected, but no traffic will be forwarded from this host/subnet to the external network (unless a 'grant_access_to_safe_zone' rule is given)

**`no_internet 192.168.31.19 `**

### no_internet_deny
Alias for no_internet

### no_internet_drop
Disallows traffic from an internal host or an internal subnet using DROP. Local traffic to and from this host/subnet will be unaffected, but no traffic will be forwarded from this host/subnet to the external network (unless a 'grant_access_to_safe_zone' rule is given)

**`drop_internet 192.168.31.19 `**


### add_safe_destination
To be used in conjuction with restrict_internet. Adds IP addresses to a protected zone
NOTE: The protected zone is a static list from the perspective of GLARS. The IP addresses of these domains will get resolved *only* at the time that GLARS is run. If at a later time the domain changes IP, there will be no way to update the IP addresses in the protected zone, until glars is re-run.
This function is not really intended to be used directly. A much better way to add destinations to a protected zone (and keep them up to date, as well as have the ability to match subdomains, etc.) is to use the ipset feature of the dnsmasq DNS/DHCP server. This is mainly for debugging purposes.

You can determine what domains are needed for a particular website/app by listening to DNS requests while loading your website/app and adding the domains that are needed, until all functionality is achieved. See also the ipset feature in dnsmasq.

The following 2 domains, when used with restrict_internet will allow a host on the local network to connect *only* to wikipedia.
You can add as many domains as you wish.

**`add_safe_destination safe-sites-1 www.wikipedia.org`**
**`add_safe_destination safe-sites-1 upload.wikimedia.org`**


### grant_access_to_safe_zone
Allows a host/subnet to reach a "safe zone" (basically, a group of destinations, collected in an ipset of the same name). This is only effective if the host/subnet will have a no_internet() rule applied to it. If no such rule is applied to the host, then this function is a no-op, since the host can already reach all destinations anyway (except the blacklisted ones)

By default, protected zones (ipsets) are empty. You can add destinations to a protected zone using add_safe_destination or any other method of populating the ipset (such as the 'ipset' feature in dnsmasq).

You can add any number of hosts to a protected zone, and can add a host to any number of protected zones.

NOTE: This feature is really intended to be used with the ipset feature in dnsmasq - that way subdomains can also be matched, and the list can be kept dynamically updated. This can be a very effective way of sandboxing certain untrusted devices (or people!)

The following command, used with the 2 add_safe_destination examples above, will allow $my_android_device to reach nothing on the Internet except Wikipedia.


**`grant_access_to_safe_zone $my_android_device safe-sites-1`**




### limit_connections_to_public_port
Limit the number of connections that can be made to a public port on this router
Note that this implies port_open() on that port

**`limit_connections_to_public_port tcp 22 12/min`**



### limit_connections_to_internal_host
Limit the number of connections that can be made to an internal host on the network
This is the sum of all connections made to this host on all its forwarded ports.

**`limit_connections_to_internal_host $FOO_IP 10/min`**


### limit_connections_to_internal_port
Limit the number of connections that can be made to a port that is forwared to a host on the internal network

**`limit_connections_to_internal_port 80 60/min`**


### TODO:
Add limit_connections_from_* functions
Update documentation to explain bandwidth classes and classify_* functions.
