#!/bin/bash

### 1: Drop invalid packets ### 
# Drop incoming packets with INVALID connection tracking state
iptables -t mangle -A PREROUTING -m conntrack --ctstate INVALID -j DROP

### 2: Drop TCP packets that are new and are not SYN ### 
# Drop incoming non-SYN TCP packets in NEW connection state
iptables -t mangle -A PREROUTING -p tcp ! --syn -m conntrack --ctstate NEW -j DROP

### 3: Drop SYN packets with suspicious MSS value ### 
# Drop incoming TCP packets in NEW connection state with TCPMSS values outside the specified range
iptables -t mangle -A PREROUTING -p tcp -m conntrack --ctstate NEW -m tcpmss ! --mss 536:65535 -j DROP

### 4: Block packets with bogus TCP flags ### 
# Drop incoming TCP packets with specific TCP flags combinations
iptables -t mangle -A PREROUTING -p tcp --tcp-flags FIN,SYN FIN,SYN -j DROP
iptables -t mangle -A PREROUTING -p tcp --tcp-flags SYN,RST SYN,RST -j DROP
iptables -t mangle -A PREROUTING -p tcp --tcp-flags FIN,RST FIN,RST -j DROP
iptables -t mangle -A PREROUTING -p tcp --tcp-flags FIN,ACK FIN -j DROP
iptables -t mangle -A PREROUTING -p tcp --tcp-flags ACK,URG URG -j DROP
iptables -t mangle -A PREROUTING -p tcp --tcp-flags ACK,PSH PSH -j DROP
iptables -t mangle -A PREROUTING -p tcp --tcp-flags ALL NONE -j DROP

### 5: Block spoofed packets ### 
# Drop incoming packets from specific address ranges. You might want to adjust these if you're running Docker containers or you are actually using the below ip ranges.
iptables -t mangle -A PREROUTING -s 224.0.0.0/3 -j DROP
iptables -t mangle -A PREROUTING -s 169.254.0.0/16 -j DROP
iptables -t mangle -A PREROUTING -s 172.16.0.0/12 -j DROP
iptables -t mangle -A PREROUTING -s 192.0.2.0/24 -j DROP
iptables -t mangle -A PREROUTING -s 192.168.0.0/16 -j DROP
iptables -t mangle -A PREROUTING -s 10.0.0.0/8 -j DROP
iptables -t mangle -A PREROUTING -s 0.0.0.0/8 -j DROP
iptables -t mangle -A PREROUTING -s 240.0.0.0/5 -j DROP
iptables -t mangle -A PREROUTING -s 127.0.0.0/8 ! -i lo -j DROP

### 6: Drop ICMP (you usually don't need this protocol) ### 
# Drop incoming ICMP packets
iptables -t mangle -A PREROUTING -p icmp -j DROP

### 7: Limit connections per source IP (80 in our case, you can adjust that value to your needs) ### 
# Reject incoming TCP connections if the number of connections exceeds the limit
iptables -A INPUT -p tcp -m connlimit --connlimit-above 80 -j REJECT --reject-with tcp-reset

### 8: Drop fragments in all chains ### 
# Drop incoming fragmented packets
iptables -t mangle -A PREROUTING -f -j DROP
