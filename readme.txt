1.方案
1.1.浏览器添加代理+本地代理程序
1.2.iptables设置转发数据转发规则+本地代理程序
1.3.netfilter数据转发+本地代理程序
1.4.iptables设置QUEUE动作规则+ip_queue+libnet
yum install epel-release
yum install gcc
yum install iptables-devel
insmod /lib/modules/2.6.32-431.el6.x86_64/kernel/net/ipv4/netfilter/ip_queue.ko
iptables -A INPUT -p tcp --sport 80 -j QUEUE
iptables -A OUTPUT -p tcp --dport 80 -j QUEUE
编译程序
gcc -g http.c -o http -lipq 
1.5.netfilter数据截断发送给用户态+ip_queue+libnet
1.6.netfilter数据截断+libpcap数据包抓取+libnet数据包发送
1.7.netfilter+netlink+libnet
