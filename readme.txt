1.����
1.1.�������Ӵ���+���ش������
1.2.iptables����ת������ת������+���ش������
1.3.netfilter����ת��+���ش������
1.4.iptables����QUEUE��������+ip_queue+libnet
yum install epel-release
yum install gcc
yum install iptables-devel
insmod /lib/modules/2.6.32-431.el6.x86_64/kernel/net/ipv4/netfilter/ip_queue.ko
iptables -A INPUT -p tcp --sport 80 -j QUEUE
iptables -A OUTPUT -p tcp --dport 80 -j QUEUE
�������
gcc -g http.c -o http -lipq 
1.5.netfilter���ݽضϷ��͸��û�̬+ip_queue+libnet
1.6.netfilter���ݽض�+libpcap���ݰ�ץȡ+libnet���ݰ�����
1.7.netfilter+netlink+libnet
