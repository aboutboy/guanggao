����
1��libipq.so(�Ѿ��ϲ�����Ŀ��)
2��ip_queue.ko(����netfilter֧�ִ�ģ��)
3��iptables(androidϵͳ�Դ�)
4�������ںˣ�֧��netfilter

��ֲ
1�������ںˣ�֧��netfilter
	ִ��make memuconfig������netfilterѡ��
	Networking-->Networking Options�µ�Network Packet Filtering Framework
	Core Netfilter Configuration(����Netfilter����)��IP��Netfilter Configuration ��IP��Netfilter���ã�
2����������õ�external/webad
3���޸Ŀ��������ļ�device/mediatek/mt6582/init.mt6582.rc����ĩβ���
	service webad /system/bin/webad
    	class main
    	user system
    	group system
4����android��Ŀ¼ִ��make����
5��������������ļ�����ˢ��