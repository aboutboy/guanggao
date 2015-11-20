依赖
1、libipq.so(已经合并到项目中)
2、ip_queue.ko(开启netfilter会支持此模块)
3、iptables(android系统自带)
4、配置内核，支持netfilter(默认已经开启)

移植
1、如果内核不支持netfilter
	执行make memuconfig，开启netfilter选项
	Networking-->Networking Options-->Network Packet Filtering Framework-->
	Core Netfilter Configuration(核心Netfilter配置)和IP：Netfilter Configuration （IP：Netfilter配置）
2、将代码放置到external/webad
3、修改开机启动文件device/mediatek/mt6582/init.mt6582.rc，在末尾添加
	service webad /system/bin/webad
    	class main
    	user system
    	group system
4、在android根目录执行make命令
5、将编译出来的文件进行刷机