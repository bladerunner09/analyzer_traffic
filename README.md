HTTP Traffic Analyzer
=====================

The output stats looks as follows (only http!):

	government.ru: 4 packets (2 OUT / 2 IN) Traffic: 956B (922B OUT / 34B IN)
	mc.yandex.ru: 2 packets (1 OUT / 1 IN) Traffic: 382B (280B OUT / 102B IN)

Using the utility
-----------------

When analyzing HTTP traffic on live traffic:

	Basic usage:
		analyzer_traffic [-h] [-r calc_period] [-p dst_port] [-i interface]

	Options:
		-i interface   : Use the specified interface.
		-p dst_port    : Use the specified port (optional parameter, the default is 80)
		-r calc_period : The period in seconds to calculate rates. If not provided default is 5 seconds
		-h             : Displays this help message and exits

To select the specified interface, enter the following command in a terminal:
	
	$ ip link show
	
Example for running the program:

	daniil@xxx:~/Desktop/analyzer_traffic$ ip link show
	
	1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN mode DEFAULT group default qlen 1000
    	 link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
	2: enp0s3: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc fq_codel state UP mode DEFAULT group default qlen 1000
    	 link/ether 08:00:27:0d:96:36 brd ff:ff:ff:ff:ff:ff
    	
    	daniil@xxx:~/Desktop/analyzer_traffic$ sudo ./build/analyzer_traffic -i enp0s3
	
		
