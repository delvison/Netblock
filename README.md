#About#

Netblock is a python script possible of blocking victims connected to the same
gateway from internet access via ARP spoofing. Netblock is capable of blocking
one, multiple, or all victims on the same network.


#How to use#

Netblock runs in CLI. Install the script by executing:

				sudo sh install.sh

Execute Netblock by typing netblock in CLI. Here is what netblock will look like
while running:

				--------------------
				Connected ips:
				0)	10.12.26.1		00:00:0c:07:ac:1a
				1)	10.12.26.2		c8:4c:75:6a:55:40
				2)	10.12.26.3		c8:4c:75:6a:55:80
				3)	10.12.26.7		d0:57:4c:53:7d:42
				4)	10.12.26.9		58:bc:27:00:11:42
				5)	10.12.26.10		58:bc:27:bc:f5:c3
				6)	10.12.26.42		00:90:0b:13:f0:a5
				7)	10.12.26.8		58:bc:27:c2:78:42
				8)	10.12.26.74		18:03:73:3d:90:cb
				9)	10.12.26.84		18:03:73:3d:83:6f
				10)	10.12.26.95		00:26:66:d3:49:f2
				11)	10.12.26.108	00:18:7b:e1:27:83
				12)	10.12.26.124	d4:be:d9:fc:8a:0d
				13)	10.12.26.129	18:03:73:3d:9a:b1
				14)	10.12.26.161	18:03:73:4d:a3:4c
				15)	10.12.26.165	18:03:73:4e:99:27
				16)	10.12.26.173	18:03:73:3d:92:05
				--------------------
				Blocked: [10.12.26.10, 10.12.26.9 ]
				Gateway ip:  10.12.26.1
				Gateway mac: 00:00:0c:07:ac:1a
				--------------------
				Who do you want to block? (Select victim in blocked list to unblock)
				(r - Refresh, a - Kill all, q - quit)
				>


To block a victim simply type in the number of their IP seen in the list.

To unblock a victim simply type the number of their IP seen in the list.

Blocked victims can be seen towards the bottom in a list.

NOTE: The python library scapy must be installed in order to use Netblock.
