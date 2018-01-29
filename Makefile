all:
	gcc -std=gnu99 ksc.c -lpcap -I. -L./pcap -o ksc
