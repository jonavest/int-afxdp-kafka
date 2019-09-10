# AF_XDP INT monitor connected to Kafka

This is the XDP_AF implementation for INT report parsing and Kafka production. 

To install the INT monitor, clone the net-next linux kernel, optionally check out the revision `8b89d8dad5df177032e7e97ecfb18f01134e0e4b`, and put the xdp_kafka.c file into the `net-next/samples/bpf` directory. Modify the Makefile accordingly to include the project. For example, put these code snippets in their appropriate place:
  
  xdpkafka-objs := xdp_kafka.o

  HOSTLDLIBS_xdpkafka     += -pthread -lrdkafka
  
  hostprogs-y += xdpkafka
  
  
Then run `make`. Afterwards, the program can be run with `./xdpkafka enp101s0f1`. It will accept INT traffic on that interface, and output performance data. 
  
