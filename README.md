# AF_XDP INT monitor connected to Kafka

This is the XDP_AF implementation for INT report parsing and Kafka production. 

To install the INT monitor, clone the net-next linux kernel, optionally check out the revision `8b89d8dad5df177032e7e97ecfb18f01134e0e4b`, and put the xdp_kafka.c file into the `net-next/samples/bpf` directory. Modify the Makefile accordingly to include the project. For example, put these code snippets in their appropriate place:
  
`xdpkafka-objs := xdp_kafka.o`

`HOSTLDLIBS_xdpkafka     += -pthread -lrdkafka`
  
`hostprogs-y += xdpkafka`
  
  
Then run `make`. Afterwards, the program can be run with `./xdpkafka enp101s0f1`. It will accept INT traffic on that interface, and output performance data. 
  
The data output can be configured by modifying `static void dump_stats(void)` method. 

There are four parameters configurable by preprocessor directives. 

 * `#define DEBUG_HEXDUMP`: Enables hex dumping of incoming packets. 
 * `#define DEBUG_INTDUMP`: Enables INT data dumping of incoming packets. 
 * `#define KAFKA_ENABLE`: Enables Kafka producer. Please check the the `kafka_push_msg` method for exacly how the Kafka messages are produced, and check the `main` method for Kafka producer configuration. 
 * `#define PARSER_ENABLE`: Enables INT parsing. Without this, the program doesn't parse INT data and essentially does nothing. 
 
These parameters are for debugging purposes, and could be useful if you try to get the program up and running. Good luck! 
