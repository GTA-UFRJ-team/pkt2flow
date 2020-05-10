# pkt2flow
This tools transform a packet input in a flow output based on the 5-tuple

Configuration

In the file configuration.h is possible to set the abstraction configuration before compiling the code


Instalation

	sudo apt install libpcap0.8-dev

	gcc -Wall -o pkt2flow pkt2flow.c -lpcap -lm

Execution

./pkt2flow [pcap-file]

For live capture, do not set pcap-file option

Testing

Execute the code with the dataset/sample.pcap 

The output must be equal to the sample.csv file


Features


	bpf_u_int32 flowSize;			/* total flow size in bytes */
	bpf_u_int32 smallestPacket;		/* smallest packet of the flow */
	bpf_u_int32 largestPacket;		/* largest packet of the flow */
	bpf_u_int32 totalPackets;		/* total packets of the flow */
	bpf_u_int32 totalPSH;			/* total PSH flags of the flow */
	bpf_u_int32 totalURG;			/* total URG flags of the flow */	
	bpf_u_int32 totalFIN;			/* total FIN flags of the flow */	
	bpf_u_int32 totalACK;			/* total ACK flags of the flow */	
	bpf_u_int32 totalCWR;			/* total CWR flags of the flow */	
	bpf_u_int32 totalECE;			/* total ECE flags of the flow */	
	bpf_u_int32 totalPUSH;			/* total PUSH flags of the flow */	
	bpf_u_int32 totalRST;			/* total RST flags of the flow */	
	bpf_u_int32 totalSYN;			/* total SYN flags of the flow */	
	double meanPacketSize;			/* mean packet size of the flow */
	double stdPacketSize;			/* standart deviation of packets size */
	double meanTimePacket;			/* mean time between packets in microseconds */
	double stdTimePacket;			/* standart deviation time between packets in microseconds */
	time_t minTimePacket;			/* minimum time between packets in microseconds */
	time_t maxTimePacket;			/* maximum time between packets in microseconds */
	time_t totalTime;			/* time between the first and the last packets, the maximum time is WINDOW_SIZE time */
	time_t firstTime;			/* first packet time in microseconds */
	time_t lastTime;			/* last packet time in microseconds */

