#define IP_STR		16		/* ip string biggest size: 000 .000.000.000\0 */
#define FIT_USEC	1000000		/* fit all times to microseconds */
#define BLOCK_TIMER	-1		/* stop the timer that remove flows from the list */
#define IP_TYPE		8		/* code of IP protocol */


/* ethernet headers are always exactly 14 bytes [1] */
#define SIZE_ETHERNET 14

/* Ethernet addresses are 6 bytes */
#define ETHER_ADDR_LEN	6

#define MAXBYTES2CAPTURE 2048

/* Ethernet header */
struct sniff_ethernet {
        u_char  ether_dhost[ETHER_ADDR_LEN];    /* destination host address */
        u_char  ether_shost[ETHER_ADDR_LEN];    /* source host address */
        u_short ether_type;                     /* IP? ARP? RARP? etc */
};

/* IP header */
struct sniff_ip {
        u_char  ip_vhl;                 /* version << 4 | header length >> 2 */
        u_char  ip_tos;                 /* type of service */
        u_short ip_len;                 /* total length */
        u_short ip_id;                  /* identification */
        u_short ip_off;                 /* fragment offset field */
        #define IP_RF 0x8000            /* reserved fragment flag */
        #define IP_DF 0x4000            /* dont fragment flag */
        #define IP_MF 0x2000            /* more fragments flag */
        #define IP_OFFMASK 0x1fff       /* mask for fragmenting bits */
        u_char  ip_ttl;                 /* time to live */
        u_char  ip_p;                   /* protocol */
        u_short ip_sum;                 /* checksum */
        struct  in_addr ip_src,ip_dst;  /* source and dest address */
};
#define IP_HL(ip)               (((ip)->ip_vhl) & 0x0f)
#define IP_V(ip)                (((ip)->ip_vhl) >> 4)

/* TCP header */
typedef u_int tcp_seq;

struct sniff_tcp {
        u_short th_sport;               /* source port */
        u_short th_dport;               /* destination port */
        tcp_seq th_seq;                 /* sequence number */
        tcp_seq th_ack;                 /* acknowledgement number */
        u_char  th_offx2;               /* data offset, rsvd */
	#define TH_OFF(th)      (((th)->th_offx2 & 0xf0) >> 4)
        u_char  th_flags;
        #define TH_FIN  0x01
        #define TH_SYN  0x02
        #define TH_RST  0x04
        #define TH_PUSH 0x08
        #define TH_ACK  0x10
        #define TH_URG  0x20
        #define TH_ECE  0x40
        #define TH_CWR  0x80
        #define TH_FLAGS        (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
        u_short th_win;                 /* window */
        u_short th_sum;                 /* checksum */
        u_short th_urp;                 /* urgent pointer */
};


struct sniff_udp{
	u_short uh_sport;  		/* source port */
	u_short uh_dport;		/* destination port */
	u_short uh_ulen;		/* length */
	u_short uh_sum;			/* checksum */
};

/* Flow features */
typedef struct flowFeatures{
	bpf_u_int32 flowSize;				/* total flow size in bytes */
	bpf_u_int32 smallestPacket;			/* smallest packet of the flow */
	bpf_u_int32 largestPacket;			/* largest packet of the flow */
	bpf_u_int32 totalPackets;			/* total packets of the flow */
	bpf_u_int32 totalPSH;				/* total PSH flags of the flow */
	bpf_u_int32 totalURG;				/* total URG flags of the flow */	
	bpf_u_int32 totalFIN;				/* total FIN flags of the flow */	
	bpf_u_int32 totalACK;				/* total ACK flags of the flow */	
	bpf_u_int32 totalCWR;				/* total CWR flags of the flow */	
	bpf_u_int32 totalECE;				/* total ECE flags of the flow */	
	bpf_u_int32 totalPUSH;				/* total PUSH flags of the flow */	
	bpf_u_int32 totalRST;				/* total RST flags of the flow */	
	bpf_u_int32 totalSYN;				/* total SYN flags of the flow */	
	double meanPacketSize;				/* mean packet size of the flow */
	double stdPacketSize;				/* standart deviation of packets size */
	double meanTimePacket;				/* mean time between packets in microseconds */
	double stdTimePacket;				/* standart deviation time between packets in microseconds */
	time_t minTimePacket;				/* minimum time between packets in microseconds */
	time_t maxTimePacket;				/* maximum time between packets in microseconds */
	time_t totalTime;				/* time between the first and the last packets, the maximum time is 2 seconds */
	time_t firstTime;				/* first packet time in microseconds */
	time_t lastTime;				/* last packet time in microseconds */
} flowFeatures_t;

/* Flow header definition */
typedef struct flowID{
	char ipDst[IP_STR+1];
	char ipSrc[IP_STR+1];
	unsigned short int portDst;
	unsigned short int portSrc;
	unsigned short int protocol;
	double time; 					/* time to expire the flow entry */
} flowID_t;

/* List of current active flows */
typedef struct flowList{
	flowID_t flowHeader;
	flowFeatures_t flowFeatures;
	bool active;
	struct flowList *next,*last;
} flowList_t;


typedef enum {
	ok,
	erroEmptyPointer,
	erroEntryExistsAlready,
	erroFlowDontExist
}erroTypes;
