/*
 * Author: Lucas Airam Castro de Souza
 * Laboratory: Grupo de Teleinformática e Automação
 * University: Universidade Federal do Rio de Janeiro
 *
 *
 *
 * Configuration: set output file and flow time window size in configuration.h
 *
 * Usage: ./pkt2flow [pcapfile]
 * 
 * Output: file
 *
 * 
 *
 * */



#include <math.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <string.h>
#include <pcap.h>
#include <ctype.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>


#include "oneDirection-noTcpState-structures.h"
#include "oneDirection-noTcpState-functionHeader.h"
#include "configuration.h"



FILE 		*FLOWS_RESULTS;				/* file to wirte results */		
flowList_t 	*LIST_FIRST;				/* contains all active flows */ 
bool 		empty;					/* indicates if the list is empty */
flowList_t 	*LIST_LAST;			/* contains the final address */ 
double		timer;					/* contains the time to remove the oldest flow */
 

/******************************** Flow list interaction functions **********************************/

flowList_t * 
findFlow(flowID_t flow, bool *find)
{
	flowList_t *currentFlow;
	currentFlow = LIST_FIRST;
	

	while(currentFlow->flowHeader.ipDst)
	{

		if(	
			!(strcmp(currentFlow->flowHeader.ipSrc,flow.ipSrc)) &&
			!(strcmp(currentFlow->flowHeader.ipDst,flow.ipDst)) &&	
			currentFlow->flowHeader.portSrc == flow.portSrc &&
			currentFlow->flowHeader.portDst == flow.portDst &&
			currentFlow->flowHeader.protocol == flow.protocol
				)
		{
			*(find) = true;
			return currentFlow;
		}
		currentFlow = currentFlow->next;
	}
	*(find) = false;
	return NULL;
}

int 
flowAdd(flowID_t flow)
{
	flowList_t *newEntry;	     	/* if the list is not empty, this variable will allocate the new entry */


	if(empty)
	{
		/* get flow header */
		strcpy(LIST_FIRST->flowHeader.ipSrc,flow.ipSrc);
		strcpy(LIST_FIRST->flowHeader.ipDst,flow.ipDst);
		LIST_FIRST->flowHeader.portSrc 		= flow.portSrc;
		LIST_FIRST->flowHeader.portDst 		= flow.portDst;
		LIST_FIRST->flowHeader.protocol 	= flow.protocol;
		LIST_FIRST->flowHeader.time 		= flow.time;
		LIST_FIRST->active 			= false;
		empty 					= false;
		
		/* set the timer */
		timer = flow.time;
	
		/* allocate the next element */
		newEntry = (flowList_t *)(malloc(sizeof(flowList_t)));
		newEntry->last 		= LIST_FIRST;
		newEntry->next 		= NULL;
		newEntry->active 	= true;
		LIST_LAST 		= newEntry;
		LIST_FIRST->next 	= LIST_LAST;
		return ok;
	}

	/* for the second flow or greater */

	/* get flow header */
	strcpy(LIST_LAST->flowHeader.ipSrc,flow.ipSrc);
	strcpy(LIST_LAST->flowHeader.ipDst,flow.ipDst);
	LIST_LAST->flowHeader.portSrc 		= flow.portSrc;
	LIST_LAST->flowHeader.portDst 		= flow.portDst;
	LIST_LAST->flowHeader.protocol 		= flow.protocol;
	LIST_LAST->flowHeader.time 		= flow.time;
	LIST_LAST->active			= false;	

	/* allocate the next element */
	newEntry = (flowList_t *)(malloc(sizeof(flowList_t)));
	newEntry->last 		= LIST_LAST;
	newEntry->next 		= NULL;
	newEntry->flowHeader.ipSrc[0] = '\0';
	newEntry->flowHeader.ipDst[0] = '\0';
	newEntry->active 	= true;
	LIST_LAST->next 	= newEntry;
	LIST_LAST 		= newEntry;
	return ok;
}

/*************************************************************************************************************/

/************************************ update features functions ***************************************************************/

int 
updateFlowFeaturesOTHER(flowID_t flow, const struct pcap_pkthdr *packet)
{
	flowList_t *flowEntry;
	bool find;

	
	flowEntry = findFlow(flow, &find);
	
	if(!find)
		return erroEmptyPointer;



	/* verify if it is the first packet of the flow to add the time */
	if(!flowEntry->active)
	{
		/* initialize ip features */
		flowEntry->flowFeatures.firstTime 	= packet->ts.tv_sec*FIT_USEC + packet->ts.tv_usec;
		flowEntry->flowFeatures.lastTime 	= packet->ts.tv_sec*FIT_USEC + packet->ts.tv_usec;
		flowEntry->flowFeatures.flowSize 	= packet->len;
		flowEntry->flowFeatures.smallestPacket 	= packet->len;
		flowEntry->flowFeatures.largestPacket 	= packet->len;
		flowEntry->flowFeatures.minTimePacket 	= FIT_USEC*WINDOW_SIZE;			
		flowEntry->flowFeatures.maxTimePacket 	= 0;			
		flowEntry->flowFeatures.meanTimePacket	= 0;			
		flowEntry->flowFeatures.stdTimePacket 	= 0;
		flowEntry->flowFeatures.stdPacketSize 	= 0;
		flowEntry->flowFeatures.meanPacketSize 	= packet->len;
		flowEntry->flowFeatures.totalPackets 	= 1;
		
		
		/* set tcp features in 0 */
		flowEntry->flowFeatures.totalFIN 	=  0;
		flowEntry->flowFeatures.totalSYN 	=  0;
		flowEntry->flowFeatures.totalRST 	=  0;
		flowEntry->flowFeatures.totalPUSH 	=  0;
		flowEntry->flowFeatures.totalACK	=  0;
		flowEntry->flowFeatures.totalURG 	=  0;
		flowEntry->flowFeatures.totalECE 	=  0;
		flowEntry->flowFeatures.totalCWR 	=  0;
			
		flowEntry->active			= true;	

		return ok;
		

	}
	
	/* calcule metricts for other cases */
	long int totalPkt = flowEntry->flowFeatures.totalPackets; 
	double timeElapsed;

	/* second packet needs special process of mean and standart deviation */
	if(flowEntry->flowFeatures.totalPackets == 1)
	{
		/* time between two consecutives packets */
		timeElapsed = packet->ts.tv_sec*FIT_USEC + packet->ts.tv_usec - flowEntry->flowFeatures.lastTime;

		flowEntry->flowFeatures.lastTime =  packet->ts.tv_sec*FIT_USEC + packet->ts.tv_usec;
	
		flowEntry->flowFeatures.meanPacketSize = (packet->len + flowEntry->flowFeatures.meanPacketSize)/2.0;

		flowEntry->flowFeatures.stdPacketSize = sqrt((pow(packet->len-flowEntry->flowFeatures.meanPacketSize,2)+
			pow(flowEntry->flowFeatures.smallestPacket - flowEntry->flowFeatures.meanPacketSize,2))/2.0);
				

		/* initialize time features */
		flowEntry->flowFeatures.meanTimePacket = timeElapsed;
		flowEntry->flowFeatures.maxTimePacket = timeElapsed;
		flowEntry->flowFeatures.minTimePacket = timeElapsed;
		flowEntry->flowFeatures.stdTimePacket = 0.0;
		flowEntry->flowFeatures.lastTime = packet->ts.tv_sec*FIT_USEC + packet->ts.tv_usec;


	
		if(flowEntry->flowFeatures.largestPacket < packet->len)
			flowEntry->flowFeatures.largestPacket = packet->len;
		if(flowEntry->flowFeatures.smallestPacket > packet->len)
			flowEntry->flowFeatures.smallestPacket = packet->len;
		
			
		flowEntry->flowFeatures.totalPackets++;
		flowEntry->flowFeatures.flowSize += packet->len;
		
		return ok;		
	}


	/**************************************** update features for other packets **********************************************/
	
	/* time between two consecutives packets in microseconds */
	timeElapsed = packet->ts.tv_sec*FIT_USEC + packet->ts.tv_usec - flowEntry->flowFeatures.lastTime;	


	flowEntry->flowFeatures.stdPacketSize = sqrt((
				flowEntry->flowFeatures.stdPacketSize+(totalPkt/(totalPkt+1.0))*
				pow(packet->len-flowEntry->flowFeatures.meanPacketSize,2))/totalPkt);

	flowEntry->flowFeatures.meanPacketSize = (packet->len+(flowEntry->flowFeatures.meanPacketSize * totalPkt))/(totalPkt+1.0);


	flowEntry->flowFeatures.stdTimePacket = sqrt((
				flowEntry->flowFeatures.stdTimePacket + (totalPkt/(totalPkt+1.0))*
				pow(timeElapsed - flowEntry->flowFeatures.meanTimePacket,2))/totalPkt);

	

	flowEntry->flowFeatures.meanTimePacket = (timeElapsed+(flowEntry->flowFeatures.meanTimePacket * totalPkt))/(totalPkt+1.0);
	
	/* largest and smallest time and size features */
	if(flowEntry->flowFeatures.largestPacket < packet->len)
		flowEntry->flowFeatures.largestPacket = packet->len;

	if(flowEntry->flowFeatures.smallestPacket > packet->len)
		flowEntry->flowFeatures.smallestPacket = packet->len;

	if(timeElapsed > flowEntry->flowFeatures.maxTimePacket)
		flowEntry->flowFeatures.maxTimePacket = timeElapsed;

	if(timeElapsed < flowEntry->flowFeatures.minTimePacket)
		flowEntry->flowFeatures.minTimePacket = timeElapsed;


	flowEntry->flowFeatures.totalPackets++;
	flowEntry->flowFeatures.lastTime = packet->ts.tv_sec*FIT_USEC + packet->ts.tv_usec;
	flowEntry->flowFeatures.flowSize += packet->len;
	return ok;

}
int 
updateFlowFeaturesUDP(flowID_t flow, const struct pcap_pkthdr *packet, const struct sniff_udp *udp)
{
	flowList_t *flowEntry;
	bool find;

	
	flowEntry = findFlow(flow, &find);
	
	if(!find)
		return erroEmptyPointer;



	/* verify if it is the first packet of the flow to add the time */
	if(!flowEntry->active)
	{
		/* initialize ip features */
		flowEntry->flowFeatures.firstTime 	= packet->ts.tv_sec*FIT_USEC + packet->ts.tv_usec;
		flowEntry->flowFeatures.lastTime 	= packet->ts.tv_sec*FIT_USEC + packet->ts.tv_usec;
		flowEntry->flowFeatures.flowSize 	= packet->len;
		flowEntry->flowFeatures.smallestPacket 	= packet->len;
		flowEntry->flowFeatures.largestPacket 	= packet->len;
		flowEntry->flowFeatures.minTimePacket 	= FIT_USEC*WINDOW_SIZE;			
		flowEntry->flowFeatures.maxTimePacket 	= 0;			
		flowEntry->flowFeatures.meanTimePacket	= 0;			
		flowEntry->flowFeatures.stdTimePacket 	= 0;
		flowEntry->flowFeatures.stdPacketSize 	= 0;
		flowEntry->flowFeatures.meanPacketSize 	= packet->len;
		flowEntry->flowFeatures.totalPackets 	= 1;
		
		
		/* set tcp features in 0 */
		flowEntry->flowFeatures.totalFIN 	=  0;
		flowEntry->flowFeatures.totalSYN 	=  0;
		flowEntry->flowFeatures.totalRST 	=  0;
		flowEntry->flowFeatures.totalPUSH 	=  0;
		flowEntry->flowFeatures.totalACK	=  0;
		flowEntry->flowFeatures.totalURG 	=  0;
		flowEntry->flowFeatures.totalECE 	=  0;
		flowEntry->flowFeatures.totalCWR 	=  0;
			
		flowEntry->active			= true;	

		return ok;
		

	}
	
	/* calcule metricts for other cases */
	long int totalPkt = flowEntry->flowFeatures.totalPackets; 
	double timeElapsed;

	/* second packet needs special process of mean and standart deviation */
	if(flowEntry->flowFeatures.totalPackets == 1)
	{
		/* time between two consecutives packets */
		timeElapsed = packet->ts.tv_sec*FIT_USEC + packet->ts.tv_usec - flowEntry->flowFeatures.lastTime;

		flowEntry->flowFeatures.lastTime =  packet->ts.tv_sec*FIT_USEC + packet->ts.tv_usec;
	
		flowEntry->flowFeatures.meanPacketSize = (packet->len + flowEntry->flowFeatures.meanPacketSize)/2.0;

		flowEntry->flowFeatures.stdPacketSize = sqrt((pow(packet->len-flowEntry->flowFeatures.meanPacketSize,2)+
			pow(flowEntry->flowFeatures.smallestPacket - flowEntry->flowFeatures.meanPacketSize,2))/2.0);
				

		/* initialize time features */
		flowEntry->flowFeatures.meanTimePacket = timeElapsed;
		flowEntry->flowFeatures.maxTimePacket = timeElapsed;
		flowEntry->flowFeatures.minTimePacket = timeElapsed;
		flowEntry->flowFeatures.stdTimePacket = 0.0;
		flowEntry->flowFeatures.lastTime = packet->ts.tv_sec*FIT_USEC + packet->ts.tv_usec;


	
		if(flowEntry->flowFeatures.largestPacket < packet->len)
			flowEntry->flowFeatures.largestPacket = packet->len;
		if(flowEntry->flowFeatures.smallestPacket > packet->len)
			flowEntry->flowFeatures.smallestPacket = packet->len;
		
			
		flowEntry->flowFeatures.totalPackets++;
		flowEntry->flowFeatures.flowSize += packet->len;
		
		return ok;		
	}


	/**************************************** update features for other packets **********************************************/
	
	/* time between two consecutives packets in microseconds */
	timeElapsed = packet->ts.tv_sec*FIT_USEC + packet->ts.tv_usec - flowEntry->flowFeatures.lastTime;	


	flowEntry->flowFeatures.stdPacketSize = sqrt((
				flowEntry->flowFeatures.stdPacketSize+(totalPkt/(totalPkt+1.0))*
				pow(packet->len-flowEntry->flowFeatures.meanPacketSize,2))/totalPkt);

	flowEntry->flowFeatures.meanPacketSize = (packet->len+(flowEntry->flowFeatures.meanPacketSize * totalPkt))/(totalPkt+1.0);


	flowEntry->flowFeatures.stdTimePacket = sqrt((
				flowEntry->flowFeatures.stdTimePacket + (totalPkt/(totalPkt+1.0))*
				pow(timeElapsed - flowEntry->flowFeatures.meanTimePacket,2))/totalPkt);

	

	flowEntry->flowFeatures.meanTimePacket = (timeElapsed+(flowEntry->flowFeatures.meanTimePacket * totalPkt))/(totalPkt+1.0);
	
	/* largest and smallest time and size features */
	if(flowEntry->flowFeatures.largestPacket < packet->len)
		flowEntry->flowFeatures.largestPacket = packet->len;

	if(flowEntry->flowFeatures.smallestPacket > packet->len)
		flowEntry->flowFeatures.smallestPacket = packet->len;

	if(timeElapsed > flowEntry->flowFeatures.maxTimePacket)
		flowEntry->flowFeatures.maxTimePacket = timeElapsed;

	if(timeElapsed < flowEntry->flowFeatures.minTimePacket)
		flowEntry->flowFeatures.minTimePacket = timeElapsed;


	flowEntry->flowFeatures.totalPackets++;
	flowEntry->flowFeatures.lastTime = packet->ts.tv_sec*FIT_USEC + packet->ts.tv_usec;
	flowEntry->flowFeatures.flowSize += packet->len;
	return ok;

}


int 
updateFlowFeaturesTCP(flowID_t flow, const struct pcap_pkthdr *packet, const struct sniff_tcp *tcp)
{
	flowList_t *flowEntry;
	bool find;

	
	flowEntry = findFlow(flow, &find);
	
	if(!find)
		return erroEmptyPointer;



	/* verify if it is the first packet of the flow to add the time */
	if(!flowEntry->active)
	{



		/* initialize ip features */
		flowEntry->flowFeatures.firstTime 	= packet->ts.tv_sec*FIT_USEC + packet->ts.tv_usec;
		flowEntry->flowFeatures.lastTime 	= packet->ts.tv_sec*FIT_USEC + packet->ts.tv_usec;
		flowEntry->flowFeatures.flowSize 	= packet->len;
		flowEntry->flowFeatures.smallestPacket 	= packet->len;
		flowEntry->flowFeatures.largestPacket 	= packet->len;
		flowEntry->flowFeatures.minTimePacket 	= FIT_USEC*WINDOW_SIZE;			
		flowEntry->flowFeatures.maxTimePacket 	= 0;			
		flowEntry->flowFeatures.meanTimePacket	= 0;			
		flowEntry->flowFeatures.stdTimePacket 	= 0;
		flowEntry->flowFeatures.stdPacketSize 	= 0;
		flowEntry->flowFeatures.meanPacketSize 	= packet->len;
		flowEntry->flowFeatures.totalPackets 	= 1;
		
		
		/* initialize tcp features */
		flowEntry->flowFeatures.totalFIN 	= (TH_FIN & tcp->th_flags) ? 1 : 0;
		flowEntry->flowFeatures.totalSYN 	= (TH_SYN & tcp->th_flags) ? 1 : 0;
		flowEntry->flowFeatures.totalRST 	= (TH_RST & tcp->th_flags) ? 1 : 0;
		flowEntry->flowFeatures.totalPUSH 	= (TH_PUSH & tcp->th_flags)? 1 : 0;
		flowEntry->flowFeatures.totalACK	= (TH_ACK & tcp->th_flags) ? 1 : 0;
		flowEntry->flowFeatures.totalURG 	= (TH_URG & tcp->th_flags) ? 1 : 0;
		flowEntry->flowFeatures.totalECE 	= (TH_ECE & tcp->th_flags) ? 1 : 0;
		flowEntry->flowFeatures.totalCWR 	= (TH_CWR & tcp->th_flags) ? 1 : 0;
			
		
		flowEntry->active			= true;	
				
		return ok;
		

	}
	
	/* calcule metricts for other cases */
	long int totalPkt = flowEntry->flowFeatures.totalPackets; 
	double timeElapsed;

	/* second packet needs special process of mean and standart deviation */
	if(flowEntry->flowFeatures.totalPackets == 1)
	{
		/* time between two consecutives packets */
		timeElapsed = packet->ts.tv_sec*FIT_USEC + packet->ts.tv_usec - flowEntry->flowFeatures.lastTime;

		flowEntry->flowFeatures.lastTime =  packet->ts.tv_sec*FIT_USEC + packet->ts.tv_usec;
	
		flowEntry->flowFeatures.meanPacketSize = (packet->len + flowEntry->flowFeatures.meanPacketSize)/2.0;

		flowEntry->flowFeatures.stdPacketSize = sqrt((pow(packet->len-flowEntry->flowFeatures.meanPacketSize,2)+
			pow(flowEntry->flowFeatures.smallestPacket - flowEntry->flowFeatures.meanPacketSize,2))/2.0);
				

		/* initialize time features */
		flowEntry->flowFeatures.meanTimePacket = timeElapsed;
		flowEntry->flowFeatures.maxTimePacket = timeElapsed;
		flowEntry->flowFeatures.minTimePacket = timeElapsed;
		flowEntry->flowFeatures.stdTimePacket = 0.0;
		flowEntry->flowFeatures.lastTime = packet->ts.tv_sec*FIT_USEC + packet->ts.tv_usec;

		/* tcp flags */
		if(TH_FIN & tcp->th_flags)
			flowEntry->flowFeatures.totalFIN++;
		if(TH_SYN & tcp->th_flags)
			flowEntry->flowFeatures.totalSYN++;
		if(TH_RST & tcp->th_flags)
			flowEntry->flowFeatures.totalRST++;
		if(TH_PUSH & tcp->th_flags)
			flowEntry->flowFeatures.totalPUSH++;
		if(TH_ACK & tcp->th_flags)
			flowEntry->flowFeatures.totalACK++;
		if(TH_URG & tcp->th_flags)
			flowEntry->flowFeatures.totalURG++;
		if(TH_ECE & tcp->th_flags)
			flowEntry->flowFeatures.totalECE++;
		if(TH_CWR & tcp->th_flags)
			flowEntry->flowFeatures.totalCWR++;

	
		if(flowEntry->flowFeatures.largestPacket < packet->len)
			flowEntry->flowFeatures.largestPacket = packet->len;
		if(flowEntry->flowFeatures.smallestPacket > packet->len)
			flowEntry->flowFeatures.smallestPacket = packet->len;
		
			
		flowEntry->flowFeatures.totalPackets++;
		flowEntry->flowFeatures.flowSize += packet->len;
		
		return ok;		
	}


	/**************************************** update features for other packets **********************************************/
	
	/* time between two consecutives packets in microseconds */
	timeElapsed = packet->ts.tv_sec*FIT_USEC + packet->ts.tv_usec - flowEntry->flowFeatures.lastTime;	


	flowEntry->flowFeatures.stdPacketSize = sqrt((
				flowEntry->flowFeatures.stdPacketSize+(totalPkt/(totalPkt+1.0))*
				pow(packet->len-flowEntry->flowFeatures.meanPacketSize,2))/totalPkt);

	flowEntry->flowFeatures.meanPacketSize = (packet->len+(flowEntry->flowFeatures.meanPacketSize * totalPkt))/(totalPkt+1.0);


	flowEntry->flowFeatures.stdTimePacket = sqrt((
				flowEntry->flowFeatures.stdTimePacket + (totalPkt/(totalPkt+1.0))*
				pow(timeElapsed - flowEntry->flowFeatures.meanTimePacket,2))/totalPkt);

	

	flowEntry->flowFeatures.meanTimePacket = (timeElapsed+(flowEntry->flowFeatures.meanTimePacket * totalPkt))/(totalPkt+1.0);
	
	/* largest and smallest time and size features */
	if(flowEntry->flowFeatures.largestPacket < packet->len)
		flowEntry->flowFeatures.largestPacket = packet->len;

	if(flowEntry->flowFeatures.smallestPacket > packet->len)
		flowEntry->flowFeatures.smallestPacket = packet->len;

	if(timeElapsed > flowEntry->flowFeatures.maxTimePacket)
		flowEntry->flowFeatures.maxTimePacket = timeElapsed;

	if(timeElapsed < flowEntry->flowFeatures.minTimePacket)
		flowEntry->flowFeatures.minTimePacket = timeElapsed;


	/* tcp flags */
	if(TH_FIN & tcp->th_flags)
		flowEntry->flowFeatures.totalFIN++;
	if(TH_SYN & tcp->th_flags)
		flowEntry->flowFeatures.totalSYN++;
	if(TH_RST & tcp->th_flags)
		flowEntry->flowFeatures.totalRST++;
	if(TH_PUSH & tcp->th_flags)
		flowEntry->flowFeatures.totalPUSH++;
	if(TH_ACK & tcp->th_flags)
		flowEntry->flowFeatures.totalACK++;
	if(TH_URG & tcp->th_flags)
		flowEntry->flowFeatures.totalURG++;
	if(TH_ECE & tcp->th_flags)
		flowEntry->flowFeatures.totalECE++;
	if(TH_CWR & tcp->th_flags)
		flowEntry->flowFeatures.totalCWR++;



	flowEntry->flowFeatures.totalPackets++;
	flowEntry->flowFeatures.lastTime = packet->ts.tv_sec*FIT_USEC + packet->ts.tv_usec;
	flowEntry->flowFeatures.flowSize += packet->len;
	
	return ok;
}


/*************************************************************************************************************/


/****************************************** save flows functions *********************************************/

void
saveAllFlows(void)
{
	while(!empty)
	{
		saveExpiredFlow(LIST_FIRST);
		flowRemove();
	}
	return;
}

void 
printFlow(flowList_t *flow)
{

	flow->flowFeatures.totalTime = flow->flowFeatures.lastTime - flow->flowFeatures.firstTime;


	/* save features */
	printf("%s,%s,%u,%u,%u,%u,%u,%u,%u,%g,%g,%li,%li,%f,%g,%u,%u,%u,%u,%u,%u,%u,%u,%f\n",
			flow->flowHeader.ipSrc,						/*  1 */
			flow->flowHeader.ipDst,						/*  2 */
			flow->flowHeader.portSrc,                                       /*  3 */
			flow->flowHeader.portDst,                                       /*  4 */
			flow->flowHeader.protocol,                                      /*  5 */ 
			flow->flowFeatures.flowSize,                                    /*  6 */
			flow->flowFeatures.totalPackets,                                /*  7 */ 
			flow->flowFeatures.smallestPacket,                              /*  8 */
			flow->flowFeatures.largestPacket,                               /*  9 */ 
			flow->flowFeatures.meanPacketSize,                              /* 10 */
			flow->flowFeatures.stdPacketSize,                               /* 11 */ 
			flow->flowFeatures.minTimePacket,                               /* 12 */ 
			flow->flowFeatures.maxTimePacket,                               /* 13 */ 
			(double)flow->flowFeatures.meanTimePacket/FIT_USEC,             /* 14 */ 
			flow->flowFeatures.stdTimePacket,                               /* 15 */ 
			flow->flowFeatures.totalFIN,                                    /* 16 */ 
			flow->flowFeatures.totalSYN,                                    /* 17 */ 
			flow->flowFeatures.totalRST,                                    /* 18 */ 
			flow->flowFeatures.totalPUSH,                                   /* 19 */ 
			flow->flowFeatures.totalACK,                                    /* 21 */ 
			flow->flowFeatures.totalURG,                                    /* 22 */ 
			flow->flowFeatures.totalECE,                                    /* 23 */ 
			flow->flowFeatures.totalCWR,                                    /* 24 */ 
			(double)flow->flowFeatures.totalTime/FIT_USEC			/* 25 */ 
			);                                                              
	return;
}

void 
saveExpiredFlow(flowList_t *flow)
{
	
	if(!flow->flowHeader.ipSrc[0])
		return;

	flow->flowFeatures.totalTime = flow->flowFeatures.lastTime - flow->flowFeatures.firstTime;

	/* save features */
	fprintf(FLOWS_RESULTS,"%s,%s,%u,%u,%u,%u,%u,%u,%u,%g,%g,%li,%li,%f,%g,%u,%u,%u,%u,%u,%u,%u,%u,%f\n",
			flow->flowHeader.ipSrc,						/*  1 */
			flow->flowHeader.ipDst,						/*  2 */
			flow->flowHeader.portSrc,                                       /*  3 */
			flow->flowHeader.portDst,                                       /*  4 */
			flow->flowHeader.protocol,                                      /*  5 */ 
			flow->flowFeatures.flowSize,                                    /*  6 */
			flow->flowFeatures.totalPackets,                                /*  7 */ 
			flow->flowFeatures.smallestPacket,                              /*  8 */
			flow->flowFeatures.largestPacket,                               /*  9 */ 
			flow->flowFeatures.meanPacketSize,                              /* 10 */
			flow->flowFeatures.stdPacketSize,                               /* 11 */ 
			flow->flowFeatures.minTimePacket,                               /* 12 */ 
			flow->flowFeatures.maxTimePacket,                               /* 13 */ 
			(double)flow->flowFeatures.meanTimePacket/FIT_USEC,             /* 14 */ 
			flow->flowFeatures.stdTimePacket,                               /* 15 */ 
			flow->flowFeatures.totalFIN,                                    /* 16 */ 
			flow->flowFeatures.totalSYN,                                    /* 17 */ 
			flow->flowFeatures.totalRST,                                    /* 18 */ 
			flow->flowFeatures.totalPUSH,                                   /* 19 */ 
			flow->flowFeatures.totalACK,                                    /* 21 */ 
			flow->flowFeatures.totalURG,                                    /* 22 */ 
			flow->flowFeatures.totalECE,                                    /* 23 */ 
			flow->flowFeatures.totalCWR,                                    /* 24 */ 
			(double)flow->flowFeatures.totalTime/FIT_USEC			/* 25 */ 
			);                                                              

//	fclose(FLOWS_RESULTS);
	return;
}

/*****************************************************************************************************************/

/*************************************** copy functions **********************************************************/

void
copyHeader(flowID_t copy, flowID_t original)
{	
	strcpy(copy.ipSrc,original.ipSrc);
	strcpy(copy.ipDst,original.ipDst);
	copy.portSrc 	= original.portSrc;
	copy.portDst 	= original.portDst;
	copy.protocol 	= original.protocol;
	copy.time 	= original.time;
	return;
}


void
copyFeatures(flowFeatures_t copy, flowFeatures_t original)
{

	copy.flowSize	 	= original.flowSize;	 
	copy.smallestPacket	= original.smallestPacket;	 
	copy.largestPacket	= original.largestPacket;	 
	copy.totalPackets	= original.totalPackets;	 
	copy.totalPSH	 	= original.totalPSH;	 
	copy.totalURG	 	= original.totalURG;	 
	copy.totalFIN	 	= original.totalFIN;	 
	copy.totalACK	 	= original.totalACK;	 
	copy.totalCWR	 	= original.totalCWR;	 
	copy.totalECE	 	= original.totalECE;	 
	copy.totalPUSH	 	= original.totalPUSH;	 
	copy.totalRST	 	= original.totalRST;	 
	copy.totalSYN	 	= original.totalSYN;	 
	copy.meanPacketSize	= original.meanPacketSize;	 
	copy.stdPacketSize	= original.stdPacketSize;	 
	copy.meanTimePacket 	= original.meanTimePacket;	 
	copy.stdTimePacket	= original.stdTimePacket;	 
	copy.minTimePacket	= original.minTimePacket;	 
	copy.maxTimePacket	= original.maxTimePacket;	 
	copy.totalTime	 	= original.totalTime;	 
	copy.firstTime	 	= original.firstTime;	 
	copy.lastTime	 	= original.lastTime;	 
	return;
}

/**********************************************************************************************************************/

int 
flowRemove(void)
{
 	flowList_t *aux;
	
	if(!empty)						/* if the flow is on the list */
	{

			if(LIST_FIRST->next)			/* the flow is the first element, but have more elements */
			{
				/* remove the flow and bring the second to the top */
				aux = LIST_FIRST;
				LIST_FIRST = LIST_FIRST->next;
				timer = LIST_FIRST->flowHeader.time;
				free(aux);
				return ok;
				
			}
			
			/* list is empty now */	
			LIST_FIRST = LIST_LAST;
			empty = true;				
			timer = BLOCK_TIMER;			/* disable the alarm */
			return ok;


	}
	return erroFlowDontExist;

}


void 
checkExpiredFlows(double currentTime)
{
	while(timer <= currentTime && timer > 0)
	{
		saveExpiredFlow(LIST_FIRST); 					/* save flow features and remove the entry */
		flowRemove();							/* remove flow entry */
	}
	return;
}








void
processPacket (u_char *arg, const struct pcap_pkthdr *pkthdr, const u_char *packet)
{
	
	/* packet headers */
	const struct sniff_ethernet *ethernet; 						/* ETHERNET header */
	const struct sniff_ip *ip; 							/* IP header */
	const struct sniff_tcp *tcp; 							/* TCP header */
	const struct sniff_udp *udp; 							/* UDP header */

	/* current time in microseconds based on the packet header */
	time_t currentTime = pkthdr->ts.tv_sec*FIT_USEC + pkthdr->ts.tv_usec;

	

	flowID_t newFlow;

	/* variable to check if the header is valid */	
	int size_ip;
	int size_tcp;
	bool find = false;
	u_short size_udp;

	unsigned short int protocol_check;

	
	ethernet = (struct sniff_ethernet *)(packet);

	/* verifying if the packet is an IP packet */
	if(ethernet->ether_type != IP_TYPE)
		return;

	ip = (struct sniff_ip *)(packet + SIZE_ETHERNET);

	size_ip = IP_HL(ip)*4;

	if(size_ip < 20)
		return;						/* Invalid IP header length */
	


	

	/* determine protocol */
	switch(ip->ip_p)
	{
		case IPPROTO_TCP:
			protocol_check = 1;
			break;
		case IPPROTO_UDP:
			protocol_check = 0;
			break;

		/* not implemented cases */

		case IPPROTO_ICMP:
			return;
		case IPPROTO_IP:
			return;
		default:
			return;

	}
	

	/* set flow IP source and destination */
	strcpy(newFlow.ipSrc,inet_ntoa(ip->ip_src));
	strcpy(newFlow.ipDst,inet_ntoa(ip->ip_dst));


	/* tcp protocol */
	if(protocol_check)
	{
		
		tcp = (struct sniff_tcp *)(packet + SIZE_ETHERNET + size_ip);
		size_tcp = TH_OFF(tcp)*4;
		

		if(size_tcp < 20)
		{
			return;					/* Invalid TCP header length */
		}
		/* mount the flow header */
		newFlow.portDst = ntohs(tcp->th_dport);
		newFlow.portSrc = ntohs(tcp->th_sport);
		newFlow.protocol = 6;
		
		
	
		/* verifyes if the flows already exists */
		findFlow(newFlow, &find);
		
		/* try to add the flow to the list */
		if(!find)	
		{
			newFlow.time = pkthdr->ts.tv_sec*FIT_USEC + pkthdr->ts.tv_usec + WINDOW_SIZE*FIT_USEC;
			flowAdd(newFlow);
		}
		
		/* search for expired flows */
		checkExpiredFlows((double)currentTime);

		/* update features */
		updateFlowFeaturesTCP(newFlow,pkthdr,tcp);
	
		
		return;
	}

	/* udp protocol */
	if(!protocol_check)
	{
		udp = (struct sniff_udp *)(packet + SIZE_ETHERNET + size_ip);
		size_udp = udp->uh_ulen;
		
		if(size_udp < 8)
			return;				/* Invalid UDP header length */
		
		/* mount the flow header */
		newFlow.portDst = ntohs(udp->uh_dport);
		newFlow.portSrc = ntohs(udp->uh_sport);
		newFlow.protocol = 17;
			

		findFlow(newFlow, &find);
		
		/* try to add the flow to the list */
		if(!find)	
		{
			newFlow.time = pkthdr->ts.tv_sec*FIT_USEC + pkthdr->ts.tv_usec + WINDOW_SIZE*FIT_USEC;
			flowAdd(newFlow);
		}

		/* update features */
		updateFlowFeaturesUDP(newFlow,pkthdr,udp);
		
		
		/* search for expired flows */	
		checkExpiredFlows((double)currentTime);

		return;
	}

	/* for other cases, only ip features are extracted */
	
	/* mount the flow header */
	newFlow.portDst = 0;
	newFlow.portSrc = 0;
	newFlow.protocol = 1;
		

	findFlow(newFlow, &find);
	
	/* try to add the flow to the list */
	if(!find)	
	{
		newFlow.time = pkthdr->ts.tv_sec*FIT_USEC + pkthdr->ts.tv_usec + WINDOW_SIZE*FIT_USEC;
		flowAdd(newFlow);
	}

	/* update features */
	updateFlowFeaturesOTHER(newFlow,pkthdr);
	
	
	/* search for expired flows */	
	checkExpiredFlows((double)currentTime);

	return;

}
	


int 
main(int argc, char **argv){
	int count=0;
	pcap_t *descr = NULL;
    	char errbuf[PCAP_ERRBUF_SIZE], *device=NULL;
	memset(errbuf,0,PCAP_ERRBUF_SIZE);
	
	FLOWS_RESULTS = fopen(FILE_RESULTS,"a");	
	LIST_LAST = (flowList_t *)(malloc(sizeof(flowList_t))); 
	LIST_LAST->next = NULL;
	LIST_LAST->last = NULL;
	LIST_FIRST = LIST_LAST;

	empty = true;	
	
	/* read from a file */
	if(argc > 1)
	{
		/* open file */
		descr = pcap_open_offline(argv[1],errbuf);

		if(pcap_loop(descr, 0, processPacket, NULL) < 0)
			return true;
		
		saveAllFlows();
		fclose(FLOWS_RESULTS);
		return ok;
	}

	

	/* Get the name of the first device suitable for capture */
    	device = pcap_lookupdev(errbuf);
    	printf("Opening device %s\n", device);

    	/* Open device in promiscuous mode */
    	descr = pcap_open_live(device, MAXBYTES2CAPTURE,1, 512, errbuf);

    	/* Loop forever &  call processPacket() for every received packet */
    	pcap_loop(descr, -1, processPacket, (u_char *)&count);    
	fclose(FLOWS_RESULTS);
	
	return ok;
}




