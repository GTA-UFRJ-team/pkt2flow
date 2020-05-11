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


#include "structures.h"
#include "functionHeader.h"
#include "configuration.h"



FILE 		*FLOWS_RESULTS;				/* file to wirte results */		
flowList_t 	*LIST_FIRST;				/* contains all active flows */ 
bool 		empty;					/* indicates if the list is empty */
flowList_t 	*LIST_LAST;			/* contains the final address */ 
double		timer;					/* contains the time to remove the oldest flow */
 

/******************************** Flow list interaction functions **********************************/

flowList_t * 
findFlow(flowID_t flow, bool *find, char *direction)
{
	flowList_t *currentFlow;
	currentFlow = LIST_FIRST;
	

	while(currentFlow->flowHeader.ipDst)
	{

		if(	
			(!(strcmp(currentFlow->flowHeader.ipSrc,flow.ipSrc)) &&
			!(strcmp(currentFlow->flowHeader.ipDst,flow.ipDst)) &&	
			currentFlow->flowHeader.portSrc == flow.portSrc &&
			currentFlow->flowHeader.portDst == flow.portDst &&
			currentFlow->flowHeader.protocol == flow.protocol)
				)
		{
			*(find) = true;
			*(direction) = FORWARD;
			return currentFlow;
		}
		
		if(	
			(!(strcmp(currentFlow->flowHeader.ipSrc,flow.ipDst)) &&
			!(strcmp(currentFlow->flowHeader.ipDst,flow.ipSrc)) &&	
			currentFlow->flowHeader.portSrc == flow.portDst &&
			currentFlow->flowHeader.portDst == flow.portSrc &&
			currentFlow->flowHeader.protocol == flow.protocol)
				)
		{
			*(find) = true;
			*(direction) = BACKWARD;
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
		LIST_FIRST->flowHeader.portSrc 			= flow.portSrc;
		LIST_FIRST->flowHeader.portDst 			= flow.portDst;
		LIST_FIRST->flowHeader.protocol 		= flow.protocol;
		LIST_FIRST->flowHeader.time 			= flow.time;
		LIST_FIRST->flowFeatures.totalForwardPackets	= 0;	
		LIST_FIRST->flowFeatures.totalBackwardPackets	= 0;	
		empty 						= false;
		
		/* set the timer */
		timer = flow.time;
	
		/* allocate the next element */
		newEntry = (flowList_t *)(malloc(sizeof(flowList_t)));
		newEntry->last 		= LIST_FIRST;
		newEntry->next 		= NULL;
		LIST_LAST 		= newEntry;
		LIST_FIRST->next 	= LIST_LAST;
		return ok;
	}

	/* for the second flow or greater */

	/* get flow header */
	strcpy(LIST_LAST->flowHeader.ipSrc,flow.ipSrc);
	strcpy(LIST_LAST->flowHeader.ipDst,flow.ipDst);
	LIST_LAST->flowHeader.portSrc 			= flow.portSrc;
	LIST_LAST->flowHeader.portDst 			= flow.portDst;
	LIST_LAST->flowHeader.protocol 			= flow.protocol;
	LIST_LAST->flowHeader.time 			= flow.time;
	LIST_LAST->flowFeatures.totalForwardPackets	= 0;	
	LIST_LAST->flowFeatures.totalBackwardPackets	= 0;	

	/* allocate the next element */
	newEntry = (flowList_t *)(malloc(sizeof(flowList_t)));
	newEntry->last 		= LIST_LAST;
	newEntry->next 		= NULL;
	newEntry->flowHeader.ipSrc[0] = '\0';
	newEntry->flowHeader.ipDst[0] = '\0';
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
	char direction;
	
	flowEntry = findFlow(flow, &find, &direction);
	
	if(!find)
		return erroEmptyPointer;


	if(direction == FORWARD)
	{
		/* verify if it is the first packet of the flow to add the time */
		if(!flowEntry->flowFeatures.totalForwardPackets)
		{



			/* initialize ip features */
			flowEntry->flowFeatures.firstForwardTime 	= packet->ts.tv_sec*FIT_USEC + packet->ts.tv_usec;
			flowEntry->flowFeatures.lastForwardTime 	= packet->ts.tv_sec*FIT_USEC + packet->ts.tv_usec;
			flowEntry->flowFeatures.flowForwardSize 	= packet->len;
			flowEntry->flowFeatures.smallestForwardPacket 	= packet->len;
			flowEntry->flowFeatures.largestForwardPacket 	= packet->len;
			flowEntry->flowFeatures.minForwardTimePacket 	= FIT_USEC*WINDOW_SIZE;			
			flowEntry->flowFeatures.maxForwardTimePacket 	= 0;			
			flowEntry->flowFeatures.meanForwardTimePacket	= 0;			
			flowEntry->flowFeatures.stdForwardTimePacket 	= 0;
			flowEntry->flowFeatures.stdForwardPacketSize 	= 0;
			flowEntry->flowFeatures.meanForwardPacketSize 	= packet->len;
			flowEntry->flowFeatures.totalForwardPackets 	= 1;
			
			
			/* set tcp features in 0 */
			flowEntry->flowFeatures.totalForwardFIN 	=  0;
			flowEntry->flowFeatures.totalForwardSYN 	=  0;
			flowEntry->flowFeatures.totalForwardRST 	=  0;
			flowEntry->flowFeatures.totalForwardPUSH 	=  0;
			flowEntry->flowFeatures.totalForwardACK		=  0;
			flowEntry->flowFeatures.totalForwardURG 	=  0;
			flowEntry->flowFeatures.totalForwardECE 	=  0;
			flowEntry->flowFeatures.totalForwardCWR 	=  0;
					
			return ok;
			

		}
		
		/* calcule metricts for other cases */
		long int totalPkt = flowEntry->flowFeatures.totalForwardPackets; 
		double timeElapsed;

		/* second packet needs special process of mean and standart deviation */
		if(flowEntry->flowFeatures.totalForwardPackets == 1)
		{
			/* time between two consecutives packets */
			timeElapsed = packet->ts.tv_sec*FIT_USEC + packet->ts.tv_usec - flowEntry->flowFeatures.lastForwardTime;

			flowEntry->flowFeatures.lastForwardTime =  packet->ts.tv_sec*FIT_USEC + packet->ts.tv_usec;
		
			flowEntry->flowFeatures.meanForwardPacketSize = (packet->len + 
									flowEntry->flowFeatures.meanForwardPacketSize)/2.0;

			flowEntry->flowFeatures.stdForwardPacketSize = sqrt((pow(packet->len - 
									flowEntry->flowFeatures.meanForwardPacketSize,2)+
									pow(flowEntry->flowFeatures.smallestForwardPacket - 
									flowEntry->flowFeatures.meanForwardPacketSize,2))/2.0);
					

			/* initialize time features */
			flowEntry->flowFeatures.meanForwardTimePacket = timeElapsed;
			flowEntry->flowFeatures.maxForwardTimePacket = timeElapsed;
			flowEntry->flowFeatures.minForwardTimePacket = timeElapsed;
			flowEntry->flowFeatures.stdForwardTimePacket = 0.0;
			flowEntry->flowFeatures.lastForwardTime = packet->ts.tv_sec*FIT_USEC + packet->ts.tv_usec;


		
			if(flowEntry->flowFeatures.largestForwardPacket < packet->len)
				flowEntry->flowFeatures.largestForwardPacket = packet->len;
			if(flowEntry->flowFeatures.smallestForwardPacket > packet->len)
				flowEntry->flowFeatures.smallestForwardPacket = packet->len;
			
				
			flowEntry->flowFeatures.totalForwardPackets++;
			flowEntry->flowFeatures.flowForwardSize += packet->len;
			
			return ok;		
		}


		/**************************************** update features for other packets ******************************************/
		
		/* time between two consecutives packets in microseconds */
		timeElapsed = packet->ts.tv_sec*FIT_USEC + packet->ts.tv_usec - flowEntry->flowFeatures.lastForwardTime;	


		flowEntry->flowFeatures.stdForwardPacketSize = sqrt((
					flowEntry->flowFeatures.stdForwardPacketSize+(totalPkt/(totalPkt+1.0))*
					pow(packet->len-flowEntry->flowFeatures.meanForwardPacketSize,2))/totalPkt);

		flowEntry->flowFeatures.meanForwardPacketSize = (packet->len+
								(flowEntry->flowFeatures.meanForwardPacketSize * 
								 totalPkt))/(totalPkt+1.0);


		flowEntry->flowFeatures.stdForwardTimePacket = sqrt((
					flowEntry->flowFeatures.stdForwardTimePacket + (totalPkt/(totalPkt+1.0))*
					pow(timeElapsed - flowEntry->flowFeatures.meanForwardTimePacket,2))/totalPkt);

		

		flowEntry->flowFeatures.meanForwardTimePacket = (timeElapsed+(flowEntry->flowFeatures.meanForwardTimePacket * 
							totalPkt))/(totalPkt+1.0);
		
		/* largest and smallest time and size features */
		if(flowEntry->flowFeatures.largestForwardPacket < packet->len)
			flowEntry->flowFeatures.largestForwardPacket = packet->len;

		if(flowEntry->flowFeatures.smallestForwardPacket > packet->len)
			flowEntry->flowFeatures.smallestForwardPacket = packet->len;

		if(timeElapsed > flowEntry->flowFeatures.maxForwardTimePacket)
			flowEntry->flowFeatures.maxForwardTimePacket = timeElapsed;

		if(timeElapsed < flowEntry->flowFeatures.minForwardTimePacket)
			flowEntry->flowFeatures.minForwardTimePacket = timeElapsed;



		flowEntry->flowFeatures.totalForwardPackets++;
		flowEntry->flowFeatures.lastForwardTime = packet->ts.tv_sec*FIT_USEC + packet->ts.tv_usec;
		flowEntry->flowFeatures.flowForwardSize += packet->len;
		
		return ok;
	}

	/* verify if it is the first packet of the flow to add the time */
	if(!flowEntry->flowFeatures.totalBackwardPackets)
	{



		/* initialize ip features */
		flowEntry->flowFeatures.firstBackwardTime 	= packet->ts.tv_sec*FIT_USEC + packet->ts.tv_usec;
		flowEntry->flowFeatures.lastBackwardTime 	= packet->ts.tv_sec*FIT_USEC + packet->ts.tv_usec;
		flowEntry->flowFeatures.flowBackwardSize 	= packet->len;
		flowEntry->flowFeatures.smallestBackwardPacket 	= packet->len;
		flowEntry->flowFeatures.largestBackwardPacket 	= packet->len;
		flowEntry->flowFeatures.minBackwardTimePacket 	= FIT_USEC*WINDOW_SIZE;			
		flowEntry->flowFeatures.maxBackwardTimePacket 	= 0;			
		flowEntry->flowFeatures.meanBackwardTimePacket	= 0;			
		flowEntry->flowFeatures.stdBackwardTimePacket 	= 0;
		flowEntry->flowFeatures.stdBackwardPacketSize 	= 0;
		flowEntry->flowFeatures.meanBackwardPacketSize 	= packet->len;
		flowEntry->flowFeatures.totalBackwardPackets 	= 1;
		
		
		/* set tcp features in 0 */
		flowEntry->flowFeatures.totalBackwardFIN 	=  0;
		flowEntry->flowFeatures.totalBackwardSYN 	=  0;
		flowEntry->flowFeatures.totalBackwardRST 	=  0;
		flowEntry->flowFeatures.totalBackwardPUSH 	=  0;
		flowEntry->flowFeatures.totalBackwardACK	=  0;
		flowEntry->flowFeatures.totalBackwardURG 	=  0;
		flowEntry->flowFeatures.totalBackwardECE 	=  0;
		flowEntry->flowFeatures.totalBackwardCWR 	=  0;
				
		return ok;
		

	}
	
	/* calcule metricts for other cases */
	long int totalPkt = flowEntry->flowFeatures.totalBackwardPackets; 
	double timeElapsed;

	/* second packet needs special process of mean and standart deviation */
	if(flowEntry->flowFeatures.totalBackwardPackets == 1)
	{
		/* time between two consecutives packets */
		timeElapsed = packet->ts.tv_sec*FIT_USEC + packet->ts.tv_usec - flowEntry->flowFeatures.lastBackwardTime;

		flowEntry->flowFeatures.lastBackwardTime =  packet->ts.tv_sec*FIT_USEC + packet->ts.tv_usec;
	
		flowEntry->flowFeatures.meanBackwardPacketSize = (packet->len + 
								flowEntry->flowFeatures.meanBackwardPacketSize)/2.0;

		flowEntry->flowFeatures.stdBackwardPacketSize = sqrt((pow(packet->len - 
								flowEntry->flowFeatures.meanBackwardPacketSize,2)+
								pow(flowEntry->flowFeatures.smallestBackwardPacket - 
								flowEntry->flowFeatures.meanBackwardPacketSize,2))/2.0);
				

		/* initialize time features */
		flowEntry->flowFeatures.meanBackwardTimePacket = timeElapsed;
		flowEntry->flowFeatures.maxBackwardTimePacket = timeElapsed;
		flowEntry->flowFeatures.minBackwardTimePacket = timeElapsed;
		flowEntry->flowFeatures.stdBackwardTimePacket = 0.0;
		flowEntry->flowFeatures.lastBackwardTime = packet->ts.tv_sec*FIT_USEC + packet->ts.tv_usec;


	
		if(flowEntry->flowFeatures.largestBackwardPacket < packet->len)
			flowEntry->flowFeatures.largestBackwardPacket = packet->len;
		if(flowEntry->flowFeatures.smallestBackwardPacket > packet->len)
			flowEntry->flowFeatures.smallestBackwardPacket = packet->len;
		
			
		flowEntry->flowFeatures.totalBackwardPackets++;
		flowEntry->flowFeatures.flowBackwardSize += packet->len;
		
		return ok;		
	}


	/**************************************** update features for other packets ******************************************/
	
	/* time between two consecutives packets in microseconds */
	timeElapsed = packet->ts.tv_sec*FIT_USEC + packet->ts.tv_usec - flowEntry->flowFeatures.lastBackwardTime;	


	flowEntry->flowFeatures.stdBackwardPacketSize = sqrt((
				flowEntry->flowFeatures.stdBackwardPacketSize+(totalPkt/(totalPkt+1.0))*
				pow(packet->len-flowEntry->flowFeatures.meanBackwardPacketSize,2))/totalPkt);

	flowEntry->flowFeatures.meanBackwardPacketSize = (packet->len+
							(flowEntry->flowFeatures.meanBackwardPacketSize * 
							 totalPkt))/(totalPkt+1.0);


	flowEntry->flowFeatures.stdBackwardTimePacket = sqrt((
				flowEntry->flowFeatures.stdBackwardTimePacket + (totalPkt/(totalPkt+1.0))*
				pow(timeElapsed - flowEntry->flowFeatures.meanBackwardTimePacket,2))/totalPkt);

	

	flowEntry->flowFeatures.meanBackwardTimePacket = (timeElapsed+(flowEntry->flowFeatures.meanBackwardTimePacket * 
						totalPkt))/(totalPkt+1.0);
	
	/* largest and smallest time and size features */
	if(flowEntry->flowFeatures.largestBackwardPacket < packet->len)
		flowEntry->flowFeatures.largestBackwardPacket = packet->len;

	if(flowEntry->flowFeatures.smallestBackwardPacket > packet->len)
		flowEntry->flowFeatures.smallestBackwardPacket = packet->len;

	if(timeElapsed > flowEntry->flowFeatures.maxBackwardTimePacket)
		flowEntry->flowFeatures.maxBackwardTimePacket = timeElapsed;

	if(timeElapsed < flowEntry->flowFeatures.minBackwardTimePacket)
		flowEntry->flowFeatures.minBackwardTimePacket = timeElapsed;


	flowEntry->flowFeatures.totalBackwardPackets++;
	flowEntry->flowFeatures.lastBackwardTime = packet->ts.tv_sec*FIT_USEC + packet->ts.tv_usec;
	flowEntry->flowFeatures.flowBackwardSize += packet->len;
	
	return ok;

}


int 
updateFlowFeaturesUDP(flowID_t flow, const struct pcap_pkthdr *packet, const struct sniff_udp *udp)
{
		
	flowList_t *flowEntry;
	bool find;
	char direction;
	
	flowEntry = findFlow(flow, &find, &direction);
	
	if(!find)
		return erroEmptyPointer;


	if(direction == FORWARD)
	{
		/* verify if it is the first packet of the flow to add the time */
		if(!flowEntry->flowFeatures.totalForwardPackets)
		{



			/* initialize ip features */
			flowEntry->flowFeatures.firstForwardTime 	= packet->ts.tv_sec*FIT_USEC + packet->ts.tv_usec;
			flowEntry->flowFeatures.lastForwardTime 	= packet->ts.tv_sec*FIT_USEC + packet->ts.tv_usec;
			flowEntry->flowFeatures.flowForwardSize 	= packet->len;
			flowEntry->flowFeatures.smallestForwardPacket 	= packet->len;
			flowEntry->flowFeatures.largestForwardPacket 	= packet->len;
			flowEntry->flowFeatures.minForwardTimePacket 	= FIT_USEC*WINDOW_SIZE;			
			flowEntry->flowFeatures.maxForwardTimePacket 	= 0;			
			flowEntry->flowFeatures.meanForwardTimePacket	= 0;			
			flowEntry->flowFeatures.stdForwardTimePacket 	= 0;
			flowEntry->flowFeatures.stdForwardPacketSize 	= 0;
			flowEntry->flowFeatures.meanForwardPacketSize 	= packet->len;
			flowEntry->flowFeatures.totalForwardPackets 	= 1;
			
			
			/* set tcp features in 0 */
			flowEntry->flowFeatures.totalForwardFIN 	=  0;
			flowEntry->flowFeatures.totalForwardSYN 	=  0;
			flowEntry->flowFeatures.totalForwardRST 	=  0;
			flowEntry->flowFeatures.totalForwardPUSH 	=  0;
			flowEntry->flowFeatures.totalForwardACK		=  0;
			flowEntry->flowFeatures.totalForwardURG 	=  0;
			flowEntry->flowFeatures.totalForwardECE 	=  0;
			flowEntry->flowFeatures.totalForwardCWR 	=  0;
					
			return ok;
			

		}
		
		/* calcule metricts for other cases */
		long int totalPkt = flowEntry->flowFeatures.totalForwardPackets; 
		double timeElapsed;

		/* second packet needs special process of mean and standart deviation */
		if(flowEntry->flowFeatures.totalForwardPackets == 1)
		{
			/* time between two consecutives packets */
			timeElapsed = packet->ts.tv_sec*FIT_USEC + packet->ts.tv_usec - flowEntry->flowFeatures.lastForwardTime;

			flowEntry->flowFeatures.lastForwardTime =  packet->ts.tv_sec*FIT_USEC + packet->ts.tv_usec;
		
			flowEntry->flowFeatures.meanForwardPacketSize = (packet->len + 
									flowEntry->flowFeatures.meanForwardPacketSize)/2.0;

			flowEntry->flowFeatures.stdForwardPacketSize = sqrt((pow(packet->len - 
									flowEntry->flowFeatures.meanForwardPacketSize,2)+
									pow(flowEntry->flowFeatures.smallestForwardPacket - 
									flowEntry->flowFeatures.meanForwardPacketSize,2))/2.0);
					

			/* initialize time features */
			flowEntry->flowFeatures.meanForwardTimePacket = timeElapsed;
			flowEntry->flowFeatures.maxForwardTimePacket = timeElapsed;
			flowEntry->flowFeatures.minForwardTimePacket = timeElapsed;
			flowEntry->flowFeatures.stdForwardTimePacket = 0.0;
			flowEntry->flowFeatures.lastForwardTime = packet->ts.tv_sec*FIT_USEC + packet->ts.tv_usec;

		
			if(flowEntry->flowFeatures.largestForwardPacket < packet->len)
				flowEntry->flowFeatures.largestForwardPacket = packet->len;
			if(flowEntry->flowFeatures.smallestForwardPacket > packet->len)
				flowEntry->flowFeatures.smallestForwardPacket = packet->len;
			
				
			flowEntry->flowFeatures.totalForwardPackets++;
			flowEntry->flowFeatures.flowForwardSize += packet->len;
			
			return ok;		
		}


		/**************************************** update features for other packets ******************************************/
		
		/* time between two consecutives packets in microseconds */
		timeElapsed = packet->ts.tv_sec*FIT_USEC + packet->ts.tv_usec - flowEntry->flowFeatures.lastForwardTime;	


		flowEntry->flowFeatures.stdForwardPacketSize = sqrt((
					flowEntry->flowFeatures.stdForwardPacketSize+(totalPkt/(totalPkt+1.0))*
					pow(packet->len-flowEntry->flowFeatures.meanForwardPacketSize,2))/totalPkt);

		flowEntry->flowFeatures.meanForwardPacketSize = (packet->len+
								(flowEntry->flowFeatures.meanForwardPacketSize * 
								 totalPkt))/(totalPkt+1.0);


		flowEntry->flowFeatures.stdForwardTimePacket = sqrt((
					flowEntry->flowFeatures.stdForwardTimePacket + (totalPkt/(totalPkt+1.0))*
					pow(timeElapsed - flowEntry->flowFeatures.meanForwardTimePacket,2))/totalPkt);

		

		flowEntry->flowFeatures.meanForwardTimePacket = (timeElapsed+(flowEntry->flowFeatures.meanForwardTimePacket * 
							totalPkt))/(totalPkt+1.0);
		
		/* largest and smallest time and size features */
		if(flowEntry->flowFeatures.largestForwardPacket < packet->len)
			flowEntry->flowFeatures.largestForwardPacket = packet->len;

		if(flowEntry->flowFeatures.smallestForwardPacket > packet->len)
			flowEntry->flowFeatures.smallestForwardPacket = packet->len;

		if(timeElapsed > flowEntry->flowFeatures.maxForwardTimePacket)
			flowEntry->flowFeatures.maxForwardTimePacket = timeElapsed;

		if(timeElapsed < flowEntry->flowFeatures.minForwardTimePacket)
			flowEntry->flowFeatures.minForwardTimePacket = timeElapsed;




		flowEntry->flowFeatures.totalForwardPackets++;
		flowEntry->flowFeatures.lastForwardTime = packet->ts.tv_sec*FIT_USEC + packet->ts.tv_usec;
		flowEntry->flowFeatures.flowForwardSize += packet->len;
		
		return ok;
	}

	/* verify if it is the first packet of the flow to add the time */
	if(!flowEntry->flowFeatures.totalBackwardPackets)
	{



		/* initialize ip features */
		flowEntry->flowFeatures.firstBackwardTime 	= packet->ts.tv_sec*FIT_USEC + packet->ts.tv_usec;
		flowEntry->flowFeatures.lastBackwardTime 	= packet->ts.tv_sec*FIT_USEC + packet->ts.tv_usec;
		flowEntry->flowFeatures.flowBackwardSize 	= packet->len;
		flowEntry->flowFeatures.smallestBackwardPacket 	= packet->len;
		flowEntry->flowFeatures.largestBackwardPacket 	= packet->len;
		flowEntry->flowFeatures.minBackwardTimePacket 	= FIT_USEC*WINDOW_SIZE;			
		flowEntry->flowFeatures.maxBackwardTimePacket 	= 0;			
		flowEntry->flowFeatures.meanBackwardTimePacket	= 0;			
		flowEntry->flowFeatures.stdBackwardTimePacket 	= 0;
		flowEntry->flowFeatures.stdBackwardPacketSize 	= 0;
		flowEntry->flowFeatures.meanBackwardPacketSize 	= packet->len;
		flowEntry->flowFeatures.totalBackwardPackets 	= 1;
		
		
		/* set tcp features in 0 */
		flowEntry->flowFeatures.totalBackwardFIN 	=  0;
		flowEntry->flowFeatures.totalBackwardSYN 	=  0;
		flowEntry->flowFeatures.totalBackwardRST 	=  0;
		flowEntry->flowFeatures.totalBackwardPUSH 	=  0;
		flowEntry->flowFeatures.totalBackwardACK	=  0;
		flowEntry->flowFeatures.totalBackwardURG 	=  0;
		flowEntry->flowFeatures.totalBackwardECE 	=  0;
		flowEntry->flowFeatures.totalBackwardCWR 	=  0;
				
		return ok;
		

	}
	
	/* calcule metricts for other cases */
	long int totalPkt = flowEntry->flowFeatures.totalBackwardPackets; 
	double timeElapsed;

	/* second packet needs special process of mean and standart deviation */
	if(flowEntry->flowFeatures.totalBackwardPackets == 1)
	{
		/* time between two consecutives packets */
		timeElapsed = packet->ts.tv_sec*FIT_USEC + packet->ts.tv_usec - flowEntry->flowFeatures.lastBackwardTime;

		flowEntry->flowFeatures.lastBackwardTime =  packet->ts.tv_sec*FIT_USEC + packet->ts.tv_usec;
	
		flowEntry->flowFeatures.meanBackwardPacketSize = (packet->len + 
								flowEntry->flowFeatures.meanBackwardPacketSize)/2.0;

		flowEntry->flowFeatures.stdBackwardPacketSize = sqrt((pow(packet->len - 
								flowEntry->flowFeatures.meanBackwardPacketSize,2)+
								pow(flowEntry->flowFeatures.smallestBackwardPacket - 
								flowEntry->flowFeatures.meanBackwardPacketSize,2))/2.0);
				

		/* initialize time features */
		flowEntry->flowFeatures.meanBackwardTimePacket = timeElapsed;
		flowEntry->flowFeatures.maxBackwardTimePacket = timeElapsed;
		flowEntry->flowFeatures.minBackwardTimePacket = timeElapsed;
		flowEntry->flowFeatures.stdBackwardTimePacket = 0.0;
		flowEntry->flowFeatures.lastBackwardTime = packet->ts.tv_sec*FIT_USEC + packet->ts.tv_usec;

		/* tcp flags */

	
		if(flowEntry->flowFeatures.largestBackwardPacket < packet->len)
			flowEntry->flowFeatures.largestBackwardPacket = packet->len;
		if(flowEntry->flowFeatures.smallestBackwardPacket > packet->len)
			flowEntry->flowFeatures.smallestBackwardPacket = packet->len;
		
			
		flowEntry->flowFeatures.totalBackwardPackets++;
		flowEntry->flowFeatures.flowBackwardSize += packet->len;
		
		return ok;		
	}


	/**************************************** update features for other packets ******************************************/
	
	/* time between two consecutives packets in microseconds */
	timeElapsed = packet->ts.tv_sec*FIT_USEC + packet->ts.tv_usec - flowEntry->flowFeatures.lastBackwardTime;	


	flowEntry->flowFeatures.stdBackwardPacketSize = sqrt((
				flowEntry->flowFeatures.stdBackwardPacketSize+(totalPkt/(totalPkt+1.0))*
				pow(packet->len-flowEntry->flowFeatures.meanBackwardPacketSize,2))/totalPkt);

	flowEntry->flowFeatures.meanBackwardPacketSize = (packet->len+
							(flowEntry->flowFeatures.meanBackwardPacketSize * 
							 totalPkt))/(totalPkt+1.0);


	flowEntry->flowFeatures.stdBackwardTimePacket = sqrt((
				flowEntry->flowFeatures.stdBackwardTimePacket + (totalPkt/(totalPkt+1.0))*
				pow(timeElapsed - flowEntry->flowFeatures.meanBackwardTimePacket,2))/totalPkt);

	

	flowEntry->flowFeatures.meanBackwardTimePacket = (timeElapsed+(flowEntry->flowFeatures.meanBackwardTimePacket * 
						totalPkt))/(totalPkt+1.0);
	
	/* largest and smallest time and size features */
	if(flowEntry->flowFeatures.largestBackwardPacket < packet->len)
		flowEntry->flowFeatures.largestBackwardPacket = packet->len;

	if(flowEntry->flowFeatures.smallestBackwardPacket > packet->len)
		flowEntry->flowFeatures.smallestBackwardPacket = packet->len;

	if(timeElapsed > flowEntry->flowFeatures.maxBackwardTimePacket)
		flowEntry->flowFeatures.maxBackwardTimePacket = timeElapsed;

	if(timeElapsed < flowEntry->flowFeatures.minBackwardTimePacket)
		flowEntry->flowFeatures.minBackwardTimePacket = timeElapsed;





	flowEntry->flowFeatures.totalBackwardPackets++;
	flowEntry->flowFeatures.lastBackwardTime = packet->ts.tv_sec*FIT_USEC + packet->ts.tv_usec;
	flowEntry->flowFeatures.flowBackwardSize += packet->len;
	
	return ok;

		

}
			


int 
updateFlowFeaturesTCP(flowID_t flow, const struct pcap_pkthdr *packet, const struct sniff_tcp *tcp)
{
	flowList_t *flowEntry;
	bool find;
	char direction;
	
	flowEntry = findFlow(flow, &find, &direction);
	
	if(!find)
		return erroEmptyPointer;


	if(direction == FORWARD)
	{
		/* verify if it is the first packet of the flow to add the time */
		if(!flowEntry->flowFeatures.totalForwardPackets)
		{



			/* initialize ip features */
			flowEntry->flowFeatures.firstForwardTime 	= packet->ts.tv_sec*FIT_USEC + packet->ts.tv_usec;
			flowEntry->flowFeatures.lastForwardTime 	= packet->ts.tv_sec*FIT_USEC + packet->ts.tv_usec;
			flowEntry->flowFeatures.flowForwardSize 	= packet->len;
			flowEntry->flowFeatures.smallestForwardPacket 	= packet->len;
			flowEntry->flowFeatures.largestForwardPacket 	= packet->len;
			flowEntry->flowFeatures.minForwardTimePacket 	= FIT_USEC*WINDOW_SIZE;			
			flowEntry->flowFeatures.maxForwardTimePacket 	= 0;			
			flowEntry->flowFeatures.meanForwardTimePacket	= 0;			
			flowEntry->flowFeatures.stdForwardTimePacket 	= 0;
			flowEntry->flowFeatures.stdForwardPacketSize 	= 0;
			flowEntry->flowFeatures.meanForwardPacketSize 	= packet->len;
			flowEntry->flowFeatures.totalForwardPackets 	= 1;
			
			
			/* initialize tcp features */
			flowEntry->flowFeatures.totalForwardFIN 	= (TH_FIN & tcp->th_flags) ? 1 : 0;
			flowEntry->flowFeatures.totalForwardSYN 	= (TH_SYN & tcp->th_flags) ? 1 : 0;
			flowEntry->flowFeatures.totalForwardRST 	= (TH_RST & tcp->th_flags) ? 1 : 0;
			flowEntry->flowFeatures.totalForwardPUSH 	= (TH_PUSH & tcp->th_flags)? 1 : 0;
			flowEntry->flowFeatures.totalForwardACK		= (TH_ACK & tcp->th_flags) ? 1 : 0;
			flowEntry->flowFeatures.totalForwardURG 	= (TH_URG & tcp->th_flags) ? 1 : 0;
			flowEntry->flowFeatures.totalForwardECE 	= (TH_ECE & tcp->th_flags) ? 1 : 0;
			flowEntry->flowFeatures.totalForwardCWR 	= (TH_CWR & tcp->th_flags) ? 1 : 0;
					
			return ok;
			

		}
		
		/* calcule metricts for other cases */
		long int totalPkt = flowEntry->flowFeatures.totalForwardPackets; 
		double timeElapsed;

		/* second packet needs special process of mean and standart deviation */
		if(flowEntry->flowFeatures.totalForwardPackets == 1)
		{
			/* time between two consecutives packets */
			timeElapsed = packet->ts.tv_sec*FIT_USEC + packet->ts.tv_usec - flowEntry->flowFeatures.lastForwardTime;

			flowEntry->flowFeatures.lastForwardTime =  packet->ts.tv_sec*FIT_USEC + packet->ts.tv_usec;
		
			flowEntry->flowFeatures.meanForwardPacketSize = (packet->len + 
									flowEntry->flowFeatures.meanForwardPacketSize)/2.0;

			flowEntry->flowFeatures.stdForwardPacketSize = sqrt((pow(packet->len - 
									flowEntry->flowFeatures.meanForwardPacketSize,2)+
									pow(flowEntry->flowFeatures.smallestForwardPacket - 
									flowEntry->flowFeatures.meanForwardPacketSize,2))/2.0);
					

			/* initialize time features */
			flowEntry->flowFeatures.meanForwardTimePacket = timeElapsed;
			flowEntry->flowFeatures.maxForwardTimePacket = timeElapsed;
			flowEntry->flowFeatures.minForwardTimePacket = timeElapsed;
			flowEntry->flowFeatures.stdForwardTimePacket = 0.0;
			flowEntry->flowFeatures.lastForwardTime = packet->ts.tv_sec*FIT_USEC + packet->ts.tv_usec;

			/* tcp flags */
			if(TH_FIN & tcp->th_flags)
				flowEntry->flowFeatures.totalForwardFIN++;
			if(TH_SYN & tcp->th_flags)
				flowEntry->flowFeatures.totalForwardSYN++;
			if(TH_RST & tcp->th_flags)
				flowEntry->flowFeatures.totalForwardRST++;
			if(TH_PUSH & tcp->th_flags)
				flowEntry->flowFeatures.totalForwardPUSH++;
			if(TH_ACK & tcp->th_flags)
				flowEntry->flowFeatures.totalForwardACK++;
			if(TH_URG & tcp->th_flags)
				flowEntry->flowFeatures.totalForwardURG++;
			if(TH_ECE & tcp->th_flags)
				flowEntry->flowFeatures.totalForwardECE++;
			if(TH_CWR & tcp->th_flags)
				flowEntry->flowFeatures.totalForwardCWR++;

		
			if(flowEntry->flowFeatures.largestForwardPacket < packet->len)
				flowEntry->flowFeatures.largestForwardPacket = packet->len;
			if(flowEntry->flowFeatures.smallestForwardPacket > packet->len)
				flowEntry->flowFeatures.smallestForwardPacket = packet->len;
			
				
			flowEntry->flowFeatures.totalForwardPackets++;
			flowEntry->flowFeatures.flowForwardSize += packet->len;
			
			return ok;		
		}


		/**************************************** update features for other packets ******************************************/
		
		/* time between two consecutives packets in microseconds */
		timeElapsed = packet->ts.tv_sec*FIT_USEC + packet->ts.tv_usec - flowEntry->flowFeatures.lastForwardTime;	


		flowEntry->flowFeatures.stdForwardPacketSize = sqrt((
					flowEntry->flowFeatures.stdForwardPacketSize+(totalPkt/(totalPkt+1.0))*
					pow(packet->len-flowEntry->flowFeatures.meanForwardPacketSize,2))/totalPkt);

		flowEntry->flowFeatures.meanForwardPacketSize = (packet->len+
								(flowEntry->flowFeatures.meanForwardPacketSize * 
								 totalPkt))/(totalPkt+1.0);


		flowEntry->flowFeatures.stdForwardTimePacket = sqrt((
					flowEntry->flowFeatures.stdForwardTimePacket + (totalPkt/(totalPkt+1.0))*
					pow(timeElapsed - flowEntry->flowFeatures.meanForwardTimePacket,2))/totalPkt);

		

		flowEntry->flowFeatures.meanForwardTimePacket = (timeElapsed+(flowEntry->flowFeatures.meanForwardTimePacket * 
							totalPkt))/(totalPkt+1.0);
		
		/* largest and smallest time and size features */
		if(flowEntry->flowFeatures.largestForwardPacket < packet->len)
			flowEntry->flowFeatures.largestForwardPacket = packet->len;

		if(flowEntry->flowFeatures.smallestForwardPacket > packet->len)
			flowEntry->flowFeatures.smallestForwardPacket = packet->len;

		if(timeElapsed > flowEntry->flowFeatures.maxForwardTimePacket)
			flowEntry->flowFeatures.maxForwardTimePacket = timeElapsed;

		if(timeElapsed < flowEntry->flowFeatures.minForwardTimePacket)
			flowEntry->flowFeatures.minForwardTimePacket = timeElapsed;


		/* tcp flags */
		if(TH_FIN & tcp->th_flags)
			flowEntry->flowFeatures.totalForwardFIN++;
		if(TH_SYN & tcp->th_flags)
			flowEntry->flowFeatures.totalForwardSYN++;
		if(TH_RST & tcp->th_flags)
			flowEntry->flowFeatures.totalForwardRST++;
		if(TH_PUSH & tcp->th_flags)
			flowEntry->flowFeatures.totalForwardPUSH++;
		if(TH_ACK & tcp->th_flags)
			flowEntry->flowFeatures.totalForwardACK++;
		if(TH_URG & tcp->th_flags)
			flowEntry->flowFeatures.totalForwardURG++;
		if(TH_ECE & tcp->th_flags)
			flowEntry->flowFeatures.totalForwardECE++;
		if(TH_CWR & tcp->th_flags)
			flowEntry->flowFeatures.totalForwardCWR++;



		flowEntry->flowFeatures.totalForwardPackets++;
		flowEntry->flowFeatures.lastForwardTime = packet->ts.tv_sec*FIT_USEC + packet->ts.tv_usec;
		flowEntry->flowFeatures.flowForwardSize += packet->len;
		
		return ok;
	}

	/* verify if it is the first packet of the flow to add the time */
	if(!flowEntry->flowFeatures.totalBackwardPackets)
	{



		/* initialize ip features */
		flowEntry->flowFeatures.firstBackwardTime 	= packet->ts.tv_sec*FIT_USEC + packet->ts.tv_usec;
		flowEntry->flowFeatures.lastBackwardTime 	= packet->ts.tv_sec*FIT_USEC + packet->ts.tv_usec;
		flowEntry->flowFeatures.flowBackwardSize 	= packet->len;
		flowEntry->flowFeatures.smallestBackwardPacket 	= packet->len;
		flowEntry->flowFeatures.largestBackwardPacket 	= packet->len;
		flowEntry->flowFeatures.minBackwardTimePacket 	= FIT_USEC*WINDOW_SIZE;			
		flowEntry->flowFeatures.maxBackwardTimePacket 	= 0;			
		flowEntry->flowFeatures.meanBackwardTimePacket	= 0;			
		flowEntry->flowFeatures.stdBackwardTimePacket 	= 0;
		flowEntry->flowFeatures.stdBackwardPacketSize 	= 0;
		flowEntry->flowFeatures.meanBackwardPacketSize 	= packet->len;
		flowEntry->flowFeatures.totalBackwardPackets 	= 1;
		
		
		/* initialize tcp features */
		flowEntry->flowFeatures.totalBackwardFIN 	= (TH_FIN & tcp->th_flags) ? 1 : 0;
		flowEntry->flowFeatures.totalBackwardSYN 	= (TH_SYN & tcp->th_flags) ? 1 : 0;
		flowEntry->flowFeatures.totalBackwardRST 	= (TH_RST & tcp->th_flags) ? 1 : 0;
		flowEntry->flowFeatures.totalBackwardPUSH 	= (TH_PUSH & tcp->th_flags)? 1 : 0;
		flowEntry->flowFeatures.totalBackwardACK		= (TH_ACK & tcp->th_flags) ? 1 : 0;
		flowEntry->flowFeatures.totalBackwardURG 	= (TH_URG & tcp->th_flags) ? 1 : 0;
		flowEntry->flowFeatures.totalBackwardECE 	= (TH_ECE & tcp->th_flags) ? 1 : 0;
		flowEntry->flowFeatures.totalBackwardCWR 	= (TH_CWR & tcp->th_flags) ? 1 : 0;
				
		return ok;
		

	}
	
	/* calcule metricts for other cases */
	long int totalPkt = flowEntry->flowFeatures.totalBackwardPackets; 
	double timeElapsed;

	/* second packet needs special process of mean and standart deviation */
	if(flowEntry->flowFeatures.totalBackwardPackets == 1)
	{
		/* time between two consecutives packets */
		timeElapsed = packet->ts.tv_sec*FIT_USEC + packet->ts.tv_usec - flowEntry->flowFeatures.lastBackwardTime;

		flowEntry->flowFeatures.lastBackwardTime =  packet->ts.tv_sec*FIT_USEC + packet->ts.tv_usec;
	
		flowEntry->flowFeatures.meanBackwardPacketSize = (packet->len + 
								flowEntry->flowFeatures.meanBackwardPacketSize)/2.0;

		flowEntry->flowFeatures.stdBackwardPacketSize = sqrt((pow(packet->len - 
								flowEntry->flowFeatures.meanBackwardPacketSize,2)+
								pow(flowEntry->flowFeatures.smallestBackwardPacket - 
								flowEntry->flowFeatures.meanBackwardPacketSize,2))/2.0);
				

		/* initialize time features */
		flowEntry->flowFeatures.meanBackwardTimePacket = timeElapsed;
		flowEntry->flowFeatures.maxBackwardTimePacket = timeElapsed;
		flowEntry->flowFeatures.minBackwardTimePacket = timeElapsed;
		flowEntry->flowFeatures.stdBackwardTimePacket = 0.0;
		flowEntry->flowFeatures.lastBackwardTime = packet->ts.tv_sec*FIT_USEC + packet->ts.tv_usec;

		/* tcp flags */
		if(TH_FIN & tcp->th_flags)
			flowEntry->flowFeatures.totalBackwardFIN++;
		if(TH_SYN & tcp->th_flags)
			flowEntry->flowFeatures.totalBackwardSYN++;
		if(TH_RST & tcp->th_flags)
			flowEntry->flowFeatures.totalBackwardRST++;
		if(TH_PUSH & tcp->th_flags)
			flowEntry->flowFeatures.totalBackwardPUSH++;
		if(TH_ACK & tcp->th_flags)
			flowEntry->flowFeatures.totalBackwardACK++;
		if(TH_URG & tcp->th_flags)
			flowEntry->flowFeatures.totalBackwardURG++;
		if(TH_ECE & tcp->th_flags)
			flowEntry->flowFeatures.totalBackwardECE++;
		if(TH_CWR & tcp->th_flags)
			flowEntry->flowFeatures.totalBackwardCWR++;

	
		if(flowEntry->flowFeatures.largestBackwardPacket < packet->len)
			flowEntry->flowFeatures.largestBackwardPacket = packet->len;
		if(flowEntry->flowFeatures.smallestBackwardPacket > packet->len)
			flowEntry->flowFeatures.smallestBackwardPacket = packet->len;
		
			
		flowEntry->flowFeatures.totalBackwardPackets++;
		flowEntry->flowFeatures.flowBackwardSize += packet->len;
		
		return ok;		
	}


	/**************************************** update features for other packets ******************************************/
	
	/* time between two consecutives packets in microseconds */
	timeElapsed = packet->ts.tv_sec*FIT_USEC + packet->ts.tv_usec - flowEntry->flowFeatures.lastBackwardTime;	


	flowEntry->flowFeatures.stdBackwardPacketSize = sqrt((
				flowEntry->flowFeatures.stdBackwardPacketSize+(totalPkt/(totalPkt+1.0))*
				pow(packet->len-flowEntry->flowFeatures.meanBackwardPacketSize,2))/totalPkt);

	flowEntry->flowFeatures.meanBackwardPacketSize = (packet->len+
							(flowEntry->flowFeatures.meanBackwardPacketSize * 
							 totalPkt))/(totalPkt+1.0);


	flowEntry->flowFeatures.stdBackwardTimePacket = sqrt((
				flowEntry->flowFeatures.stdBackwardTimePacket + (totalPkt/(totalPkt+1.0))*
				pow(timeElapsed - flowEntry->flowFeatures.meanBackwardTimePacket,2))/totalPkt);

	

	flowEntry->flowFeatures.meanBackwardTimePacket = (timeElapsed+(flowEntry->flowFeatures.meanBackwardTimePacket * 
						totalPkt))/(totalPkt+1.0);
	
	/* largest and smallest time and size features */
	if(flowEntry->flowFeatures.largestBackwardPacket < packet->len)
		flowEntry->flowFeatures.largestBackwardPacket = packet->len;

	if(flowEntry->flowFeatures.smallestBackwardPacket > packet->len)
		flowEntry->flowFeatures.smallestBackwardPacket = packet->len;

	if(timeElapsed > flowEntry->flowFeatures.maxBackwardTimePacket)
		flowEntry->flowFeatures.maxBackwardTimePacket = timeElapsed;

	if(timeElapsed < flowEntry->flowFeatures.minBackwardTimePacket)
		flowEntry->flowFeatures.minBackwardTimePacket = timeElapsed;


	/* tcp flags */
	if(TH_FIN & tcp->th_flags)
		flowEntry->flowFeatures.totalBackwardFIN++;
	if(TH_SYN & tcp->th_flags)
		flowEntry->flowFeatures.totalBackwardSYN++;
	if(TH_RST & tcp->th_flags)
		flowEntry->flowFeatures.totalBackwardRST++;
	if(TH_PUSH & tcp->th_flags)
		flowEntry->flowFeatures.totalBackwardPUSH++;
	if(TH_ACK & tcp->th_flags)
		flowEntry->flowFeatures.totalBackwardACK++;
	if(TH_URG & tcp->th_flags)
		flowEntry->flowFeatures.totalBackwardURG++;
	if(TH_ECE & tcp->th_flags)
		flowEntry->flowFeatures.totalBackwardECE++;
	if(TH_CWR & tcp->th_flags)
		flowEntry->flowFeatures.totalBackwardCWR++;



	flowEntry->flowFeatures.totalBackwardPackets++;
	flowEntry->flowFeatures.lastBackwardTime = packet->ts.tv_sec*FIT_USEC + packet->ts.tv_usec;
	flowEntry->flowFeatures.flowBackwardSize += packet->len;
	
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

/**  rever ordem das características ***/
void 
saveExpiredFlow(flowList_t *flow)
{
	double totalDuration,first,last;
	
	if(!flow->flowHeader.ipSrc[0])
		return;

	flow->flowFeatures.totalForwardTime = flow->flowFeatures.lastForwardTime - flow->flowFeatures.firstForwardTime;
	flow->flowFeatures.totalBackwardTime = flow->flowFeatures.lastBackwardTime - flow->flowFeatures.firstBackwardTime;

	if(flow->flowFeatures.totalForwardPackets > 1 && flow->flowFeatures.totalBackwardPackets > 1)
	{
		if(flow->flowFeatures.lastForwardTime > flow->flowFeatures.lastBackwardTime)
			last = flow->flowFeatures.lastForwardTime;
		else
			last = flow->flowFeatures.lastBackwardTime;
		
		if(flow->flowFeatures.firstForwardTime > flow->flowFeatures.firstBackwardTime)
			first = flow->flowFeatures.firstForwardTime;
		else
			first = flow->flowFeatures.firstBackwardTime;

		totalDuration = last - first;

	}
	else if(flow->flowFeatures.totalForwardPackets > 1)
	{
		totalDuration = flow->flowFeatures.totalForwardPackets;	
	}
	else
	{
		totalDuration = flow->flowFeatures.totalBackwardPackets;		
	}


	/* save features */
	fprintf(FLOWS_RESULTS,"%s,%u,%s,%u,%u,%u,%u,%u,%u,%g,%g,%li,%li,%f,%g,%u,%u,%u,%u,%u,%u,%u,%u,%f,%u,%u,%u,%u,%g,%g,%li,%li,%f,%g,%u,%u,%u,%u,%u,%u,%u,%u,%f,%f\n",

			/********************************** flow header ******************************/

			flow->flowHeader.ipSrc,						       /*  1 */
			flow->flowHeader.portSrc,                                              /*  2 */
			flow->flowHeader.ipDst,						       /*  3 */
			flow->flowHeader.portDst,                                              /*  4 */
			flow->flowHeader.protocol,                                             /*  5 */ 


			/******************************* forward features *****************************/



			flow->flowFeatures.flowForwardSize,                                    /*  6 */
			flow->flowFeatures.totalForwardPackets,                                /*  7 */ 
			flow->flowFeatures.smallestForwardPacket,                              /*  8 */
			flow->flowFeatures.largestForwardPacket,                               /*  9 */ 
			flow->flowFeatures.meanForwardPacketSize,                              /* 10 */
			flow->flowFeatures.stdForwardPacketSize,                               /* 11 */ 
			flow->flowFeatures.minForwardTimePacket,                               /* 12 */ 
			flow->flowFeatures.maxForwardTimePacket,                               /* 13 */ 
			(double)flow->flowFeatures.meanForwardTimePacket/FIT_USEC,             /* 14 */ 
			flow->flowFeatures.stdForwardTimePacket,                               /* 15 */ 
			flow->flowFeatures.totalForwardFIN,                                    /* 16 */ 
			flow->flowFeatures.totalForwardSYN,                                    /* 17 */ 
			flow->flowFeatures.totalForwardRST,                                    /* 18 */ 
			flow->flowFeatures.totalForwardPUSH,                                   /* 19 */ 
			flow->flowFeatures.totalForwardACK,                                    /* 21 */ 
			flow->flowFeatures.totalForwardURG,                                    /* 22 */ 
			flow->flowFeatures.totalForwardECE,                                    /* 23 */ 
			flow->flowFeatures.totalForwardCWR,                                    /* 24 */ 
			(double)flow->flowFeatures.totalForwardTime/FIT_USEC,		       /* 25 */ 

			/******************************* backward features ****************************/

			flow->flowFeatures.flowBackwardSize,                                   /* 26 */
			flow->flowFeatures.totalBackwardPackets,                               /* 27 */ 
			flow->flowFeatures.smallestBackwardPacket,                             /* 28 */
			flow->flowFeatures.largestBackwardPacket,                              /* 29 */ 
			flow->flowFeatures.meanBackwardPacketSize,                             /* 30 */
			flow->flowFeatures.stdBackwardPacketSize,                              /* 31 */ 
			flow->flowFeatures.minBackwardTimePacket,                              /* 32 */ 
			flow->flowFeatures.maxBackwardTimePacket,                              /* 33 */ 
			(double)flow->flowFeatures.meanBackwardTimePacket/FIT_USEC,            /* 34 */ 
			flow->flowFeatures.stdBackwardTimePacket,                              /* 35 */ 
			flow->flowFeatures.totalBackwardFIN,                                   /* 36 */ 
			flow->flowFeatures.totalBackwardSYN,                                   /* 37 */ 
			flow->flowFeatures.totalBackwardRST,                                   /* 38 */ 
			flow->flowFeatures.totalBackwardPUSH,                                  /* 39 */ 
			flow->flowFeatures.totalBackwardACK,                                   /* 40 */ 
			flow->flowFeatures.totalBackwardURG,                                   /* 41 */ 
			flow->flowFeatures.totalBackwardECE,                                   /* 42 */ 
			flow->flowFeatures.totalBackwardCWR,                                   /* 43 */ 
			(double)flow->flowFeatures.totalBackwardTime/FIT_USEC,		       /* 44 */ 
			(double)totalDuration/FIT_USEC		       			       /* 45 */ 



			);                                                              

	return;
}

/*****************************************************************************************************************/


int 
flowRemove(void)
{
 	flowList_t *aux;
	
	if(!empty)						/* if the FIFO is not empty  the list */
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

	
	
	char direction;
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
		findFlow(newFlow, &find, &direction);
		
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
			

		findFlow(newFlow, &find, &direction);
		
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
		

	findFlow(newFlow, &find, &direction);
	
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




