
int updateFlowFeaturesTCP(flowID_t , const struct pcap_pkthdr *, const struct sniff_tcp *);
int updateFlowFeaturesUDP(flowID_t , const struct pcap_pkthdr *, const struct sniff_udp *);
int updateFlowFeaturesOTHER(flowID_t , const struct pcap_pkthdr *);
int flowRemove(void);
int flowAdd(flowID_t);

void checkExpiredFlows(double);
void saveExpiredFlow(flowList_t *);
void printFlow(flowList_t *);
void saveAllFlows(void);
void copyHeader(flowID_t,flowID_t);
void copyFeatures(flowFeatures_t,flowFeatures_t);

flowList_t *findFlow(flowID_t , bool *, char *);



