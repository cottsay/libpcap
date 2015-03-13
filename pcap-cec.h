pcap_t *cec_create(const char *, char *, int *);
int cec_findalldevs(pcap_if_t **devlistp, char *errbuf);

#define CEC_IFACE "cec"
#define CEC_MAX_ADAPTERS 8

#define CEC_BUF_LEN 16
#define CEC_MSG_SIZE 16
