#include <stdlib.h>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <libcec/cecc.h>

#include "pcap-int.h"
#include "pcap-cec.h"

struct pcap_cec
{
	cec_adapter adapter;
	uint8_t buffer[CEC_BUF_LEN][CEC_MSG_SIZE];
	uint8_t buffer_len[CEC_BUF_LEN];
	uint8_t buffer_read_loc;
	uint8_t buffer_write_loc;
};

enum pcap_cec_state
{
	PCAP_CEC_FREE = 0,
	PCAP_CEC_INITIALISED = 1,
	PCAP_CEC_OPEN = 2,
};

static int cec_init(void);
static void cec_uninit(void);
static int cec_activate(pcap_t *);
static void cec_cleanup(pcap_t *);
static int cec_find_adapter(cec_adapter *, int);
static int cec_message_cb(void *, const cec_log_message);
static int cec_setfilter(pcap_t *, struct bpf_program *);
static int cec_inject(pcap_t *, const void *, size_t);
static int cec_stats(pcap_t *, struct pcap_stat *);
static int cec_read(pcap_t *, int, pcap_handler, u_char *);

enum pcap_cec_state global_state = PCAP_CEC_FREE;
ICECCallbacks cec_callbacks =
{
	.CBCecLogMessage = &cec_message_cb,
};
libcec_configuration cec_conf =
{
	.bMonitorOnly = 1,
	.callbacks = &cec_callbacks,
	.clientVersion = CEC_CLIENT_VERSION_2_2_0,
};

static int cec_init(void)
{
	switch(global_state)
	{
	case PCAP_CEC_FREE:
		if(cec_initialise(&cec_conf) < 1)
		{
			return -1;
		}
		atexit(&cec_uninit);
		global_state = PCAP_CEC_INITIALISED;
		break;
	case PCAP_CEC_INITIALISED:
	case PCAP_CEC_OPEN:
		break;
	default:
		return -1;
	}

	return 0;
}

static void cec_uninit(void)
{
	cec_destroy();
	global_state = PCAP_CEC_FREE;
}

static int cec_activate(pcap_t *handle)
{
	int ret;
	struct pcap_cec *handlep = handle->priv;

	ret = cec_init();
	if (ret < 0)
	{
		snprintf(handle->errbuf, PCAP_ERRBUF_SIZE, "Failed to initialise libCEC");
		return -1;
	}

	if (global_state == PCAP_CEC_OPEN)
	{
		snprintf(handle->errbuf, PCAP_ERRBUF_SIZE, "The C interface to libCEC supports only one active adapter at a time");
		return -1;
	}

	global_state = PCAP_CEC_OPEN;

	if (handle->opt.rfmon)
	{
		snprintf(handle->errbuf, PCAP_ERRBUF_SIZE, "Monitor mode is not supported by CEC devices");
		global_state = PCAP_CEC_INITIALISED;
		return PCAP_ERROR_RFMON_NOTSUP;
	}

	cec_conf.callbackParam = (void *)handlep;
	cec_enable_callbacks(cec_conf.callbackParam, cec_conf.callbacks);
	ret = cec_open(handlep->adapter.comm, 1000);
	if (ret < 1)
	{
		snprintf(handle->errbuf, PCAP_ERRBUF_SIZE, "Failed to open libCEC device %s: %d", handlep->adapter.comm, ret);
		global_state = PCAP_CEC_INITIALISED;
		return -1;
	}

	handle->selectable_fd = -1;
	handle->linktype = DLT_CEC;
	handle->read_op = cec_read;
	handle->inject_op = cec_inject; /* Unfinished. */
	handle->setfilter_op = cec_setfilter; /* Not implemented. */
	handle->setdirection_op = NULL; /* Not implemented. */
	handle->set_datalink_op = NULL; /* Can't change data link type */
	handle->getnonblock_op = NULL;
	handle->setnonblock_op = NULL;
	handle->stats_op = cec_stats;
	handle->cleanup_op = cec_cleanup;

	return 0;
}

static void cec_cleanup(pcap_t *p)
{
	if (p == NULL)
		return;
	cec_close();
	pcap_cleanup_live_common(p);
}

static int cec_find_adapter(cec_adapter *adapter, int devnum)
{
	int i;
	int ret;
	cec_adapter cec_adapters[CEC_MAX_ADAPTERS];

	ret = cec_init();
	if (ret < 0)
		return -1;

	ret = cec_find_adapters(cec_adapters, CEC_MAX_ADAPTERS, NULL);
	if (ret != 1)
		return -1;

	if (devnum < 1 || devnum > ret)
		return -1;

	*adapter = cec_adapters[devnum - 1];

	return 0;
}

pcap_t *cec_create(const char *device, char *ebuf, int *is_ours)
{
	const char *cp;
	char *cpend;
	long devnum;
	pcap_t *p;
	cec_adapter adapter;

	/* Does this look like a CEC device? */
	cp = strrchr(device, '/');
	if (cp == NULL)
		cp = device;
	/* Does it begin with CEC_IFACE? */
	if (strncmp(cp, CEC_IFACE, sizeof CEC_IFACE - 1) != 0)
	{
		/* Nope, doesn't begin with CEC_IFACE */
		*is_ours = 0;
		return NULL;
	}
	/* Yes - is CEC_IFACE followed by a number? */
	cp += sizeof CEC_IFACE - 1;
	devnum = strtol(cp, &cpend, 10);
	if (cpend == cp || *cpend != '\0')
	{
		/* Not followed by a number. */
		*is_ours = 0;
		return NULL;
	}
	if (devnum < 1 || devnum > CEC_MAX_ADAPTERS)
	{
		/* Followed by a non-valid number. */
		*is_ours = 0;
		return NULL;
	}

	/* OK, it's probably ours. */
	*is_ours = 1;

	if (cec_find_adapter(&adapter, devnum) < 0)
	{
		return NULL;
	}

	p = pcap_create_common(device, ebuf, sizeof (struct pcap_cec));
	if (p == NULL)
	{
		return NULL;
	}

	struct pcap_cec *ps = p->priv;
	if (ps == NULL)
	{
		free(p);
		return NULL;
	}

	ps->adapter = adapter;
	ps->buffer_read_loc = 0;
	ps->buffer_write_loc = 0;
	p->activate_op = cec_activate;

	return p;
}

int cec_findalldevs(pcap_if_t **devlistp, char *errbuf)
{
	int i;
	int ret;
	cec_adapter cec_adapters[CEC_MAX_ADAPTERS];

	ret = cec_init();
	if (ret < 0)
		return -1;

	ret = cec_find_adapters(cec_adapters, CEC_MAX_ADAPTERS, NULL);
	if (ret < 0)
		return -1;
	else if (ret == 0)
		return 0;

	for (i = 0; i < ret; i++)
	{
		char dev_name[5];
		char dev_desc[1024];
		snprintf(dev_name, 5, CEC_IFACE "%u", i + 1);
		snprintf(dev_desc, 1024, "CEC device at %s", cec_adapters[i].comm);

		if (pcap_add_if(devlistp, dev_name, 0, dev_desc, errbuf) < 0)
			return -1;
	}

	return 0;
}

static int cec_message_cb(void *context, const cec_log_message msg)
{
	unsigned char i;
	struct pcap_cec *handlep = (struct pcap_cec *)context;

	if (msg.level != CEC_LOG_TRAFFIC)
		return 0;

	const char *msg_ptr = msg.message + 3;
	const char *msg_end = msg.message + strlen(msg.message);

	for (i = 0; msg_ptr < msg_end && i < CEC_MSG_SIZE; i++)
	{
		if(sscanf(msg_ptr, "%hhx", &handlep->buffer[handlep->buffer_write_loc][i]) != 1)
			break;
		msg_ptr += 3;
	}

	handlep->buffer_len[handlep->buffer_write_loc] = i;

	(handlep->buffer_write_loc >= CEC_BUF_LEN - 1) ? handlep->buffer_write_loc =0 : handlep->buffer_write_loc++;

	return 0;
}

static int cec_setfilter(pcap_t *p, struct bpf_program *fp)
{
	// NOT IMPLEMENTED
	return 0;
}

static int cec_inject(pcap_t *handle, const void *buf, size_t size)
{
	int ret;
	uint8_t *data = (uint8_t *)buf;

	if (size == 0)
		return 0;

	cec_command pkt =
	{
		.destination = data[0] & 0xf,
		.initiator = data[0] << 0xf,
		.opcode_set = (size > 1) ? 1 : 0,
	};

	if (size > 1)
		pkt.opcode = data[1];

	if (size > 2)
	{
		pkt.parameters.size = size - 2;
		memcpy(pkt.parameters.data, &data[2], pkt.parameters.size);
	}

	ret = cec_transmit(&pkt);
	if (ret < 0)
		return -1;

	// TODO: Not Finished?

	return 0;
}

static int cec_stats(pcap_t *handle, struct pcap_stat *stats)
{
	// NOT IMPLEMENTED
	return 0;
}

static int cec_read(pcap_t *handle, int max_packets, pcap_handler callback, u_char *user)
{
	int ret = 0;
	struct pcap_cec *handlep = handle->priv;
	struct pcap_pkthdr pkth;

	for (ret = 0; handlep->buffer_read_loc != handlep->buffer_write_loc && (ret < max_packets || max_packets < 0); ret++)
	{
		if(-1 == gettimeofday(&pkth.ts, NULL))
		{
			snprintf(handle->errbuf, PCAP_ERRBUF_SIZE, "Can't get time of day");
			return -1;
		}
		pkth.caplen = handlep->buffer_len[handlep->buffer_read_loc];
		pkth.len = pkth.caplen;
		callback(user, &pkth, handlep->buffer[handlep->buffer_read_loc]);
		(handlep->buffer_read_loc >= CEC_BUF_LEN - 1) ? handlep->buffer_read_loc =0 : handlep->buffer_read_loc++;
	}

	return ret;
}
