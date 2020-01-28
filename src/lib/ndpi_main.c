#include <stdio.h>
#include <stdlib.h>
#define NDPI_MAX_SUPPORTED_PROTOCOLS NDPI_LAST_IMPLEMENTED_PROTOCOL
#define CUSTOM_CATEGORY_LABEL_LEN 32
#define NUM_CUSTOM_CATEGORIES 5
#define NDPI_PROTOCOL_BITMASK ndpi_protocol_bitmask_struct_t
#define NDPI_MAX_NUM_CUSTOM_PROTOCOLS (NDPI_NUM_BITS - NDPI_LAST_IMPLEMENTED_PROTOCOL)
typedef struct ndpi_default_ports_tree_node
{
	ndpi_proto_defaults_t *proto;
	u_int8_t customUserProto;
	u_int16_t default_port;
} ndpi_default_ports_tree_node_t;
typedef struct ndpi_proto_defaults
{
	char *protoName;
	ndpi_protocol_category_t protoCategory;
	u_int8_t can_have_a_subprotocol;
	u_int16_t protoId, protoIdx;
	u_int16_t master_tcp_protoId[2], master_udp_protoId[2]; /* The main protocols on which this sub-protocol sits on */
	ndpi_protocol_breed_t protoBreed;
	void (*func)(struct ndpi_detection_module_struct *, struct ndpi_flow_struct *flow);
} ndpi_proto_defaults_t;
typedef enum
{
	NDPI_LOG_ERROR,
	NDPI_LOG_TRACE,
	NDPI_LOG_DEBUG,
	NDPI_LOG_DEBUG_EXTRA
} ndpi_log_level_t;
typedef struct _ndpi_automa
{
	void *ac_automa; /* Real type is AC_AUTOMATA_t */
	u_int8_t ac_automa_finalized;
} ndpi_automa;
struct ndpi_detection_module_struct
{
	//array of type unint32 with size depend on NDPI_NUM_BITS = 512
	//and NDPI_BITS sizeof(unint32)*8
	NDPI_PROTOCOL_BITMASK detection_bitmask;
	NDPI_PROTOCOL_BITMASK generic_http_packet_bitmask;

	u_int32_t current_ts;
	u_int32_t ticks_per_second;

#ifdef NDPI_ENABLE_DEBUG_MESSAGES
	void *user_data;
#endif
	char custom_category_labels[NUM_CUSTOM_CATEGORIES][CUSTOM_CATEGORY_LABEL_LEN];
	/* callback function buffer */
	struct ndpi_call_function_struct callback_buffer[NDPI_MAX_SUPPORTED_PROTOCOLS + 1];
	u_int32_t callback_buffer_size;

	struct ndpi_call_function_struct callback_buffer_tcp_no_payload[NDPI_MAX_SUPPORTED_PROTOCOLS + 1];
	u_int32_t callback_buffer_size_tcp_no_payload;

	struct ndpi_call_function_struct callback_buffer_tcp_payload[NDPI_MAX_SUPPORTED_PROTOCOLS + 1];
	u_int32_t callback_buffer_size_tcp_payload;

	struct ndpi_call_function_struct callback_buffer_udp[NDPI_MAX_SUPPORTED_PROTOCOLS + 1];
	u_int32_t callback_buffer_size_udp;

	struct ndpi_call_function_struct callback_buffer_non_tcp_udp[NDPI_MAX_SUPPORTED_PROTOCOLS + 1];
	u_int32_t callback_buffer_size_non_tcp_udp;

	ndpi_default_ports_tree_node_t *tcpRoot, *udpRoot;

	ndpi_log_level_t ndpi_log_level; /* default error */

#ifdef NDPI_ENABLE_DEBUG_MESSAGES
	/* debug callback, only set when debug is used */
	ndpi_debug_function_ptr ndpi_debug_printf;
	const char *ndpi_debug_print_file;
	const char *ndpi_debug_print_function;
	u_int32_t ndpi_debug_print_line;
	NDPI_PROTOCOL_BITMASK debug_bitmask;
#endif

	/* misc parameters */
	u_int32_t tcp_max_retransmission_window_size;

	u_int32_t directconnect_connection_ip_tick_timeout;

	/* subprotocol registration handler */
	struct ndpi_subprotocol_conf_struct subprotocol_conf[NDPI_MAX_SUPPORTED_PROTOCOLS + 1];

	u_int ndpi_num_supported_protocols;
	u_int ndpi_num_custom_protocols;

	/* HTTP/DNS/HTTPS host matching */
	ndpi_automa host_automa,					   /* Used for DNS/HTTPS */
		content_automa,							   /* Used for HTTP subprotocol_detection */
		subprotocol_automa,						   /* Used for HTTP subprotocol_detection */
		bigrams_automa, impossible_bigrams_automa; /* TOR */
	/* IMPORTANT: please update ndpi_finalize_initalization() whenever you add a new automa */

	struct
	{
#ifdef HAVE_HYPERSCAN
		struct hs *hostnames;
		unsigned int num_to_load;
		struct hs_list *to_load;
#else
		ndpi_automa hostnames, hostnames_shadow;
#endif
		void ipAddresses, *ipAddresses_shadow; /* Patricia */
		u_int8_t categories_loaded;
	} custom_categories;

	/* IP-based protocol detection */
	void *protocols_ptree;

	/* irc parameters */
	u_int32_t irc_timeout;
	/* gnutella parameters */
	u_int32_t gnutella_timeout;
	/* battlefield parameters */
	u_int32_t battlefield_timeout;
	/* thunder parameters */
	u_int32_t thunder_timeout;
	/* SoulSeek parameters */
	u_int32_t soulseek_connection_ip_tick_timeout;
	/* rtsp parameters */
	u_int32_t rtsp_connection_timeout;
	/* tvants parameters */
	u_int32_t tvants_connection_timeout;
	/* rstp */
	u_int32_t orb_rstp_ts_timeout;
	/* yahoo */
	u_int8_t yahoo_detect_http_connections;
	u_int32_t yahoo_lan_video_timeout;
	u_int32_t zattoo_connection_timeout;
	u_int32_t jabber_stun_timeout;
	u_int32_t jabber_file_transfer_timeout;
	u_int8_t ip_version_limit;
	/* NDPI_PROTOCOL_BITTORRENT */
	struct hash_ip4p_table *bt_ht;
#ifdef NDPI_DETECTION_SUPPORT_IPV6
	struct hash_ip4p_table *bt6_ht;
#endif

	/* BT_ANNOUNCE */
	struct bt_announce *bt_ann;
	int bt_ann_len;

	/* NDPI_PROTOCOL_OOKLA */
	struct ndpi_lru_cache *ookla_cache;

	/* NDPI_PROTOCOL_TINC */
	struct cache *tinc_cache;

	/* NDPI_PROTOCOL_STUN and subprotocols */
	struct ndpi_lru_cache *stun_cache;

	ndpi_proto_defaults_t proto_defaults[NDPI_MAX_SUPPORTED_PROTOCOLS + NDPI_MAX_NUM_CUSTOM_PROTOCOLS];

	u_int8_t direction_detect_disable : 1, /* disable internal detection of packet direction */
		disable_metadata_export : 1		   /* No metadata is exported */
		;

	void hyperscan; /* Intel Hyperscan */
};

struct ndpi_detection_module_struct *ndpi_init_detection_module(ndpi_init_prefs prefs)
{
	struct ndpi_detection_module_struct *ndpi_str = ndpi_malloc(sizeof(struct ndpi_detection_module_struct));
	int i;

	if (ndpi_str == NULL)
	{
#ifdef NDPI_ENABLE_DEBUG_MESSAGES
		NDPI_LOG_ERR(ndpi_str, "ndpi_init_detection_module initial malloc failed for ndpi_str\n");
#endif /* NDPI_ENABLE_DEBUG_MESSAGES */
		return (NULL);
	}

	memset(ndpi_str, 0, sizeof(struct ndpi_detection_module_struct));

#ifdef NDPI_ENABLE_DEBUG_MESSAGES
	set_ndpi_debug_function(ndpi_str, (ndpi_debug_function_ptr)ndpi_debug_printf);
#endif /* NDPI_ENABLE_DEBUG_MESSAGES */

	if ((ndpi_str->protocols_ptree = ndpi_New_Patricia(32 /* IPv4 */)) != NULL)
		ndpi_init_ptree_ipv4(ndpi_str, ndpi_str->protocols_ptree,
							 host_protocol_list,
							 prefs & ndpi_dont_load_tor_hosts);

	NDPI_BITMASK_RESET(ndpi_str->detection_bitmask);
#ifdef NDPI_ENABLE_DEBUG_MESSAGES
	ndpi_str->user_data = NULL;
#endif

	ndpi_str->ticks_per_second = 1000; /* ndpi_str->ticks_per_second */
	ndpi_str->tcp_max_retransmission_window_size = NDPI_DEFAULT_MAX_TCP_RETRANSMISSION_WINDOW_SIZE;
	ndpi_str->directconnect_connection_ip_tick_timeout =
		NDPI_DIRECTCONNECT_CONNECTION_IP_TICK_TIMEOUT * ndpi_str->ticks_per_second;

	ndpi_str->rtsp_connection_timeout = NDPI_RTSP_CONNECTION_TIMEOUT * ndpi_str->ticks_per_second;
	ndpi_str->tvants_connection_timeout = NDPI_TVANTS_CONNECTION_TIMEOUT * ndpi_str->ticks_per_second;
	ndpi_str->irc_timeout = NDPI_IRC_CONNECTION_TIMEOUT * ndpi_str->ticks_per_second;
	ndpi_str->gnutella_timeout = NDPI_GNUTELLA_CONNECTION_TIMEOUT * ndpi_str->ticks_per_second;

	ndpi_str->battlefield_timeout = NDPI_BATTLEFIELD_CONNECTION_TIMEOUT * ndpi_str->ticks_per_second;

	ndpi_str->thunder_timeout = NDPI_THUNDER_CONNECTION_TIMEOUT * ndpi_str->ticks_per_second;
	ndpi_str->yahoo_detect_http_connections = NDPI_YAHOO_DETECT_HTTP_CONNECTIONS;

	ndpi_str->yahoo_lan_video_timeout = NDPI_YAHOO_LAN_VIDEO_TIMEOUT * ndpi_str->ticks_per_second;
	ndpi_str->zattoo_connection_timeout = NDPI_ZATTOO_CONNECTION_TIMEOUT * ndpi_str->ticks_per_second;
	ndpi_str->jabber_stun_timeout = NDPI_JABBER_STUN_TIMEOUT * ndpi_str->ticks_per_second;
	ndpi_str->jabber_file_transfer_timeout = NDPI_JABBER_FT_TIMEOUT * ndpi_str->ticks_per_second;
	ndpi_str->soulseek_connection_ip_tick_timeout = NDPI_SOULSEEK_CONNECTION_IP_TICK_TIMEOUT * ndpi_str->ticks_per_second;

	ndpi_str->ndpi_num_supported_protocols = NDPI_MAX_SUPPORTED_PROTOCOLS;
	ndpi_str->ndpi_num_custom_protocols = 0;

	ndpi_str->host_automa.ac_automa = ac_automata_init(ac_match_handler);
	ndpi_str->content_automa.ac_automa = ac_automata_init(ac_match_handler);
	ndpi_str->bigrams_automa.ac_automa = ac_automata_init(ac_match_handler);
	ndpi_str->impossible_bigrams_automa.ac_automa = ac_automata_init(ac_match_handler);

	if ((sizeof(categories) / sizeof(char *)) != NDPI_PROTOCOL_NUM_CATEGORIES)
	{
		NDPI_LOG_ERR(ndpi_str, "[NDPI] invalid categories length: expected %u, got %u\n",
					 NDPI_PROTOCOL_NUM_CATEGORIES, (unsigned int)(sizeof(categories) / sizeof(char *)));
		return (NULL);
	}

#ifdef HAVE_HYPERSCAN
	ndpi_str->custom_categories.num_to_load = 0, ndpi_str->custom_categories.to_load = NULL;
	ndpi_str->custom_categories.hostnames = NULL;
#else
	ndpi_str->custom_categories.hostnames.ac_automa = ac_automata_init(ac_match_handler);
	ndpi_str->custom_categories.hostnames_shadow.ac_automa = ac_automata_init(ac_match_handler);
#endif

	ndpi_str->custom_categories.ipAddresses = ndpi_New_Patricia(32 /* IPv4 */);
	ndpi_str->custom_categories.ipAddresses_shadow = ndpi_New_Patricia(32 /* IPv4 */);

	if ((ndpi_str->custom_categories.ipAddresses == NULL) || (ndpi_str->custom_categories.ipAddresses_shadow == NULL))
		return (NULL);

	ndpi_init_protocol_defaults(ndpi_str);

	for (i = 0; i < NUM_CUSTOM_CATEGORIES; i++)
		snprintf(ndpi_str->custom_category_labels[i],
				 CUSTOM_CATEGORY_LABEL_LEN, "User custom category %u", (unsigned int)(i + 1));

	return (ndpi_str);
}
static int fill_prefix_v4(prefix_t *p, const struct in_addr *a, int b, int mb)
{
	do
	{
		if (b < 0 || b > mb)
			return (-1);

		memset(p, 0, sizeof(prefix_t));
		memcpy(&p->add.sin, a, (mb + 7) / 8);
		p->family = AF_INET;
		p->bitlen = b;
		p->ref_count = 0;
	} while (0);

	return (0);
}
static patricia_node_t *add_to_ptree(patricia_tree_t *tree, int family, void *addr, int bits)
{
	prefix_t prefix;
	patricia_node_t *node;

	fill_prefix_v4(&prefix, (struct in_addr *)addr, bits, tree->maxbits);

	node = ndpi_patricia_lookup(tree, &prefix);

	return (node);
}
static void ndpi_init_ptree_ipv4(struct ndpi_detection_module_struct *ndpi_str, void *ptree, ndpi_network host_list[], u_int8_t skip_tor_hosts)
{
	int i;

	for (i = 0; host_list[i].network != 0x0; i++)
	{
		struct in_addr pin;
		patricia_node_t *node;

		if (skip_tor_hosts && (host_list[i].value == NDPI_PROTOCOL_TOR))
			continue;

		pin.s_addr = htonl(host_list[i].network);
		if ((node = add_to_ptree(ptree, AF_INET,
								 &pin, host_list[i].cidr /* bits */)) != NULL)
			node->value.user_value = host_list[i].value;
	}
}
/* ********************************************************************************* */

void ndpi_connection_tracking(struct ndpi_detection_module_struct *ndpi_str,
							  struct ndpi_flow_struct *flow)
{
	if (!flow)
	{
		return;
	}
	else
	{
		/* const for gcc code optimization and cleaner code */
		struct ndpi_packet_struct *packet = &flow->packet;
		const struct ndpi_iphdr *iph = packet->iph;
#ifdef NDPI_DETECTION_SUPPORT_IPV6
		const struct ndpi_ipv6hdr *iphv6 = packet->iphv6;
#endif
		const struct ndpi_tcphdr *tcph = packet->tcp;
		const struct ndpi_udphdr *udph = flow->packet.udp;

		packet->tcp_retransmission = 0, packet->packet_direction = 0;

		if (ndpi_str->direction_detect_disable)
		{
			packet->packet_direction = flow->packet_direction;
		}
		else
		{
			if (iph != NULL && ntohl(iph->saddr) < ntohl(iph->daddr))
				packet->packet_direction = 1;

#ifdef NDPI_DETECTION_SUPPORT_IPV6
			if (iphv6 != NULL && NDPI_COMPARE_IPV6_ADDRESS_STRUCTS(&iphv6->ip6_src,
																   &iphv6->ip6_dst) != 0)
				packet->packet_direction = 1;
#endif
		}

		packet->packet_lines_parsed_complete = 0;

		if (flow->init_finished == 0)
		{
			flow->init_finished = 1;
			flow->setup_packet_direction = packet->packet_direction;
		}

		if (tcph != NULL)
		{
			/* reset retried bytes here before setting it */
			packet->num_retried_bytes = 0;

			if (!ndpi_str->direction_detect_disable)
				packet->packet_direction = (ntohs(tcph->source) < ntohs(tcph->dest)) ? 1 : 0;

			if (tcph->syn != 0 && tcph->ack == 0 && flow->l4.tcp.seen_syn == 0 && flow->l4.tcp.seen_syn_ack == 0 && flow->l4.tcp.seen_ack == 0)
			{
				flow->l4.tcp.seen_syn = 1;
			}
			if (tcph->syn != 0 && tcph->ack != 0 && flow->l4.tcp.seen_syn == 1 && flow->l4.tcp.seen_syn_ack == 0 && flow->l4.tcp.seen_ack == 0)
			{
				flow->l4.tcp.seen_syn_ack = 1;
			}
			if (tcph->syn == 0 && tcph->ack == 1 && flow->l4.tcp.seen_syn == 1 && flow->l4.tcp.seen_syn_ack == 1 && flow->l4.tcp.seen_ack == 0)
			{
				flow->l4.tcp.seen_ack = 1;
			}
			if ((flow->next_tcp_seq_nr[0] == 0 && flow->next_tcp_seq_nr[1] == 0) || (flow->next_tcp_seq_nr[0] == 0 || flow->next_tcp_seq_nr[1] == 0))
			{
				/* initialize tcp sequence counters */
				/* the ack flag needs to be set to get valid sequence numbers from the other
	 * direction. Usually it will catch the second packet syn+ack but it works
	 * also for asymmetric traffic where it will use the first data packet
	 *
	 * if the syn flag is set add one to the sequence number,
	 * otherwise use the payload length.
	 */
				if (tcph->ack != 0)
				{
					flow->next_tcp_seq_nr[flow->packet.packet_direction] =
						ntohl(tcph->seq) + (tcph->syn ? 1 : packet->payload_packet_len);

					flow->next_tcp_seq_nr[1 - flow->packet.packet_direction] = ntohl(tcph->ack_seq);
				}
			}
			else if (packet->payload_packet_len > 0)
			{
				/* check tcp sequence counters */
				if (((u_int32_t)(ntohl(tcph->seq) - flow->next_tcp_seq_nr[packet->packet_direction])) >
					ndpi_str->tcp_max_retransmission_window_size)
				{

					packet->tcp_retransmission = 1;

					/* CHECK IF PARTIAL RETRY IS HAPPENING */
					if ((flow->next_tcp_seq_nr[packet->packet_direction] - ntohl(tcph->seq) < packet->payload_packet_len))
					{
						/* num_retried_bytes actual_payload_len hold info about the partial retry
	       analyzer which require this info can make use of this info
	       Other analyzer can use packet->payload_packet_len */
						packet->num_retried_bytes = (u_int16_t)(flow->next_tcp_seq_nr[packet->packet_direction] - ntohl(tcph->seq));
						packet->actual_payload_len = packet->payload_packet_len - packet->num_retried_bytes;
						flow->next_tcp_seq_nr[packet->packet_direction] = ntohl(tcph->seq) + packet->payload_packet_len;
					}
				}

				/* normal path
	   actual_payload_len is initialized to payload_packet_len during tcp header parsing itself.
	   It will be changed only in case of retransmission */
				else
				{
					packet->num_retried_bytes = 0;
					flow->next_tcp_seq_nr[packet->packet_direction] = ntohl(tcph->seq) + packet->payload_packet_len;
				}
			}

			if (tcph->rst)
			{
				flow->next_tcp_seq_nr[0] = 0;
				flow->next_tcp_seq_nr[1] = 0;
			}
		}
		else if (udph != NULL)
		{
			if (!ndpi_str->direction_detect_disable)
				packet->packet_direction = (htons(udph->source) < htons(udph->dest)) ? 1 : 0;
		}

		if (flow->packet_counter < MAX_PACKET_COUNTER && packet->payload_packet_len)
		{
			flow->packet_counter++;
		}

		if (flow->packet_direction_counter[packet->packet_direction] < MAX_PACKET_COUNTER && packet->payload_packet_len)
		{
			flow->packet_direction_counter[packet->packet_direction]++;
		}

		if (flow->byte_counter[packet->packet_direction] + packet->payload_packet_len >
			flow->byte_counter[packet->packet_direction])
		{
			flow->byte_counter[packet->packet_direction] += packet->payload_packet_len;
		}
	}
}

/* ********************************************************************************* */

static int ndpi_init_packet_header(struct ndpi_detection_module_struct *ndpi_str,
								   struct ndpi_flow_struct *flow,
								   unsigned short packetlen)
{
	const struct ndpi_iphdr *decaps_iph = NULL;
	u_int16_t l3len;
	u_int16_t l4len;
	const u_int8_t *l4ptr;
	u_int8_t l4protocol;
	u_int8_t l4_result;

	if (!flow)
		return (1);

	/* reset payload_packet_len, will be set if ipv4 tcp or udp */
	flow->packet.payload_packet_len = 0;
	flow->packet.l4_packet_len = 0;
	flow->packet.l3_packet_len = packetlen;

	flow->packet.tcp = NULL, flow->packet.udp = NULL;
	flow->packet.generic_l4_ptr = NULL;
#ifdef NDPI_DETECTION_SUPPORT_IPV6
	flow->packet.iphv6 = NULL;
#endif /* NDPI_DETECTION_SUPPORT_IPV6 */

	ndpi_apply_flow_protocol_to_packet(flow, &flow->packet);

	l3len = flow->packet.l3_packet_len;

#ifdef NDPI_DETECTION_SUPPORT_IPV6
	if (flow->packet.iph != NULL)
	{
#endif /* NDPI_DETECTION_SUPPORT_IPV6 */

		decaps_iph = flow->packet.iph;

#ifdef NDPI_DETECTION_SUPPORT_IPV6
	}
#endif /* NDPI_DETECTION_SUPPORT_IPV6 */

	if (decaps_iph && decaps_iph->version == IPVERSION && decaps_iph->ihl >= 5)
	{
		NDPI_LOG_DBG2(ndpi_str, "ipv4 header\n");
	}
#ifdef NDPI_DETECTION_SUPPORT_IPV6
	else if (decaps_iph && decaps_iph->version == 6 && l3len >= sizeof(struct ndpi_ipv6hdr) &&
			 (ndpi_str->ip_version_limit & NDPI_DETECTION_ONLY_IPV4) == 0)
	{
		NDPI_LOG_DBG2(ndpi_str, "ipv6 header\n");
		flow->packet.iphv6 = (struct ndpi_ipv6hdr *)flow->packet.iph;
		flow->packet.iph = NULL;
	}
#endif
	else
	{
		flow->packet.iph = NULL;
		return (1);
	}

	/* needed:
   *  - unfragmented packets
   *  - ip header <= packet len
   *  - ip total length >= packet len
   */

	l4ptr = NULL;
	l4len = 0;
	l4protocol = 0;

	l4_result =
		ndpi_detection_get_l4_internal(ndpi_str, (const u_int8_t *)decaps_iph, l3len, &l4ptr, &l4len, &l4protocol, 0);

	if (l4_result != 0)
	{
		return (1);
	}

	flow->packet.l4_protocol = l4protocol;
	flow->packet.l4_packet_len = l4len;
	flow->l4_proto = l4protocol;

	/* tcp / udp detection */
	if (l4protocol == IPPROTO_TCP && flow->packet.l4_packet_len >= 20 /* min size of tcp */)
	{
		/* tcp */
		flow->packet.tcp = (struct ndpi_tcphdr *)l4ptr;
		if (flow->packet.l4_packet_len >= flow->packet.tcp->doff * 4)
		{
			flow->packet.payload_packet_len =
				flow->packet.l4_packet_len - flow->packet.tcp->doff * 4;
			flow->packet.actual_payload_len = flow->packet.payload_packet_len;
			flow->packet.payload = ((u_int8_t *)flow->packet.tcp) + (flow->packet.tcp->doff * 4);

			/* check for new tcp syn packets, here
       * idea: reset detection state if a connection is unknown
       */
			if (flow->packet.tcp->syn != 0 && flow->packet.tcp->ack == 0 && flow->init_finished != 0 && flow->detected_protocol_stack[0] == NDPI_PROTOCOL_UNKNOWN)
			{
				u_int8_t backup;
				u_int16_t backup1, backup2;

				if (flow->http.url)
					ndpi_free(flow->http.url);
				if (flow->http.content_type)
					ndpi_free(flow->http.content_type);
				if (flow->http.user_agent)
					ndpi_free(flow->http.user_agent);

				backup = flow->num_processed_pkts;
				backup1 = flow->guessed_protocol_id;
				backup2 = flow->guessed_host_protocol_id;
				memset(flow, 0, sizeof(*(flow)));
				flow->num_processed_pkts = backup;
				flow->guessed_protocol_id = backup1;
				flow->guessed_host_protocol_id = backup2;

				NDPI_LOG_DBG(ndpi_str,
							 "tcp syn packet for unknown protocol, reset detection state\n");
			}
		}
		else
		{
			/* tcp header not complete */
			flow->packet.tcp = NULL;
		}
	}
	else if (l4protocol == IPPROTO_UDP && flow->packet.l4_packet_len >= 8 /* size of udp */)
	{
		flow->packet.udp = (struct ndpi_udphdr *)l4ptr;
		flow->packet.payload_packet_len = flow->packet.l4_packet_len - 8;
		flow->packet.payload = ((u_int8_t *)flow->packet.udp) + 8;
	}
	else
	{
		flow->packet.generic_l4_ptr = l4ptr;
	}

	return (0);
}

/* ********************************************************************************* */

void ndpi_process_extra_packet(struct ndpi_detection_module_struct *ndpi_str,
							   struct ndpi_flow_struct *flow,
							   const unsigned char *packet,
							   const unsigned short packetlen,
							   const u_int64_t current_tick_l,
							   struct ndpi_id_struct *src,
							   struct ndpi_id_struct *dst)
{
	if (flow == NULL)
		return;

	if (flow->server_id == NULL)
		flow->server_id = dst; /* Default */

	/* need at least 20 bytes for ip header */
	if (packetlen < 20)
	{
		return;
	}

	flow->packet.tick_timestamp_l = current_tick_l;
	flow->packet.tick_timestamp = (u_int32_t)(current_tick_l / ndpi_str->ticks_per_second);

	/* parse packet */
	flow->packet.iph = (struct ndpi_iphdr *)packet;
	/* we are interested in ipv4 packet */

	/* set up the packet headers for the extra packet function to use if it wants */
	if (ndpi_init_packet_header(ndpi_str, flow, packetlen) != 0)
		return;

	/* detect traffic for tcp or udp only */
	flow->src = src, flow->dst = dst;
	ndpi_connection_tracking(ndpi_str, flow);

	/* call the extra packet function (which may add more data/info to flow) */
	if (flow->extra_packets_func)
	{
		if ((flow->extra_packets_func(ndpi_str, flow)) == 0)
			flow->check_extra_packets = 0;
	}

	flow->num_extra_packets_checked++;
}
/* ********************************************************************************* */

/* turns a packet back to unknown */
void ndpi_int_reset_packet_protocol(struct ndpi_packet_struct *packet)
{
	int a;

	for (a = 0; a < NDPI_PROTOCOL_SIZE; a++)
		packet->detected_protocol_stack[a] = NDPI_PROTOCOL_UNKNOWN;
}

/* ********************************************************************************* */

/* ****************************************************** */

u_int16_t ndpi_guess_protocol_id(struct ndpi_detection_module_struct *ndpi_str,
								 struct ndpi_flow_struct *flow,
								 u_int8_t proto, u_int16_t sport, u_int16_t dport,
								 u_int8_t *user_defined_proto)
{
	*user_defined_proto = 0; /* Default */

	if (sport && dport)
	{
		ndpi_default_ports_tree_node_t *found = ndpi_get_guessed_protocol_id(ndpi_str, proto, sport, dport);

		if (found != NULL)
		{
			u_int16_t guessed_proto = found->proto->protoId;

			/* We need to check if the guessed protocol isn't excluded by nDPI */
			if (flow && (proto == IPPROTO_UDP) && NDPI_COMPARE_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, guessed_proto) && is_udp_guessable_protocol(guessed_proto))
				return (NDPI_PROTOCOL_UNKNOWN);
			else
			{
				*user_defined_proto = found->customUserProto;
				return (guessed_proto);
			}
		}
	}
	else
	{
		/* No TCP/UDP */

		switch (proto)
		{
		case NDPI_IPSEC_PROTOCOL_ESP:
		case NDPI_IPSEC_PROTOCOL_AH:
			return (NDPI_PROTOCOL_IP_IPSEC);
			break;
		case NDPI_GRE_PROTOCOL_TYPE:
			return (NDPI_PROTOCOL_IP_GRE);
			break;
		case NDPI_ICMP_PROTOCOL_TYPE:
			return (NDPI_PROTOCOL_IP_ICMP);
			break;
		case NDPI_IGMP_PROTOCOL_TYPE:
			return (NDPI_PROTOCOL_IP_IGMP);
			break;
		case NDPI_EGP_PROTOCOL_TYPE:
			return (NDPI_PROTOCOL_IP_EGP);
			break;
		case NDPI_SCTP_PROTOCOL_TYPE:
			return (NDPI_PROTOCOL_IP_SCTP);
			break;
		case NDPI_OSPF_PROTOCOL_TYPE:
			return (NDPI_PROTOCOL_IP_OSPF);
			break;
		case NDPI_IPIP_PROTOCOL_TYPE:
			return (NDPI_PROTOCOL_IP_IP_IN_IP);
			break;
		case NDPI_ICMPV6_PROTOCOL_TYPE:
			return (NDPI_PROTOCOL_IP_ICMPV6);
			break;
		case 112:
			return (NDPI_PROTOCOL_IP_VRRP);
			break;
		}
	}

	return (NDPI_PROTOCOL_UNKNOWN);
}

/* ********************************************************************************* */

u_int16_t ndpi_guess_host_protocol_id(struct ndpi_detection_module_struct *ndpi_str,
									  struct ndpi_flow_struct *flow)
{
	u_int16_t ret = NDPI_PROTOCOL_UNKNOWN;

	if (flow->packet.iph)
	{
		struct in_addr addr;

		addr.s_addr = flow->packet.iph->saddr;

		/* guess host protocol */
		ret = ndpi_network_ptree_match(ndpi_str, &addr);

		if (ret == NDPI_PROTOCOL_UNKNOWN)
		{
			addr.s_addr = flow->packet.iph->daddr;
			ret = ndpi_network_ptree_match(ndpi_str, &addr);
		}
	}

	return (ret);
}

/* ********************************************************************************* */

int ndpi_fill_ip_protocol_category(struct ndpi_detection_module_struct *ndpi_str,
								   u_int32_t saddr,
								   u_int32_t daddr,
								   ndpi_protocol *ret)
{
	if (ndpi_str->custom_categories.categories_loaded)
	{
		prefix_t prefix;
		patricia_node_t *node;

		if (saddr == 0)
			node = NULL;
		else
		{
			/* Make sure all in network byte order otherwise compares wont work */
			fill_prefix_v4(&prefix, (struct in_addr *)&saddr,
						   32, ((patricia_tree_t *)ndpi_str->protocols_ptree)->maxbits);
			node = ndpi_patricia_search_best(ndpi_str->custom_categories.ipAddresses, &prefix);
		}

		if (!node)
		{
			if (daddr != 0)
				fill_prefix_v4(&prefix, (struct in_addr *)&daddr,
							   32, ((patricia_tree_t *)ndpi_str->protocols_ptree)->maxbits);
			node = ndpi_patricia_search_best(ndpi_str->custom_categories.ipAddresses, &prefix);
		}

		if (node)
		{
			ret->category = (ndpi_protocol_category_t)node->value.user_value;
			return (1);
		}
	}

	ret->category = ndpi_get_proto_category(ndpi_str, *ret);

	return (0);
}

/* ********************************************************************************* */

void ndpi_fill_protocol_category(struct ndpi_detection_module_struct *ndpi_str,
								 struct ndpi_flow_struct *flow,
								 ndpi_protocol *ret)
{
	if (ndpi_str->custom_categories.categories_loaded)
	{
		if (flow->guessed_header_category != NDPI_PROTOCOL_CATEGORY_UNSPECIFIED)
		{
			flow->category = ret->category = flow->guessed_header_category;
			return;
		}

		if (flow->host_server_name[0] != '\0')
		{
			unsigned long id;
			int rc = ndpi_match_custom_category(ndpi_str, (char *)flow->host_server_name,
												strlen((char *)flow->host_server_name), &id);

			if (rc == 0)
			{
				flow->category = ret->category = (ndpi_protocol_category_t)id;
				return;
			}
		}

		if ((flow->l4.tcp.tls_seen_client_cert == 1) && (flow->protos.stun_ssl.ssl.client_certificate[0] != '\0'))
		{
			unsigned long id;
			int rc = ndpi_match_custom_category(ndpi_str,
												(char *)flow->protos.stun_ssl.ssl.client_certificate,
												strlen(flow->protos.stun_ssl.ssl.client_certificate),
												&id);

			if (rc == 0)
			{
				flow->category = ret->category = (ndpi_protocol_category_t)id;
				return;
			}
		}
	}

	flow->category = ret->category = ndpi_get_proto_category(ndpi_str, *ret);
}
/* ******************************************* */

u_int16_t ndpi_network_ptree_match(struct ndpi_detection_module_struct *ndpi_str,
								   struct in_addr *pin /* network byte order */)
{
	prefix_t prefix;
	patricia_node_t *node;

	/* Make sure all in network byte order otherwise compares wont work */
	fill_prefix_v4(&prefix, pin, 32, ((patricia_tree_t *)ndpi_str->protocols_ptree)->maxbits);
	node = ndpi_patricia_search_best(ndpi_str->protocols_ptree, &prefix);

	return (node ? node->value.user_value : NDPI_PROTOCOL_UNKNOWN);
}
/* ******************************************************************** */

ndpi_protocol ndpi_detection_process_packet(struct ndpi_detection_module_struct *ndpi_str,
											struct ndpi_flow_struct *flow,
											const unsigned char *packet,
											const unsigned short packetlen,
											const u_int64_t current_tick_l,
											struct ndpi_id_struct *src,
											struct ndpi_id_struct *dst)
{
	NDPI_SELECTION_BITMASK_PROTOCOL_SIZE ndpi_selection_packet;
	u_int32_t a;
	ndpi_protocol ret = {NDPI_PROTOCOL_UNKNOWN, NDPI_PROTOCOL_UNKNOWN, NDPI_PROTOCOL_CATEGORY_UNSPECIFIED};

	if (ndpi_str->ndpi_log_level >= NDPI_LOG_TRACE)
		NDPI_LOG(flow ? flow->detected_protocol_stack[0] : NDPI_PROTOCOL_UNKNOWN,
				 ndpi_str, NDPI_LOG_TRACE, "START packet processing\n");

	if (flow == NULL)
		return (ret);
	else
		ret.category = flow->category;

	flow->num_processed_pkts++;

	/* Init default */
	ret.master_protocol = flow->detected_protocol_stack[1], ret.app_protocol = flow->detected_protocol_stack[0];

	if (flow->server_id == NULL)
		flow->server_id = dst; /* Default */

	if (flow->detected_protocol_stack[0] != NDPI_PROTOCOL_UNKNOWN)
	{
		if (flow->check_extra_packets)
		{
			ndpi_process_extra_packet(ndpi_str, flow, packet, packetlen, current_tick_l, src, dst);
			/* Update in case of new match */
			ret.master_protocol = flow->detected_protocol_stack[1], ret.app_protocol = flow->detected_protocol_stack[0];
			return (ret);
		}
		else
		{
			goto ret_protocols;
		}
	}

	/* need at least 20 bytes for ip header */
	if (packetlen < 20)
	{
		/* reset protocol which is normally done in init_packet_header */
		ndpi_int_reset_packet_protocol(&flow->packet);
		goto invalidate_ptr;
	}

	flow->packet.tick_timestamp_l = current_tick_l;
	flow->packet.tick_timestamp = (u_int32_t)(current_tick_l / ndpi_str->ticks_per_second);

	/* parse packet */
	flow->packet.iph = (struct ndpi_iphdr *)packet;
	/* we are interested in ipv4 packet */

	if (ndpi_init_packet_header(ndpi_str, flow, packetlen) != 0)
		goto invalidate_ptr;

	/* detect traffic for tcp or udp only */
	flow->src = src, flow->dst = dst;

	ndpi_connection_tracking(ndpi_str, flow);

	/* build ndpi_selection packet bitmask */
	ndpi_selection_packet = NDPI_SELECTION_BITMASK_PROTOCOL_COMPLETE_TRAFFIC;
	if (flow->packet.iph != NULL)
		ndpi_selection_packet |= NDPI_SELECTION_BITMASK_PROTOCOL_IP | NDPI_SELECTION_BITMASK_PROTOCOL_IPV4_OR_IPV6;

	if (flow->packet.tcp != NULL)
		ndpi_selection_packet |=
			(NDPI_SELECTION_BITMASK_PROTOCOL_INT_TCP | NDPI_SELECTION_BITMASK_PROTOCOL_INT_TCP_OR_UDP);

	if (flow->packet.udp != NULL)
		ndpi_selection_packet |=
			(NDPI_SELECTION_BITMASK_PROTOCOL_INT_UDP | NDPI_SELECTION_BITMASK_PROTOCOL_INT_TCP_OR_UDP);

	if (flow->packet.payload_packet_len != 0)
		ndpi_selection_packet |= NDPI_SELECTION_BITMASK_PROTOCOL_HAS_PAYLOAD;

	if (flow->packet.tcp_retransmission == 0)
		ndpi_selection_packet |= NDPI_SELECTION_BITMASK_PROTOCOL_NO_TCP_RETRANSMISSION;

#ifdef NDPI_DETECTION_SUPPORT_IPV6
	if (flow->packet.iphv6 != NULL)
		ndpi_selection_packet |= NDPI_SELECTION_BITMASK_PROTOCOL_IPV6 | NDPI_SELECTION_BITMASK_PROTOCOL_IPV4_OR_IPV6;
#endif /* NDPI_DETECTION_SUPPORT_IPV6 */

	if ((!flow->protocol_id_already_guessed) && (
#ifdef NDPI_DETECTION_SUPPORT_IPV6
													flow->packet.iphv6 ||
#endif
													flow->packet.iph))
	{
		u_int16_t sport, dport;
		u_int8_t protocol;
		u_int8_t user_defined_proto;

		flow->protocol_id_already_guessed = 1;

#ifdef NDPI_DETECTION_SUPPORT_IPV6
		if (flow->packet.iphv6 != NULL)
		{
			protocol = flow->packet.iphv6->ip6_hdr.ip6_un1_nxt;
		}
		else
#endif
		{
			protocol = flow->packet.iph->protocol;
		}

		if (flow->packet.udp)
			sport = ntohs(flow->packet.udp->source), dport = ntohs(flow->packet.udp->dest);
		else if (flow->packet.tcp)
			sport = ntohs(flow->packet.tcp->source), dport = ntohs(flow->packet.tcp->dest);
		else
			sport = dport = 0;

		/* guess protocol */
		flow->guessed_protocol_id = (int16_t)ndpi_guess_protocol_id(ndpi_str, flow, protocol, sport, dport, &user_defined_proto);
		flow->guessed_host_protocol_id = ndpi_guess_host_protocol_id(ndpi_str, flow);

		if (ndpi_str->custom_categories.categories_loaded && flow->packet.iph)
		{
			ndpi_fill_ip_protocol_category(ndpi_str, flow->packet.iph->saddr, flow->packet.iph->daddr, &ret);
			flow->guessed_header_category = ret.category;
		}
		else
		{
			flow->guessed_header_category = NDPI_PROTOCOL_CATEGORY_UNSPECIFIED;
		}

		if (flow->guessed_protocol_id > NDPI_MAX_SUPPORTED_PROTOCOLS)
		{
			/* This is a custom protocol and it has priority over everything else */
			ret.master_protocol = NDPI_PROTOCOL_UNKNOWN,
			ret.app_protocol = flow->guessed_protocol_id ? flow->guessed_protocol_id : flow->guessed_host_protocol_id;
			ndpi_fill_protocol_category(ndpi_str, flow, &ret);
			goto invalidate_ptr;
		}

		if (user_defined_proto && flow->guessed_protocol_id != NDPI_PROTOCOL_UNKNOWN)
		{
			if (flow->packet.iph)
			{
				if (flow->guessed_host_protocol_id != NDPI_PROTOCOL_UNKNOWN)
				{
					u_int8_t protocol_was_guessed;

					/* ret.master_protocol = flow->guessed_protocol_id , ret.app_protocol = flow->guessed_host_protocol_id; /\* ****** *\/ */
					ret = ndpi_detection_giveup(ndpi_str, flow, 0, &protocol_was_guessed);
				}

				ndpi_fill_protocol_category(ndpi_str, flow, &ret);
				goto invalidate_ptr;
			}
		}
		else
		{
			/* guess host protocol */
			if (flow->packet.iph)
			{
				struct in_addr addr;

				addr.s_addr = flow->packet.iph->saddr;
				flow->guessed_host_protocol_id = ndpi_network_ptree_match(ndpi_str, &addr);

				if (flow->guessed_host_protocol_id == NDPI_PROTOCOL_UNKNOWN)
				{
					addr.s_addr = flow->packet.iph->daddr;
					flow->guessed_host_protocol_id = ndpi_network_ptree_match(ndpi_str, &addr);
				}
			}
		}
	}
}
/* ********************************************************************************* */
/* ********************************************************************************* */

ndpi_protocol ndpi_detection_giveup(struct ndpi_detection_module_struct *ndpi_str,
									struct ndpi_flow_struct *flow,
									u_int8_t enable_guess,
									u_int8_t *protocol_was_guessed)
{
	ndpi_protocol ret = {NDPI_PROTOCOL_UNKNOWN, NDPI_PROTOCOL_UNKNOWN, NDPI_PROTOCOL_CATEGORY_UNSPECIFIED};
	*protocol_was_guessed = 0;
	if (flow == NULL)
		return (ret);

	/* Init defaults */
	ret.master_protocol = flow->detected_protocol_stack[1], ret.app_protocol = flow->detected_protocol_stack[0];
	ret.category = flow->category;

	/* Ensure that we don't change our mind if detection is already complete */
	if ((ret.master_protocol != NDPI_PROTOCOL_UNKNOWN) && (ret.app_protocol != NDPI_PROTOCOL_UNKNOWN))
		return (ret);

	/* TODO: add the remaining stage_XXXX protocols */
	if (flow->detected_protocol_stack[0] == NDPI_PROTOCOL_UNKNOWN)
	{
		u_int16_t guessed_protocol_id, guessed_host_protocol_id;
		if (flow->guessed_protocol_id == NDPI_PROTOCOL_STUN)
			goto check_stun_export;
		else if ((flow->guessed_protocol_id == NDPI_PROTOCOL_HANGOUT_DUO) || (flow->guessed_protocol_id == NDPI_PROTOCOL_MESSENGER) || (flow->guessed_protocol_id == NDPI_PROTOCOL_WHATSAPP_CALL))
			ndpi_set_detected_protocol(ndpi_str, flow, flow->guessed_protocol_id, NDPI_PROTOCOL_UNKNOWN);
		else if ((flow->l4.tcp.tls_seen_client_cert == 1) && (flow->protos.stun_ssl.ssl.client_certificate[0] != '\0'))
		{
			ndpi_set_detected_protocol(ndpi_str, flow, NDPI_PROTOCOL_TLS, NDPI_PROTOCOL_UNKNOWN);
		}
		else
		{
			if ((flow->guessed_protocol_id == NDPI_PROTOCOL_UNKNOWN) && (flow->packet.l4_protocol == IPPROTO_TCP) && (flow->l4.tcp.tls_stage > 1))
				flow->guessed_protocol_id = NDPI_PROTOCOL_TLS;

			guessed_protocol_id = flow->guessed_protocol_id, guessed_host_protocol_id = flow->guessed_host_protocol_id;

			if ((guessed_host_protocol_id != NDPI_PROTOCOL_UNKNOWN) && ((flow->packet.l4_protocol == IPPROTO_UDP) && NDPI_ISSET(&flow->excluded_protocol_bitmask, guessed_host_protocol_id) && is_udp_guessable_protocol(guessed_host_protocol_id)))
				flow->guessed_host_protocol_id = guessed_host_protocol_id = NDPI_PROTOCOL_UNKNOWN;

			/* Ignore guessed protocol if they have been discarded */
			if ((guessed_protocol_id != NDPI_PROTOCOL_UNKNOWN)
				// && (guessed_host_protocol_id == NDPI_PROTOCOL_UNKNOWN)
				&& (flow->packet.l4_protocol == IPPROTO_UDP) && NDPI_ISSET(&flow->excluded_protocol_bitmask, guessed_protocol_id) && is_udp_guessable_protocol(guessed_protocol_id))
				flow->guessed_protocol_id = guessed_protocol_id = NDPI_PROTOCOL_UNKNOWN;

			if ((guessed_protocol_id != NDPI_PROTOCOL_UNKNOWN) || (guessed_host_protocol_id != NDPI_PROTOCOL_UNKNOWN))
			{
				if ((guessed_protocol_id == 0) && (flow->protos.stun_ssl.stun.num_binding_requests > 0) && (flow->protos.stun_ssl.stun.num_processed_pkts > 0))
					guessed_protocol_id = NDPI_PROTOCOL_STUN;

				if (flow->host_server_name[0] != '\0')
				{
					ndpi_protocol_match_result ret_match;
					ndpi_match_host_subprotocol(ndpi_str, flow,
												(char *)flow->host_server_name,
												strlen((const char *)flow->host_server_name),
												&ret_match,
												NDPI_PROTOCOL_DNS);
					if (ret_match.protocol_id != NDPI_PROTOCOL_UNKNOWN)
						guessed_host_protocol_id = ret_match.protocol_id;
				}

				ndpi_int_change_protocol(ndpi_str, flow,
										 guessed_host_protocol_id,
										 guessed_protocol_id);
			}
		}
	}
	else
	{
		flow->detected_protocol_stack[1] = flow->guessed_protocol_id,
		flow->detected_protocol_stack[0] = flow->guessed_host_protocol_id;

		if (flow->detected_protocol_stack[1] == flow->detected_protocol_stack[0])
			flow->detected_protocol_stack[1] = flow->guessed_host_protocol_id;
	}

	if ((flow->detected_protocol_stack[0] == NDPI_PROTOCOL_UNKNOWN) && (flow->guessed_protocol_id == NDPI_PROTOCOL_STUN))
	{
	check_stun_export:
		if (flow->protos.stun_ssl.stun.num_processed_pkts || flow->protos.stun_ssl.stun.num_udp_pkts)
		{
			// if(/* (flow->protos.stun_ssl.stun.num_processed_pkts >= NDPI_MIN_NUM_STUN_DETECTION) */
			ndpi_set_detected_protocol(ndpi_str, flow,
									   flow->guessed_host_protocol_id,
									   NDPI_PROTOCOL_STUN);
		}
	}

	ret.master_protocol = flow->detected_protocol_stack[1], ret.app_protocol = flow->detected_protocol_stack[0];

	if (ret.master_protocol == NDPI_PROTOCOL_STUN)
	{
		if (ret.app_protocol == NDPI_PROTOCOL_FACEBOOK)
			ret.app_protocol = NDPI_PROTOCOL_MESSENGER;
		else if (ret.app_protocol == NDPI_PROTOCOL_GOOGLE)
		{
			/*
			As Google has recently introduced Duo,
			we need to distinguish between it and hangout
			thing that should be handled by the STUN dissector
  	  	  */
			ret.app_protocol = NDPI_PROTOCOL_HANGOUT_DUO;
		}
	}

	if (ret.app_protocol != NDPI_PROTOCOL_UNKNOWN)
		ndpi_fill_protocol_category(ndpi_str, flow, &ret);

	return (ret);
}

/* ********************************************************************************* */

int main(void)
{
	puts("!!!Hello World!!!"); /* prints !!!Hello World!!! */
	return EXIT_SUCCESS;
}
