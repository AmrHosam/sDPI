#ifdef HAVE_CONFIG_H
#include "ndpi_config.h"
#endif
#include <stdlib.h>
#include <errno.h>
#include <sys/types.h>
#define NDPI_CURRENT_PROTO NDPI_PROTOCOL_UNKNOWN
#include "../include/ndpi_api.h"
#include <time.h>
#include "ndpi_content_match.c.inc"
#include "third_party/include/ndpi_patricia.h"
#ifndef WIN32
#include <unistd.h>
#endif
#define NDPI_MAX_SUPPORTED_PROTOCOLS NDPI_LAST_IMPLEMENTED_PROTOCOL
#define CUSTOM_CATEGORY_LABEL_LEN 32
#define NUM_CUSTOM_CATEGORIES 5
#define NDPI_PROTOCOL_BITMASK ndpi_protocol_bitmask_struct_t
#define NDPI_MAX_NUM_CUSTOM_PROTOCOLS (NDPI_NUM_BITS - NDPI_LAST_IMPLEMENTED_PROTOCOL)
static void  (*_ndpi_flow_free)(void *ptr);
static void  (*_ndpi_free)(void *ptr);
static int _ndpi_debug_callbacks = 0;
* ****************************************** */

/* Keep it in order and in sync with ndpi_protocol_category_t in ndpi_typedefs.h */
static const char* categories[] = {
  "Unspecified",
  "Media",
  "VPN",
  "Email",
  "DataTransfer",
  "Web",
  "SocialNetwork",
  "Download-FileTransfer-FileSharing",
  "Game",
  "Chat",
  "VoIP",
  "Database",
  "RemoteAccess",
  "Cloud",
  "Network",
  "Collaborative",
  "RPC",
  "Streaming",
  "System",
  "SoftwareUpdate",
  "",
  "",
  "",
  "",
  "",
  "Music",
  "Video",
  "Shopping",
  "Productivity",
  "FileSharing",
  "",
  "",
  "",
  "",
  "",
  "",
  "",
  "",
  "",
  "",
  "",
  "",
  "",
  "",
  "",
  "",
  "",
  "",
  "",
  "",
  "",
  "",
  "",
  "",
  "",
  "",
  "",
  "",
  "",
  "",
  "",
  "",
  "",
  "",
  "",
  "",
  "",
  "",
  "",
  "",
  "",
  "",
  "",
  "",
  "",
  "",
  "",
  "",
  "",
  "",
  "",
  "",
  "",
  "",
  "",
  "",
  "",
  "",
  "",
  "",
  "",
  "",
  "",
  "",
  "",
  "",
  "",
  "",
  "",
  "Mining", /* 99 */
  "Malware",
  "Advertisement",
  "Banned_Site",
  "Site_Unavailable",
  "Allowed_Site",
  "Antimalware",
};
/* ****************************************** */

static void *(*_ndpi_flow_malloc)(size_t size);
static void  (*_ndpi_flow_free)(void *ptr);

static void *(*_ndpi_malloc)(size_t size);
static void  (*_ndpi_free)(void *ptr);

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
		void *ipAddresses, *ipAddresses_shadow; /* Patricia */
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

	void *hyperscan; /* Intel Hyperscan */
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
/* ******************************************************************** */
int ndpi_match_bigram(struct ndpi_detection_module_struct *ndpi_str,
		      ndpi_automa *automa, char *bigram_to_match) {
  AC_TEXT_t ac_input_text;
  AC_REP_t match = { NDPI_PROTOCOL_UNKNOWN, NDPI_PROTOCOL_CATEGORY_UNSPECIFIED, NDPI_PROTOCOL_UNRATED };
  int rc;

  if((automa->ac_automa == NULL) || (bigram_to_match == NULL))
    return(-1);

  if(!automa->ac_automa_finalized) {
    printf("[%s:%d] [NDPI] Internal error: please call ndpi_finalize_initalization()\n", __FILE__, __LINE__);
    return(0); /* No matches */
  }

  ac_input_text.astring = bigram_to_match, ac_input_text.length = 2;
  rc = ac_automata_search(((AC_AUTOMATA_t*)automa->ac_automa), &ac_input_text, &match);

  /*
    As ac_automata_search can detect partial matches and continue the search process
    in case rc == 0 (i.e. no match), we need to check if there is a partial match
    and in this case return it
  */
  if((rc == 0) && (match.number != 0)) rc = 1;

  return(rc ? match.number : 0);
}

/* ****************************************************** */
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
/***********  recursive ndoi malloc   **************/

void* ndpi_malloc(size_t size) { return(_ndpi_malloc ? _ndpi_malloc(size) : malloc(size)); }
void set_ndpi_malloc(void* (*__ndpi_malloc)(size_t size)) { _ndpi_malloc = __ndpi_malloc; }
/* ****************************************** */

char * ndpi_strdup(const char *s)
{
  int len = strlen(s);
  char *m = ndpi_malloc(len+1);

  if(m) {
    memcpy(m, s, len);
    m[len] = '\0';
  }

  return(m);
}
/* ****************************************************** */
/* ****************************************************** */

int ndpi_match_string(void *_automa, char *string_to_match) {
  AC_REP_t match = { NDPI_PROTOCOL_UNKNOWN, NDPI_PROTOCOL_CATEGORY_UNSPECIFIED, NDPI_PROTOCOL_UNRATED };
  AC_TEXT_t ac_input_text;
  AC_AUTOMATA_t *automa = (AC_AUTOMATA_t*)_automa;
  int rc;

  if((automa == NULL)
     || (string_to_match == NULL)
     || (string_to_match[0] == '\0'))
    return(-2);

  ac_input_text.astring = string_to_match, ac_input_text.length = strlen(string_to_match);
  rc = ac_automata_search(automa, &ac_input_text, &match);

  /*
    As ac_automata_search can detect partial matches and continue the search process
    in case rc == 0 (i.e. no match), we need to check if there is a partial match
    and in this case return it
  */
  if((rc == 0) && (match.number != 0)) rc = 1;

  return(rc ? match.number : 0);
}

/* ****************************************************** */
static int ndpi_string_to_automa(struct ndpi_detection_module_struct *ndpi_str,
				 ndpi_automa *automa,
				 char *value, u_int16_t protocol_id,
				 ndpi_protocol_category_t category,
				 ndpi_protocol_breed_t breed) {
  AC_PATTERN_t ac_pattern;

  if(protocol_id >= (NDPI_MAX_SUPPORTED_PROTOCOLS+NDPI_MAX_NUM_CUSTOM_PROTOCOLS)) {
    NDPI_LOG_ERR(ndpi_str, "[NDPI] protoId=%d: INTERNAL ERROR\n", protocol_id);
    return(-1);
  }

  if(automa->ac_automa == NULL) return(-2);
  ac_pattern.astring = value,
    ac_pattern.rep.number = protocol_id,
    ac_pattern.rep.category = (u_int16_t)category,
    ac_pattern.rep.breed = (u_int16_t)breed;

#ifdef MATCH_DEBUG
  printf("Adding to automa [%s][protocol_id: %u][category: %u][breed: %u]\n",
	 value, protocol_id, category, breed);
#endif

  if(value == NULL)
    ac_pattern.length = 0;
  else
    ac_pattern.length = strlen(ac_pattern.astring);

  if(ac_automata_add(((AC_AUTOMATA_t*)automa->ac_automa), &ac_pattern) != ACERR_SUCCESS)
    return(-2);

  return(0);
}
/* ******************************************************************** */

static int ndpi_default_ports_tree_node_t_cmp(const void *a, const void *b)
{
  ndpi_default_ports_tree_node_t *fa = (ndpi_default_ports_tree_node_t*)a;
  ndpi_default_ports_tree_node_t *fb = (ndpi_default_ports_tree_node_t*)b;

  //printf("[NDPI] %s(%d, %d)\n", __FUNCTION__, fa->default_port, fb->default_port);

  return((fa->default_port == fb->default_port) ? 0 : ((fa->default_port < fb->default_port) ? -1 : 1));
}

/* ******************************************************************** */

/* This function is used to map protocol name and default ports and it MUST
   be updated whenever a new protocol is added to NDPI.

   Do NOT add web services (NDPI_SERVICE_xxx) here.
*/
static void ndpi_init_protocol_defaults(struct ndpi_detection_module_struct *ndpi_str) {
  ndpi_port_range ports_a[MAX_DEFAULT_PORTS], ports_b[MAX_DEFAULT_PORTS];
  u_int16_t no_master[2] = { NDPI_PROTOCOL_NO_MASTER_PROTO, NDPI_PROTOCOL_NO_MASTER_PROTO },
    custom_master[2];

    /* Reset all settings */
    memset(ndpi_str->proto_defaults, 0, sizeof(ndpi_str->proto_defaults));

    ndpi_set_proto_defaults(ndpi_str, NDPI_PROTOCOL_UNRATED, NDPI_PROTOCOL_UNKNOWN,
			    0 /* can_have_a_subprotocol */, no_master,
			    no_master, "Unknown", NDPI_PROTOCOL_CATEGORY_UNSPECIFIED,
			    ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			    ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);

    ndpi_set_proto_defaults(ndpi_str, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_HTTP,
			    1 /* can_have_a_subprotocol */, no_master,
			    no_master, "HTTP", NDPI_PROTOCOL_CATEGORY_WEB,
			    ndpi_build_default_ports(ports_a, 80, 0 /* ntop */, 0, 0, 0) /* TCP */,
			    ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);

    ndpi_set_proto_defaults(ndpi_str, NDPI_PROTOCOL_SAFE, NDPI_PROTOCOL_FBZERO,
			    0 /* can_have_a_subprotocol */, no_master,
			    no_master, "FacebookZero", NDPI_PROTOCOL_CATEGORY_SOCIAL_NETWORK,
			    ndpi_build_default_ports(ports_a, 443, 0, 0, 0, 0) /* TCP */,
			    ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);

    ndpi_set_proto_defaults(ndpi_str, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_WHATSAPP_CALL,
			    0 /* can_have_a_subprotocol */, no_master,
			    no_master, "WhatsAppCall", NDPI_PROTOCOL_CATEGORY_VOIP,
			    ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			    ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);

   ndpi_set_proto_defaults(ndpi_str, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_WHATSAPP,
			    0 /* can_have_a_subprotocol */, no_master,
			    no_master, "WhatsApp", NDPI_PROTOCOL_CATEGORY_CHAT,
			    ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			    ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);

   ndpi_set_proto_defaults(ndpi_str, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_WHATSAPP_FILES,
			    0 /* can_have_a_subprotocol */, no_master,
			    no_master, "WhatsAppFiles", NDPI_PROTOCOL_CATEGORY_DOWNLOAD_FT,
			    ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			    ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);

  ndpi_set_proto_defaults(ndpi_str, NDPI_PROTOCOL_SAFE, NDPI_PROTOCOL_TLS,
			    1 /* can_have_a_subprotocol */, no_master,
			    no_master, "TLS", NDPI_PROTOCOL_CATEGORY_WEB,
			    ndpi_build_default_ports(ports_a, 443, 0, 0, 0, 0) /* TCP */,
			    ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);

  ndpi_set_proto_defaults(ndpi_str, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_MESSENGER,
			    0 /* can_have_a_subprotocol */, no_master,
			    no_master, "Messenger", NDPI_PROTOCOL_CATEGORY_VOIP,
			    ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			    ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);

 ndpi_set_proto_defaults(ndpi_str, NDPI_PROTOCOL_SAFE, NDPI_PROTOCOL_GIT,
			    0 /* can_have_a_subprotocol */, no_master,
			    no_master, "Git", NDPI_PROTOCOL_CATEGORY_COLLABORATIVE,
			    ndpi_build_default_ports(ports_a, 9418, 0, 0, 0, 0),    /* TCP */
			    ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0));      /* UDP */

 /* ****************************************************** */

/* *********************************************************************************** */

ndpi_port_range * ndpi_build_default_ports(ndpi_port_range *ports,
					   u_int16_t portA,
					   u_int16_t portB,
					   u_int16_t portC,
					   u_int16_t portD,
					   u_int16_t portE) {
  int i = 0;

  ports[i].port_low = portA, ports[i].port_high = portA; i++;
  ports[i].port_low = portB, ports[i].port_high = portB; i++;
  ports[i].port_low = portC, ports[i].port_high = portC; i++;
  ports[i].port_low = portD, ports[i].port_high = portD; i++;
  ports[i].port_low = portE, ports[i].port_high = portE;

  return(ports);
}
    memset(ndpi_str, 0, sizeof(struct ndpi_detection_module_struct));

  #ifdef NDPI_ENABLE_DEBUG_MESSAGES
    set_ndpi_debug_function(ndpi_str, (ndpi_debug_function_ptr)ndpi_debug_printf);
  #endif /* NDPI_ENABLE_DEBUG_MESSAGES */

    if((ndpi_str->protocols_ptree = ndpi_New_Patricia(32 /* IPv4 */)) != NULL)
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

    ndpi_str->host_automa.ac_automa               = ac_automata_init(ac_match_handler);
    ndpi_str->content_automa.ac_automa            = ac_automata_init(ac_match_handler);
    ndpi_str->bigrams_automa.ac_automa            = ac_automata_init(ac_match_handler);
    ndpi_str->impossible_bigrams_automa.ac_automa = ac_automata_init(ac_match_handler);

    if((sizeof(categories)/sizeof(char*)) != NDPI_PROTOCOL_NUM_CATEGORIES) {
      NDPI_LOG_ERR(ndpi_str, "[NDPI] invalid categories length: expected %u, got %u\n",
  		 NDPI_PROTOCOL_NUM_CATEGORIES, (unsigned int)(sizeof(categories)/sizeof(char*)));
      return(NULL);
    }

  #ifdef HAVE_HYPERSCAN
    ndpi_str->custom_categories.num_to_load = 0, ndpi_str->custom_categories.to_load = NULL;
    ndpi_str->custom_categories.hostnames = NULL;
  #else
    ndpi_str->custom_categories.hostnames.ac_automa        = ac_automata_init(ac_match_handler);
    ndpi_str->custom_categories.hostnames_shadow.ac_automa = ac_automata_init(ac_match_handler);
  #endif

    ndpi_str->custom_categories.ipAddresses                = ndpi_New_Patricia(32 /* IPv4 */);
    ndpi_str->custom_categories.ipAddresses_shadow         = ndpi_New_Patricia(32 /* IPv4 */);

    if((ndpi_str->custom_categories.ipAddresses == NULL)
       || (ndpi_str->custom_categories.ipAddresses_shadow == NULL))
      return(NULL);

    ndpi_init_protocol_defaults(ndpi_str);

    for(i=0; i<NUM_CUSTOM_CATEGORIES; i++)
      snprintf(ndpi_str->custom_category_labels[i],
  	     CUSTOM_CATEGORY_LABEL_LEN, "User custom category %u", (unsigned int)(i+1));

    return(ndpi_str);
  }
/* ****************************************************** */

static int ac_match_handler(AC_MATCH_t *m, AC_TEXT_t *txt, AC_REP_t *match) {
 int min_len = (txt->length < m->patterns->length) ? txt->length : m->patterns->length;
 char buf[64] = { '\0' };
 int min_buf_len = (txt->length > 63 /* sizeof(buf)-1 */) ? 63 : txt->length;
 u_int buf_len = strlen(buf);

 strncpy(buf, txt->astring, min_buf_len);
 buf[min_buf_len] = '\0';

#ifdef MATCH_DEBUG
 printf("Searching [to search: %s/%u][pattern: %s/%u] [len: %d][match_num: %u][%s]\n",
	 buf, (unigned int)txt->length, m->patterns->astring, m->patterns->length, min_len,
	 m->match_num, m->patterns->astring);
#endif

 {
   char *whatfound = strstr(buf, m->patterns->astring);

#ifdef MATCH_DEBUG
   printf("[NDPI] %s() [searching=%s][pattern=%s][%s][%c]\n",
	   __FUNCTION__, buf,  m->patterns->astring,
	   whatfound ? whatfound : "<NULL>",
	   whatfound[-1]);
#endif

   /*
     The patch below allows in case of pattern ws.amazon.com
     to avoid matching aws.amazon.com whereas a.ws.amazon.com
     has to match
   */
   if(whatfound
      && (whatfound != buf)
      && (m->patterns->astring[0] != '.')  /* The searched pattern does not start with . */
      && strchr(m->patterns->astring, '.') /* The matched pattern has a . (e.g. numeric or sym IPs) */) {
     if(whatfound[-1] != '.') {
	return(0);
     } else {
	memcpy(match, &m->patterns[0].rep, sizeof(AC_REP_t)); /* Partial match? */
	return(0); /* Keep searching as probably there is a better match */
     }
   }
 }

 /*
   Return 1 for stopping to the first match.
   We might consider searching for the more
   specific match, paying more cpu cycles.
 */
 memcpy(match, &m->patterns[0].rep, sizeof(AC_REP_t));

 if(((buf_len >= min_len) && (strncmp(&buf[buf_len-min_len], m->patterns->astring, min_len) == 0))
    || (strncmp(buf, m->patterns->astring, min_len) == 0) /* begins with */
    ) {
#ifdef MATCH_DEBUG
   printf("Found match [%s][%s] [len: %d]"
	   // "[proto_id: %u]"
	   "\n",
	   buf, m->patterns->astring, min_len /* , *matching_protocol_id */);
#endif
   return(1); /* If the pattern found matches the string at the beginning we stop here */
 } else {
#ifdef MATCH_DEBUG
   printf("NO match found: continue\n");
#endif
   return(0); /* 0 to continue searching, !0 to stop */
 }
}

  /* ******************************************************************** */

  static void addDefaultPort(struct ndpi_detection_module_struct *ndpi_str,
  			   ndpi_port_range *range,
  			   ndpi_proto_defaults_t *def,
  			   u_int8_t customUserProto,
  			   ndpi_default_ports_tree_node_t **root,
  			   const char *_func, int _line) {
    u_int16_t port;

    for(port=range->port_low; port<=range->port_high; port++) {
      ndpi_default_ports_tree_node_t *node = (ndpi_default_ports_tree_node_t*)ndpi_malloc(sizeof(ndpi_default_ports_tree_node_t));
      ndpi_default_ports_tree_node_t *ret;

      if(!node) {
        NDPI_LOG_ERR(ndpi_str, "%s:%d not enough memory\n", _func, _line);
        break;
      }

      node->proto = def, node->default_port = port, node->customUserProto = customUserProto;
      ret = (ndpi_default_ports_tree_node_t*)ndpi_tsearch(node, (void*)root, ndpi_default_ports_tree_node_t_cmp); /* Add it to the tree */

      if(ret != node) {
        NDPI_LOG_DBG(ndpi_str, "[NDPI] %s:%d found duplicate for port %u: overwriting it with new value\n",
  		   _func, _line, port);

        ret->proto = def;
        ndpi_free(node);
      }
    }
    /* ****************************************************** */

    static int ndpi_add_host_url_subprotocol(struct ndpi_detection_module_struct *ndpi_str,
    					 char *_value, int protocol_id,
    					 ndpi_protocol_category_t category,
    					 ndpi_protocol_breed_t breed) {
      int rv;
      char *value = ndpi_strdup(_value);

      if(!value) return(-1);

    #ifdef DEBUG
      NDPI_LOG_DEBUG2(ndpi_str, "[NDPI] Adding [%s][%d]\n", value, protocol_id);
    #endif

      rv = ndpi_string_to_automa(ndpi_str,
    			       &ndpi_str->host_automa,
    			       value,
    			       protocol_id,
    			       category, breed);

      if(rv != 0) ndpi_free(value);

      return(rv);
    }
    /* ******************************************************************** */

    static void init_string_based_protocols(struct ndpi_detection_module_struct *ndpi_str) {
      int i;

    #ifdef HAVE_HYPERSCAN
      // TODO check return value
      init_hyperscan(ndpi_str);
    #endif

      for(i=0; host_match[i].string_to_match != NULL; i++)
        ndpi_init_protocol_match(ndpi_str, &host_match[i]);

      ndpi_enable_loaded_categories(ndpi_str);

    #ifdef MATCH_DEBUG
      // ac_automata_display(ndpi_str->host_automa.ac_automa, 'n');
    #endif

      for(i=0; ndpi_en_bigrams[i] != NULL; i++)
        ndpi_string_to_automa(ndpi_str, &ndpi_str->bigrams_automa,
    			  (char*)ndpi_en_bigrams[i],
    			  1, 1, 1);

      for(i=0; ndpi_en_impossible_bigrams[i] != NULL; i++)
        ndpi_string_to_automa(ndpi_str, &ndpi_str->impossible_bigrams_automa,
    			  (char*)ndpi_en_impossible_bigrams[i],
    			  1, 1, 1);
    }
/* ********************************************************************************** */

void ndpi_set_proto_defaults(struct ndpi_detection_module_struct *ndpi_str,
			     ndpi_protocol_breed_t breed, u_int16_t protoId,
			     u_int8_t can_have_a_subprotocol,
			     u_int16_t tcp_master_protoId[2], u_int16_t udp_master_protoId[2],
			     char *protoName, ndpi_protocol_category_t protoCategory,
			     ndpi_port_range *tcpDefPorts, ndpi_port_range *udpDefPorts) {
  char *name;
  int j;

  if(protoId >= NDPI_MAX_SUPPORTED_PROTOCOLS+NDPI_MAX_NUM_CUSTOM_PROTOCOLS) {
#ifdef DEBUG
    NDPI_LOG_ERR(ndpi_str, "[NDPI] %s/protoId=%d: INTERNAL ERROR\n", protoName, protoId);
#endif
    return;
  }

  if(ndpi_str->proto_defaults[protoId].protoName != NULL) {
#ifdef DEBUG
    NDPI_LOG_ERR(ndpi_str, "[NDPI] %s/protoId=%d: already initialized. Ignoring it\n", protoName, protoId);
#endif
    return;
  }

  name = ndpi_strdup(protoName);

  if(ndpi_str->proto_defaults[protoId].protoName)
    ndpi_free(ndpi_str->proto_defaults[protoId].protoName);

  ndpi_str->proto_defaults[protoId].protoName = name,
    ndpi_str->proto_defaults[protoId].protoCategory = protoCategory,
    ndpi_str->proto_defaults[protoId].protoId = protoId,
    ndpi_str->proto_defaults[protoId].protoBreed = breed;
  ndpi_str->proto_defaults[protoId].can_have_a_subprotocol = can_have_a_subprotocol;

  memcpy(&ndpi_str->proto_defaults[protoId].master_tcp_protoId, tcp_master_protoId, 2*sizeof(u_int16_t));
  memcpy(&ndpi_str->proto_defaults[protoId].master_udp_protoId, udp_master_protoId, 2*sizeof(u_int16_t));

  for(j=0; j<MAX_DEFAULT_PORTS; j++) {
    if(udpDefPorts[j].port_low != 0)
      addDefaultPort(ndpi_str, &udpDefPorts[j],
		     &ndpi_str->proto_defaults[protoId], 0, &ndpi_str->udpRoot, __FUNCTION__,__LINE__);

    if(tcpDefPorts[j].port_low != 0)
      addDefaultPort(ndpi_str, &tcpDefPorts[j],
		     &ndpi_str->proto_defaults[protoId], 0, &ndpi_str->tcpRoot, __FUNCTION__,__LINE__);
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
#ifdef NDPI_DETECTION_SUPPORT_IPV6
/* handle extension headers in IPv6 packets
 * arguments:
 * 	l4ptr: pointer to the byte following the initial IPv6 header
 * 	l4len: the length of the IPv6 packet excluding the IPv6 header
 * 	nxt_hdr: next header value from the IPv6 header
 * result:
 * 	l4ptr: pointer to the start of the actual packet payload
 * 	l4len: length of the actual payload
 * 	nxt_hdr: protocol of the actual payload
 * returns 0 upon success and 1 upon failure
 */
static int ndpi_handle_ipv6_extension_headers(struct ndpi_detection_module_struct *ndpi_str, const u_int8_t ** l4ptr, u_int16_t * l4len, u_int8_t * nxt_hdr)
{
  while((*nxt_hdr == 0 || *nxt_hdr == 43 || *nxt_hdr == 44 || *nxt_hdr == 60 || *nxt_hdr == 135 || *nxt_hdr == 59)) {
    u_int16_t ehdr_len;

    // no next header
    if(*nxt_hdr == 59) {
      return(1);
    }
    // fragment extension header has fixed size of 8 bytes and the first byte is the next header type
    if(*nxt_hdr == 44) {
      if(*l4len < 8) {
	return(1);
      }
      *nxt_hdr = (*l4ptr)[0];
      *l4len -= 8;
      (*l4ptr) += 8;
      continue;
    }
    // the other extension headers have one byte for the next header type
    // and one byte for the extension header length in 8 byte steps minus the first 8 bytes
    if (*l4len < 2) {
      return(1);
    }
    ehdr_len = (*l4ptr)[1];
    ehdr_len *= 8;
    ehdr_len += 8;

    if(*l4len < ehdr_len) {
      return(1);
    }
    *nxt_hdr = (*l4ptr)[0];
    *l4len -= ehdr_len;
    (*l4ptr) += ehdr_len;
  }
  return(0);
}
#endif /* NDPI_DETECTION_SUPPORT_IPV6 */

/****************************************************************************************************/
static u_int8_t ndpi_iph_is_valid_and_not_fragmented(const struct ndpi_iphdr *iph, const u_int16_t ipsize)
{
  //#ifdef REQUIRE_FULL_PACKETS
  if(ipsize < iph->ihl * 4 ||
     ipsize < ntohs(iph->tot_len) || ntohs(iph->tot_len) < iph->ihl * 4 || (iph->frag_off & htons(0x1FFF)) != 0) {
    return(0);
  }
  //#endif

  return(1);
}

/*********************************************************************************** */
static u_int8_t ndpi_detection_get_l4_internal(struct ndpi_detection_module_struct *ndpi_str,
											   const u_int8_t *l3, u_int16_t l3_len,
											   const u_int8_t **l4_return, u_int16_t *l4_len_return,
											   u_int8_t *l4_protocol_return, u_int32_t flags)
{
	const struct ndpi_iphdr *iph = NULL;
#ifdef NDPI_DETECTION_SUPPORT_IPV6
	const struct ndpi_ipv6hdr *iph_v6 = NULL;
#endif
	u_int16_t l4len = 0;
	const u_int8_t *l4ptr = NULL;
	u_int8_t l4protocol = 0;

	if (l3 == NULL || l3_len < sizeof(struct ndpi_iphdr))
		return (1);

	iph = (const struct ndpi_iphdr *)l3;

	if (iph->version == IPVERSION && iph->ihl >= 5)
	{
		NDPI_LOG_DBG2(ndpi_str, "ipv4 header\n");
	}
#ifdef NDPI_DETECTION_SUPPORT_IPV6
	else if (iph->version == 6 && l3_len >= sizeof(struct ndpi_ipv6hdr))
	{
		NDPI_LOG_DBG2(ndpi_str, "ipv6 header\n");
		iph_v6 = (const struct ndpi_ipv6hdr *)l3;
		iph = NULL;
	}
#endif
	else
	{
		return (1);
	}

	if ((flags & NDPI_DETECTION_ONLY_IPV6) && iph != NULL)
	{
		NDPI_LOG_DBG2(ndpi_str, "ipv4 header found but excluded by flag\n");
		return (1);
	}
#ifdef NDPI_DETECTION_SUPPORT_IPV6
	else if ((flags & NDPI_DETECTION_ONLY_IPV4) && iph_v6 != NULL)
	{
		NDPI_LOG_DBG2(ndpi_str, "ipv6 header found but excluded by flag\n");
		return (1);
	}
#endif

	if (iph != NULL && ndpi_iph_is_valid_and_not_fragmented(iph, l3_len))
	{
		u_int16_t len = ntohs(iph->tot_len);
		u_int16_t hlen = (iph->ihl * 4);

		l4ptr = (((const u_int8_t *)iph) + iph->ihl * 4);

		if (len == 0)
			len = l3_len;

		l4len = (len > hlen) ? (len - hlen) : 0;
		l4protocol = iph->protocol;
	}
#ifdef NDPI_DETECTION_SUPPORT_IPV6
	else if (iph_v6 != NULL && (l3_len - sizeof(struct ndpi_ipv6hdr)) >= ntohs(iph_v6->ip6_hdr.ip6_un1_plen))
	{
		l4ptr = (((const u_int8_t *)iph_v6) + sizeof(struct ndpi_ipv6hdr));
		l4len = ntohs(iph_v6->ip6_hdr.ip6_un1_plen);
		l4protocol = iph_v6->ip6_hdr.ip6_un1_nxt;

		// we need to handle IPv6 extension headers if present
		if (ndpi_handle_ipv6_extension_headers(ndpi_str, &l4ptr, &l4len, &l4protocol) != 0)
		{
			return (1);
		}
	}
#endif
	else
	{
		return (1);
	}

	if (l4_return != NULL)
	{
		*l4_return = l4ptr;
	}

	if (l4_len_return != NULL)
	{
		*l4_len_return = l4len;
	}

	if (l4_protocol_return != NULL)
	{
		*l4_protocol_return = l4protocol;
	}

	return (0);
}

/* ********************************************************************************* */
void ndpi_apply_flow_protocol_to_packet(struct ndpi_flow_struct *flow,
										struct ndpi_packet_struct *packet)
{
	memcpy(&packet->detected_protocol_stack, &flow->detected_protocol_stack, sizeof(packet->detected_protocol_stack));
	memcpy(&packet->protocol_stack_info, &flow->protocol_stack_info, sizeof(packet->protocol_stack_info));
}
/************************** */
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
/* ****************************************** */

void *ndpi_malloc(size_t size) { return (_ndpi_malloc ? _ndpi_malloc(size) : malloc(size)); }
void *ndpi_flow_malloc(size_t size) { return (_ndpi_flow_malloc ? _ndpi_flow_malloc(size) : ndpi_malloc(size)); }

/* ****************************************** */

void *ndpi_calloc(unsigned long count, size_t size)
{
	size_t len = count * size;
	void *p = ndpi_malloc(len);

	if (p)
		memset(p, 0, len);

	return (p);
}

/* ****************************************** */

void ndpi_free(void *ptr)
{
	if (_ndpi_free)
		_ndpi_free(ptr);
	else
		free(ptr);
}

/* ****************************************** */

void ndpi_flow_free(void *ptr)
{
	if (_ndpi_flow_free)
		_ndpi_flow_free(ptr);
	else
		ndpi_free_flow((struct ndpi_flow_struct *)ptr);
}

/* ****************************************** */

void *ndpi_realloc(void *ptr, size_t old_size,
				   size_t new_size)
{
	void *ret = ndpi_malloc(new_size);

	if (!ret)
		return (ret);
	else
	{
		memcpy(ret, ptr, old_size);
		ndpi_free(ptr);
		return (ret);
	}
}
/* ****************************************** */

char *ndpi_strdup(const char *s)
{
	int len = strlen(s);
	char *m = ndpi_malloc(len + 1);

	if (m)
	{
		memcpy(m, s, len);
		m[len] = '\0';
	}

	return (m);
}

/* *********************************************************************************** */

/* ****************************************************** */

/*
  These are UDP protocols that must fit a single packet
  and thus that if have NOT been detected they cannot be guessed
  as they have been excluded
*/
u_int8_t is_udp_guessable_protocol(u_int16_t l7_guessed_proto)
{
	switch (l7_guessed_proto)
	{
	case NDPI_PROTOCOL_QUIC:
	case NDPI_PROTOCOL_SNMP:
	case NDPI_PROTOCOL_NETFLOW:
		/* TODO: add more protocols (if any missing) */
		return (1);
	}

	return (0);
}

/* ****************************************************** */

/* ****************************************************** */
/* ****************************************************** */

static ndpi_default_ports_tree_node_t* ndpi_get_guessed_protocol_id(struct ndpi_detection_module_struct *ndpi_str,
								    u_int8_t proto, u_int16_t sport, u_int16_t dport) {
  ndpi_default_ports_tree_node_t node;

  if(sport && dport) {
    int low  = ndpi_min(sport, dport);
    int high = ndpi_max(sport, dport);
    const void *ret;

    node.default_port = low; /* Check server port first */
    ret = ndpi_tfind(&node,
		     (proto == IPPROTO_TCP) ? (void*)&ndpi_str->tcpRoot : (void*)&ndpi_str->udpRoot,
		     ndpi_default_ports_tree_node_t_cmp);

    if(ret == NULL) {
      node.default_port = high;
      ret = ndpi_tfind(&node,
		       (proto == IPPROTO_TCP) ? (void*)&ndpi_str->tcpRoot : (void*)&ndpi_str->udpRoot,
		       ndpi_default_ports_tree_node_t_cmp);
    }

    if(ret) return(*(ndpi_default_ports_tree_node_t**)ret);
  }

  return(NULL);
}

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
/* ****************************************************** */

ndpi_protocol_category_t ndpi_get_proto_category(struct ndpi_detection_module_struct *ndpi_str,
						 ndpi_protocol proto) {
  if(proto.category != NDPI_PROTOCOL_CATEGORY_UNSPECIFIED)
    return(proto.category);

  /* simple rule: sub protocol first, master after */
  else if((proto.master_protocol == NDPI_PROTOCOL_UNKNOWN) ||
	  (ndpi_str->proto_defaults[proto.app_protocol].protoCategory != NDPI_PROTOCOL_CATEGORY_UNSPECIFIED))
    return(ndpi_str->proto_defaults[proto.app_protocol].protoCategory);
  else
    return(ndpi_str->proto_defaults[proto.master_protocol].protoCategory);
}

/* ****************************************************** */

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
/* *********************************************** */
/* ****************************************************** */

int ndpi_match_string_id(void *_automa, char *string_to_match, u_int match_len, unsigned long *id) {
  AC_TEXT_t ac_input_text;
  AC_AUTOMATA_t *automa = (AC_AUTOMATA_t*)_automa;
  AC_REP_t match = { NDPI_PROTOCOL_UNKNOWN, NDPI_PROTOCOL_CATEGORY_UNSPECIFIED, NDPI_PROTOCOL_UNRATED };
  int rc;

  *id = -1;
  if((automa == NULL)
     || (string_to_match == NULL)
     || (string_to_match[0] == '\0'))
    return(-2);

  ac_input_text.astring = string_to_match, ac_input_text.length = match_len;
  rc = ac_automata_search(automa, &ac_input_text, &match);

  /*
    As ac_automata_search can detect partial matches and continue the search process
    in case rc == 0 (i.e. no match), we need to check if there is a partial match
    and in this case return it
  */
  if((rc == 0) && (match.number != 0)) rc = 1;

  *id = rc ? match.number : NDPI_PROTOCOL_UNKNOWN;

  return(*id != NDPI_PROTOCOL_UNKNOWN ? 0 : -1);
}

/* *********************************************** */

int ndpi_match_custom_category(struct ndpi_detection_module_struct *ndpi_str,
							   char *name, u_int name_len, unsigned long *id)
{
#ifdef HAVE_HYPERSCAN
	if (ndpi_str->custom_categories.hostnames == NULL)
		return (-1);
	else
	{
		hs_error_t rc;

		*id = (unsigned long)-1;

		rc = hs_scan(ndpi_str->custom_categories.hostnames->database,
					 name, name_len, 0,
					 ndpi_str->custom_categories.hostnames->scratch,
					 hyperscanCustomEventHandler, id);

		if (rc == HS_SCAN_TERMINATED)
		{
#ifdef DEBUG
			printf("[HS] Found category %lu for %s\n", *id, name);
#endif
			return (0);
		}
		else
			return (-1);
	}
#else
	return (ndpi_match_string_id(ndpi_str->custom_categories.hostnames.ac_automa, name, name_len, id));
#endif
}

/* *********************************************** */

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
/**********************************************************/
void check_ndpi_other_flow_func(struct ndpi_detection_module_struct *ndpi_str,
								struct ndpi_flow_struct *flow,
								NDPI_SELECTION_BITMASK_PROTOCOL_SIZE *ndpi_selection_packet)
{

	if (!flow)
	{
		return;
	}

	void *func = NULL;
	u_int32_t a;
	u_int16_t proto_index = ndpi_str->proto_defaults[flow->guessed_protocol_id].protoIdx;
	int16_t proto_id = ndpi_str->proto_defaults[flow->guessed_protocol_id].protoId;
	NDPI_PROTOCOL_BITMASK detection_bitmask;

	NDPI_SAVE_AS_BITMASK(detection_bitmask, flow->packet.detected_protocol_stack[0]);

	if ((proto_id != NDPI_PROTOCOL_UNKNOWN) && NDPI_BITMASK_COMPARE(flow->excluded_protocol_bitmask, ndpi_str->callback_buffer[proto_index].excluded_protocol_bitmask) == 0 && NDPI_BITMASK_COMPARE(ndpi_str->callback_buffer[proto_index].detection_bitmask, detection_bitmask) != 0 && (ndpi_str->callback_buffer[proto_index].ndpi_selection_bitmask & *ndpi_selection_packet) == ndpi_str->callback_buffer[proto_index].ndpi_selection_bitmask)
	{
		if ((flow->guessed_protocol_id != NDPI_PROTOCOL_UNKNOWN) && (ndpi_str->proto_defaults[flow->guessed_protocol_id].func != NULL))
			ndpi_str->proto_defaults[flow->guessed_protocol_id].func(ndpi_str, flow),
				func = ndpi_str->proto_defaults[flow->guessed_protocol_id].func;
	}

	for (a = 0; a < ndpi_str->callback_buffer_size_non_tcp_udp; a++)
	{
		if ((func != ndpi_str->callback_buffer_non_tcp_udp[a].func) && (ndpi_str->callback_buffer_non_tcp_udp[a].ndpi_selection_bitmask & *ndpi_selection_packet) == ndpi_str->callback_buffer_non_tcp_udp[a].ndpi_selection_bitmask &&
			NDPI_BITMASK_COMPARE(flow->excluded_protocol_bitmask,
								 ndpi_str->callback_buffer_non_tcp_udp[a].excluded_protocol_bitmask) == 0 &&
			NDPI_BITMASK_COMPARE(ndpi_str->callback_buffer_non_tcp_udp[a].detection_bitmask,
								 detection_bitmask) != 0)
		{

			if (ndpi_str->callback_buffer_non_tcp_udp[a].func != NULL)
				ndpi_str->callback_buffer_non_tcp_udp[a].func(ndpi_str, flow);

			if (flow->detected_protocol_stack[0] != NDPI_PROTOCOL_UNKNOWN)
				break; /* Stop after detecting the first protocol */
		}
	}
}
/********************************************************** */
void check_ndpi_udp_flow_func(struct ndpi_detection_module_struct *ndpi_str,
							  struct ndpi_flow_struct *flow,
							  NDPI_SELECTION_BITMASK_PROTOCOL_SIZE *ndpi_selection_packet)
{
	void *func = NULL;
	u_int32_t a;
	u_int16_t proto_index = ndpi_str->proto_defaults[flow->guessed_protocol_id].protoIdx;
	int16_t proto_id = ndpi_str->proto_defaults[flow->guessed_protocol_id].protoId;
	NDPI_PROTOCOL_BITMASK detection_bitmask;

	NDPI_SAVE_AS_BITMASK(detection_bitmask, flow->packet.detected_protocol_stack[0]);

	if ((proto_id != NDPI_PROTOCOL_UNKNOWN) && NDPI_BITMASK_COMPARE(flow->excluded_protocol_bitmask, ndpi_str->callback_buffer[proto_index].excluded_protocol_bitmask) == 0 && NDPI_BITMASK_COMPARE(ndpi_str->callback_buffer[proto_index].detection_bitmask, detection_bitmask) != 0 && (ndpi_str->callback_buffer[proto_index].ndpi_selection_bitmask & *ndpi_selection_packet) == ndpi_str->callback_buffer[proto_index].ndpi_selection_bitmask)
	{
		if ((flow->guessed_protocol_id != NDPI_PROTOCOL_UNKNOWN) && (ndpi_str->proto_defaults[flow->guessed_protocol_id].func != NULL))
			ndpi_str->proto_defaults[flow->guessed_protocol_id].func(ndpi_str, flow),
				func = ndpi_str->proto_defaults[flow->guessed_protocol_id].func;
	}

	for (a = 0; a < ndpi_str->callback_buffer_size_udp; a++)
	{
		if ((func != ndpi_str->callback_buffer_udp[a].func) && (ndpi_str->callback_buffer_udp[a].ndpi_selection_bitmask & *ndpi_selection_packet) == ndpi_str->callback_buffer_udp[a].ndpi_selection_bitmask && NDPI_BITMASK_COMPARE(flow->excluded_protocol_bitmask, ndpi_str->callback_buffer_udp[a].excluded_protocol_bitmask) == 0 && NDPI_BITMASK_COMPARE(ndpi_str->callback_buffer_udp[a].detection_bitmask, detection_bitmask) != 0)
		{
			ndpi_str->callback_buffer_udp[a].func(ndpi_str, flow);

			// NDPI_LOG_DBG(ndpi_str, "[UDP,CALL] dissector of protocol as callback_buffer idx =  %d\n",a);
			if (flow->detected_protocol_stack[0] != NDPI_PROTOCOL_UNKNOWN)
				break; /* Stop after detecting the first protocol */
		}
		else if (_ndpi_debug_callbacks)
			NDPI_LOG_DBG2(ndpi_str,
						  "[UDP,SKIP] dissector of protocol as callback_buffer idx =  %d\n", a);
	}
}

/* ******************************************************************** */
void check_ndpi_tcp_flow_func(struct ndpi_detection_module_struct *ndpi_str,
							  struct ndpi_flow_struct *flow,
							  NDPI_SELECTION_BITMASK_PROTOCOL_SIZE *ndpi_selection_packet)
{
	void *func = NULL;
	u_int32_t a;
	u_int16_t proto_index = ndpi_str->proto_defaults[flow->guessed_protocol_id].protoIdx;
	int16_t proto_id = ndpi_str->proto_defaults[flow->guessed_protocol_id].protoId;
	NDPI_PROTOCOL_BITMASK detection_bitmask;
	/* SET DETECTION BIT MASK FROM APP PROTOCOL */
	NDPI_SAVE_AS_BITMASK(detection_bitmask, flow->packet.detected_protocol_stack[0]);
	/* TCP PAYLOAD */
	if (flow->packet.payload_packet_len != 0)
	{ /* PROTO ID NOT NULL AND PROTOCOL IS NOT EXCLUDED BY FLOW AND SELECTION BIT MASK IS INCLUDED BY FLOW */
		if ((proto_id != NDPI_PROTOCOL_UNKNOWN) && NDPI_BITMASK_COMPARE(flow->excluded_protocol_bitmask, ndpi_str->callback_buffer[proto_index].excluded_protocol_bitmask) == 0 && NDPI_BITMASK_COMPARE(ndpi_str->callback_buffer[proto_index].detection_bitmask, detection_bitmask) != 0 && (ndpi_str->callback_buffer[proto_index].ndpi_selection_bitmask & *ndpi_selection_packet) == ndpi_str->callback_buffer[proto_index].ndpi_selection_bitmask)
		{
			/* GO TO PROTOCOL FUNC IF PROTOCOL IS UNKNOWN AND FUNC IS NOT NULL */
			if ((flow->guessed_protocol_id != NDPI_PROTOCOL_UNKNOWN) && (ndpi_str->proto_defaults[flow->guessed_protocol_id].func != NULL))
				ndpi_str->proto_defaults[flow->guessed_protocol_id].func(ndpi_str, flow),
					func = ndpi_str->proto_defaults[flow->guessed_protocol_id].func;
		}
		/* FUNC OF GUESSED PROTOCOL DIDN'T MATCH */
		if (flow->detected_protocol_stack[0] == NDPI_PROTOCOL_UNKNOWN)
		{
			for (a = 0; a < ndpi_str->callback_buffer_size_tcp_payload; a++)
			{ /* PROTO ID NOT NULL AND PROTOCOL IS NOT EXCLUDED BY FLOW AND SELECTION BIT MASK IS INCLUDED BY FLOW */
				if ((func != ndpi_str->callback_buffer_tcp_payload[a].func) && (ndpi_str->callback_buffer_tcp_payload[a].ndpi_selection_bitmask & *ndpi_selection_packet) == ndpi_str->callback_buffer_tcp_payload[a].ndpi_selection_bitmask && NDPI_BITMASK_COMPARE(flow->excluded_protocol_bitmask, ndpi_str->callback_buffer_tcp_payload[a].excluded_protocol_bitmask) == 0 && NDPI_BITMASK_COMPARE(ndpi_str->callback_buffer_tcp_payload[a].detection_bitmask, detection_bitmask) != 0)
				{
					ndpi_str->callback_buffer_tcp_payload[a].func(ndpi_str, flow);

					if (flow->detected_protocol_stack[0] != NDPI_PROTOCOL_UNKNOWN)
						break; /* Stop after detecting the first protocol */
				}
			}
		}
	}
	else
	{
		/* no payload */
		/* PROTO ID NOT NULL AND PROTOCOL IS NOT EXCLUDED BY FLOW AND SELECTION BIT MASK IS INCLUDED BY FLOW */
		if ((proto_id != NDPI_PROTOCOL_UNKNOWN) && NDPI_BITMASK_COMPARE(flow->excluded_protocol_bitmask, ndpi_str->callback_buffer[proto_index].excluded_protocol_bitmask) == 0 && NDPI_BITMASK_COMPARE(ndpi_str->callback_buffer[proto_index].detection_bitmask, detection_bitmask) != 0 && (ndpi_str->callback_buffer[proto_index].ndpi_selection_bitmask & *ndpi_selection_packet) == ndpi_str->callback_buffer[proto_index].ndpi_selection_bitmask)
		{
			/* GO TO PROTOCOL FUNC IF PROTOCOL IS UNKNOWN AND FUNC IS NOT NULL */
			if ((flow->guessed_protocol_id != NDPI_PROTOCOL_UNKNOWN) && (ndpi_str->proto_defaults[flow->guessed_protocol_id].func != NULL) && ((ndpi_str->callback_buffer[flow->guessed_protocol_id].ndpi_selection_bitmask & NDPI_SELECTION_BITMASK_PROTOCOL_HAS_PAYLOAD) == 0))
				ndpi_str->proto_defaults[flow->guessed_protocol_id].func(ndpi_str, flow),
					func = ndpi_str->proto_defaults[flow->guessed_protocol_id].func;
		}
		/* WARNING : WE SHOULD CHECK IF PROTOCOL IS STILL UNKNOWN */
		/* FUNC OF GUESSED PROTOCOL DIDN'T MATCH */
		for (a = 0; a < ndpi_str->callback_buffer_size_tcp_no_payload; a++)
		{
			if ((func != ndpi_str->callback_buffer_tcp_payload[a].func) && (ndpi_str->callback_buffer_tcp_no_payload[a].ndpi_selection_bitmask & *ndpi_selection_packet) == ndpi_str->callback_buffer_tcp_no_payload[a].ndpi_selection_bitmask && NDPI_BITMASK_COMPARE(flow->excluded_protocol_bitmask, ndpi_str->callback_buffer_tcp_no_payload[a].excluded_protocol_bitmask) == 0 && NDPI_BITMASK_COMPARE(ndpi_str->callback_buffer_tcp_no_payload[a].detection_bitmask, detection_bitmask) != 0)
			{
				ndpi_str->callback_buffer_tcp_no_payload[a].func(ndpi_str, flow);

				if (flow->detected_protocol_stack[0] != NDPI_PROTOCOL_UNKNOWN)
					break; /* Stop after detecting the first protocol */
			}
		}
	}
}

/* ********************************************************************************* */

/* ********************************************************************************* */

void ndpi_check_flow_func(struct ndpi_detection_module_struct *ndpi_str,
						  struct ndpi_flow_struct *flow,
						  NDPI_SELECTION_BITMASK_PROTOCOL_SIZE *ndpi_selection_packet)
{
	if (flow->packet.tcp != NULL)
		check_ndpi_tcp_flow_func(ndpi_str, flow, ndpi_selection_packet);
	else if (flow->packet.udp != NULL)
		check_ndpi_udp_flow_func(ndpi_str, flow, ndpi_selection_packet);
	else
		check_ndpi_other_flow_func(ndpi_str, flow, ndpi_selection_packet);
}
/* ********************************************************************************* */
/*
   This function tells if it's possible to further dissect a given flow
   0 - All possible dissection has been completed
   1 - Additional dissection is possible
*/
u_int8_t ndpi_extra_dissection_possible(struct ndpi_detection_module_struct *ndpi_str,
					struct ndpi_flow_struct *flow) {
  u_int16_t proto = flow->detected_protocol_stack[1] ? flow->detected_protocol_stack[1] : flow->detected_protocol_stack[0];

#if 0
  printf("[DEBUG] %s(%u.%u): %u\n", __FUNCTION__,
	 flow->detected_protocol_stack[0],
	 flow->detected_protocol_stack[1],
   proto);
#endif

  switch(proto) {
  case NDPI_PROTOCOL_TLS:
    if(!flow->l4.tcp.tls_srv_cert_fingerprint_processed)
      return(1);
    break;

  case NDPI_PROTOCOL_HTTP:
    if((flow->host_server_name[0] == '\0') || (flow->http.response_status_code == 0))
      return(1);
    break;

  case NDPI_PROTOCOL_DNS:
    if(flow->protos.dns.num_answers == 0)
      return(1);
    break;

  case NDPI_PROTOCOL_FTP_CONTROL:
  case NDPI_PROTOCOL_MAIL_POP:
  case NDPI_PROTOCOL_MAIL_IMAP:
  case NDPI_PROTOCOL_MAIL_SMTP:
    if(flow->protos.ftp_imap_pop_smtp.password[0] == '\0')
      return(1);
    break;

  case NDPI_PROTOCOL_SSH:
    if((flow->protos.ssh.hassh_client[0] == '\0')
       || (flow->protos.ssh.hassh_server[0] == '\0'))
      return(1);
    break;

  case NDPI_PROTOCOL_TELNET:
    if(!flow->protos.telnet.password_detected)
      return(1);
    break;
  }

  return(0);
}

/* ******************************************************************** */

static void ndpi_reset_packet_line_info(struct ndpi_packet_struct *packet)
{
	packet->parsed_lines = 0,
	packet->empty_line_position_set = 0,
	packet->host_line.ptr = NULL,
	packet->host_line.len = 0,
	packet->referer_line.ptr = NULL,
	packet->referer_line.len = 0,
	packet->content_line.ptr = NULL,
	packet->content_line.len = 0,
	packet->accept_line.ptr = NULL,
	packet->accept_line.len = 0,
	packet->user_agent_line.ptr = NULL,
	packet->user_agent_line.len = 0,
	packet->http_url_name.ptr = NULL,
	packet->http_url_name.len = 0,
	packet->http_encoding.ptr = NULL,
	packet->http_encoding.len = 0,
	packet->http_transfer_encoding.ptr = NULL,
	packet->http_transfer_encoding.len = 0,
	packet->http_contentlen.ptr = NULL,
	packet->http_contentlen.len = 0,
	packet->http_cookie.ptr = NULL,
	packet->http_cookie.len = 0,
	packet->http_origin.len = 0,
	packet->http_origin.ptr = NULL,
	packet->http_x_session_type.ptr = NULL,
	packet->http_x_session_type.len = 0,
	packet->server_line.ptr = NULL,
	packet->server_line.len = 0,
	packet->http_method.ptr = NULL,
	packet->http_method.len = 0,
	packet->http_response.ptr = NULL,
	packet->http_response.len = 0,
	packet->http_num_headers = 0;
}

/* ********************************************************************************* */

/* ********************************************************************************* */

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
		// app protocol is detected
		if (flow->check_extra_packets)
		{
			ndpi_process_extra_packet(ndpi_str, flow, packet, packetlen, current_tick_l, src, dst);
			/* Update in case of new match */
			ret.master_protocol = flow->detected_protocol_stack[1], ret.app_protocol = flow->detected_protocol_stack[0];
			return (ret);
		}
		else
			//check master protocol
			goto ret_protocols;
	}
	//app protocol is unknown

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
			flow->guessed_header_category = NDPI_PROTOCOL_CATEGORY_UNSPECIFIED;

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

	if (flow->guessed_host_protocol_id > NDPI_MAX_SUPPORTED_PROTOCOLS)
	{
		/* This is a custom protocol and it has priority over everything else */
		ret.master_protocol = NDPI_PROTOCOL_UNKNOWN, ret.app_protocol = flow->guessed_host_protocol_id;

		if (flow->packet.tcp && (ret.master_protocol == NDPI_PROTOCOL_UNKNOWN))
		{
			/* Minimal guess for HTTP/SSL-based protocols */
			int i;

			for (i = 0; i < 2; i++)
			{
				u_int16_t port = (i == 0) ? ntohs(flow->packet.tcp->dest) : ntohs(flow->packet.tcp->source);

				switch (port)
				{
				case 80:
					ret.master_protocol = NDPI_PROTOCOL_HTTP;
					break;
				case 443:
					ret.master_protocol = NDPI_PROTOCOL_TLS; /* QUIC could also match */
					break;
				}

				if (ret.master_protocol != NDPI_PROTOCOL_UNKNOWN)
					break;
			}
		}

		ndpi_check_flow_func(ndpi_str, flow, &ndpi_selection_packet);
		ndpi_fill_protocol_category(ndpi_str, flow, &ret);
		goto invalidate_ptr;
	}

	ndpi_check_flow_func(ndpi_str, flow, &ndpi_selection_packet);

	a = flow->packet.detected_protocol_stack[0];
	if (NDPI_COMPARE_PROTOCOL_TO_BITMASK(ndpi_str->detection_bitmask, a) == 0)
		a = NDPI_PROTOCOL_UNKNOWN;

	if (a != NDPI_PROTOCOL_UNKNOWN)
	{
		int i;

		for (i = 0; i < sizeof(flow->host_server_name); i++)
		{
			if (flow->host_server_name[i] != '\0')
				flow->host_server_name[i] = tolower(flow->host_server_name[i]);
			else
			{
				flow->host_server_name[i] = '\0';
				break;
			}
		}
	}

ret_protocols:
	if (flow->detected_protocol_stack[1] != NDPI_PROTOCOL_UNKNOWN)
	{
		ret.master_protocol = flow->detected_protocol_stack[1], ret.app_protocol = flow->detected_protocol_stack[0];

		if (ret.app_protocol == ret.master_protocol)
			ret.master_protocol = NDPI_PROTOCOL_UNKNOWN;
	}
	else
		ret.app_protocol = flow->detected_protocol_stack[0];

	/* Don't overwrite the category if already set */
	if (flow->category == NDPI_PROTOCOL_CATEGORY_UNSPECIFIED)
		ndpi_fill_protocol_category(ndpi_str, flow, &ret);
	else
		ret.category = flow->category;

	if ((flow->num_processed_pkts == 1) && (ret.master_protocol == NDPI_PROTOCOL_UNKNOWN) && (ret.app_protocol == NDPI_PROTOCOL_UNKNOWN) && flow->packet.tcp && (flow->packet.tcp->syn == 0) && (flow->guessed_protocol_id == 0))
	{
		u_int8_t protocol_was_guessed;

		/*
      This is a TCP flow
      - whose first packet is NOT a SYN
      - no protocol has been detected

      We don't see how future packets can match anything
      hence we giveup here
    */
		ret = ndpi_detection_giveup(ndpi_str, flow, 0, &protocol_was_guessed);
	}

invalidate_ptr:
	/*
     Invalidate packet memory to avoid accessing the pointers below
     when the packet is no longer accessible
  */
	flow->packet.iph = NULL, flow->packet.tcp = NULL, flow->packet.udp = NULL, flow->packet.payload = NULL;
	ndpi_reset_packet_line_info(&flow->packet);

	return (ret);
}

/* ********************************************************************************* */

void ndpi_int_change_flow_protocol(struct ndpi_detection_module_struct *ndpi_str,
								   struct ndpi_flow_struct *flow,
								   u_int16_t upper_detected_protocol,
								   u_int16_t lower_detected_protocol)
{
	if (!flow)
		return;
	flow->detected_protocol_stack[0] = upper_detected_protocol,
	flow->detected_protocol_stack[1] = lower_detected_protocol;
}

/* ********************************************************************************* */
/* ********************************************************************************* */

void ndpi_int_change_packet_protocol(struct ndpi_detection_module_struct *ndpi_str,
									 struct ndpi_flow_struct *flow,
									 u_int16_t upper_detected_protocol,
									 u_int16_t lower_detected_protocol)
{
	struct ndpi_packet_struct *packet = &flow->packet;
	/* NOTE: everything below is identically to change_flow_protocol
   *        except flow->packet If you want to change something here,
   *        don't! Change it for the flow function and apply it here
   *        as well */

	if (!packet)
		return;

	packet->detected_protocol_stack[0] = upper_detected_protocol,
	packet->detected_protocol_stack[1] = lower_detected_protocol;
}

/* ******************************************************************** */

/* ntop */
void ndpi_set_bitmask_protocol_detection(char *label,
										 struct ndpi_detection_module_struct *ndpi_str,
										 const NDPI_PROTOCOL_BITMASK *detection_bitmask,
										 const u_int32_t idx,
										 u_int16_t ndpi_protocol_id,
										 void (*func)(struct ndpi_detection_module_struct *, struct ndpi_flow_struct *flow),
										 const NDPI_SELECTION_BITMASK_PROTOCOL_SIZE ndpi_selection_bitmask,
										 u_int8_t b_save_bitmask_unknow,
										 u_int8_t b_add_detection_bitmask)
{
	/*
    Compare specify protocol bitmask with main detection bitmask
  */
	if (NDPI_COMPARE_PROTOCOL_TO_BITMASK(*detection_bitmask, ndpi_protocol_id) != 0)
	{
#ifdef DEBUG
		NDPI_LOG_DBG2(ndpi_str
					  "[NDPI] ndpi_set_bitmask_protocol_detection: %s : [callback_buffer] idx= %u, [proto_defaults] protocol_id=%u\n",
					  label, idx, ndpi_protocol_id);
#endif

		if (ndpi_str->proto_defaults[ndpi_protocol_id].protoIdx != 0)
		{
			NDPI_LOG_DBG2(ndpi_str,
						  "[NDPI] Internal error: protocol %s/%u has been already registered\n", label, ndpi_protocol_id);
#ifdef DEBUG
		}
		else
		{
			NDPI_LOG_DBG2(ndpi_str,
						  "[NDPI] Adding %s with protocol id %d\n", label, ndpi_protocol_id);
#endif
		}

		/*
      Set function and index protocol within proto_default structure for port protocol detection
      and callback_buffer function for DPI protocol detection
    */
		ndpi_str->proto_defaults[ndpi_protocol_id].protoIdx = idx;
		ndpi_str->proto_defaults[ndpi_protocol_id].func = ndpi_str->callback_buffer[idx].func = func;

		/*
      Set ndpi_selection_bitmask for protocol
    */
		ndpi_str->callback_buffer[idx].ndpi_selection_bitmask = ndpi_selection_bitmask;

		/*
      Reset protocol detection bitmask via NDPI_PROTOCOL_UNKNOWN and than add specify protocol bitmast to callback
      buffer.
    */
		if (b_save_bitmask_unknow)
			NDPI_SAVE_AS_BITMASK(ndpi_str->callback_buffer[idx].detection_bitmask, NDPI_PROTOCOL_UNKNOWN);
		if (b_add_detection_bitmask)
			NDPI_ADD_PROTOCOL_TO_BITMASK(ndpi_str->callback_buffer[idx].detection_bitmask, ndpi_protocol_id);

		NDPI_SAVE_AS_BITMASK(ndpi_str->callback_buffer[idx].excluded_protocol_bitmask, ndpi_protocol_id);
	}
}

/* ********************************************************************************* */

/* generic function for changing the protocol
 *
 * what it does is:
 * 1.update the flow protocol stack with the new protocol
 * 2.update the packet protocol stack with the new protocol
 */
void ndpi_int_change_protocol(struct ndpi_detection_module_struct *ndpi_str,
							  struct ndpi_flow_struct *flow,
							  u_int16_t upper_detected_protocol,
							  u_int16_t lower_detected_protocol)
{
	if ((upper_detected_protocol == NDPI_PROTOCOL_UNKNOWN) && (lower_detected_protocol != NDPI_PROTOCOL_UNKNOWN))
		upper_detected_protocol = lower_detected_protocol;

	if (upper_detected_protocol == lower_detected_protocol)
		lower_detected_protocol = NDPI_PROTOCOL_UNKNOWN;

	if ((upper_detected_protocol != NDPI_PROTOCOL_UNKNOWN) && (lower_detected_protocol == NDPI_PROTOCOL_UNKNOWN))
	{
		if ((flow->guessed_host_protocol_id != NDPI_PROTOCOL_UNKNOWN) && (upper_detected_protocol != flow->guessed_host_protocol_id))
		{
			if (ndpi_str->proto_defaults[upper_detected_protocol].can_have_a_subprotocol)
			{
				lower_detected_protocol = upper_detected_protocol;
				upper_detected_protocol = flow->guessed_host_protocol_id;
			}
		}
	}

	ndpi_int_change_flow_protocol(ndpi_str, flow,
								  upper_detected_protocol, lower_detected_protocol);
	ndpi_int_change_packet_protocol(ndpi_str, flow,
									upper_detected_protocol, lower_detected_protocol);
}

/* ********************************************************************************* */

void ndpi_set_detected_protocol(struct ndpi_detection_module_struct *ndpi_str,
								struct ndpi_flow_struct *flow,
								u_int16_t upper_detected_protocol,
								u_int16_t lower_detected_protocol)
{
	struct ndpi_id_struct *src = flow->src, *dst = flow->dst;
	ndpi_int_change_protocol(ndpi_str, flow, upper_detected_protocol, lower_detected_protocol);
	if (src != NULL)
	{
		NDPI_ADD_PROTOCOL_TO_BITMASK(src->detected_protocol_bitmask, upper_detected_protocol);
		if (lower_detected_protocol != NDPI_PROTOCOL_UNKNOWN)
			NDPI_ADD_PROTOCOL_TO_BITMASK(src->detected_protocol_bitmask, lower_detected_protocol);
	}
	if (dst != NULL)
	{
		NDPI_ADD_PROTOCOL_TO_BITMASK(dst->detected_protocol_bitmask, upper_detected_protocol);

		if (lower_detected_protocol != NDPI_PROTOCOL_UNKNOWN)
			NDPI_ADD_PROTOCOL_TO_BITMASK(dst->detected_protocol_bitmask, lower_detected_protocol);
	}
}
/* ****************************************************** */
/* ****************************************************** */

int ndpi_match_string_subprotocol(struct ndpi_detection_module_struct *ndpi_str,
								  char *string_to_match, u_int string_to_match_len,
								  ndpi_protocol_match_result *ret_match,
								  u_int8_t is_host_match)
{
	AC_TEXT_t ac_input_text;
	ndpi_automa *automa = is_host_match ? &ndpi_str->host_automa : &ndpi_str->content_automa;
	AC_REP_t match = {NDPI_PROTOCOL_UNKNOWN, NDPI_PROTOCOL_CATEGORY_UNSPECIFIED, NDPI_PROTOCOL_UNRATED};

	if ((automa->ac_automa == NULL) || (string_to_match_len == 0))
		return (NDPI_PROTOCOL_UNKNOWN);

	if (!automa->ac_automa_finalized)
	{
		printf("[%s:%d] [NDPI] Internal error: please call ndpi_finalize_initalization()\n", __FILE__, __LINE__);
		return (0); /* No matches */
	}

	ac_input_text.astring = string_to_match, ac_input_text.length = string_to_match_len;
	ac_automata_search(((AC_AUTOMATA_t *)automa->ac_automa), &ac_input_text, &match);

	/* We need to take into account also rc==0 that is used for partial matches */
	ret_match->protocol_id = match.number,
	ret_match->protocol_category = match.category,
	ret_match->protocol_breed = match.breed;

	return (match.number);
}

#ifdef HAVE_HYPERSCAN

/* ******************************************************************** */

static int hyperscanEventHandler(unsigned int id, unsigned long long from,
								 unsigned long long to, unsigned int flags, void *ctx)
{
	*((int *)ctx) = (int)id;

	NDPI_LOG_DBG2(ndpi_str, "[NDPI] Match with: %d [from: %llu][to: %llu]\n", id, from, to);

	/* return HS_SCAN_TERMINATED; */
	return (0); /* keep searching */
}

#endif

/* **************************************** */
/* **************************************** */

static u_int8_t ndpi_is_more_generic_protocol(u_int16_t previous_proto, u_int16_t new_proto)
{
	/* Sometimes certificates are more generic than previously identified protocols */

	if ((previous_proto == NDPI_PROTOCOL_UNKNOWN) || (previous_proto == new_proto))
		return (0);

	switch (previous_proto)
	{
	case NDPI_PROTOCOL_WHATSAPP_CALL:
	case NDPI_PROTOCOL_WHATSAPP_FILES:
		if (new_proto == NDPI_PROTOCOL_WHATSAPP)
			return (1);
	}

	return (0);
}

/* ****************************************************** */
static u_int16_t ndpi_automa_match_string_subprotocol(struct ndpi_detection_module_struct *ndpi_str,
													  struct ndpi_flow_struct *flow,
													  char *string_to_match, u_int string_to_match_len,
													  u_int16_t master_protocol_id,
													  ndpi_protocol_match_result *ret_match,
													  u_int8_t is_host_match)
{
	int matching_protocol_id;
	struct ndpi_packet_struct *packet = &flow->packet;

#ifndef HAVE_HYPERSCAN
	matching_protocol_id = ndpi_match_string_subprotocol(ndpi_str, string_to_match,
														 string_to_match_len, ret_match,
														 is_host_match);
#else
	struct hs *hs = (struct hs *)ndpi_str->hyperscan;
	hs_error_t status;

	matching_protocol_id = NDPI_PROTOCOL_UNKNOWN;
	/*
    TODO HYPERSCAN
    In case of match fill up ret_match and set flow protocol + category
  */
	status = hs_scan(hs->database, string_to_match,
					 string_to_match_len, 0, hs->scratch,
					 hyperscanEventHandler, &matching_protocol_id);

	if (status == HS_SUCCESS)
	{
		NDPI_LOG_DBG2(ndpi_str, "[NDPI] Hyperscan engine completed normally. Result: %s [%d][%s]\n",
					  ndpi_get_proto_name(ndpi_str, matching_protocol_id), matching_protocol_id, string_to_match);
	}
	else if (status == HS_SCAN_TERMINATED)
	{
		NDPI_LOG_DBG2(ndpi_str, "[NDPI] Hyperscan engine was terminated by callback. Result: %s [%d][%s]\n",
					  ndpi_get_proto_name(ndpi_str, matching_protocol_id), matching_protocol_id, string_to_match);
	}
	else
	{
		NDPI_LOG_DBG2(ndpi_str, "[NDPI] Hyperscan returned with error.\n");
	}

	ret_match->protocol_id = matching_protocol_id,
	ret_match->protocol_category = ndpi_str->proto_defaults[matching_protocol_id].protoCategory,
	ret_match->protocol_breed = ndpi_str->proto_defaults[matching_protocol_id].protoBreed;
#endif

#ifdef DEBUG
	{
		char m[256];
		int len = ndpi_min(sizeof(m), string_to_match_len);

		strncpy(m, string_to_match, len);
		m[len] = '\0';

		NDPI_LOG_DBG2(ndpi_str, "[NDPI] ndpi_match_host_subprotocol(%s): %s\n",
					  m, ndpi_str->proto_defaults[matching_protocol_id].protoName);
	}
#endif

	if ((matching_protocol_id != NDPI_PROTOCOL_UNKNOWN) && (!ndpi_is_more_generic_protocol(packet->detected_protocol_stack[0], matching_protocol_id)))
	{
		/* Move the protocol on slot 0 down one position */
		packet->detected_protocol_stack[1] = master_protocol_id,
		packet->detected_protocol_stack[0] = matching_protocol_id;

		flow->detected_protocol_stack[0] = packet->detected_protocol_stack[0],
		flow->detected_protocol_stack[1] = packet->detected_protocol_stack[1];

		if (flow->category == NDPI_PROTOCOL_CATEGORY_UNSPECIFIED)
			flow->category = ret_match->protocol_category;

		return (packet->detected_protocol_stack[0]);
	}

#ifdef DEBUG
	string_to_match[string_to_match_len] = '\0';
	NDPI_LOG_DBG2(ndpi_str, "[NTOP] Unable to find a match for '%s'\n", string_to_match);
#endif

	ret_match->protocol_id = NDPI_PROTOCOL_UNKNOWN,
	ret_match->protocol_category = NDPI_PROTOCOL_CATEGORY_UNSPECIFIED,
	ret_match->protocol_breed = NDPI_PROTOCOL_UNRATED;

	return (NDPI_PROTOCOL_UNKNOWN);
}

/* ****************************************************** */
/* *********************************************** */

int ndpi_get_custom_category_match(struct ndpi_detection_module_struct *ndpi_str,
				   char *name_or_ip, u_int name_len, unsigned long *id) {
  char ipbuf[64], *ptr;
  struct in_addr pin;
  u_int cp_len = ndpi_min(sizeof(ipbuf)-1, name_len);

  if(!ndpi_str->custom_categories.categories_loaded)
    return(-1);

  if(cp_len > 0) {
    memcpy(ipbuf, name_or_ip, cp_len);
    ipbuf[cp_len] = '\0';
  } else
    ipbuf[0] = '\0';

  ptr = strrchr(ipbuf, '/');

  if(ptr)
    ptr[0] = '\0';

  if(inet_pton(AF_INET, ipbuf, &pin) == 1) {
    /* Search IP */
    prefix_t prefix;
    patricia_node_t *node;

    /* Make sure all in network byte order otherwise compares wont work */
    fill_prefix_v4(&prefix, &pin, 32, ((patricia_tree_t*)ndpi_str->protocols_ptree)->maxbits);
    node = ndpi_patricia_search_best(ndpi_str->custom_categories.ipAddresses, &prefix);

    if(node) {
      *id = node->value.user_value;
      return(0);
    }

    return(-1);
  } else
    /* Search Host */
    return(ndpi_match_custom_category(ndpi_str, name_or_ip, name_len, id));
}

/* *********************************************** */

u_int16_t ndpi_match_host_subprotocol(struct ndpi_detection_module_struct *ndpi_str,
									  struct ndpi_flow_struct *flow,
									  char *string_to_match, u_int string_to_match_len,
									  ndpi_protocol_match_result *ret_match,
									  u_int16_t master_protocol_id)
{
	u_int16_t rc = ndpi_automa_match_string_subprotocol(ndpi_str,
														flow, string_to_match, string_to_match_len,
														master_protocol_id, ret_match, 1);

	if ((flow->category == NDPI_PROTOCOL_CATEGORY_UNSPECIFIED) && (ret_match->protocol_category == NDPI_PROTOCOL_CATEGORY_UNSPECIFIED))
	{
		unsigned long id = ret_match->protocol_category;

		if (ndpi_get_custom_category_match(ndpi_str, string_to_match, string_to_match_len, &id) != -1)
		{
			if (id != -1)
			{
				flow->category = ret_match->protocol_category = id;
				rc = master_protocol_id;
			}
		}
	}

	return (rc);
}

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
/*********************************************************************************** */

/* ********************************************************************************* */

void ndpi_set_log_level(struct ndpi_detection_module_struct *ndpi_str, u_int l)
{
	ndpi_str->ndpi_log_level = l;
}
int ndpi_load_categories_file(struct ndpi_detection_module_struct *ndpi_str, const char *path)
{
	char buffer[512], *line, *name, *category, *saveptr;
	FILE *fd;
	int len;

	fd = fopen(path, "r");

	if (fd == NULL)
	{
		NDPI_LOG_ERR(ndpi_str, "Unable to open file %s [%s]\n", path, strerror(errno));
		return (-1);
	}

	while (fd)
	{
		line = fgets(buffer, sizeof(buffer), fd);

		if (line == NULL)
			break;

		len = strlen(line);

		if ((len <= 1) || (line[0] == '#'))
			continue;

		line[len - 1] = '\0';
		name = strtok_r(line, "\t", &saveptr);

		if (name)
		{
			category = strtok_r(NULL, "\t", &saveptr);

			if (category)
				ndpi_load_category(ndpi_str, name, (ndpi_protocol_category_t)atoi(category));
		}
	}

	fclose(fd);
	ndpi_enable_loaded_categories(ndpi_str);

	return (0);
}
void ndpi_finalize_initalization(struct ndpi_detection_module_struct *ndpi_str)
{
	u_int i;

	for (i = 0; i < 4; i++)
	{
		ndpi_automa *automa;

		switch (i)
		{
		case 0:
			automa = &ndpi_str->host_automa;
			break;

		case 1:
			automa = &ndpi_str->content_automa;
			break;

		case 2:
			automa = &ndpi_str->bigrams_automa;
			break;

		case 3:
			automa = &ndpi_str->impossible_bigrams_automa;
			break;
		}

		ac_automata_finalize((AC_AUTOMATA_t *)automa->ac_automa);
		automa->ac_automa_finalized = 1;
	}
}

/*****************************/
void ndpi_set_protocol_detection_bitmask2(struct ndpi_detection_module_struct *ndpi_str,
										  const NDPI_PROTOCOL_BITMASK *dbm)
{
	NDPI_PROTOCOL_BITMASK detection_bitmask_local;
	NDPI_PROTOCOL_BITMASK *detection_bitmask = &detection_bitmask_local;
	u_int32_t a = 0;

	NDPI_BITMASK_SET(detection_bitmask_local, *dbm);
	NDPI_BITMASK_SET(ndpi_str->detection_bitmask, *dbm);
	/* set this here to zero to be interrupt safe */
	ndpi_str->callback_buffer_size = 0;

	/* HTTP */
	init_http_dissector(ndpi_str, &a, detection_bitmask);
	/* TLS */
	init_tls_dissector(ndpi_str, &a, detection_bitmask);

	/* WHATSAPP */
	init_whatsapp_dissector(ndpi_str, &a, detection_bitmask);

	/* GIT */
	init_git_dissector(ndpi_str, &a, detection_bitmask);

	/* DNS */
	init_dns_dissector(ndpi_str, &a, detection_bitmask);

#ifdef CUSTOM_NDPI_PROTOCOLS
#include "../../../nDPI-custom/custom_ndpi_main_init.c"
#endif

	/* ----------------------------------------------------------------- */

	ndpi_str->callback_buffer_size = a;

	NDPI_LOG_DBG2(ndpi_str,
				  "callback_buffer_size is %u\n", ndpi_str->callback_buffer_size);

	/* now build the specific buffer for tcp, udp and non_tcp_udp */
	ndpi_str->callback_buffer_size_tcp_payload = 0;
	ndpi_str->callback_buffer_size_tcp_no_payload = 0;
	for (a = 0; a < ndpi_str->callback_buffer_size; a++)
	{
		if ((ndpi_str->callback_buffer[a].ndpi_selection_bitmask & (NDPI_SELECTION_BITMASK_PROTOCOL_INT_TCP |
																	NDPI_SELECTION_BITMASK_PROTOCOL_INT_TCP_OR_UDP |
																	NDPI_SELECTION_BITMASK_PROTOCOL_COMPLETE_TRAFFIC)) != 0)
		{
			if (_ndpi_debug_callbacks)
				NDPI_LOG_DBG2(ndpi_str,
							  "callback_buffer_tcp_payload, adding buffer %u as entry %u\n", a,
							  ndpi_str->callback_buffer_size_tcp_payload);

			memcpy(&ndpi_str->callback_buffer_tcp_payload[ndpi_str->callback_buffer_size_tcp_payload],
				   &ndpi_str->callback_buffer[a], sizeof(struct ndpi_call_function_struct));
			ndpi_str->callback_buffer_size_tcp_payload++;

			if ((ndpi_str->callback_buffer[a].ndpi_selection_bitmask & NDPI_SELECTION_BITMASK_PROTOCOL_HAS_PAYLOAD) == 0)
			{
				if (_ndpi_debug_callbacks)
					NDPI_LOG_DBG2(ndpi_str,
								  "\tcallback_buffer_tcp_no_payload, additional adding buffer %u to no_payload process\n", a);

				memcpy(&ndpi_str->callback_buffer_tcp_no_payload
							[ndpi_str->callback_buffer_size_tcp_no_payload],
					   &ndpi_str->callback_buffer[a],
					   sizeof(struct ndpi_call_function_struct));
				ndpi_str->callback_buffer_size_tcp_no_payload++;
			}
		}
	}

	ndpi_str->callback_buffer_size_udp = 0;
	for (a = 0; a < ndpi_str->callback_buffer_size; a++)
	{
		if ((ndpi_str->callback_buffer[a].ndpi_selection_bitmask & (NDPI_SELECTION_BITMASK_PROTOCOL_INT_UDP |
																	NDPI_SELECTION_BITMASK_PROTOCOL_INT_TCP_OR_UDP |
																	NDPI_SELECTION_BITMASK_PROTOCOL_COMPLETE_TRAFFIC)) != 0)
		{
			if (_ndpi_debug_callbacks)
				NDPI_LOG_DBG2(ndpi_str,
							  "callback_buffer_size_udp: adding buffer : %u as entry %u\n", a, ndpi_str->callback_buffer_size_udp);

			memcpy(&ndpi_str->callback_buffer_udp[ndpi_str->callback_buffer_size_udp],
				   &ndpi_str->callback_buffer[a], sizeof(struct ndpi_call_function_struct));
			ndpi_str->callback_buffer_size_udp++;
		}
	}

	ndpi_str->callback_buffer_size_non_tcp_udp = 0;
	for (a = 0; a < ndpi_str->callback_buffer_size; a++)
	{
		if ((ndpi_str->callback_buffer[a].ndpi_selection_bitmask & (NDPI_SELECTION_BITMASK_PROTOCOL_INT_TCP |
																	NDPI_SELECTION_BITMASK_PROTOCOL_INT_UDP |
																	NDPI_SELECTION_BITMASK_PROTOCOL_INT_TCP_OR_UDP)) == 0 ||
			(ndpi_str->callback_buffer[a].ndpi_selection_bitmask & NDPI_SELECTION_BITMASK_PROTOCOL_COMPLETE_TRAFFIC) != 0)
		{
			if (_ndpi_debug_callbacks)
				NDPI_LOG_DBG2(ndpi_str,
							  "callback_buffer_non_tcp_udp: adding buffer : %u as entry %u\n", a, ndpi_str->callback_buffer_size_non_tcp_udp);

			memcpy(&ndpi_str->callback_buffer_non_tcp_udp[ndpi_str->callback_buffer_size_non_tcp_udp],
				   &ndpi_str->callback_buffer[a], sizeof(struct ndpi_call_function_struct));
			ndpi_str->callback_buffer_size_non_tcp_udp++;
		}
	}
/* ****************************************** */
void ndpi_free(void *ptr) {
  if(_ndpi_free)
    _ndpi_free(ptr);
  else
    free(ptr);
}
/* ****************************************************** */
void ndpi_free_flow(struct ndpi_flow_struct *flow) {
  if(flow) {
  if(flow->http.url)            ndpi_free(flow->http.url);
    if(flow->http.content_type) ndpi_free(flow->http.content_type);
    if(flow->http.user_agent)   ndpi_free(flow->http.user_agent);

    if(flow->l4_proto == IPPROTO_TCP) {
      if(flow->l4.tcp.tls_srv_cert_fingerprint_ctx)
	ndpi_free(flow->l4.tcp.tls_srv_cert_fingerprint_ctx);
    }

    ndpi_free(flow);
  }
}
void ndpi_flow_free(void *ptr)
{
  if(_ndpi_flow_free)
    _ndpi_flow_free(ptr);
  else
    ndpi_free_flow((struct ndpi_flow_struct *) ptr);
}

/* ****************************************************** */
/* ******************************************************************** */

u_int ndpi_get_num_supported_protocols(struct ndpi_detection_module_struct *ndpi_str)
{
  return (ndpi_str->ndpi_num_supported_protocols);
}

/* ******************************************************************** */

void ndpi_lru_free_cache(struct ndpi_lru_cache *c) {
  ndpi_free(c->entries);
  ndpi_free(c);
}

void ndpi_exit_detection_module(struct ndpi_detection_module_struct *ndpi_str) {
  if(ndpi_str != NULL) {
    int i;

    for(i=0; i<(int)ndpi_str->ndpi_num_supported_protocols; i++)
    {
      if(ndpi_str->proto_defaults[i].protoName)
	      ndpi_free(ndpi_str->proto_defaults[i].protoName);
    }

    /* NDPI_PROTOCOL_TINC */
    if(ndpi_str->tinc_cache)
      cache_free((cache_t)(ndpi_str->tinc_cache));

    if(ndpi_str->ookla_cache)
      ndpi_lru_free_cache(ndpi_str->ookla_cache);

    if(ndpi_str->stun_cache)
      ndpi_lru_free_cache(ndpi_str->stun_cache);

    if(ndpi_str->protocols_ptree)
      ndpi_Destroy_Patricia((patricia_tree_t*)ndpi_str->protocols_ptree, free_ptree_data);

    if(ndpi_str->udpRoot != NULL)
      ndpi_tdestroy(ndpi_str->udpRoot, ndpi_free);
    if(ndpi_str->tcpRoot != NULL)
      ndpi_tdestroy(ndpi_str->tcpRoot, ndpi_free);

    if(ndpi_str->host_automa.ac_automa != NULL)
      ac_automata_release((AC_AUTOMATA_t*)ndpi_str->host_automa.ac_automa, 1 /* free patterns strings memory */);

    if(ndpi_str->content_automa.ac_automa != NULL)
      ac_automata_release((AC_AUTOMATA_t*)ndpi_str->content_automa.ac_automa, 0);

    if(ndpi_str->bigrams_automa.ac_automa != NULL)
      ac_automata_release((AC_AUTOMATA_t*)ndpi_str->bigrams_automa.ac_automa, 0);

    if(ndpi_str->impossible_bigrams_automa.ac_automa != NULL)
      ac_automata_release((AC_AUTOMATA_t*)ndpi_str->impossible_bigrams_automa.ac_automa, 0);

#ifdef HAVE_HYPERSCAN
    destroy_hyperscan(ndpi_str);

    while(ndpi_str->custom_categories.to_load != NULL) {
      struct hs_list *next = ndpi_str->custom_categories.to_load->next;

      ndpi_free(ndpi_str->custom_categories.to_load->expression);
      ndpi_free(ndpi_str->custom_categories.to_load);
      ndpi_str->custom_categories.to_load = next;
    }

    free_hyperscan_memory(ndpi_str->custom_categories.hostnames);
#else
    if(ndpi_str->custom_categories.hostnames.ac_automa != NULL)
      ac_automata_release((AC_AUTOMATA_t*)ndpi_str->custom_categories.hostnames.ac_automa, 1 /* free patterns strings memory */);

    if(ndpi_str->custom_categories.hostnames_shadow.ac_automa != NULL)
      ac_automata_release((AC_AUTOMATA_t*)ndpi_str->custom_categories.hostnames_shadow.ac_automa, 1 /* free patterns strings memory */);
#endif

    if(ndpi_str->custom_categories.ipAddresses != NULL)
      ndpi_Destroy_Patricia((patricia_tree_t*)ndpi_str->custom_categories.ipAddresses, free_ptree_data);

    if(ndpi_str->custom_categories.ipAddresses_shadow != NULL)
      ndpi_Destroy_Patricia((patricia_tree_t*)ndpi_str->custom_categories.ipAddresses_shadow, free_ptree_data);

    ndpi_free(ndpi_str);
  }
}


char* ndpi_get_proto_name(struct ndpi_detection_module_struct *ndpi_str, u_int16_t proto_id) {
  if((proto_id >= ndpi_str->ndpi_num_supported_protocols)
     || (proto_id >= (NDPI_MAX_SUPPORTED_PROTOCOLS+NDPI_MAX_NUM_CUSTOM_PROTOCOLS))
     || (ndpi_str->proto_defaults[proto_id].protoName == NULL))
    proto_id = NDPI_PROTOCOL_UNKNOWN;

  return(ndpi_str->proto_defaults[proto_id].protoName);
}
/* ****************************************************** */

char* ndpi_protocol2name(struct ndpi_detection_module_struct *ndpi_str,
			 ndpi_protocol proto, char *buf, u_int buf_len) {
  if((proto.master_protocol != NDPI_PROTOCOL_UNKNOWN)
     && (proto.master_protocol != proto.app_protocol)) {
    if(proto.app_protocol != NDPI_PROTOCOL_UNKNOWN)
      snprintf(buf, buf_len, "%s.%s",
	       ndpi_get_proto_name(ndpi_str, proto.master_protocol),
	       ndpi_get_proto_name(ndpi_str, proto.app_protocol));
    else
      snprintf(buf, buf_len, "%s",
	       ndpi_get_proto_name(ndpi_str, proto.master_protocol));
  } else
    snprintf(buf, buf_len, "%s",
	     ndpi_get_proto_name(ndpi_str, proto.app_protocol));

  return(buf);
}

/* ****************************************************** */

const char* ndpi_category_get_name(struct ndpi_detection_module_struct *ndpi_str,
				   ndpi_protocol_category_t category) {
  if((!ndpi_str) || (category >= NDPI_PROTOCOL_NUM_CATEGORIES)) {
    static char b[24];

    if(!ndpi_str)
      snprintf(b, sizeof(b), "NULL nDPI");
    else
      snprintf(b, sizeof(b), "Invalid category %d", (int)category);
    return(b);
  }

  if((category >= NDPI_PROTOCOL_CATEGORY_CUSTOM_1) && (category <= NDPI_PROTOCOL_CATEGORY_CUSTOM_5)) {
    switch(category) {
    case NDPI_PROTOCOL_CATEGORY_CUSTOM_1:
      return(ndpi_str->custom_category_labels[0]);
    case NDPI_PROTOCOL_CATEGORY_CUSTOM_2:
      return(ndpi_str->custom_category_labels[1]);
    case NDPI_PROTOCOL_CATEGORY_CUSTOM_3:
      return(ndpi_str->custom_category_labels[2]);
    case NDPI_PROTOCOL_CATEGORY_CUSTOM_4:
      return(ndpi_str->custom_category_labels[3]);
    case NDPI_PROTOCOL_CATEGORY_CUSTOM_5:
      return(ndpi_str->custom_category_labels[4]);
    case NDPI_PROTOCOL_NUM_CATEGORIES:
      return("Code should not use this internal constant");
    default:
      return("Unspecified");
    }
  } else
    return(categories[category]);
}

/* ****************************************************** */

char* ndpi_protocol2id(struct ndpi_detection_module_struct *ndpi_str,
		       ndpi_protocol proto, char *buf, u_int buf_len) {
  if((proto.master_protocol != NDPI_PROTOCOL_UNKNOWN)
     && (proto.master_protocol != proto.app_protocol)) {
    if(proto.app_protocol != NDPI_PROTOCOL_UNKNOWN)
      snprintf(buf, buf_len, "%u.%u",
	       proto.master_protocol, proto.app_protocol);
    else
      snprintf(buf, buf_len, "%u", proto.master_protocol);
  } else
    snprintf(buf, buf_len, "%u", proto.app_protocol);

  return(buf);
}

/* ****************************************************** */

ndpi_protocol_breed_t ndpi_get_proto_breed(struct ndpi_detection_module_struct *ndpi_str,
					   u_int16_t proto_id) {
  if((proto_id >= ndpi_str->ndpi_num_supported_protocols)
     || (proto_id >= (NDPI_MAX_SUPPORTED_PROTOCOLS+NDPI_MAX_NUM_CUSTOM_PROTOCOLS))
     || (ndpi_str->proto_defaults[proto_id].protoName == NULL))
    proto_id = NDPI_PROTOCOL_UNKNOWN;

  return(ndpi_str->proto_defaults[proto_id].protoBreed);
}

/* ****************************************************** */

char* ndpi_get_proto_breed_name(struct ndpi_detection_module_struct *ndpi_str, ndpi_protocol_breed_t breed_id) 
{
  switch(breed_id) {
  case NDPI_PROTOCOL_SAFE:
    return("Safe");
    break;
  case NDPI_PROTOCOL_ACCEPTABLE:
    return("Acceptable");
    break;
  case NDPI_PROTOCOL_FUN:
    return("Fun");
    break;
  case NDPI_PROTOCOL_UNSAFE:
    return("Unsafe");
    break;
  case NDPI_PROTOCOL_POTENTIALLY_DANGEROUS:
    return("Potentially Dangerous");
    break;
  case NDPI_PROTOCOL_DANGEROUS:
    return("Dangerous");
    break;
  case NDPI_PROTOCOL_UNRATED:
  default:
    return("Unrated");
    break;
  }
}
int main(void)
{
	puts("!!!Hello World!!!"); /* prints !!!Hello World!!! */
	return EXIT_SUCCESS;
}
