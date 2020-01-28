
#include <stdio.h>
#include <stdlib.h>
#define NDPI_MAX_SUPPORTED_PROTOCOLS     NDPI_LAST_IMPLEMENTED_PROTOCOL
#define CUSTOM_CATEGORY_LABEL_LEN 32
#define NUM_CUSTOM_CATEGORIES      5
#define NDPI_PROTOCOL_BITMASK ndpi_protocol_bitmask_struct_t
#define NDPI_MAX_NUM_CUSTOM_PROTOCOLS    (NDPI_NUM_BITS-NDPI_LAST_IMPLEMENTED_PROTOCOL)
typedef struct ndpi_default_ports_tree_node {
  ndpi_proto_defaults_t *proto;
  u_int8_t customUserProto;
  u_int16_t default_port;
} ndpi_default_ports_tree_node_t;
typedef struct ndpi_proto_defaults {
  char *protoName;
  ndpi_protocol_category_t protoCategory;
  u_int8_t can_have_a_subprotocol;
  u_int16_t protoId, protoIdx;
  u_int16_t master_tcp_protoId[2], master_udp_protoId[2]; /* The main protocols on which this sub-protocol sits on */
  ndpi_protocol_breed_t protoBreed;
  void (*func) (struct ndpi_detection_module_struct *, struct ndpi_flow_struct *flow);
} ndpi_proto_defaults_t;
typedef enum {
	      NDPI_LOG_ERROR,
	      NDPI_LOG_TRACE,
	      NDPI_LOG_DEBUG,
	      NDPI_LOG_DEBUG_EXTRA
} ndpi_log_level_t;
typedef struct _ndpi_automa {
  void *ac_automa; /* Real type is AC_AUTOMATA_t */
  u_int8_t ac_automa_finalized;
} ndpi_automa;
struct ndpi_detection_module_struct {
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
		  ndpi_automa host_automa,                     /* Used for DNS/HTTPS */
		    content_automa,                            /* Used for HTTP subprotocol_detection */
		    subprotocol_automa,                        /* Used for HTTP subprotocol_detection */
		    bigrams_automa, impossible_bigrams_automa; /* TOR */
		  /* IMPORTANT: please update ndpi_finalize_initalization() whenever you add a new automa */

		  struct {
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
		  int    bt_ann_len;

		  /* NDPI_PROTOCOL_OOKLA */
		  struct ndpi_lru_cache *ookla_cache;

		  /* NDPI_PROTOCOL_TINC */
		  struct cache *tinc_cache;

		  /* NDPI_PROTOCOL_STUN and subprotocols */
		  struct ndpi_lru_cache *stun_cache;

		  ndpi_proto_defaults_t proto_defaults[NDPI_MAX_SUPPORTED_PROTOCOLS+NDPI_MAX_NUM_CUSTOM_PROTOCOLS];

		  u_int8_t direction_detect_disable:1, /* disable internal detection of packet direction */
		    disable_metadata_export:1   /* No metadata is exported */
		    ;

		  void hyperscan; /* Intel Hyperscan */
	};
/* ********************************************************************************* */

ndpi_protocol ndpi_detection_process_packet(struct ndpi_detection_module_struct *ndpi_str,
					    struct ndpi_flow_struct *flow,
					    const unsigned char *packet,
					    const unsigned short packetlen,
					    const u_int64_t current_tick_l,
					    struct ndpi_id_struct *src,
					    struct ndpi_id_struct *dst) {
  NDPI_SELECTION_BITMASK_PROTOCOL_SIZE ndpi_selection_packet;
  u_int32_t a;
  ndpi_protocol ret = { NDPI_PROTOCOL_UNKNOWN, NDPI_PROTOCOL_UNKNOWN, NDPI_PROTOCOL_CATEGORY_UNSPECIFIED };

  if(ndpi_str->ndpi_log_level >= NDPI_LOG_TRACE)
    NDPI_LOG(flow ? flow->detected_protocol_stack[0]:NDPI_PROTOCOL_UNKNOWN,
	     ndpi_str, NDPI_LOG_TRACE, "START packet processing\n");

  if(flow == NULL)
    return(ret);
  else
    ret.category = flow->category;

  flow->num_processed_pkts++;

  /* Init default */
  ret.master_protocol = flow->detected_protocol_stack[1], ret.app_protocol = flow->detected_protocol_stack[0];
						}
/* ********************************************************************************* */
int main(void) {
	puts("!!!Hello World!!!"); /* prints !!!Hello World!!! */
	return EXIT_SUCCESS;
}
