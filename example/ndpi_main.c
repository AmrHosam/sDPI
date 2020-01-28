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

struct ndpi_detection_module_struct *ndpi_init_detection_module(ndpi_init_prefs prefs) 
  {
    struct ndpi_detection_module_struct *ndpi_str = ndpi_malloc(sizeof(struct ndpi_detection_module_struct));
    int i;

    if(ndpi_str == NULL) {
  #ifdef NDPI_ENABLE_DEBUG_MESSAGES
      NDPI_LOG_ERR(ndpi_str, "ndpi_init_detection_module initial malloc failed for ndpi_str\n");
  #endif /* NDPI_ENABLE_DEBUG_MESSAGES */
      return(NULL);
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
static int fill_prefix_v4(prefix_t *p, const struct in_addr *a, int b, int mb) 
 {
    do {
      if(b < 0 || b > mb)
        return(-1);

      memset(p, 0, sizeof(prefix_t));
      memcpy(&p->add.sin, a, (mb+7)/8);
      p->family = AF_INET;
      p->bitlen = b;
      p->ref_count = 0;
    } while(0);

    return(0);
  }
static patricia_node_t* add_to_ptree(patricia_tree_t *tree, int family,void *addr, int bits)
 {
    prefix_t prefix;
    patricia_node_t *node;

    fill_prefix_v4(&prefix, (struct in_addr*)addr, bits, tree->maxbits);

    node = ndpi_patricia_lookup(tree, &prefix);

    return(node);
 }
static void ndpi_init_ptree_ipv4(struct ndpi_detection_module_struct *ndpi_str,void *ptree, ndpi_network host_list[],u_int8_t skip_tor_hosts) 
  {
    int i;

    for(i=0; host_list[i].network != 0x0; i++) {
      struct in_addr pin;
      patricia_node_t *node;

      if(skip_tor_hosts && (host_list[i].value == NDPI_PROTOCOL_TOR))
        continue;

      pin.s_addr = htonl(host_list[i].network);
      if((node = add_to_ptree(ptree, AF_INET,
            &pin, host_list[i].cidr /* bits */)) != NULL)
        node->value.user_value = host_list[i].value;
    }
  }
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
/* ********************************************************************************* */

ndpi_protocol ndpi_detection_giveup(struct ndpi_detection_module_struct *ndpi_str,
				    struct ndpi_flow_struct *flow,
				    u_int8_t enable_guess,
				    u_int8_t *protocol_was_guessed) 
{
  ndpi_protocol ret = { NDPI_PROTOCOL_UNKNOWN, NDPI_PROTOCOL_UNKNOWN, NDPI_PROTOCOL_CATEGORY_UNSPECIFIED };
  *protocol_was_guessed = 0;
  if(flow == NULL)
    return(ret);

  /* Init defaults */
  ret.master_protocol = flow->detected_protocol_stack[1], ret.app_protocol = flow->detected_protocol_stack[0];
  ret.category = flow->category;

  /* Ensure that we don't change our mind if detection is already complete */
  if((ret.master_protocol != NDPI_PROTOCOL_UNKNOWN) && (ret.app_protocol != NDPI_PROTOCOL_UNKNOWN))
    return(ret);

  /* TODO: add the remaining stage_XXXX protocols */
  if(flow->detected_protocol_stack[0] == NDPI_PROTOCOL_UNKNOWN) 
  {
	      u_int16_t guessed_protocol_id, guessed_host_protocol_id;
    if(flow->guessed_protocol_id == NDPI_PROTOCOL_STUN)
      goto check_stun_export;
    else if((flow->guessed_protocol_id == NDPI_PROTOCOL_HANGOUT_DUO)
	    || (flow->guessed_protocol_id == NDPI_PROTOCOL_MESSENGER)
	    || (flow->guessed_protocol_id == NDPI_PROTOCOL_WHATSAPP_CALL))
      ndpi_set_detected_protocol(ndpi_str, flow, flow->guessed_protocol_id, NDPI_PROTOCOL_UNKNOWN);
    else if((flow->l4.tcp.tls_seen_client_cert == 1)
	    && (flow->protos.stun_ssl.ssl.client_certificate[0] != '\0')) 
	{
      ndpi_set_detected_protocol(ndpi_str, flow, NDPI_PROTOCOL_TLS, NDPI_PROTOCOL_UNKNOWN);
    } 
	else
	{	
     	if((flow->guessed_protocol_id == NDPI_PROTOCOL_UNKNOWN)
	 	&& (flow->packet.l4_protocol == IPPROTO_TCP)
	 	&& (flow->l4.tcp.tls_stage > 1))
	 	flow->guessed_protocol_id = NDPI_PROTOCOL_TLS;
	
     	guessed_protocol_id = flow->guessed_protocol_id, guessed_host_protocol_id = flow->guessed_host_protocol_id;
	
     	if((guessed_host_protocol_id != NDPI_PROTOCOL_UNKNOWN)
	 	&& ((flow->packet.l4_protocol == IPPROTO_UDP)
	 	    && NDPI_ISSET(&flow->excluded_protocol_bitmask, guessed_host_protocol_id)
	 	    && is_udp_guessable_protocol(guessed_host_protocol_id)
	 	    ))
	 		flow->guessed_host_protocol_id = guessed_host_protocol_id = NDPI_PROTOCOL_UNKNOWN;
	
     	 /* Ignore guessed protocol if they have been discarded */
     	if((guessed_protocol_id != NDPI_PROTOCOL_UNKNOWN)
	 	// && (guessed_host_protocol_id == NDPI_PROTOCOL_UNKNOWN)
	 	&& (flow->packet.l4_protocol == IPPROTO_UDP)
	 	&& NDPI_ISSET(&flow->excluded_protocol_bitmask, guessed_protocol_id)
	 	&& is_udp_guessable_protocol(guessed_protocol_id))
	 	flow->guessed_protocol_id = guessed_protocol_id = NDPI_PROTOCOL_UNKNOWN;

    	if((guessed_protocol_id != NDPI_PROTOCOL_UNKNOWN)
		|| (guessed_host_protocol_id != NDPI_PROTOCOL_UNKNOWN)) 
		{
			if((guessed_protocol_id == 0)
			   && (flow->protos.stun_ssl.stun.num_binding_requests > 0)
			   && (flow->protos.stun_ssl.stun.num_processed_pkts > 0))
			  guessed_protocol_id = NDPI_PROTOCOL_STUN;

			if(flow->host_server_name[0] != '\0') 
			{
			  ndpi_protocol_match_result ret_match;
			  ndpi_match_host_subprotocol(ndpi_str, flow,
						      (char *)flow->host_server_name,
						      strlen((const char*)flow->host_server_name),
						      &ret_match,
						      NDPI_PROTOCOL_DNS);
			  if(ret_match.protocol_id != NDPI_PROTOCOL_UNKNOWN)
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

  	  if(flow->detected_protocol_stack[1] == flow->detected_protocol_stack[0])
  	    flow->detected_protocol_stack[1] = flow->guessed_host_protocol_id;
  	}

  	if((flow->detected_protocol_stack[0] == NDPI_PROTOCOL_UNKNOWN)
     && (flow->guessed_protocol_id == NDPI_PROTOCOL_STUN)) 
	{
  		check_stun_export:
    	if(flow->protos.stun_ssl.stun.num_processed_pkts || flow->protos.stun_ssl.stun.num_udp_pkts) 
		{
    	  // if(/* (flow->protos.stun_ssl.stun.num_processed_pkts >= NDPI_MIN_NUM_STUN_DETECTION) */
    	  ndpi_set_detected_protocol(ndpi_str, flow,
					 flow->guessed_host_protocol_id,
					 NDPI_PROTOCOL_STUN);
    	}
  	}

 	ret.master_protocol = flow->detected_protocol_stack[1], ret.app_protocol = flow->detected_protocol_stack[0];

  	if(ret.master_protocol == NDPI_PROTOCOL_STUN) 
  	{
  	  if(ret.app_protocol == NDPI_PROTOCOL_FACEBOOK)
  	    ret.app_protocol = NDPI_PROTOCOL_MESSENGER;
  	  else if(ret.app_protocol == NDPI_PROTOCOL_GOOGLE) 
		{
  	  	  /*
			As Google has recently introduced Duo,
			we need to distinguish between it and hangout
			thing that should be handled by the STUN dissector
  	  	  */
  	  	  ret.app_protocol = NDPI_PROTOCOL_HANGOUT_DUO;
  	  }
  	}
  
  	if(ret.app_protocol != NDPI_PROTOCOL_UNKNOWN)
  	  ndpi_fill_protocol_category(ndpi_str, flow, &ret);  
  
  return(ret);
}

/* ********************************************************************************* */

int main(void) {
	puts("!!!Hello World!!!"); /* prints !!!Hello World!!! */
	return EXIT_SUCCESS;
}
