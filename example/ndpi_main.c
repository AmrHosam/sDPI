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
