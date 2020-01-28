#include "ndpi_define.h"
#define NUM_CUSTOM_CATEGORIES      5
#define CUSTOM_CATEGORY_LABEL_LEN 32
typedef struct ndpi_protocol_bitmask_struct 
    {
    ndpi_ndpi_mask fds_bits[NDPI_NUM_FDS_BITS];
    } ndpi_protocol_bitmask_struct_t;
/* Abstract categories to group the protocols. */
typedef enum 
    {
          NDPI_PROTOCOL_CATEGORY_UNSPECIFIED = 0,   /* For general services and unknown protocols */
          NDPI_PROTOCOL_CATEGORY_MEDIA,             /* Multimedia and streaming */
          NDPI_PROTOCOL_CATEGORY_VPN,               /* Virtual Private Networks */
          NDPI_PROTOCOL_CATEGORY_MAIL,              /* Protocols to send/receive/sync emails */
          NDPI_PROTOCOL_CATEGORY_DATA_TRANSFER,     /* AFS/NFS and similar protocols */
          NDPI_PROTOCOL_CATEGORY_WEB,               /* Web/mobile protocols and services */
          NDPI_PROTOCOL_CATEGORY_SOCIAL_NETWORK,    /* Social networks */
          NDPI_PROTOCOL_CATEGORY_DOWNLOAD_FT,       /* Download, FTP, file transfer/sharing */
          NDPI_PROTOCOL_CATEGORY_GAME,              /* Online games */
          NDPI_PROTOCOL_CATEGORY_CHAT,              /* Instant messaging */
          NDPI_PROTOCOL_CATEGORY_VOIP,              /* Real-time communications and conferencing */
          NDPI_PROTOCOL_CATEGORY_DATABASE,          /* Protocols for database communication */
          NDPI_PROTOCOL_CATEGORY_REMOTE_ACCESS,     /* Remote access and control */
          NDPI_PROTOCOL_CATEGORY_CLOUD,             /* Online cloud services */
          NDPI_PROTOCOL_CATEGORY_NETWORK,           /* Network infrastructure protocols */
          NDPI_PROTOCOL_CATEGORY_COLLABORATIVE,     /* Software for collaborative development, including Webmail */
          NDPI_PROTOCOL_CATEGORY_RPC,               /* High level network communication protocols */
          NDPI_PROTOCOL_CATEGORY_STREAMING,         /* Streaming protocols */
          NDPI_PROTOCOL_CATEGORY_SYSTEM_OS,         /* System/Operating System level applications */
          NDPI_PROTOCOL_CATEGORY_SW_UPDATE,         /* Software update */

          /* See #define NUM_CUSTOM_CATEGORIES */
          NDPI_PROTOCOL_CATEGORY_CUSTOM_1,          /* User custom category 1 */
          NDPI_PROTOCOL_CATEGORY_CUSTOM_2,          /* User custom category 2 */
          NDPI_PROTOCOL_CATEGORY_CUSTOM_3,          /* User custom category 3 */
          NDPI_PROTOCOL_CATEGORY_CUSTOM_4,          /* User custom category 4 */
          NDPI_PROTOCOL_CATEGORY_CUSTOM_5,          /* User custom category 5 */

          /* Further categories... */
          NDPI_PROTOCOL_CATEGORY_MUSIC,
          NDPI_PROTOCOL_CATEGORY_VIDEO,
          NDPI_PROTOCOL_CATEGORY_SHOPPING,
          NDPI_PROTOCOL_CATEGORY_PRODUCTIVITY,
          NDPI_PROTOCOL_CATEGORY_FILE_SHARING,

          /* Some custom categories */
          CUSTOM_CATEGORY_MINING           = 99,
          CUSTOM_CATEGORY_MALWARE          = 100,
          CUSTOM_CATEGORY_ADVERTISEMENT    = 101,
          CUSTOM_CATEGORY_BANNED_SITE      = 102,
          CUSTOM_CATEGORY_SITE_UNAVAILABLE = 103,
          CUSTOM_CATEGORY_ALLOWED_SITE     = 104,
          /*
        The category below is used to track communications made by
        security applications (e.g. sophosxl.net, spamhaus.org)
        to track malware, spam etc.
          */
          CUSTOM_CATEGORY_ANTIMALWARE      = 105,

          /*
        IMPORTANT

        Please keep in sync with

        static const char* categories[] = { ..}

        in ndpi_main.c
          */

          NDPI_PROTOCOL_NUM_CATEGORIES /*
                         NOTE: Keep this as last member
                         Unused as value but useful to getting the number of elements
                         in this datastructure
                       */
    } ndpi_protocol_category_t;
struct ndpi_detection_module_struct 
  {
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

    void *hyperscan; /* Intel Hyperscan */
    };
/* GNU C */
#define PACK_ON
#define PACK_OFF  __attribute__((packed))

/* NDPI_LOG_LEVEL */
typedef enum {
	      NDPI_LOG_ERROR,
	      NDPI_LOG_TRACE,
	      NDPI_LOG_DEBUG,
	      NDPI_LOG_DEBUG_EXTRA
} ndpi_log_level_t;
typedef enum {
  ndpi_no_tunnel = 0,
  ndpi_gtp_tunnel,
  ndpi_capwap_tunnel,
  ndpi_tzsp_tunnel,
  ndpi_l2tp_tunnel,
} ndpi_packet_tunnel;

/* NDPI_MASK_SIZE */
typedef u_int32_t ndpi_ndpi_mask;

/* NDPI_PROTO_BITMASK_STRUCT */
typedef struct ndpi_protocol_bitmask_struct {
  ndpi_ndpi_mask fds_bits[NDPI_NUM_FDS_BITS];
} ndpi_protocol_bitmask_struct_t;
/**************************************** */
struct ndpi_packet_struct 
{
  const struct ndpi_iphdr *iph;
#ifdef NDPI_DETECTION_SUPPORT_IPV6
  const struct ndpi_ipv6hdr *iphv6;
#endif
  const struct ndpi_tcphdr *tcp;
  const struct ndpi_udphdr *udp;
  const u_int8_t *generic_l4_ptr;	/* is set only for non tcp-udp traffic */
  const u_int8_t *payload;

  u_int32_t tick_timestamp;
  u_int64_t tick_timestamp_l;

  u_int16_t detected_protocol_stack[NDPI_PROTOCOL_SIZE];
  u_int8_t detected_subprotocol_stack[NDPI_PROTOCOL_SIZE];

#ifndef WIN32
  __attribute__ ((__packed__))
#endif
  u_int16_t protocol_stack_info;

  struct ndpi_int_one_line_struct line[NDPI_MAX_PARSE_LINES_PER_PACKET];
  /* HTTP headers */
  struct ndpi_int_one_line_struct host_line;
  struct ndpi_int_one_line_struct forwarded_line;
  struct ndpi_int_one_line_struct referer_line;
  struct ndpi_int_one_line_struct content_line;
  struct ndpi_int_one_line_struct accept_line;
  struct ndpi_int_one_line_struct user_agent_line;
  struct ndpi_int_one_line_struct http_url_name;
  struct ndpi_int_one_line_struct http_encoding;
  struct ndpi_int_one_line_struct http_transfer_encoding;
  struct ndpi_int_one_line_struct http_contentlen;
  struct ndpi_int_one_line_struct http_cookie;
  struct ndpi_int_one_line_struct http_origin;
  struct ndpi_int_one_line_struct http_x_session_type;
  struct ndpi_int_one_line_struct server_line;
  struct ndpi_int_one_line_struct http_method;
  struct ndpi_int_one_line_struct http_response; /* the first "word" in this pointer is the
						    response code in the packet (200, etc) */
  u_int8_t http_num_headers; /* number of found (valid) header lines in HTTP request or response */

  u_int16_t l3_packet_len;
  u_int16_t l4_packet_len;
  u_int16_t payload_packet_len;
  u_int16_t actual_payload_len;
  u_int16_t num_retried_bytes;
  u_int16_t parsed_lines;
  u_int16_t parsed_unix_lines;
  u_int16_t empty_line_position;
  u_int8_t tcp_retransmission;
  u_int8_t l4_protocol;

  u_int8_t tls_certificate_detected:4, tls_certificate_num_checks:4;
  u_int8_t packet_lines_parsed_complete:1,
    packet_direction:1, empty_line_position_set:1, pad:5;
};
/*********************************************************** */
struct ndpi_flow_struct {
  u_int16_t detected_protocol_stack[NDPI_PROTOCOL_SIZE];
#ifndef WIN32
  __attribute__ ((__packed__))
#endif
  u_int16_t protocol_stack_info;

  /* init parameter, internal used to set up timestamp,... */
  u_int16_t guessed_protocol_id, guessed_host_protocol_id, guessed_category, guessed_header_category;
  u_int8_t l4_proto, protocol_id_already_guessed:1, host_already_guessed:1,
    init_finished:1, setup_packet_direction:1, packet_direction:1, check_extra_packets:1;

  /*
    if ndpi_struct->direction_detect_disable == 1
    tcp sequence number connection tracking
  */
  u_int32_t next_tcp_seq_nr[2];

  u_int8_t max_extra_packets_to_check;
  u_int8_t num_extra_packets_checked;
  u_int8_t num_processed_pkts; /* <= WARNING it can wrap but we do expect people to giveup earlier */

  int (*extra_packets_func) (struct ndpi_detection_module_struct *, struct ndpi_flow_struct *flow);

  /*
    the tcp / udp / other l4 value union
    used to reduce the number of bytes for tcp or udp protocol states
  */
  union {
    struct ndpi_flow_tcp_struct tcp;
    struct ndpi_flow_udp_struct udp;
  } l4;

  /*
    Pointer to src or dst that identifies the
    server of this connection
  */
  struct ndpi_id_struct *server_id;
  /* HTTP host or DNS query */
  u_char host_server_name[256];

  /*
    This structure below will not not stay inside the protos
    structure below as HTTP is used by many subprotocols
    such as FaceBook, Google... so it is hard to know
    when to use it or not. Thus we leave it outside for the
    time being.
  */
  struct {
    ndpi_http_method method;
    char *url, *content_type, *user_agent;
    u_int8_t num_request_headers, num_response_headers;
    u_int8_t request_version; /* 0=1.0 and 1=1.1. Create an enum for this? */
    u_int16_t response_status_code; /* 200, 404, etc. */
  } http;

  union {
    /* the only fields useful for nDPI and ntopng */
    struct {
      u_int8_t num_queries, num_answers, reply_code, is_query;
      u_int16_t query_type, query_class, rsp_type;
      ndpi_ip_addr_t rsp_addr; /* The first address in a DNS response packet */
    } dns;

    struct {
      u_int8_t request_code;
      u_int8_t version;
    } ntp;

    struct {
      
      char hostname[24], domain[24], username[24];
    } kerberos;

    struct {
      struct {
	u_int16_t ssl_version;
	char client_certificate[64], server_certificate[64], server_organization[64];
	u_int32_t notBefore, notAfter;
	char ja3_client[33], ja3_server[33];
	u_int16_t server_cipher;
	ndpi_cipher_weakness server_unsafe_cipher;
      } ssl;

      struct {
	u_int8_t num_udp_pkts, num_processed_pkts, num_binding_requests;
      } stun;

      /* We can have STUN over SSL/TLS thus they need to live together */
    } stun_ssl;

    struct {
      char client_signature[48], server_signature[48];
      char hassh_client[33], hassh_server[33];
    } ssh;

    struct {
      u_int8_t last_one_byte_pkt, last_byte;
    } imo;
    
    struct {
      u_int8_t username_detected:1, username_found:1,
	password_detected:1, password_found:1,
	skip_next:1, _pad:3;
      u_int8_t character_id;
      char username[32], password[32];
    } telnet;
    
    struct {
      char answer[96];
    } mdns;

    struct {
      char version[32];
    } ubntac2;

    struct {
      /* Via HTTP User-Agent */
      u_char detected_os[32];
      /* Via HTTP X-Forwarded-For */
      u_char nat_ip[24];
    } http;

    struct {
      u_int8_t auth_found:1, auth_failed:1, _pad:5;
      char username[16], password[16];
    } ftp_imap_pop_smtp;
  
    struct {
      /* Bittorrent hash */
      u_char hash[20];
    } bittorrent;

    struct {
      char fingerprint[48];
      char class_ident[48];
    } dhcp;
  } protos;

  /*** ALL protocol specific 64 bit variables here ***/

  /* protocols which have marked a connection as this connection cannot be protocol XXX, multiple u_int64_t */
  NDPI_PROTOCOL_BITMASK excluded_protocol_bitmask;

  ndpi_protocol_category_t category;

  /* NDPI_PROTOCOL_REDIS */
  u_int8_t redis_s2d_first_char, redis_d2s_first_char;

  u_int16_t packet_counter;		      // can be 0 - 65000
  u_int16_t packet_direction_counter[2];
  u_int16_t byte_counter[2];
  /* NDPI_PROTOCOL_BITTORRENT */
  u_int8_t bittorrent_stage;		      // can be 0 - 255

  /* NDPI_PROTOCOL_DIRECTCONNECT */
  u_int8_t directconnect_stage:2;	      // 0 - 1

  /* NDPI_PROTOCOL_YAHOO */
  u_int8_t sip_yahoo_voice:1;

  /* NDPI_PROTOCOL_HTTP */
  u_int8_t http_detected:1;

  /* NDPI_PROTOCOL_RTSP */
  u_int8_t rtsprdt_stage:2, rtsp_control_flow:1;

  /* NDPI_PROTOCOL_YAHOO */
  u_int8_t yahoo_detection_finished:2;

  /* NDPI_PROTOCOL_ZATTOO */
  u_int8_t zattoo_stage:3;

  /* NDPI_PROTOCOL_QQ */
  u_int8_t qq_stage:3;

  /* NDPI_PROTOCOL_THUNDER */
  u_int8_t thunder_stage:2;		        // 0 - 3

  /* NDPI_PROTOCOL_OSCAR */
  u_int8_t oscar_ssl_voice_stage:3, oscar_video_voice:1;

  /* NDPI_PROTOCOL_FLORENSIA */
  u_int8_t florensia_stage:1;

  /* NDPI_PROTOCOL_SOCKS */
  u_int8_t socks5_stage:2, socks4_stage:2;      // 0 - 3

  /* NDPI_PROTOCOL_EDONKEY */
  u_int8_t edonkey_stage:2;	                // 0 - 3

  /* NDPI_PROTOCOL_FTP_CONTROL */
  u_int8_t ftp_control_stage:2;

  /* NDPI_PROTOCOL_RTMP */
  u_int8_t rtmp_stage:2;

  /* NDPI_PROTOCOL_PANDO */
  u_int8_t pando_stage:3;

  /* NDPI_PROTOCOL_STEAM */
  u_int16_t steam_stage:3, steam_stage1:3, steam_stage2:2, steam_stage3:2;

  /* NDPI_PROTOCOL_PPLIVE */
  u_int8_t pplive_stage1:3, pplive_stage2:2, pplive_stage3:2;

  /* NDPI_PROTOCOL_STARCRAFT */
  u_int8_t starcraft_udp_stage : 3;	// 0-7

  /* NDPI_PROTOCOL_OPENVPN */
  u_int8_t ovpn_session_id[8];
  u_int8_t ovpn_counter;

  /* NDPI_PROTOCOL_TINC */
  u_int8_t tinc_state;
  struct tinc_cache_entry tinc_cache_entry;

  /* NDPI_PROTOCOL_CSGO */
  u_int8_t csgo_strid[18],csgo_state,csgo_s2;
  u_int32_t csgo_id2;

  /* NDPI_PROTOCOL_1KXUN || NDPI_PROTOCOL_IQIYI */
  u_int16_t kxun_counter, iqiyi_counter;

  /* internal structures to save functions calls */
  struct ndpi_packet_struct packet;
  struct ndpi_flow_struct *flow;
  struct ndpi_id_struct *src;
  struct ndpi_id_struct *dst;
};

/* ++++++++++++++++++++++++ IP header ++++++++++++++++++++++++ */

PACK_ON
struct ndpi_iphdr {
#if defined(__LITTLE_ENDIAN__)
  u_int8_t ihl:4, version:4;
#elif defined(__BIG_ENDIAN__)
  u_int8_t version:4, ihl:4;
#else
# error "Byte order must be defined"
#endif
  u_int8_t tos;
  u_int16_t tot_len;
  u_int16_t id;
  u_int16_t frag_off;
  u_int8_t ttl;
  u_int8_t protocol;
  u_int16_t check;
  u_int32_t saddr;
  u_int32_t daddr;
} PACK_OFF;

/* +++++++++++++++++++++++ IPv6 header +++++++++++++++++++++++ */
/* rfc3542 */

PACK_ON
struct ndpi_in6_addr {
  union {
    u_int8_t   u6_addr8[16];
    u_int16_t  u6_addr16[8];
    u_int32_t  u6_addr32[4];
    u_int64_t  u6_addr64[2];
  } u6_addr;  /* 128-bit IP6 address */
} PACK_OFF;

PACK_ON
struct ndpi_ip6_hdrctl {
  u_int32_t ip6_un1_flow;
  u_int16_t ip6_un1_plen;
  u_int8_t ip6_un1_nxt;
  u_int8_t ip6_un1_hlim;
} PACK_OFF;

PACK_ON
struct ndpi_ipv6hdr {
  struct ndpi_ip6_hdrctl ip6_hdr;
  struct ndpi_in6_addr ip6_src;
  struct ndpi_in6_addr ip6_dst;
} PACK_OFF;
/* +++++++++++++++++++++++ TCP header +++++++++++++++++++++++ */

PACK_ON
struct ndpi_tcphdr
{
  u_int16_t source;
  u_int16_t dest;
  u_int32_t seq;
  u_int32_t ack_seq;
#if defined(__LITTLE_ENDIAN__)
  u_int16_t res1:4, doff:4, fin:1, syn:1, rst:1, psh:1, ack:1, urg:1, ece:1, cwr:1;
#elif defined(__BIG_ENDIAN__)
  u_int16_t doff:4, res1:4, cwr:1, ece:1, urg:1, ack:1, psh:1, rst:1, syn:1, fin:1;
#else
# error "Byte order must be defined"
#endif
  u_int16_t window;
  u_int16_t check;
  u_int16_t urg_ptr;
} PACK_OFF;

/* +++++++++++++++++++++++ UDP header +++++++++++++++++++++++ */

PACK_ON
struct ndpi_udphdr
{
  u_int16_t source;
  u_int16_t dest;
  u_int16_t len;
  u_int16_t check;
} PACK_OFF;
typedef struct ndpi_proto {
  /*
    Note
    below we do not use ndpi_protocol_id_t as users can define their own
    custom protocols and thus the typedef could be too short in size.
  */
  u_int16_t master_protocol /* e.g. HTTP */, app_protocol /* e.g. FaceBook */;
  ndpi_protocol_category_t category;
} ndpi_protocol;