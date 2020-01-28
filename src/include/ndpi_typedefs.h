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
