# define NDPI_LOG(proto, mod, log_level, args...) { /* printf(args); */ }
# define NDPI_LOG_ERR(mod, args...)  { printf(args); }
# define NDPI_LOG_INFO(mod, args...) { /* printf(args); */ }
# define NDPI_LOG_DBG(mod,  args...) { /* printf(args); */ }
# define NDPI_LOG_DBG2(mod, args...) { /* printf(args); */ }
#define NDPI_PROTOCOL_BITMASK ndpi_protocol_bitmask_struct_t
/* IMPORTANT: order according to its severity */
#define NDPI_CIPHER_SAFE                        0
#define NDPI_CIPHER_WEAK                        1
#define NDPI_CIPHER_INSECURE                    2
