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
/** macro to compare 2 IPv6 addresses with each other to identify the "smaller" IPv6 address  */
#define NDPI_COMPARE_IPV6_ADDRESS_STRUCTS(x,y)  \
  ((x.u6_addr.u6_addr64[0] < y.u6_addr.u6_addr64[0]) || ((x.u6_addr.u6_addr64[0] == y.u6_addr.u6_addr64[0]) && (x.u6_addr.u6_addr64[1] < y.u6_addr.u6_addr64[1])))

#define NDPI_NUM_BITS              512

#define NDPI_BITS /* 32 */ (sizeof(ndpi_ndpi_mask) * 8 /* number of bits in a byte */)        /* bits per mask */
#define howmanybits(x, y)   (((x)+((y)-1))/(y))


#define NDPI_SET(p, n)    ((p)->fds_bits[(n)/NDPI_BITS] |=  (1ul << (((u_int32_t)n) % NDPI_BITS)))
#define NDPI_CLR(p, n)    ((p)->fds_bits[(n)/NDPI_BITS] &= ~(1ul << (((u_int32_t)n) % NDPI_BITS)))
#define NDPI_ISSET(p, n)  ((p)->fds_bits[(n)/NDPI_BITS] &   (1ul << (((u_int32_t)n) % NDPI_BITS)))
#define NDPI_ZERO(p)      memset((char *)(p), 0, sizeof(*(p)))
#define NDPI_ONE(p)       memset((char *)(p), 0xFF, sizeof(*(p)))

#define NDPI_NUM_FDS_BITS     howmanybits(NDPI_NUM_BITS, NDPI_BITS)

#define NDPI_PROTOCOL_BITMASK ndpi_protocol_bitmask_struct_t

#define NDPI_BITMASK_ADD(a,b)     NDPI_SET(&a,b)
#define NDPI_BITMASK_DEL(a,b)     NDPI_CLR(&a,b)
#define NDPI_BITMASK_RESET(a)     NDPI_ZERO(&a)
#define NDPI_BITMASK_SET_ALL(a)   NDPI_ONE(&a)
#define NDPI_BITMASK_SET(a, b)    { memcpy(&a, &b, sizeof(NDPI_PROTOCOL_BITMASK)); }

/* this is a very very tricky macro *g*,
 * the compiler will remove all shifts here if the protocol is static...
 */
#define NDPI_ADD_PROTOCOL_TO_BITMASK(bmask,value)     NDPI_SET(&bmask,value)
#define NDPI_DEL_PROTOCOL_FROM_BITMASK(bmask,value)   NDPI_CLR(&bmask,value)
#define NDPI_COMPARE_PROTOCOL_TO_BITMASK(bmask,value) NDPI_ISSET(&bmask,value)

#define NDPI_SAVE_AS_BITMASK(bmask,value)  { NDPI_ZERO(&bmask) ; NDPI_ADD_PROTOCOL_TO_BITMASK(bmask, value); }


#define ndpi_min(a,b)   ((a < b) ? a : b)
#define ndpi_max(a,b)   ((a > b) ? a : b)
