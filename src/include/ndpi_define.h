# define NDPI_LOG(proto, mod, log_level, args...) { /* printf(args); */ }
# define NDPI_LOG_ERR(mod, args...)  { printf(args); }
# define NDPI_LOG_INFO(mod, args...) { /* printf(args); */ }
# define NDPI_LOG_DBG(mod,  args...) { /* printf(args); */ }
# define NDPI_LOG_DBG2(mod, args...) { /* printf(args); */ }