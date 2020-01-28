#define prefix_touchar(prefix) ((u_char *)&(prefix)->add.sin)
#define BIT_TEST(f, b)  ((f) & (b))
patricia_tree_t *ndpi_New_Patricia (int maxbits);
#ifdef WIN32
#define PATRICIA_MAXBITS	128
#else
#define PATRICIA_MAXBITS	(sizeof(struct in6_addr) * 8)
#endif
patricia_node_t *ndpi_patricia_lookup (patricia_tree_t *patricia, prefix_t *prefix);