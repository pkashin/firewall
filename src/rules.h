#ifndef SRC_RULES_H_
#define SRC_RULES_H_

#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdbool.h>
#include <network_utils.h>

// Максимальное количество правил
#define MAX_RULES 100

typedef struct {
    struct in_addr src;
    int src_prefix;
    struct in_addr dst;
    int dst_prefix;
    protocol_t proto;
    verdict_t verdict;
} rule_t;

extern rule_t rules[MAX_RULES];
extern int rules_count;

bool add_rule(const char *src_ip, int src_prefix, const char *dst_ip,
              int dst_prefix, protocol_t proto, verdict_t verdict);
void init_rules(void);
void print_rules(void);

#endif  // SRC_RULES_H_
