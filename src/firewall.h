#ifndef SRC_FIREWALL_H_
#define SRC_FIREWALL_H_

#include <stdbool.h>
#include <packet_utils.h>

verdict_t check_packet(packet_t const *packet);
bool match_ip(struct in_addr rule_ip, int prefix, struct in_addr packet_ip);

#endif  // SRC_FIREWALL_H_
