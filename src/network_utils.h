#ifndef SRC_NETWORK_UTILS_H_
#define SRC_NETWORK_UTILS_H_

#include <arpa/inet.h>
#include <netinet/in.h>

// Определение перечисления для протоколов
typedef enum {
    ANY = 0,
    TCP = 6,
    UDP = 17
} protocol_t;

// Определение перечисления для вердиктов
typedef enum {
    ACCEPT,
    DROP
} verdict_t;

struct in_addr ip2bin(const char *ip_str);
const char* ip2str(struct in_addr ip, char *buffer, size_t buffer_size);
const char* proto2str(protocol_t proto);
const char* verdict2str(verdict_t verdict);

#endif  // SRC_NETWORK_UTILS_H_
