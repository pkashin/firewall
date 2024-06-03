#ifndef SRC_PACKET_UTILS_H_
#define SRC_PACKET_UTILS_H_

#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdbool.h>
#include <stdint.h>

#define MAX_LINE_LENGTH 100

// Определение перечисления для протоколов
typedef enum {
    ANY = -1,
    TCP = 6,
    UDP = 17
} protocol_t;

// Структура для хранения преобразованного пакета
typedef struct {
    struct in_addr src;
    struct in_addr dst;
    protocol_t proto;
} packet_t;

// Определение перечисления для вердиктов
typedef enum {
    ACCEPT,
    DROP
} verdict_t;

int test();
bool is_valid_ip(const char *ip);
bool is_valid_prefix(int prefix);
struct in_addr ip2bin(const char *ip_str);
const char* ip2str(struct in_addr ip, char *buffer, size_t buffer_size);
const char* proto2str(protocol_t proto);
protocol_t num2proto(const int *num);
const char* verdict2str(verdict_t verdict);

void parse_pkts();

#endif  // SRC_PACKET_UTILS_H_
