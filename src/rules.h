#ifndef SRC_RULES_H_
#define SRC_RULES_H_

#include <arpa/inet.h>
#include <netinet/in.h>
#include <packet_utils.h>

// Значения по умолчанию
#define DEFAULT_IP_PREFIX 32
#define DEFAULT_IP "0.0.0.0"
#define DEFAULT_PROTOCOL ANY

// Структура для хранения преобразованных правил
typedef struct {
    struct in_addr src;
    int src_prefix;
    struct in_addr dst;
    int dst_prefix;
    protocol_t proto;
    verdict_t verdict;
} rule_t;

// Глобальные переменные для хранения правил и их количества
extern rule_t *rules;
extern int rules_count;

// Указатель на функцию для выделения памяти
extern void* (*allocate_memory)(size_t size);

int init_rules();
void print_rules();
void free_rules();

#endif  // SRC_RULES_H_
