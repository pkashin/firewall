#include <stdio.h>
#include <stdlib.h>
#include <rules.h>


// Структура для хранения исходных параметров правил
typedef struct {
    const char *src_ip;
    int src_prefix;
    const char *dst_ip;
    int dst_prefix;
    protocol_t proto;
    verdict_t verdict;
} rule_src_t;

// Глобальные переменные для хранения правил и их количества
rule_t *rules = NULL;
int rules_count = 0;

// Указатель на функцию для выделения памяти
void* (*allocate_memory)(size_t size) = malloc;

// Функция для инициализации правил
int init_rules() {
    int exit_code = EXIT_SUCCESS;
    // Пример добавления правил
    rule_src_t rule_src[] = {
//            {"192.168.1.0", 24, DEFAULT_IP, 0, TCP, ACCEPT},
            {"10.0.1.11", DEFAULT_IP_PREFIX, "1.1.1.1", DEFAULT_IP_PREFIX, TCP, ACCEPT},
            {"10.0.2.12", DEFAULT_IP_PREFIX, "1.1.1.1", DEFAULT_IP_PREFIX, TCP, DROP},
            {"10.0.2.12", DEFAULT_IP_PREFIX, "8.8.8.8", DEFAULT_IP_PREFIX, TCP, ACCEPT},
            {"10.0.3.13", DEFAULT_IP_PREFIX, DEFAULT_IP, 0, DEFAULT_PROTOCOL, ACCEPT},
            {DEFAULT_IP, 0, "1.2.3.4", DEFAULT_IP_PREFIX, UDP, DROP},
            {DEFAULT_IP, 0, "1.2.3.4", DEFAULT_IP_PREFIX, DEFAULT_PROTOCOL, ACCEPT},
            {DEFAULT_IP, 0, "10.0.9.1", DEFAULT_IP_PREFIX, TCP, DROP},
            {"10.0.5.0", 24, DEFAULT_IP, 0, DEFAULT_PROTOCOL, ACCEPT},

            // Правила с некоректными данными - для тестирования
//            {"256.255.255.255", 24, "255.255.255.255", 0, DEFAULT_PROTOCOL, ACCEPT},
//            {"0", 33, "0.255.255.400", 0, DEFAULT_PROTOCOL, ACCEPT},
//            {"256.255.255.255", -1, "255.255.255.255", 0, DEFAULT_PROTOCOL, ACCEPT},
//            {"-1", 24, "255.255.255.255", 0, DEFAULT_PROTOCOL, ACCEPT},
//            {"99999999999999999999", 24, "255.255.255.255", 0, DEFAULT_PROTOCOL, ACCEPT},
//            {DEFAULT_IP, 100, "10.0.9.1", DEFAULT_IP_PREFIX, TCP, DROP},
    };

    // Подсчет количества правил
    rules_count = sizeof(rule_src) / sizeof(rule_src[0]);

    // Динамическое выделение памяти для массива правил
    rules = (rule_t *)allocate_memory(rules_count * sizeof(rule_t));
    if (rules == NULL) {
        fprintf(stderr, "Memory allocation failed\n");
        exit_code = EXIT_FAILURE;
    } else {
        int count = 0;
        for (int i = 0; i < rules_count; i++) {
            // Проверка корректности IP-адресов и префиксов
            if (!is_valid_ip(rule_src[i].src_ip) || !is_valid_ip(rule_src[i].dst_ip) ||
                !is_valid_prefix(rule_src[i].src_prefix) || !is_valid_prefix(rule_src[i].dst_prefix)) {
                fprintf(stderr, "Invalid IP address or prefix: %s/%d or %s/%d\n",
                        rule_src[i].src_ip, rule_src[i].src_prefix,
                        rule_src[i].dst_ip, rule_src[i].dst_prefix);
                continue;
            }

            rule_t *rule = &rules[i];
            rule->src.s_addr = ip2bin(rule_src[i].src_ip).s_addr;
            rule->src_prefix = rule_src[i].src_prefix;
            rule->dst.s_addr = ip2bin(rule_src[i].dst_ip).s_addr;
            rule->dst_prefix = rule_src[i].dst_prefix;
            rule->proto = rule_src[i].proto;
            rule->verdict = rule_src[i].verdict;
            count++;
        }
        rules_count = count;
    }

    return exit_code;
}

// Функция для вывода правил
void print_rules() {
    printf("Total rules: %d\n", rules_count);
    printf("%-6s %-22s %-22s %-10s %-8s\n", "Rule", "Source/Prefix",
           "Destination/Prefix", "Protocol", "Verdict");
    for (int i = 0; i < rules_count; i++) {
        char src_ip[INET_ADDRSTRLEN];
        char dst_ip[INET_ADDRSTRLEN];
        ip2str(rules[i].src, src_ip, INET_ADDRSTRLEN);
        ip2str(rules[i].dst, dst_ip, INET_ADDRSTRLEN);
        printf("%-6d %-15s/%-2d  =>  %-15s/%-2d      %-8s %-8s\n",
               i + 1, src_ip, rules[i].src_prefix, dst_ip, rules[i].dst_prefix,
               proto2str(rules[i].proto), verdict2str(rules[i].verdict));
    }
}

// Функция для освобождения памяти
void free_rules() {
    if (rules != NULL) {
        free(rules);
        rules = NULL;
    }
    rules_count = 0;
}
