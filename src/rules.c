#include <stdio.h>
#include <stdbool.h>
#include <network_utils.h>
#include <rules.h>

// Максимальное количество правил
#define MAX_RULES 100

rule_t rules[MAX_RULES];  // Определение массива правил
int rules_count = 0;      // Количество правил

// Добавление правила
// Добавление правила
bool add_rule(const char *src_ip, int src_prefix, const char *dst_ip,
              int dst_prefix, protocol_t proto, verdict_t verdict) {
    bool result = false;
    if (rules_count >= MAX_RULES) {
        fprintf(stderr, "Rule limit exceeded\n");
    } else {
        rule_t *rule = &rules[rules_count];
        rule->src.s_addr = ip2bin(src_ip).s_addr;
        rule->src_prefix = src_prefix;
        rule->dst.s_addr = ip2bin(dst_ip).s_addr;
        rule->dst_prefix = dst_prefix;
        rule->proto = proto;
        rule->verdict = verdict;

        rules_count++;
        result = true;
    }

    return result;
}

/*
 * Примечание по заполнению правил:
 * 1. Если IP-адрес без префикса, то префикс равен 32
 * 2. Если IP-адрес отсутствует, то он равен 0.0.0.0 и префикс равен 0
 * 3. Если протокол отсутствует, то он равен ANY
 * 4. Отсутствие вердикта недопустимо - это ошибка исходных данных
 */

// Инициализация правил
void init_rules() {
    add_rule("10.0.1.11", 32, "1.1.1.1", 32, TCP, ACCEPT);
    add_rule("10.0.2.12", 32, "1.1.1.1", 32, TCP, DROP);
    add_rule("10.0.2.12", 32, "8.8.8.8", 32, TCP, ACCEPT);
    add_rule("10.0.3.13", 32, "0.0.0.0", 0, ANY, ACCEPT);
    add_rule("0.0.0.0", 0, "1.2.3.4", 32, UDP, DROP);
    add_rule("0.0.0.0", 0, "1.2.3.4", 32, ANY, ACCEPT);
    add_rule("0.0.0.0", 0, "10.0.9.1", 32, TCP, DROP);
    add_rule("10.0.5.0", 24, "0.0.0.0", 0, ANY, ACCEPT);
//    add_rule("255.255.255.255", 24, "255.255.255.255", 0, ANY, ACCEPT);
}

// Вывод правил
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
