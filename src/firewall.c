#include <firewall.h>
#include <rules.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

verdict_t check_packet(packet_t const *packet) {
    verdict_t verdict = DROP;

    for (int i = 0; i < rules_count; i++) {
        if (packet->proto != rules[i].proto && rules[i].proto != ANY) {
            // Если протокол не совпадает пропускаем правило
            continue;
        } else if (match_ip(rules[i].src, rules[i].src_prefix, packet->src) &&
        match_ip(rules[i].dst, rules[i].dst_prefix, packet->dst)) {
            verdict = rules[i].verdict;
            break;
        }
    }

    return verdict;
}

// Функция для поиска совпадений IP-адресов: пакета и правил файрвола с учетом префикса
bool match_ip(struct in_addr rule_ip, int prefix, struct in_addr packet_ip) {
    int result = false;
    if ((prefix == 0 && rule_ip.s_addr == 0) || (rule_ip.s_addr == packet_ip.s_addr && prefix == 32)) {
        result = true;
    } else {
        struct in_addr mask;

        // Создание маски
        if (prefix == 0) {
            mask.s_addr = 0;
        } else {
            mask.s_addr = htonl(~((1 << (32 - prefix)) - 1));
        }

        result = (packet_ip.s_addr & mask.s_addr) == (rule_ip.s_addr & mask.s_addr);
    }

    return result;
}
