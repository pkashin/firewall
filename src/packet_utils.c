#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <packet_utils.h>
#include <firewall.h>

// Структура для хранения пакета
typedef struct {
    char src_ip[INET_ADDRSTRLEN];
    char dst_ip[INET_ADDRSTRLEN];
    int src_port;
    int dst_port;
    int proto;
} packet_src_t;

// Обработка пакетов из стандартного ввода
void parse_pkts() {
    char line[MAX_LINE_LENGTH];

    while (fgets(line, sizeof(line), stdin)) {
        // Создаем объект для хранения пакета
        packet_src_t packet;
        memset(&packet, 0, sizeof(packet));  // Инициализация структуры
        if (sscanf(line, "%15s %15s %d %d %d",
                   packet.src_ip, packet.dst_ip,
                   &packet.src_port, &packet.dst_port,
                   &packet.proto) != 5) {
            fprintf(stderr, "Invalid input format\n");
            continue;
        } else {
            // Проверка корректности IP-адресов и протокола
            if (!is_valid_ip(packet.src_ip) || !is_valid_ip(packet.dst_ip)||
                (num2proto(&packet.proto) == ANY)) {
                fprintf(stderr, "Invalid IP address or protocol: %s or %s or %d\n",
                        packet.src_ip, packet.dst_ip, packet.proto);
                continue;
            } else {
                // Создаем структуру to_check
                packet_t to_check;
                to_check.src = ip2bin(packet.src_ip);
                to_check.dst = ip2bin(packet.dst_ip);
                to_check.proto = num2proto(&packet.proto);

                // Передаем структуру функции check_packet
                verdict_t verdict = check_packet(&to_check);
                printf("%s\n", verdict2str(verdict));
            }
        }
    }
}

// Функция для проверки корректности IP-адресов
bool is_valid_ip(const char *ip) {
    struct in_addr addr;
    return inet_pton(AF_INET, ip, &addr);
}

// Функция для проверки корректности префикса
bool is_valid_prefix(int prefix) {
    return prefix >= 0 && prefix <= 32;
}

// Преобразования строкового IP-адреса в бинарный формат
struct in_addr ip2bin(const char *ip_str) {
    struct in_addr ip_bin;
    if (inet_pton(AF_INET, ip_str, &ip_bin) != 1) {
        perror("inet_pton");
        ip_bin.s_addr = INADDR_NONE;  // Устанавливаем недопустимый адрес
    }
    return ip_bin;
}

// Преобразование IP-адреса из бинарного формата в строковый
const char* ip2str(struct in_addr ip, char *buffer, size_t buffer_size) {
    inet_ntop(AF_INET, &ip, buffer, buffer_size);
    return buffer;
}

// Преобразование протокола в строку для вывода правил
const char* proto2str(protocol_t proto) {
    const char* result;

    switch (proto) {
        case TCP:
            result = "TCP";
            break;
        case UDP:
            result = "UDP";
            break;
        case ANY:
            result = "ANY";
            break;
    }

    return result;
}

// Преобразование числа в протокол
protocol_t num2proto(const int *num) {
    protocol_t result = ANY;

    if (*num == 6) {
        result = TCP;
    } else if (*num == 17) {
        result = UDP;
    }

    return result;
}

// Преобразование вердикта в строку
const char* verdict2str(verdict_t verdict) {
    switch (verdict) {
        case ACCEPT: return "ACCEPT";
        case DROP: return "DROP";
    }
    return "";
}
