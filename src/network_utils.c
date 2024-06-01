#include <network_utils.h>
#include <stdio.h>

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

// Преобразование протокола в строку
const char* proto2str(protocol_t proto) {
    switch (proto) {
        case TCP: return "TCP";
        case UDP: return "UDP";
        case ANY: return "ANY";
    }
    return "";
}

// Преобразование вердикта в строку
const char* verdict2str(verdict_t verdict) {
    switch (verdict) {
        case ACCEPT: return "ACCEPT";
        case DROP: return "DROP";
    }
    return "";
}
