#include <check.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <network_utils.h>

// Тест для ip2bin
START_TEST(test_ip2bin_valid_ip) {
    const char *ip_str = "192.168.1.1";
    struct in_addr ip_bin = ip2bin(ip_str);
    ck_assert_uint_ne(ip_bin.s_addr, INADDR_NONE);
}
END_TEST

START_TEST(test_ip2bin_invalid_ip) {
    const char *ip_str = "invalid_ip";
    struct in_addr ip_bin = ip2bin(ip_str);
    ck_assert_uint_eq(ip_bin.s_addr, INADDR_NONE);
}
END_TEST

// Тест для ip2str
START_TEST(test_ip2str) {
    struct in_addr ip_bin;
    ip_bin.s_addr = inet_addr("192.168.1.1");
    char buffer[INET_ADDRSTRLEN];
    const char *ip_str = ip2str(ip_bin, buffer, INET_ADDRSTRLEN);
    ck_assert_str_eq(ip_str, "192.168.1.1");
}
END_TEST

// Тест для proto2str
START_TEST(test_proto2str_tcp) {
    ck_assert_str_eq(proto2str(TCP), "TCP");
}
END_TEST

START_TEST(test_proto2str_udp) {
    ck_assert_str_eq(proto2str(UDP), "UDP");
}
END_TEST

START_TEST(test_proto2str_any) {
    ck_assert_str_eq(proto2str(ANY), "ANY");
}
END_TEST

START_TEST(test_proto2str_invalid) {
    ck_assert_str_eq(proto2str(-1), "");  // Проверка для некорректного значения
}
END_TEST

// Тест для verdict2str
START_TEST(test_verdict2str_accept) {
    ck_assert_str_eq(verdict2str(ACCEPT), "ACCEPT");
}
END_TEST

START_TEST(test_verdict2str_drop) {
    ck_assert_str_eq(verdict2str(DROP), "DROP");
}
END_TEST

START_TEST(test_verdict2str_invalid) {
    ck_assert_str_eq(verdict2str(-1), "");  // Проверка для некорректного значения
}
END_TEST

// Создание тестового набора
Suite *network_utils_suite(void) {
    Suite *s;
    TCase *tc_core;

    s = suite_create("NetworkUtils");

    /* Core test case */
    tc_core = tcase_create("Core");

    tcase_add_test(tc_core, test_ip2bin_valid_ip);
    tcase_add_test(tc_core, test_ip2bin_invalid_ip);
    tcase_add_test(tc_core, test_ip2str);
    tcase_add_test(tc_core, test_proto2str_tcp);
    tcase_add_test(tc_core, test_proto2str_udp);
    tcase_add_test(tc_core, test_proto2str_any);
    tcase_add_test(tc_core, test_proto2str_invalid);
    tcase_add_test(tc_core, test_verdict2str_accept);
    tcase_add_test(tc_core, test_verdict2str_drop);
    tcase_add_test(tc_core, test_verdict2str_invalid);
    suite_add_tcase(s, tc_core);

    return s;
}

// Запуск тестов
int main(void) {
    int number_failed;
    Suite *s;
    SRunner *sr;

    s = network_utils_suite();
    sr = srunner_create(s);

    srunner_run_all(sr, CK_NORMAL);
    number_failed = srunner_ntests_failed(sr);
    srunner_free(sr);
    return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}
