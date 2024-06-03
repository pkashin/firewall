#include <check.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "dispatcher.h"
#include "firewall.h"
#include "packet_utils.h"
#include "rules.h"

// Mock functions
void* mock_allocate_memory(size_t size) {
    (void)size;  // Избегаем предупреждения о неиспользуемом параметре
    return NULL;  // Всегда возвращаем NULL для моделирования ошибки выделения памяти
}

START_TEST(test_is_valid_ip) {
    ck_assert(is_valid_ip("192.168.1.1"));
    ck_assert(!is_valid_ip("256.256.256.256"));
    ck_assert(!is_valid_ip("invalid_ip"));
}
END_TEST

START_TEST(test_is_valid_prefix) {
    ck_assert(is_valid_prefix(24));
    ck_assert(!is_valid_prefix(33));
    ck_assert(!is_valid_prefix(-1));
}
END_TEST

START_TEST(test_ip2bin) {
    struct in_addr addr = ip2bin("192.168.1.1");
    ck_assert_str_eq(inet_ntoa(addr), "192.168.1.1");

    // Проверка на некорректный IP-адрес
    struct in_addr invalid_addr = ip2bin("999.999.999.999");
    ck_assert_int_eq(invalid_addr.s_addr, INADDR_NONE);
}
END_TEST

START_TEST(test_proto2str) {
    ck_assert_str_eq(proto2str(TCP), "TCP");
    ck_assert_str_eq(proto2str(UDP), "UDP");
    ck_assert_str_eq(proto2str(ANY), "ANY");
}
END_TEST

START_TEST(test_num2proto) {
    ck_assert_int_eq(num2proto(&(int){6}), TCP);
    ck_assert_int_eq(num2proto(&(int){17}), UDP);
    ck_assert_int_eq(num2proto(&(int){-1}), ANY);
    ck_assert_int_eq(num2proto(&(int){999}), ANY);  // Invalid protocol number
}
END_TEST

START_TEST(test_verdict2str) {
    ck_assert_str_eq(verdict2str(ACCEPT), "ACCEPT");
    ck_assert_str_eq(verdict2str(DROP), "DROP");

    // Проверка для неверного значения вердикта
    verdict_t invalid_verdict = (verdict_t)999;
    ck_assert_str_eq(verdict2str(invalid_verdict), "");
}
END_TEST

START_TEST(test_match_ip) {
    struct in_addr rule_ip, packet_ip1, packet_ip2;
    rule_ip.s_addr = inet_addr("192.168.1.0");
    packet_ip1.s_addr = inet_addr("192.168.1.1");
    packet_ip2.s_addr = inet_addr("192.168.2.1");

    // Проверка совпадения для префикса 24
    int prefix_24 = 24;
    ck_assert(match_ip(rule_ip, prefix_24, packet_ip1));
    ck_assert(!match_ip(rule_ip, prefix_24, packet_ip2));

    // Проверка совпадения для префикса 32
    int prefix_32 = 32;
    ck_assert(!match_ip(rule_ip, prefix_32, packet_ip1));
    ck_assert(match_ip(rule_ip, prefix_32, rule_ip));

    // Проверка совпадения для префикса 0
    int prefix_0 = 0;
    struct in_addr any_ip;
    any_ip.s_addr = inet_addr("0.0.0.0");
    ck_assert(match_ip(any_ip, prefix_0, any_ip));
}
END_TEST

START_TEST(test_check_packet) {
    rule_t test_rules[] = {
            {ip2bin("192.168.1.1"), 32, ip2bin("10.0.0.1"), 32, TCP, ACCEPT},
            {ip2bin("192.168.1.0"), 24, ip2bin("10.0.0.0"), 24, UDP, DROP}
    };
    rules = test_rules;
    rules_count = 2;

    packet_t packet1 = {ip2bin("192.168.1.1"), ip2bin("10.0.0.1"), TCP};
    packet_t packet2 = {ip2bin("192.168.1.2"), ip2bin("10.0.0.2"), UDP};

    ck_assert_int_eq(check_packet(&packet1), ACCEPT);
    ck_assert_int_eq(check_packet(&packet2), DROP);
}
END_TEST

START_TEST(test_init_rules) {
    ck_assert_int_eq(init_rules(), EXIT_SUCCESS);
    ck_assert_int_eq(rules_count, 8);
    free_rules();

    allocate_memory = mock_allocate_memory;
    ck_assert_int_eq(init_rules(), EXIT_FAILURE);
    ck_assert_ptr_null(rules);
    free_rules();
}
END_TEST

START_TEST(test_print_rules) {
    init_rules();
    print_rules();
    free_rules();
}
END_TEST

START_TEST(test_free_rules) {
    init_rules();
    free_rules();
    ck_assert_ptr_eq(rules, NULL);
    ck_assert_int_eq(rules_count, 0);
}
END_TEST

START_TEST(test_parse_pkts) {
    init_rules();

    // Redirect stdin to a string
    const char *input = "192.168.1.1 10.0.0.1 1234 5678 6\n";
    FILE *input_stream = fmemopen((void *)input, strlen(input), "r");
    FILE *original_stdin = stdin;
    stdin = input_stream;

    parse_pkts();

    // Restore stdin
    stdin = original_stdin;
    fclose(input_stream);

    free_rules();
}
END_TEST

START_TEST(test_run_no_args) {
    init_rules();

    // Redirect stdin to a temporary file to avoid infinite wait
    char temp_filename[] = "/tmp/test_run_no_args.XXXXXX";
    int temp_fd = mkstemp(temp_filename);
    if (temp_fd == -1) {
        perror("mkstemp");
        ck_abort_msg("Failed to create temporary file");
    }
    FILE *input_stream = fdopen(temp_fd, "r");
    if (!input_stream) {
        perror("fdopen");
        ck_abort_msg("Failed to open temporary file stream");
    }
    FILE *original_stdin = stdin;
    stdin = input_stream;

    char *argv[] = {"program_name"};
    int argc = 1;
    ck_assert_int_eq(run(argc, argv), EXIT_SUCCESS);

    // Restore stdin
    stdin = original_stdin;
    fclose(input_stream);
    unlink(temp_filename);

    free_rules();
}
END_TEST

START_TEST(test_run_with_args_rules) {
    init_rules();

    // Redirect stdin to a temporary file to avoid infinite wait
    char temp_filename[] = "/tmp/test_run_with_args_rules.XXXXXX";
    int temp_fd = mkstemp(temp_filename);
    if (temp_fd == -1) {
        perror("mkstemp");
        ck_abort_msg("Failed to create temporary file");
    }
    FILE *input_stream = fdopen(temp_fd, "r");
    if (!input_stream) {
        perror("fdopen");
        ck_abort_msg("Failed to open temporary file stream");
    }
    FILE *original_stdin = stdin;
    stdin = input_stream;

    char *argv[] = {"program_name", "-r"};
    int argc = 2;
    ck_assert_int_eq(run(argc, argv), EXIT_SUCCESS);

    // Restore stdin
    stdin = original_stdin;
    fclose(input_stream);
    unlink(temp_filename);

    free_rules();
}
END_TEST

START_TEST(test_run_with_args_unknown) {
    init_rules();

    char *argv[] = {"program_name", "-x"};
    int argc = 2;
    ck_assert_int_eq(run(argc, argv), EXIT_FAILURE);

    free_rules();
}
END_TEST

START_TEST(test_run_init_rules_failure) {
    allocate_memory = mock_allocate_memory;
    init_rules();

    char *argv[] = {"program_name"};
    int argc = 1;

    ck_assert_int_eq(run(argc, argv), EXIT_FAILURE);

    free_rules();
}
END_TEST

START_TEST(test_parse_pkts_invalid_ip) {
    init_rules();

    // Redirect stdin to a string with invalid IP addresses
    const char *input = "256.256.256.256 256.256.256.256 1234 5678 6\n";
    FILE *input_stream = fmemopen((void *)input, strlen(input), "r");
    FILE *original_stdin = stdin;
    stdin = input_stream;

    parse_pkts();

    // Restore stdin
    stdin = original_stdin;
    fclose(input_stream);

    free_rules();
}
END_TEST

START_TEST(test_parse_pkts_invalid_format) {
    init_rules();

    // Redirect stdin to a string with invalid format
    const char *input = "invalid input format\n";
    FILE *input_stream = fmemopen((void *)input, strlen(input), "r");
    FILE *original_stdin = stdin;
    stdin = input_stream;

    parse_pkts();

    // Restore stdin
    stdin = original_stdin;
    fclose(input_stream);

    free_rules();
}
END_TEST

Suite *firewall_suite(void) {
    Suite *s;
    TCase *tc_core;

    s = suite_create("Firewall");

    /* Core test case */
    tc_core = tcase_create("Core");

    tcase_add_test(tc_core, test_is_valid_ip);
    tcase_add_test(tc_core, test_is_valid_prefix);
    tcase_add_test(tc_core, test_ip2bin);
    tcase_add_test(tc_core, test_proto2str);
    tcase_add_test(tc_core, test_num2proto);
    tcase_add_test(tc_core, test_verdict2str);
    tcase_add_test(tc_core, test_match_ip);
    tcase_add_test(tc_core, test_check_packet);
    tcase_add_test(tc_core, test_init_rules);
    tcase_add_test(tc_core, test_print_rules);
    tcase_add_test(tc_core, test_free_rules);
    tcase_add_test(tc_core, test_parse_pkts);
    tcase_add_test(tc_core, test_parse_pkts_invalid_ip);
    tcase_add_test(tc_core, test_parse_pkts_invalid_format);
    tcase_add_test(tc_core, test_run_no_args);
    tcase_add_test(tc_core, test_run_with_args_rules);
    tcase_add_test(tc_core, test_run_with_args_unknown);
    tcase_add_test(tc_core, test_run_init_rules_failure);
    suite_add_tcase(s, tc_core);

    return s;
}

int main(void) {
    int number_failed;
    Suite *s;
    SRunner *sr;

    s = firewall_suite();
    sr = srunner_create(s);

    srunner_run_all(sr, CK_NORMAL);
    number_failed = srunner_ntests_failed(sr);
    srunner_free(sr);
    return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}
