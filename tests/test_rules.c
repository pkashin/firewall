#include <stdlib.h>
#include <check.h>
#include <rules.h>

// Тест на успешное добавление правила
START_TEST(test_add_rule_success) {
    rules_count = 0;  // Сброс счетчика правил
    bool result = add_rule("192.168.1.1", 32, "192.168.1.2", 32, TCP, ACCEPT);
    ck_assert_msg(result, "Failed to add rule");
    ck_assert_int_eq(rules_count, 1);
    ck_assert_uint_eq(rules[0].src.s_addr, ip2bin("192.168.1.1").s_addr);
    ck_assert_int_eq(rules[0].src_prefix, 32);
    ck_assert_uint_eq(rules[0].dst.s_addr, ip2bin("192.168.1.2").s_addr);
    ck_assert_int_eq(rules[0].dst_prefix, 32);
    ck_assert_int_eq(rules[0].proto, TCP);
    ck_assert_int_eq(rules[0].verdict, ACCEPT);
}
END_TEST

// Тест на превышение лимита правил
START_TEST(test_add_rule_limit_exceeded) {
    rules_count = MAX_RULES;  // Устанавливаем счетчик правил на максимум
    bool result = add_rule("192.168.1.1", 32, "192.168.1.2", 32, TCP, ACCEPT);
    ck_assert_msg(!result, "Rule should not be added when limit is exceeded");
    ck_assert_int_eq(rules_count, MAX_RULES);
}
END_TEST

// Тест на инициализацию правил
START_TEST(test_init_rules) {
    rules_count = 0;  // Сброс счетчика правил
    init_rules();
    ck_assert_int_eq(rules_count, 8);
    // Можно добавить дополнительные проверки для каждого правила
}
END_TEST

// Создание тестового набора
Suite *rules_suite(void) {
    Suite *s;
    TCase *tc_core;

    s = suite_create("Rules");

    /* Core test case */
    tc_core = tcase_create("Core");

    tcase_add_test(tc_core, test_add_rule_success);
    tcase_add_test(tc_core, test_add_rule_limit_exceeded);
    tcase_add_test(tc_core, test_init_rules);
    suite_add_tcase(s, tc_core);

    return s;
}

// Запуск тестов
int main(void) {
    int number_failed;
    Suite *s;
    SRunner *sr;

    s = rules_suite();
    sr = srunner_create(s);

    srunner_run_all(sr, CK_NORMAL);
    number_failed = srunner_ntests_failed(sr);
    srunner_free(sr);

    return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}
