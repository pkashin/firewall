#include <check.h>
#include <stdlib.h>
#include <dispatcher.h>

// Тест на проверку вывода правил
START_TEST(test_run_with_rules_argument) {
    int argc = 2;
    char *argv[] = {"program_name", "--rules"};
    char **argv_ptr = argv;

    int result = run(&argc, &argv_ptr);
    ck_assert_int_eq(result, EXIT_SUCCESS);
}
END_TEST

// Тест на проверку неизвестного аргумента
START_TEST(test_run_with_unknown_argument) {
    int argc = 2;
    char *argv[] = {"program_name", "--unknown"};
    char **argv_ptr = argv;

    int result = run(&argc, &argv_ptr);
    ck_assert_int_eq(result, EXIT_FAILURE);
}
END_TEST

// Тест на проверку отсутствия аргументов
START_TEST(test_run_with_no_arguments) {
    int argc = 1;
    char *argv[] = {"program_name"};
    char **argv_ptr = argv;

    int result = run(&argc, &argv_ptr);
    ck_assert_int_eq(result, EXIT_SUCCESS);
}
END_TEST

// Создание тестового набора
Suite *dispatcher_suite(void) {
    Suite *s;
    TCase *tc_core;

    s = suite_create("Dispatcher");

    /* Core test case */
    tc_core = tcase_create("Core");

    tcase_add_test(tc_core, test_run_with_rules_argument);
    tcase_add_test(tc_core, test_run_with_unknown_argument);
    tcase_add_test(tc_core, test_run_with_no_arguments);
    suite_add_tcase(s, tc_core);

    return s;
}

// Запуск тестов
int main(void) {
    int number_failed;
    Suite *s;
    SRunner *sr;

    s = dispatcher_suite();
    sr = srunner_create(s);

    srunner_run_all(sr, CK_NORMAL);
    number_failed = srunner_ntests_failed(sr);
    srunner_free(sr);
    return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}
