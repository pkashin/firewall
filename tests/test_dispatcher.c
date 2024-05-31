#include <check.h>
#include <stdlib.h>
#include <dispatcher.h>

// Тестовая функция для проверки работы функции run
START_TEST(test_run) {
    int result = run();
    ck_assert_int_eq(result, 0);
}
END_TEST

// Создание тестовой группы
Suite* dispatcher_suite(void) {
    Suite *s;
    TCase *tc_core;

    s = suite_create("Dispatcher");

    /* Core test case */
    tc_core = tcase_create("Core");

    tcase_add_test(tc_core, test_run);

    suite_add_tcase(s, tc_core);

    return s;
}

// Основная функция для запуска тестов
int main(void) {
    int number_failed;
    Suite *s;
    SRunner *sr;

    s = dispatcher_suite();
    sr = srunner_create(s);

    srunner_run_all(sr, CK_NORMAL);
    number_failed = srunner_ntests_failed(sr);
    srunner_free(sr);

    return (number_failed == 0) ? 0 : 1;
}
