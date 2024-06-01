#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dispatcher.h>
#include <rules.h>

int run(const int *argc, char ***argv) {
    // Инициализация правил
    init_rules();

    int exit_code = EXIT_SUCCESS;

    // Обработка аргументов командной строки
    if (*argc > 1) {
        if (strcmp((*argv)[1], "-r") == 0 || strcmp((*argv)[1], "--rules") == 0) {
            print_rules();
        } else {
            fprintf(stderr, "Unknown option: %s\nUsage: %s [-r | --rules]\n", (*argv)[1], (*argv)[0]);
            exit_code = EXIT_FAILURE;
        }
    } else {
        // Если аргументов нет, продолжаем выполнение
        printf("No arguments provided. Continuing execution...\n");
    }

    return exit_code;
}
