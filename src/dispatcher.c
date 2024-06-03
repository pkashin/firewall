#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dispatcher.h>
#include <rules.h>

#define MAX_LINE_LENGTH 100

int run(int argc, char **argv) {
    int exit_code = EXIT_SUCCESS;

    // Инициализация правил
    if (init_rules() != EXIT_SUCCESS) {
        fprintf(stderr, "Failed to initialize rules\n");
        exit_code = EXIT_FAILURE;
    // Обработка аргументов командной строки
    } else if (argc > 1) {
        if (strcmp(argv[1], "-r") == 0 || strcmp(argv[1], "--rules") == 0) {
            print_rules();
            parse_pkts();
        } else {
            fprintf(stderr, "Unknown option: %s\nUsage: %s [-r | --rules]\n", argv[1], argv[0]);
            exit_code = EXIT_FAILURE;
        }
    } else {
        parse_pkts();
    }

    // Освобождение памяти
    free_rules();

    return exit_code;
}
