#include "../config/demo_config.h"

int main(int argc, char *argv[]) {
    if (argc < 2) {
        printf("Usage: %s <text-to-hash>\n", argv[0]);
        return 1;
    }
    const char *input = argv[1];
    compute_and_print_hashes((const uint8_t*)input, strlen(input));
    return 0;
}