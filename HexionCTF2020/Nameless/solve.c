#include <time.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <stdio.h>

unsigned char ___out_txt_orig[] = {
  0x16, 0xec, 0x23, 0xc3, 0x06, 0x01, 0xb1, 0xf0, 0x61, 0x4a, 0xf4, 0x81,
  0x35, 0x16, 0xef, 0xaa, 0x5b, 0x3f, 0x38, 0x51, 0x62, 0x0f, 0x21, 0x13,
  0x64, 0xe7, 0x67, 0xee, 0x41, 0x7b, 0x3a, 0xb9, 0xec, 0xb1
};
unsigned int ___out_txt_orig_len = 34;



int main(void)
{
    time_t current_time = time(NULL);
    while (true)
    {
        printf("Current time: %lu\n", current_time);
        srand(current_time);

        uint8_t test_buf[6] = {0x16, 0xec, 0x23, 0xc3, 0x06, 0x01};
        for (size_t i = 0; i < 6; ++i)
        {
            test_buf[i] ^= ((rand() % 0x666) + 1);
        }

        if (0 == memcmp("hexCTF", test_buf, 6))
        {
            printf("Correct time is: %lu\n", current_time);
            srand(current_time);
            for (size_t i = 0; i < ___out_txt_orig_len; ++i)
            {
                putchar(___out_txt_orig[i] ^ ((rand() % 0x666) + 1));
            }
            putchar('\n');
            break;
        }

        current_time -= 1;
    }

    return 0;
}
