typedef unsigned long long word;
extern word rotate_or_forward(word, word);
int mainCRTStartup(void) {
    if (rotate_or_forward(0x123456789abcu, 0x123456789abcu) != 0x123456789abc0000ull) return 1;
    if (rotate_or_forward(0x8000000000000001ull, 0x8000000000000001ull) != 0x8000000000000036ull) return 2;
    if (rotate_or_forward(0x10042u, 99u) != 0x10075u) return 3;
    return 0;
}
