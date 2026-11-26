typedef unsigned long long word;
__declspec(noinline) word forward_word(word x) {
    return x ^ 0x37;
}
__declspec(noinline) word rotate_or_forward(word x, word pivot) {
    if (x == pivot) {
        word rotated = (x << 16) | (x >> 48);
        if ((rotated & 0xffffu) == 0) return rotated;
        x = (rotated >> 16) | (rotated << 48);
    }
    return forward_word(x);
}
