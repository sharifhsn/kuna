struct Pair { float lane[2]; };
__declspec(noinline) float sample_lane(const struct Pair *pair, unsigned index) {
    volatile struct Pair copy = *pair;
    return copy.lane[index];
}
static const struct Pair pair = {{1.5f, -2.25f}};
int mainCRTStartup(void) {
    return sample_lane(&pair, 0) != 1.5f || sample_lane(&pair, 1) != -2.25f;
}
int _fltused;
