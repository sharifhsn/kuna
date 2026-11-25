// A freestanding CodeView fixture with one inline site in each named caller.
static __forceinline unsigned scale_and_bias(unsigned value) {
    volatile unsigned scaled = value * 3;
    return scaled + 7;
}

extern "C" __declspec(noinline) unsigned sample_left(unsigned value) {
    return scale_and_bias(value) + 11;
}

extern "C" __declspec(noinline) unsigned sample_right(unsigned value) {
    return scale_and_bias(value) * 5;
}

extern "C" unsigned mainCRTStartup() {
    return sample_left(2) + sample_right(4);
}
