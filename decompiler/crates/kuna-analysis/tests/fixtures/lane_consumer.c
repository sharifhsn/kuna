#include <stdint.h>
#include <string.h>
struct Pair { float lane[2]; };
extern float sample_lane(const struct Pair *, unsigned);

int main(void) {
    const uint32_t bits[][2] = {{0x3fc00000,0xc0100000}, {0,0x80000000},
                                {0x7fc00123,0x7f800000}, {0xff800000,1}};
    for (unsigned i=0; i<4; ++i) {
        struct Pair p;
        memcpy(&p, bits[i], sizeof p);
        for (unsigned j=0; j<2; ++j) {
            float v=sample_lane(&p,j);
            uint32_t observed;
            memcpy(&observed,&v,sizeof observed);
            if (observed!=bits[i][j]) return 1;
        }
    }
    return 0;
}
