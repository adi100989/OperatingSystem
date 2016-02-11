// pass_struct.h
#include "linux/limits.h"
/* Structure for Passing Arguments from User space to Kernel Space */
struct myargs {
        char infile[NAME_MAX];
        char outfile[NAME_MAX];
        int keylen;
        unsigned char keybuf[16];
        int flags; // value 0 as encrypting , value 1 as decrypting
};

