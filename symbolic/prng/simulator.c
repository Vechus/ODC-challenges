#include <stdio.h>
#include <stdlib.h>
#include "MTwister/mtwister.h"

int main(int argc, char **argv) {

    unsigned long seed = atol(argv[1]);
    unsigned long guess = atol(argv[2]);

    //printf("Seed: %lx, guess: %x\n", seed, guess);

    for(unsigned long s = seed; s < seed + 100000000; s++) {
        MTRand r = seedRand(s);
        int i;
        for(i=0; i<1000; i++) {
            genRandLong(&r);
        }
        long gen = genRandLong(&r);
        if(gen == guess) {
            printf("FOUND %lx\n", s);
            break;
        }
    }
     /*else {
        printf("Was %x", gen);
    }*/
    return 0;

}
