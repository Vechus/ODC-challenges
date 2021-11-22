#!/usr/bin/env python

# Copyright © 2020 Dr. Henning Kopp, SCHUTZWERK GmbH
#
# Permission is hereby granted, free of charge, to any person
# obtaining a copy of this software and associated documentation files
# (the “Software”), to deal in the Software without restriction,
# including without limitation the rights to use, copy, modify, merge,
# publish, distribute, sublicense, and/or sell copies of the Software,
# and to permit persons to whom the Software is furnished to do so,
# subject to the following conditions:
#
# The above copyright notice and this permission notice shall be
# included in all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED “AS IS”, WITHOUT WARRANTY OF ANY KIND,
# EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
# MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
# NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
# BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
# ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
# CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

# Randomness is the true foundation of mathematics.
# -- Gregory Chaitin

# This code clones a pseudorandom number generator (PRNG). The
# attacked PRNG is the Mersenne Twister (MT19937)
# (https://en.wikipedia.org/wiki/Mersenne_Twister) as it is used nearly
# everywhere.


# An accompanying blog post with explanation of the code can be found
# at https://www.schutzwerk.com/en/43/posts/attacking_a_random_number_generator/


# The internal state of MT19937 consists of 624 32-bit integers. Each of
# those correspond to an output. In particular, there is a temper
# function that maps an integer of the internal state to an output. This
# function is invertible. I.e., there is a function "untemper" that can
# even be computed analytically.
# If I have 624 consecutive numbers from an MT19937 output, I
# can recover the whole internal state.

# I use the implementation of MT19937 from here:
# https://github.com/james727/MTP

from z3 import *
import time

# heavily based on https://github.com/james727/MTP
# Usage:
# generator = mersenne_rng(seed = 123)
# random_number = generator.get_random_number()


class mersenne_rng(object):
    def __init__(self, seed=5489):
        self.state = [0]*624
        self.f = 1812433253
        self.m = 397
        self.u = 11
        self.s = 7
        self.b = 0x9D2C5680
        self.t = 15
        self.c = 0xEFC60000
        self.l = 18
        self.index = 624
        self.lower_mask = (1 << 31)-1
        self.upper_mask = 1 << 31

        # update state
        self.state[0] = seed
        for i in range(1, 624):
            self.state[i] = self.int_32(
                self.f*(self.state[i-1] ^ (self.state[i-1] >> 30)) + i)

    def twist(self):
        for i in range(624):
            temp = self.int_32(
                (self.state[i] & self.upper_mask)+(self.state[(i+1) % 624] & self.lower_mask))
            temp_shift = temp >> 1
            if temp % 2 != 0:
                temp_shift = temp_shift ^ 0x9908b0df
            self.state[i] = self.state[(i+self.m) % 624] ^ temp_shift
        self.index = 0

    def temper(self, in_value):
        y = in_value
        y = y ^ (y >> self.u)
        y = y ^ ((y << self.s) & self.b)
        y = y ^ ((y << self.t) & self.c)
        y = y ^ (y >> self.l)
        return y

    def get_random_number(self):
        if self.index >= 624:
            self.twist()
        out = self.temper(self.state[self.index])
        self.index += 1
        return self.int_32(out)

    def int_32(self, number):
        return int(0xFFFFFFFF & number)


# compare with
# https://blog.infosectcbr.com.au/2019/08/cryptopals-challenge-23-clone-mt19937.html

def untemper(out):
    """
    This is the untemper function, i.e., the inverse of temper. This
    is solved automatically using the SMT solver Z3. I could prpbably
    do it by hand, but there is a certain elegance in untempering symbolically.
    """
    y1 = BitVec('y1', 64)
    y2 = BitVec('y2', 64)
    y3 = BitVec('y3', 64)
    y4 = BitVec('y4', 64)
    y = BitVecVal(out, 64)
    s = Solver()
    equations = [
        y2 == y1 ^ (LShR(y1, 11)),
        y3 == y2 ^ ((y2 << 7) & 0x9D2C5680),
        y4 == y3 ^ ((y3 << 15) & 0xEFC60000),
        y == y4 ^ (LShR(y4, 18))
    ]
    s.add(equations)
    s.check()
    return s.model()[y1].as_long()


def recover_state_mt(numbers):
    """
    This function recovers the internal state of MT19937 given a
    sequence of outputs. Note that there can be multiple states of an
    MT19937 that yield the same sequence of outputs.
    """
    state = []
    for n in numbers[0:624]:
        state.append(untemper(n))
    return state


def main():
    """
    This function tests the implementation.
    We clone the RNG from its output and compare the next generated
    outputs of the real and the cloned PRNG. Then, we try to recover
    the seed.
    """
    random_num = 0x75cd873 #input("Input random number: ")

    for i in range(0xffffffff):
        s = time.time()
        rng = mersenne_rng(i)
        for j in range(1000):
            rng.get_random_number()
        chosen = rng.get_random_number()
        print(time.time() - s)
        if chosen == random_num:
            print("Found! Seed: ", i)

    print("WTF NOT FOUND??")
    '''
    rng = mersenne_rng(1337)
    print(f"real internal state of PRNG: {rng.state[0:10]} ...")
    random_nums = []
    print("generating random numbers")
    for i in range(624):
        random_nums.append(rng.get_random_number())
    print(f"generated numbers: {random_nums[0:10]} ... ")
    print("recover internal state of PRNG")
    recovered_state = recover_state_mt(random_nums)
    print(f"recovered internal state: {recovered_state[0:10]} ... ")
    print("cloning PRNG")
    cloned_rng = mersenne_rng()
    cloned_rng.state = recovered_state

    print("check equality of next 1000 outputs from the real and cloned rng")
    for i in range(1000):
        assert(cloned_rng.get_random_number() == rng.get_random_number())
    print('Success!')
    '''


if __name__ == "__main__":
    main()
