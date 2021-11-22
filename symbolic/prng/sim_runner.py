import os
from multiprocessing import *
import time
from pwn import *

if args.LOCAL:
    r = process('./pnrg')

    number = str(int(r.readline().decode().split(',')[0], 16))
    print(number)
elif args.REMOTE:
    r = remote('training.jinblack.it', 2020)

    number = str(int(r.readline().decode().split(',')[0], 16))
    print(number)
else:
    number = '4241769204'

processes = [(str(i), number) for i in range(0, 0xffffffff, 100000000)]


def run_process(argv, event):
    print(argv, event)
    out = os.popen('./simulator {} {}'.format(argv[0], argv[1])).read()
    if out.find("FOUND") != -1:
        print("SUCCESS ", out)
        event.set()
    else:
        print(out)


print("start " + str(len(processes)))
s = time.time()
pool = Pool(processes=24)
m = Manager()
event = m.Event()
for proc in processes:
    pool.apply_async(run_process, (proc, event))
pool.close()
event.wait()
pool.terminate()
print(time.time() - s)

if args.LOCAL or args.REMOTE:
    r.interactive()
