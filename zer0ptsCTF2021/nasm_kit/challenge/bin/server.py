import os
import random
import string
import subprocess

def waitcode_to_exitcode(status):
    if os.WIFSIGNALED(status):
        return -os.WTERMSIG(status)
    elif os.WIFEXITED(status):
        return os.WEXITSTATUS(status)
    elif os.WIFSTOPPED(status):
        return -os.WSTOPSIG(status)
    return "???"


def randstr(l):
    return ''.join([random.choice(string.ascii_letters) for i in range(l)])

def check(code):
    if len(code) > 0x1000:
        print("[-] Too large")
        return False
    if 'incbin' in code:
        print("[-] You can't guess the filename of the flag")
        return False
    if '%' in code:
        print("[-] Macro is disabled just in case")
        return False
    return True

if __name__ == '__main__':
    print("* Paste your assembly code to emulate ('EOF' to end)")

    # read code
    code  = 'BITS 64\n'
    code += 'ORG 0\n'
    while True:
        line = input()
        if line == 'EOF':
            break
        code += line + '\n'

    # check code
    if not check(code):
        exit(1)

    # save to file
    name = "/tmp/" + randstr(32)
    with open(f"{name}.S", "w") as f:
        f.write(code)

    # assemble
    p = subprocess.Popen(["/usr/bin/nasm",
                          "-fbin", f"{name}.S",
                          "-o", f"{name}.bin"])
    if p.wait(timeout=1) != 0:
        print("[-] Assemble failed")
        exit(1)

    os.remove(f"{name}.S")

    # emulate
    try:
        pid = os.fork()
        if pid == 0:
            os.execl("./x64-emulator", "./x64-emulator", f"{name}.bin")
            os._exit(0)
        else:
            _, wait_status = os.waitpid(pid, 0)
            print("exit code: {}".format(waitcode_to_exitcode(wait_status)))
    except Exception as e:
        print(e)
    finally:
        pass
        # os.remove(f"{name}.bin")
