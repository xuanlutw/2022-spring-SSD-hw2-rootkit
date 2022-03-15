#! /usr/bin/python3
import os

def test (condition):
    if condition:
        print("PASS")
    else:
        print("FAIL")

print("===== Install Module =====")

os.system("rmmod rootkit")
os.system("rm /dev/rootkit")

os.system("insmod rootkit.ko")
major = int(os.popen("dmesg").read().split("\n")[-2][-4:])
print(f"major = {major}")
os.system(f"mknod /dev/rootkit c {major} 0")


print("===== Test HIDE =====")

os.system("./test HIDE")
test("rootkit" not in os.popen("lsmod").read())

os.system("./test HIDE")
test("rootkit" in os.popen("lsmod").read())

os.system("./test HIDE")
test("rootkit" not in os.popen("lsmod").read())

os.system("./test HIDE")
test("rootkit" in os.popen("lsmod").read())


print("===== Test MASQ =====")

os.system("./test MASQ < MASQ.in.1")
log = os.popen("ps -q 1 -o comm").read().split("\n")
test("QQAAQQ" == log[1].strip())

print("===== Test HOOK =====")

os.system("./test HOOK")
os.system("ls > /dev/null")
log = os.popen("dmesg").read().split("\n")
test("exec /bin/sh"    in log[-5])
test("exec /bin/ls"    in log[-4])
test("exec /bin/sh"    in log[-3])
test("exec /bin/dmesg" in log[-2])

# TODO: How to test poweroff @@

# exec should work after removed the rootkitmodule
os.system("rmmod rootkit")
os.system("rm /dev/rootkit")
os.system("ls > /dev/null")
test(True)
