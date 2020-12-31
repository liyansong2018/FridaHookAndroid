import frida
import sys
import time

def read_js(file):
    with open(file, encoding='UTF-8') as fp:
        return fp.read()

def on_message(message, data):
    if message["type"] == "send":
        print("[+] {}".format(message["payload"]))
    else:
        print("[-] {}".format(message))

'''
# 运行时hook
remote_device = frida.get_usb_device()
print(remote_device)
session = remote_device.attach("com.example.testfrida")

'''
# spawn hook
device = frida.get_usb_device()
pid = device.spawn(["com.example.testfrida"])
device.resume(pid)
time.sleep(1) #Without it Java.perform silently fails
session = device.attach(pid)

src = read_js("./common_function.js")
script = session.create_script(src)
script.on("message", on_message)
script.load()
sys.stdin.read()