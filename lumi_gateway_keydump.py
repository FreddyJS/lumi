import os
import telnetlib
import subprocess
import hashlib
import binascii

HOME = "/home/pi/OpenOCD"
CMD = "openocd -f raspberrypi3-native.cfg -f openocd.cfg -c init"
CMD_LIST = CMD.split(" ")

RAM_START = 0x00000
RAM_END = 0x10000
STEPS = 0x2000

if __name__ == "__main__":
    # Check if running as root for OpenOCD
    uid = os.getuid()
    if uid != 0:
        print("You are not root.")
        exit(1)

    # Change directory to OpenOCD home and start OpenOCD
    os.chdir(HOME)
    ocd_proc = subprocess.Popen(CMD_LIST, stderr=subprocess.PIPE)
    print("OpenOCD started. PID: {}\n".format(ocd_proc.pid))

    # Wait for OpenOCD to be ready by reading stderr (?)
    for line in iter(ocd_proc.stderr.readline, b''):
        print(" > " + line.decode("utf-8"), end="")
        if "wmcore.cpu: hardware has 6 breakpoints, 4 watchpoints" in line.decode("utf-8"):
            break

    # OpenOCD is ready, start telnet client to connect to the gateway
    print("\nOpenOCD ready. Starting telnet...")
    tn = telnetlib.Telnet("localhost", 4444)
    tn.read_until(b"> ")

    print("Telnet connected. Reading RAM...")

    # Read RAM. We read 0x1000 bytes at a time because it didn't work with the whole RAM
    ram = ""
    for i in range(RAM_START, RAM_END, STEPS):
        command = "mdb 0x{:05x} 0x{:05x}\n".format(i, STEPS)
        print("Reading RAM from 0x{:05x} to 0x{:05x}... ({})".format(i, i + STEPS - 1, command.strip()))

        # Send command and read output
        tn.write(command.encode("utf-8"))

        # Read until prompt and clean output
        out = tn.read_until(b"> ").replace(b"\r\n", b"\n").replace(b"> ", b"")
        out = out.replace(command.encode("utf-8"), b"")
        ram += out.decode("utf-8")

    # Now dump the device keys
    print("\nReading device keys...")
    tn.write(b"mdb 0x2000037e 0x08\n")
    out = tn.read_until(b"> ").replace(b"\r\n", b"\n").replace(b"> ", b"").decode("utf-8")
    mac = out.split("0x2000037e: ")[1]

    tn.write(b"mdb 0x20000386 0x08\n")
    out = tn.read_until(b"> ").replace(b"\r\n", b"\n").replace(b"> ", b"").decode("utf-8")
    did = out.split("0x20000386: ")[1]

    tn.write(b"mdb 0x2000038e 0x10\n")
    out = tn.read_until(b"> ").replace(b"\r\n", b"\n").replace(b"> ", b"").decode("utf-8")
    key = out.split("0x2000038e: ")[1]

    print(" > aTag_mac: " + mac, end="")
    print(" > aTag_did: " + did, end="")
    print(" > aTag_key: " + key)

    # AES Encryption Key --> key = md5sum(token)
    # The token is the key in hex format
    key = key.replace(" ", "").strip()
    print(" > Token:   0x" + key)

    aes_key = hashlib.md5(binascii.unhexlify(key)).hexdigest()
    print(" > AES key: 0x" + aes_key)

    # AES Encryption IV --> iv = md5sum(key+token)
    # The token is the key in hex format
    # The key is the md5sum of the token
    aes_iv = hashlib.md5(binascii.unhexlify(aes_key + key)).hexdigest()
    print(" > AES IV:  0x" + aes_iv)

    # Close telnet connection
    tn.close()
    print("\nTelnet closed.")

    # Delete empty lines
    ram_formated = ""
    for line in ram.split("\n"):
        line = line.strip()
        if line != "":
            ram_formated += line + "\n"

    # Write RAM to file
    with open("ram.bin", "w") as f:
        f.write(ram_formated)

    # Change permissions because we are root
    os.system("chmod 666 ram.bin")

    # Terminate OpenOCD
    print("OpenOCD terminated.")
    os.system("kill -9 {}".format(ocd_proc.pid))
    exit(0)
