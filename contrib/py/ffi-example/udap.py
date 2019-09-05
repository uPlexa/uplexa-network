#!/usr/bin/env python3


from ctypes import *
import signal
import time
import threading


class UDAP(threading.Thread):

    lib = None
    ctx = None

    def signal(self, sig):
        if self.ctx and self.lib:
            self.lib.udap_main_signal(self.ctx, int(sig))

    def run(self):
        code = self.lib.udap_main_run(self.ctx)
        print("udap_main_run exited with status {}".format(code))


def main():
    udap = UDAP()
    udap.lib = CDLL("./libudap.so")
    udap.ctx = udap.lib.udap_main_init(b'daemon.ini')
    if udap.ctx:
        udap.start()
        try:
            while True:
                print("busy loop")
                time.sleep(1)
        except KeyboardInterrupt:
            udap.signal(signal.SIGINT)
        finally:
            udap.lib.udap_main_free(udap.ctx)
            return


if __name__ == '__main__':
    main()
