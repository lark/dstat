### Author: Wang Jian <larkwang@gmail.com>

import re

global subprocess
import subprocess

class dstat_plugin(dstat):
    """
    Display ipsec tunnel traffic statistic. Especially useful for ipsec hub.
    Written for strongSwan.
    """
    def __init__(self):

        self.name = 'ipsec (bps)'

        self.vars = []
        lines = subprocess.check_output(["ipsec", "statusall"]).splitlines()
        for l in lines:
            m = re.search(" *(.*):.*rekeying", l)
            if m:
                name = m.group(1)
                self.vars.append(name)

        self.type = 's'
        self.width = 11
        self.scale = 0

        self.counter1 = {}
        self.counter2 = {}
        self.re = re.compile(" *(.*):.* (.*) bytes_i.*, (.*) bytes_o")

    def extract(self):
        for name in self.vars:
            if not self.counter2.has_key(name):
                self.counter2[name] = { 'rx': 0, 'tx': 0 }
            if not self.counter1.has_key(name):
                self.counter1[name] = { 'rx': 0, 'tx': 0 }

        self.output = ''

        lines = subprocess.check_output(["ipsec", "statusall"]).splitlines()
        for l in lines:
            m = self.re.search(l)
            if m:
                name = m.group(1)
                rx = long(m.group(2))
                tx = long(m.group(3))
                # after rekey, new ESP tunnel is created. new ESP tunnel is ignored
                # to see new tunnel statistics, you need to restart dstat
                if name in self.vars:
                    self.counter2[name] = { 'rx': rx, 'tx': tx }

        for name in self.vars:
            rx_rate = (self.counter2[name]['rx'] - self.counter1[name]['rx']) * 8.0 / elapsed
            tx_rate = (self.counter2[name]['tx'] - self.counter1[name]['tx']) * 8.0 / elapsed

            self.output += "%s %s " % (cprint(rx_rate, type = 'd', width = 5, scale = 1000),
                                       cprint(tx_rate, type = 'd', width = 5, scale = 1000))

        if step == op.delay:
            self.counter1.update(self.counter2)

# vim:ts=4:sw=4:et
