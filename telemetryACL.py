# -*- coding: utf-8 -*-

from __future__ import print_function, with_statement
import subprocess


def main():
    with open('telemetry.txt', 'r') as tf:
        telemetry = [line.rstrip('\n') for line in tf][2:]
    with open('acl.txt', 'w') as tf:
        ips = {}
        for record in telemetry:
            ip = nslookup(record)
            if len(ip) > 0:
                s = '! ' + str(record)
                print(s, file=tf)
                for x in ip:
                    print('access-list 121 deny tcp any host ' + str(x) + ' log', file=tf)
        print('access-list 121 permit tcp any any', file=tf)


def nslookup(dom):
    process = subprocess.Popen(['nslookup', dom], stdout=subprocess.PIPE)
    output = process.communicate()[0].split('\n')

    res = []
    for data in output:
        if 'Address' in data:
            res.append(data.replace('Address: ', ''))
    return res[1:]


if __name__ == '__main__':
    main()