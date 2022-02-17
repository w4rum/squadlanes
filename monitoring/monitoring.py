import gzip
import os
import re
from datetime import datetime, timedelta
from typing import Set, Tuple, List

import matplotlib.pyplot as plt


def read_log_file(path: str) -> Set[Tuple[datetime, str]]:
    print("read file")
    if path.endswith(".gz"):
        with gzip.open(path, "rt") as f:
            log_data = f.read()
    else:
        with open(path, "r") as f:
            log_data = f.read()
    accesses = set()
    # look for accesses to the index file
    pattern = re.compile(r'([^-]*) - - \[([^\]]*)\] "GET /(\?[^ ]*)? HTTP/[^"]+')
    print("scan")
    splitlines = log_data.splitlines()
    for i, line in enumerate(splitlines):
        if i % 1000 == 0:
            print(f"{i / len(splitlines) * 100 : .2f}%")
        match = re.match(pattern, line)  # note: re.match is a lot faster than re.search
        if match is None:
            continue
        ip, timestamp_str = match.group(1, 2)
        timestamp = datetime.strptime(timestamp_str, "%d/%b/%Y:%H:%M:%S %z")
        accesses.add((timestamp, ip))
    return accesses


def unique_ips(access_list: List[Tuple[datetime, str]]):
    s = set()
    for timestamp, ip in access_list:
        if ip in s:
            continue
        s.add(ip)
        yield timestamp, ip


def anti_unique_ips(access_list: List[Tuple[datetime, str]]):
    s = set()
    for timestamp, ip in access_list:
        if ip in s:
            yield timestamp, ip
            continue
        s.add(ip)


def plot(shown_list, plt, label):
    cur_hour = shown_list[0][0]
    delta = timedelta(days=1)
    x = []
    y = []
    while cur_hour <= shown_list[-1][0]:
        x.append(cur_hour)
        in_range = 0
        for timestamp, _ in shown_list:
            if cur_hour < timestamp <= cur_hour + delta:
                in_range += 1
        y.append(in_range)
        cur_hour += delta

    plt.plot(x, y, label=label)


if __name__ == "__main__":
    # LOG_DIR = "/var/log/nginx"
    LOG_DIR = "."
    print("read")
    accesses = read_log_file(f"{LOG_DIR}/access.log")

    print("sort")
    access_list = sorted(list(accesses), key=lambda tup: tup[0])
    print("filter unique")
    access_list_uniq = list(unique_ips(access_list))
    # print("filter non-unique")
    # access_list_returning = list(anti_unique_ips(access_list))

    print("plot 1")
    plot(access_list, plt, "accesses")
    print("plot 2")
    plot(access_list_uniq, plt, "first-time visitors")
    # print("plot 3")
    # plot(access_list_uniq, plt, "returning visitors")
    print(access_list_uniq)

    print("render")
    X_LABEL = "timestamp"
    Y_LABEL = "accesses per day"

    plt.xlabel(X_LABEL)
    plt.ylabel(Y_LABEL)
    plt.legend()
    plt.show()
