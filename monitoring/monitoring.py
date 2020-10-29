import gzip
import os
import re
from datetime import datetime, timedelta
from typing import Set, Tuple, List

import matplotlib.pyplot as plt


def read_log_file(path: str) -> Set[Tuple[datetime, str]]:
    if path.endswith(".gz"):
        with gzip.open(path, "rt") as f:
            log_data = f.read()
    else:
        with open(path, "r") as f:
            log_data = f.read()
    accesses = set()
    for line in log_data.splitlines():
        pattern = re.compile(r'([^-]*) - - \[([^\]]*)\] "GET /raas-data.yaml')
        match = re.match(pattern, line)
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


if __name__ == '__main__':
    # LOG_DIR = "/var/log/nginx"
    LOG_DIR = "."
    accesses = set()
    for filename in os.listdir(LOG_DIR):
        if filename.startswith("access."):
            accesses |= read_log_file(f"{LOG_DIR}/{filename}")

    access_list = sorted(list(accesses), key=lambda tup: tup[0])
    access_list_uniq = list(unique_ips(access_list))
    access_list_returning = list(anti_unique_ips(access_list))

    shown_list = access_list

    cur_hour = access_list[0][0]
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

    X_LABEL = "timestamp"
    Y_LABEL = "returning accesses"

    fig = plt.figure()
    plt.xlabel(X_LABEL)
    plt.ylabel(Y_LABEL)

    ax = plt.axes()
    ax.plot(x, y)

    plt.show()
