#!/usr/bin/env python3
"""Offline, read-only analyzer for the CSV from steering_impersonate.py.

Usage:
    python leaf_can_diagnostics.py steering_diagnostics.csv

Never connects to a vehicle, uses Panda, transmits CAN, or controls a relay.
"""
import argparse
import csv
from collections import Counter, defaultdict
from pathlib import Path

KNOWN = {
    0x169: 'LKAS steering command',
    0x185: 'Steering angle / LKAS status feedback',
    0x27A: 'Turn-signal lamp state',
    0x3AF: 'Hazard switch',
    0x280: 'Cancel message',
    0x2B1: 'ProPILOT HUD',
    0x4CC: 'ProPILOT HUD info',
}
STATUSES = {5: 'INACTIVE (DBC)', 6: 'ACTIVE (DBC)',
            9: 'FAULT (DBC)', 14: 'UNKNOWN 14 (observed)'}


def decode_185(data):
    if len(data) < 8:
        return None
    raw = (data[2] << 10) | (data[3] << 2) | (data[4] >> 6)
    return 1310 - 0.01 * raw, (data[6] >> 4) & 0x0F


def analyze(path):
    counts = Counter()
    times = defaultdict(list)
    statuses = Counter()
    angles = []
    problems = []
    rows = 0
    with path.open('r', newline='', encoding='utf-8-sig') as stream:
        reader = csv.DictReader(stream)
        needed = {'Timestamp', 'Bus', 'CAN_ID', 'Data'}
        if not needed.issubset(reader.fieldnames or []):
            raise ValueError('Expected CSV columns: Timestamp,Bus,CAN_ID,Data')
        for lineno, row in enumerate(reader, start=2):
            try:
                t = float(row['Timestamp'])
                bus = int(row['Bus'])
                can_id = int(row['CAN_ID'], 0)
                data = bytes.fromhex(row['Data'])
            except (ValueError, TypeError, KeyError) as exc:
                problems.append(f'Line {lineno}: invalid record ({exc})')
                continue
            rows += 1
            key = (bus, can_id)
            counts[key] += 1
            times[key].append(t)
            if can_id == 0x185:
                result = decode_185(data)
                if result:
                    angle, status = result
                    angles.append(angle)
                    statuses[status] += 1
                else:
                    problems.append(f'Line {lineno}: 0x185 shorter than 8 bytes')
    print(f'Valid frames: {rows:,} | Distinct bus/ID pairs: {len(counts)}')
    print('\nBUS   CAN ID   COUNT   EST. Hz   DESCRIPTION')
    for (bus, can_id), count in sorted(counts.items()):
        timestamps = times[(bus, can_id)]
        span = max(timestamps) - min(timestamps) if len(timestamps) > 1 else 0
        hz = (count - 1) / span if span > 0 else 0
        print(f'{bus:>3}   0x{can_id:03X} {count:>8} {hz:>9.1f}   {KNOWN.get(can_id, "") }')
    print('\nLKAS_STATUS from 0x185 (observations, not proof commands were accepted):')
    for status, count in sorted(statuses.items()):
        print(f'  {status:2d}: {count:>7} samples - {STATUSES.get(status, "UNDEFINED")}')
    if angles:
        print(f'Steering angle: min {min(angles):+.2f} deg, '
              f'max {max(angles):+.2f} deg')
    if problems:
        print(f'\nWarnings ({len(problems)}):')
        for msg in problems[:15]:
            print(' ', msg)
    if not counts:
        print('No usable CAN records found.')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('csv_file', type=Path)
    args = parser.parse_args()
    if not args.csv_file.is_file():
        parser.error(f'CSV does not exist: {args.csv_file}')
    analyze(args.csv_file)


if __name__ == '__main__':
    main()
