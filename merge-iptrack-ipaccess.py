## File : merge-iptrack-ipaccess.py
## // 500.2 26.7.9
## About:
##
## Reads iptrack\{PROTOCOL}.{ip-literal}.blk files and merges each
## protocol's blocked IPs into the corresponding config\ipaccess-{protocol}.dat.
## Writes merged output to config\ipaccess-{protocol}-new.dat.
##
## Reduces to class C or B subnets when multiple IPs share the same prefix.
## Optionally deletes the processed .blk files with --delete.
##
## Usage:
##   python merge-iptrack-ipaccess.py
##       [--reduce c|b]
##       [--delete]
##       --ipaccess <location of ipaccess-*.dat files>
##       --iptrack  <location of {PROTOCOL}.{ip-literal}.blk files>
##
## Example:
##   python merge-iptrack-ipaccess.py --ipaccess config\ --iptrack iptrack\

import os
import ipaddress
import sys
import argparse
from datetime import datetime


def reduce_class_b(ip_list):
    class_b_dict = {}
    for ip in ip_list:
        key = '.'.join(str(ip.network_address).split('.')[:2])
        class_b_dict.setdefault(key, []).append(ip)
    final_list = []
    for key, ips in class_b_dict.items():
        if len(ips) >= 2:
            ips = [ipaddress.ip_network(key + '.0.0/16', strict=False)]
        final_list += ips
    return final_list


def reduce_class_c(ip_list):
    class_c_dict = {}
    for ip in ip_list:
        key = '.'.join(str(ip.network_address).split('.')[:3])
        class_c_dict.setdefault(key, []).append(ip)
    final_list = []
    for key, ips in class_c_dict.items():
        if len(ips) >= 2:
            ips = [ipaddress.ip_network(key + '.0/24', strict=False)]
        final_list += ips
    return final_list


def read_ipaccess(file_path):
    ip_list = []
    if not os.path.exists(file_path):
        return ip_list
    with open(file_path, 'r') as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith('#') or line.startswith(';'):
                continue
            line = line.lstrip('+-').replace(' ', '/')
            try:
                ip_list.append(ipaddress.ip_network(line, strict=False))
            except ValueError:
                pass
    return ip_list


def scan_blk_files(iptrack_dir):
    """Return dict: {PROTOCOL: [(ip_network, blk_path), ...]}
    IPs with last octet 0 are treated as /24 blocks (BlockClassC=1 in iptrack.ini).
    """
    by_proto = {}
    if not os.path.isdir(iptrack_dir):
        print(f"ERROR: iptrack directory not found: {iptrack_dir}", file=sys.stderr)
        sys.exit(1)
    for fname in os.listdir(iptrack_dir):
        if not fname.lower().endswith('.blk'):
            continue
        # format: {PROTOCOL}.{ip-literal}.blk
        # e.g.  HTTP.1.2.3.4.blk  ->  parts = ['HTTP','1','2','3','4','blk']
        parts = fname.split('.')
        if len(parts) < 6:       # need proto + 4 octets + blk
            continue
        proto = parts[0].upper()
        ip_str = '.'.join(parts[1:-1])
        try:
            ipaddress.ip_address(ip_str)  # validate
        except ValueError:
            continue
        # last octet 0 = BlockClassC ban -> /24 block
        if parts[-2] == '0':
            net = ipaddress.ip_network(ip_str + '/24', strict=False)
        else:
            net = ipaddress.ip_network(ip_str, strict=False)
        by_proto.setdefault(proto, []).append((net, os.path.join(iptrack_dir, fname)))
    return by_proto


def merge_protocol(proto, entries, ipaccess_dir, reduce_opt, do_delete):
    proto_lower = proto.lower()
    ipaccess_file = os.path.join(ipaccess_dir, f"ipaccess-{proto_lower}.dat")
    out_file      = os.path.join(ipaccess_dir, f"ipaccess-{proto_lower}-new.dat")

    existing = read_ipaccess(ipaccess_file)
    new_ips  = [net for net, blk_path in entries]

    merged = list(set(existing + new_ips))
    merged = sorted(merged, key=lambda x: x.network_address)

    if 'b' in reduce_opt:
        merged = reduce_class_b(merged)
    if 'c' in reduce_opt:
        merged = reduce_class_c(merged)

    merged = sorted(merged, key=lambda x: x.network_address)

    with open(out_file, 'w') as f:
        f.write(f"# Created by merge-iptrack-ipaccess.py on {datetime.now()}\n")
        f.write(f"# ipaccess file : {ipaccess_file}\n")
        f.write(f"# blk files     : {len(entries)}\n")
        f.write(f"# total entries : {len(merged)}\n")
        for ip in merged:
            if ip.prefixlen == 32:
                f.write(f"-{ip.network_address}\n")
            else:
                f.write(f"-{ip}\n")

    print(f"[{proto}] {len(entries)} blk + {len(existing)} existing -> "
          f"{len(merged)} entries -> {out_file}")

    if do_delete:
        for _net, blk_path in entries:
            try:
                os.remove(blk_path)
                print(f"  deleted {blk_path}")
            except OSError as e:
                print(f"  WARNING: could not delete {blk_path}: {e}", file=sys.stderr)


def main():
    parser = argparse.ArgumentParser(
        description="Merge iptrack .blk files into ipaccess-{protocol}.dat")
    parser.add_argument("--reduce", choices=["b", "c"], default="c",
        help="Reduce to class B (/16) or C (/24) when 2+ IPs share prefix (default: c)")
    parser.add_argument("--delete", action="store_true",
        help="Delete processed .blk files after merging")
    parser.add_argument("--ipaccess", required=True,
        help="Directory containing ipaccess-*.dat files (e.g. config\\)")
    parser.add_argument("--iptrack", required=True,
        help="Directory containing {PROTOCOL}.{ip}.blk files (e.g. iptrack\\)")
    args = parser.parse_args()

    by_proto = scan_blk_files(args.iptrack)
    if not by_proto:
        print("No .blk files found in", args.iptrack)
        sys.exit(0)

    for proto in sorted(by_proto.keys()):
        merge_protocol(proto, by_proto[proto], args.ipaccess, args.reduce, args.delete)


main()
