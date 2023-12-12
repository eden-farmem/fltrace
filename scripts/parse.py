# Work with raw fltrace output to find callsites 

import argparse
from enum import Enum
import os
import sys
import subprocess
import pandas as pd
import re

TIMECOL = "tstamp"

# parse /proc/<pid>/maps
MAPS_LINE_RE = re.compile(r"""
    (?P<addr_start>[0-9a-f]+)-(?P<addr_end>[0-9a-f]+)\s+  # Address
    (?P<perms>\S+)\s+                                     # Permissions
    (?P<offset>[0-9a-f]+)\s+                              # Map offset
    (?P<dev>\S+)\s+                                       # Device node
    (?P<inode>\d+)\s+                                     # Inode
    (?P<path>.*)\s+                                   # path
""", re.VERBOSE)


class Record:
    """A line in /proc/<pid>/maps"""
    addr_start: int
    addr_end: int
    perms: str
    offset: int
    dev: str
    inode: int
    path: str

    def parse(filename):
        records = []
        with open(filename) as fd:
            for line in fd:
                m = MAPS_LINE_RE.match(line)
                if not m:
                    print("Skipping: %s" % line)
                    continue
                addr_start, addr_end, perms, offset, _, _, path = m.groups()
                r = Record()
                r.addr_start = int(addr_start, 16)
                r.addr_end = int(addr_end, 16)
                r.offset = int(offset, 16)
                r.perms = perms
                r.path = path
                records.append(r)
        return records

    def find_record(records, addr):
        for r in records:
            if addr >= r.addr_start and addr < r.addr_end:
                return r
        return None


class LibOrExe:
    """A library or executable mapped into process memory"""
    records: list
    ips: list
    path: str
    base_addr: int
    codemap: dict

    def __init__(self, records):
        """For libs collected from /proc/<pid>/maps"""
        self.records = records
        self.path = records[0].path
        self.base_addr = min([r.addr_start for r in records])
        self.ips = []
        self.codemap = {}

    def code_location(self, ipx):
        """Lookup the library to find code location for an ip"""
        assert ipx in self.ips, "ip does not fall in lib: " + ipx
        if not self.codemap and self.ips:
            ips = self.ips
            # offset the ips if the lib is loaded at a high address
            if self.base_addr >= 2**32:
                ips_int = [int(ip, 16) for ip in self.ips]
                ips = [hex(ip - self.base_addr) for ip in ips_int]
            locations = lookup_code_locations(self.path, ips)
            self.codemap = dict(zip(self.ips, locations))
        return self.codemap[ipx]


def lookup_code_locations(libpath, ips):
    """Lookup a library using addr2line to find code location for each ip"""
    assert os.path.exists(libpath), "can't locate lib: " + libpath
    sys.stderr.write("looking up {} for {} ips\n".format(libpath, len(ips)))
    locations = subprocess.check_output(     \
        ['addr2line', '-p', '-i', '-e', libpath] + list(ips)) \
        .decode('utf-8')    \
        .replace("\n (inlined by) ", "<<<")   \
        .split("\n")
    locations.remove("")
    assert(len(locations) == len(ips))
    return locations


class FaultOp(Enum):
    """Enumerates the memory access operations that result in a fault"""
    READ = "read"
    WRITE = "write"
    WRPROTECT = "wrprotect"

    def parse(flags):
        """Get the access op from the flags column"""
        op = flags & 0x1F
        if op == 0:   return FaultOp.READ
        if op == 1:   return FaultOp.WRITE
        if op == 3:   return FaultOp.WRPROTECT
        raise Exception("unknown op: {}".format(op))
    
    def __str__(self):
        return self.value


class FaultType(Enum):
    """Enumerates the fault types (defined in fltrace)"""
    REGULAR = "regular"
    ZEROPAGE = "zero"

    def parse(flags):
        """Get the fault type from the flags column"""
        type = flags >> 5
        if type == 0:   return FaultType.REGULAR
        if type == 1:   return FaultType.ZEROPAGE
        raise Exception("unknown type: {}".format(type))

    def __str__(self):
        return self.value


def main():
    parser = argparse.ArgumentParser("Process input and write csv-formatted data to stdout/output file")
    parser.add_argument('-i', '--input', action='store', nargs='+', help="path to the input/data file(s)", required=True)
    parser.add_argument('-st', '--start', action='store', type=int,  help='start tstamp to filter data')
    parser.add_argument('-et', '--end', action='store', type=int, help='end tstamp to filter data')
    parser.add_argument('-fo', '--faultop', action='store', type=FaultOp, choices=list(FaultOp), help='filter for a specific fault op')
    parser.add_argument('-fr', '--frcutoff', action='store', type=int,  help='cut off the seconds where fault rate per second is less than this')
    parser.add_argument('-b', '--binary', action='store', help='path to the binary file to locate code location')
    parser.add_argument('-pm', '--procmap', action='store', help='path to the proc maps file to locate unresolved libraries')
    parser.add_argument('-ma', '--maxaddrs', action='store_true', help='just return max uniq addrs')
    parser.add_argument('-o', '--out', action='store', help="path to the output file")
    args = parser.parse_args()

    # read in
    dfs = []
    for file in args.input:
        if not os.path.exists(file):
            print("can't locate input file: {}".format(file))
            exit(1)

        tempdf = pd.read_csv(file, skipinitialspace=True)
        sys.stderr.write("rows read from {}: {}\n".format(file, len(tempdf)))
        dfs.append(tempdf)
    df = pd.concat(dfs, ignore_index=True)

    # time filter
    if args.start:  df = df[df[TIMECOL] >= args.start]
    if args.end:    df = df[df[TIMECOL] <= args.end]

    # op col renamd to flags
    FLAGSCOL="flags"
    if "kind" in df:
            FLAGSCOL="kind"

    # group by ip or trace
    TRACECOL="ip"
    if "trace" in df:
        TRACECOL="trace"

    # return max uniq addrs if specified
    if args.maxaddrs:
        df = df[df[FLAGSCOL] < 32]  # filter out zero-page faults
        df = df.groupby("addr").size().reset_index(name='count')
        print(len(df.index))
        return

    # group faults by trace
    if "pages" in df:
        df = df.groupby([TRACECOL, FLAGSCOL])["pages"].sum().reset_index(name='count')
    else:
        df = df.groupby([TRACECOL, FLAGSCOL]).size().reset_index(name='count')
    df = df.rename(columns={TRACECOL: "ips"})
    df = df.sort_values("count", ascending=False)
    df["percent"] = (df['count'] / df['count'].sum()) * 100
    df["percent"] = df["percent"].astype(int)

    # NOTE: adding more columns after grouping traces is fine

    # evaluate op & type
    if df.empty:
        df["op"] = []
        df["type"] = []
    else:
        df["op"] = df.apply(lambda r: FaultOp.parse(r[FLAGSCOL]).value, axis=1)
        df["type"] = df.apply(lambda r: FaultType.parse(r[FLAGSCOL]).value, axis=1)
    
    # filter by op
    if args.faultop:    df = df[df["op"] == args.faultop.value]

    # get all unique ips
    iplists = df['ips'].str.split("|")
    ips = set(sum(iplists, []))
    ips.discard("")

    # if procmap is available, look up library locations
    libmap = {}
    libs = {}
    if args.procmap:
        assert os.path.exists(args.procmap)
        records = Record.parse(args.procmap)
        for ip in ips:
            lib = Record.find_record(records, int(ip, 16))
            assert lib, "can't find lib for ip: {}".format(ip)
            assert lib.path, "no lib file path for ip: {}".format(ip)
            if lib.path not in libs:
                librecs = [r for r in records if r.path == lib.path]
                libs[lib.path] = LibOrExe(librecs)
            libs[lib.path].ips.append(ip)
            libmap[ip] = lib.path
        # print(libmap)
        # print(libs)

    # make a new lib column
    def liblookup(ips):
        iplist = ips.split("|")
        lib = "<//>".join([libmap[ip] if ip in libmap else "??" for ip in iplist])
        return lib
    df['lib'] = df['ips'].apply(liblookup)

    # if binary is provided, use it to look up code locations
    codemap = {}
    if args.binary:
        locations = lookup_code_locations(args.binary, ips)
        codemap = dict(zip(ips, locations))
        # print(codemap)
    
    # make a new code column
    def codelookup(ips):
        iplist = ips.split("|")
        locations = []
        for ip in iplist:
            if ip in libmap:
                lib = libs[libmap[ip]]
                locations.append(lib.code_location(ip))
            elif ip in codemap:
                locations.append(codemap[ip])
            else:
                locations.append("??:?")
        code = "<//>".join(locations)
        return code
    df['code'] = df['ips'].apply(codelookup)

    # write out
    out = args.out if args.out else sys.stdout
    df.to_csv(out, index=False, header=True)

if __name__ == '__main__':
    main()
