#
# Build flame graph format from stack traces
#

import argparse
import csv
import os
import re
from collections import defaultdict

## Exclude these file sections from the flame graph
# E.g., to avoid recursive stacks. Hard-coding for now.
# (vertical cuts, this will only remove some rows from the flame graph)
EXCLUDED_SECTIONS = {
    "example.c": [(0, 0)],  # example exclude from linenum to linenum 
}

## Exclude traces with these file sections from the flame graph
# (horizantal cuts, this will remove entire traces from the flame graph)
EXCLUDED_TRACES = {
    "example.c": [(0, 0)],  # example exclude from linenum to linenum           
}

### Definitions
class CodeFile:
    """Source code file"""
    def __init__(self, dirpath, name, local):
        self.dirpath = dirpath
        self.name = name
        self.local = local

    def __str__(self):
        dirpath = self.dirpath + "/" if self.dirpath else ""
        return "{}{}".format(dirpath, self.name)

    def __eq__(self, other):
        return self.dirpath == other.dirpath and self.name == other.name


class CodePointer:
    """Pointer to a code location"""

    def __init__(self, ip):
        self.ip = ip
        self.tcount = 0     # unique traces containing this ip
        self.fcount = 0     # number of faults at this ip
        self.ops = set()    # ops seen at this code pointer

        # fill these once
        self.file = None
        self.line = None
        self.pd = None      # path discriminator
        self.lib = None
        self.inlineparents = []  # parent code pointers if inlined
        self.originalcp = None    # original code pointer if inlined

    def add_code_location(self, text):
        """Fill the code location details parsed from a string"""
        # expected format: <filepath>:<line> (discriminator <pd>)
        local = False
        pattern = r"([^:]*):([0-9?]+)\s*(\(discriminator ([0-9]+)\))*"
        match = re.fullmatch(pattern, text)
        assert match and len(match.groups()) == 4
        filepath = match.groups()[0]
        filename = filepath.split("/")[-1]
        dirpath = filepath[:-len(filename)].rstrip("/")
        file = CodeFile(dirpath, filename, local)
        line = match.groups()[1]
        if "?" in line:     line = 0
        self.file = file
        self.line = int(line)
        self.pd = match.groups()[3] if match.groups()[3] else None

    def flamegraph_name(self, leaf=False, nolib=False):
        """ customized name for the flame graph viz. """
        prefix = os.path.basename(self.lib) if self.lib else "Unknown"
        filename = os.path.basename(self.file.name) if self.file else None
        # filename = os.path.join(self.file.dirpath, self.file.name) if self.file else None
        suffix = "{}:{}".format(filename, self.line) if filename else self.ip
        s = "{}|{}".format(prefix, suffix) if not nolib else suffix
        if self.pd:   s += " ({})".format(self.pd)
        # add suffix for coloring
        if leaf:
            originalcp = self.originalcp if self.originalcp else self
            if len(originalcp.ops) == 1:
                op = list(originalcp.ops)[0]
                if op == "read":            s += "[r]"
                elif op == "wrprotect":     s += "[p]"
                elif op == "write":         s += "[w]"
            elif "read" not in originalcp.ops:    s += "[w]"
        return s

    def ignore(self):
        """Ignore this code pointer when writing to the flame graph"""
        ignore = False
        if self.file and self.line: 
            if self.file.name in EXCLUDED_SECTIONS:
                for (start, end) in EXCLUDED_SECTIONS[self.file.name]:
                    if start <= self.line <= end:
                        ignore = True
                        break
        return ignore

    def ignore_trace(self):
        """Ignore traces with this code pointer when writing to the flame graph"""
        ignore = False
        if self.file and self.line: 
            if self.file.name in EXCLUDED_TRACES:
                for (start, end) in EXCLUDED_TRACES[self.file.name]:
                    if start <= self.line <= end:
                        ignore = True
                        break
        return ignore

    def __eq__(self, other):
        return self.ip == other.ip


class CodeLink:
    """(Directed) Link between two code pointers"""

    def __init__(self, left, right):
        self.lip = left
        self.rip = right
        self.tcount = 0     # unique traces containing this link
        self.fcount = 0     # number of faults with this link

    def __str__(self):
        return "{} -> {}".format(self.lip, self.rip)

    def __eq__(self, other):
        return self.lip == other.lip and self.rip == other.rip


class Fault:
    """Fault info for a single fault"""
    trace = None            # stack trace, list of ips
    count = None
    op = None
    type = None

    def __eq__(self, other):
        return "|".join(self.trace) == "|".join(other.trace)


class FaultTraces:
    """Fault traces for a single run"""
    runid = None
    faults = None           # list of faults
    codepointers = None     # map from ip to code pointers
    codelinks = None        # map from code pointer to code pointers
    files = None            # set of all known source files
    sigips = None           # ips that fall in the signal handler
    libs = None             # set of all known libraries

    def __init__(self):
        self.faults = []
        self.codepointers = {}
        self.codelinks = {}
        self.files = set()
        self.libs = set()


def parse_fault_from_csv_row(ftraces, row, srcdir=None):
    """Parse fault info from a row the csv trace file"""
    fault = Fault()
    fault.trace = row["ips"].split("|")
    fault.count = int(row["count"])
    fault.op = row["op"]
    fault.type = row["type"]
    ftraces.faults.append(fault)

    # parse libs if available
    libs = [None] * len(fault.trace)
    if "lib" in row:
        libs = row["lib"].split("<//>")
        assert(len(libs) == len(fault.trace))
        ftraces.libs.update(libs)

    # add code locations
    previp = None
    codes = row["code"].split("<//>")
    assert len(codes) == len(fault.trace)
    for ip, code, lib in zip(fault.trace, codes, libs):
        if not ip:
            continue

        # add code pointer
        if ip not in ftraces.codepointers:
            ftraces.codepointers[ip] = CodePointer(ip)
        codepointer = ftraces.codepointers[ip]

        # parse and save location information
        local = False
        if codepointer.file is None:
            if code and "??" not in code:
                # main code location
                mcode = code.split("<<<")[0]
                codepointer.add_code_location(mcode)
                ftraces.files.add(str(codepointer.file))

                # figure out if this is local code based on the file path
                if not srcdir or codepointer.file.dirpath.startswith(srcdir):
                    local = True

                # inlined locations
                inlinedcodes = code.split("<<<")[1:]
                for icode in inlinedcodes:
                    if icode and "??" not in icode:
                        # do not add these to global maps
                        inlinedpointer = CodePointer(ip)
                        inlinedpointer.add_code_location(icode)
                        inlinedpointer.originalcp = codepointer
                        inlinedpointer.lib = lib
                        inlinedpointer.local = (not srcdir or inlinedpointer.file.dirpath.startswith(srcdir))
                        ftraces.files.add(str(inlinedpointer.file))
                        codepointer.inlineparents.append(inlinedpointer)
            codepointer.lib = lib
            codepointer.local = local

        codepointer.tcount += 1
        codepointer.fcount += fault.count
        codepointer.ops.add(fault.op)
        ftraces.codepointers[ip] = codepointer

        # save code link
        if previp:
            if (previp, ip) not in ftraces.codelinks:
                ftraces.codelinks[(previp, ip)] = CodeLink(previp, ip)
            codelink = ftraces.codelinks[(previp, ip)]
            codelink.tcount += 1
            codelink.fcount += fault.count
        previp = ip

    # delete ips that fall in the signal handler and check
    # that they are the same in all traces
    IPS_IN_SIGNAL_HANDLER = 2
    sigips = []
    for _ in range(IPS_IN_SIGNAL_HANDLER):
        sigips.append(fault.trace.pop(0))
    assert ftraces.sigips is None or sigips == ftraces.sigips
    ftraces.sigips = sigips

    # reverse the trace (we get it in bottom-up order)
    if "" in fault.trace:
        fault.trace.remove("")
    fault.trace.reverse()

def get_locations_from_trace(ftraces, trace, nolib=False, annotleaf=False, local=False):
    """Get code locations in text from a trace"""
    locations = []
    ignore = False
    is_leaf = True
    for i, ip in enumerate(reversed(trace)):
        cp = ftraces.codepointers[ip]
        if cp.ignore_trace():
            return None
        for c in cp.inlineparents:
            # if c.ignore_trace():
            #     return None
            if (local and not c.local):
                continue
            locations.append(c.flamegraph_name(is_leaf, nolib=nolib))
            is_leaf = False
        if cp.ignore() or (local and not cp.local):
            continue
        locations.append(cp.flamegraph_name(is_leaf, nolib))
        is_leaf = False
    return reversed(locations)

### Main

def main():
    # parse args
    parser = argparse.ArgumentParser("Build fault graph from trace files")
    parser.add_argument('-i', '--input', action='store', nargs='+', help="path to the input trace file(s)", required=True)
    parser.add_argument('-s', '--srcdir', action='store', help='base path to the app source code', default="")
    parser.add_argument('-c', '--cutoff', action='store', type=int, help='pruning cutoff as percentage of total fault count')
    parser.add_argument('-z', '--zero', action='store_true', help='consider only zero faults', default=False)
    parser.add_argument('-nz', '--nonzero', action='store_true', help='consider only non-zero faults', default=False)
    parser.add_argument('-l', '--local', action='store_true', help='consider only local code locations', default=False)
    parser.add_argument('-p', '--plain', action='store_true', help='write code locations and their count in plain text instead of flame graph', default=False)
    parser.add_argument('-o', '--output', action='store', help='path to the output flame graph data', required=True)
    # flamegraph formatting options
    parser.add_argument('-nl', '--nolib', action='store_true', help='do not include library name', default=False)
    args = parser.parse_args()

    # read in
    traces = FaultTraces()
    for file in args.input:
        with open(file) as csvfile:
            csvreader = csv.DictReader(csvfile)
            for row in csvreader:
                parse_fault_from_csv_row(traces, row, args.srcdir)

    # print some info
    print("Unique Traces: {}".format(len(traces.faults)))
    print("Unique code locations: {}".format(len(traces.codepointers)))
    knowncps = [cp for cp in traces.codepointers.values() if cp.file is not None]
    print("Known code locations: {}".format(len(knowncps)))
    print("Total source files: {}".format(len(traces.files)))

    # filter for zero faults
    if args.zero:
        traces.faults = [f for f in traces.faults if f.type == "zero"]
    if args.nonzero:
        traces.faults = [f for f in traces.faults if f.type != "zero"]

    # prune traces (simplest way to prune: remove all traces below 
    # a certain fault count)
    if args.cutoff:
        traces.faults.sort(key=lambda f: f.count, reverse=True)
        fsum = sum([f.count for f in traces.faults])
        cutoff = fsum * args.cutoff / 100
        fsum = 0
        cutoffidx = len(traces.faults)
        for i, f in enumerate(traces.faults):
            fsum += f.count
            if fsum >= cutoff:
                cutoffidx = i
                break
        traces.faults = traces.faults[:cutoffidx]
        print("Unique {}% Traces: {}".format(args.cutoff, len(traces.faults)))

    # write in plain text if requested
    if args.plain:
        codecounts = defaultdict(int)
        for f in traces.faults:
            locations = get_locations_from_trace(traces, f.trace, args.nolib, \
                annotleaf=False, local=args.local)
            if not locations:
                print("ERROR! Trace ignored. Count: {}".format(f.count))
                for ip in f.trace:
                    cp = traces.codepointers[ip]
                    for c in reversed(cp.inlineparents):
                        print(c.file, c.line, c.lib, c.local, c.ignore())
                    print(cp.file, cp.line, cp.lib, cp.local, cp.ignore())
                return
            cpname = locations[-1]
            if f.type == "zero":    cpname += " (zero)"
            cpname += " ({})".format(f.op)
            codecounts[cpname] += f.count
        # print(codecounts)
        codecounts = sorted(codecounts.items(), key=lambda x: x[1], reverse=True)
        total = sum([v for _,v in codecounts])
        pdf = {k: round(100*v/total, 2) for k,v in codecounts}
        cdf = {k: round(100*sum([v for _,v in codecounts[:i+1]])/total, 2) \
            for i,(k,v) in enumerate(codecounts)}
        with open(args.output, "w") as fp:
            fp.write("count,percent,cdf,code\n")
            for cpname, count in codecounts:
                fp.write("{},{},{},{}\n".format(count, pdf[cpname], cdf[cpname], cpname))        
        print("Total: {}, 95%: {}".format(len(cdf), 1 + min([i for i,v in enumerate(cdf.values()) if v >= 95])))
        return

    # return in flamegraph format (default)
    with open(args.output, "w") as fp:
        for f in traces.faults:
            locations = get_locations_from_trace(traces, f.trace, args.nolib, \
                annotleaf=True, local=args.local)
            if locations is not None:
                tracestr = ";".join(locations)
                fp.write("{} {}\n".format(tracestr, f.count))
        print("Wrote {} traces to {}".format(len(traces.faults), args.output))


if __name__ == "__main__":
    main()
