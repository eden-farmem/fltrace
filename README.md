# fltrace
This tool captures page faults  with source code locations




#### Requirements
- Linux kernel 5.9 or higher (recently tested on 5.15)
- [jemalloc](https://github.com/jemalloc/jemalloc). To set-up jemalloc, run:
    ```
    ./deps.sh --force
    ```
-  [addr2line](https://man7.org/linux/man-pages/man1/addr2line.1.html)
- python3

#### Build
```
make clean
make

# if needed, try the following flags for debugging
make SAFEMODE=1   # build tool with a bunch of safety checks
make DEBUG=1      # build tool with (very) verbose logging
```

#### Run
1. To record a trace, run:
    ```
    fltrace record -L <localmem> -M <maxmem> -- <command>
    ```
    - `-L` (Local/mapped memory limit) and `-M` (max memory the command needs to run) are required arguments (in MB); there should be enough memory on the system to hold both these sizes (combined) and max memory should be enough to hold the command's resident memory at its peak. See `fltrace --help` output for more options.
    - The tool will output a trace file (default: `fltrace-data-faults-<pid>-<hcore>.out`) in the current directory, one per each process that the command spawns and for each tracing thread (See `--cores` option). The trace contains one fault per line with fault information like timestamp, page address, the call stack and some flags (defined in `inc/rmem/fsampler.h`) among others.  It also saves `/proc/pid/maps` as `fltrace-data-procmaps-<pid>.out` for each process to lookup the source code locations later and a stats file `fltrace-data-stats-<pid>.out` with some statistics on the run (for debugging). 

2. To parse the tool output and report the call-sites (source code locations) ordered by their faulting frequency, run:
    ```
    fltrace report
    ```
    - This will look back into libraries to figure out callsites and output a csv-formatted file `fltrace-data-report-<pid>.out` with information grouped by callsites.

3. To visualize the reported source code locations (currently in a 
flamegraph style), run:
    ```
    fltrace visualize
    ```
    - This will output a flamegraph svg file `fltrace-flamegraph.svg` after collapsing callstacks which shows them by their page fault frequency. It also outputs another flamegraph just for allocation faults. Use your favorite browser/svg-viewer to view the svg files.

#### Example
With a GAPBS BFS workload (https://github.com/sbeamer/gapbs.git) 
```
git clone https://github.com/sbeamer/gapbs.git
cd gapbs/
make CXX_FLAGS="-g"     # build with debug symbols
cd ..
./fltrace record -L=1000 -M=1000 -- ./gapbs/bfs -g 20 -n 1      # run with ample memory (1GB)
cat fltrace-data-stats-<pid>.out | grep -o "memory_used:\([0-9]\+\)" | tail -1      # max memory used by the command  
./fltrace record -L=140 -M=1000 -- ./gapbs/bfs -g 20 -n 1       # re-run with half the memory to generate faults (140 MB)
./fltrace report 
./fltrace visualize
```
The above commands will generate a flamegraph svg file `fltrace-data-flamegraph-<pid>.svg` which looks like this:
![flamegraph](./flamegraph-example.png)


#### Acknowledgements
- Borrowed the [base](./base) library from [Shenango](https://github.com/shenango/shenango/tree/master/base)
- Hat tips to [@wantonsolutions](https://github.com/wantonsolutions) and [@alexliu0809](https://github.com/alexliu0809) for their help with testing

  
(An earlier version of) this tool was used to get the measurements on page faulting code locations in our [WORDS'23 short paper](https://cseweb.ucsd.edu/~snoeren/papers/eden-words23.pdf). If you use this tool for your research, consider citing the paper:
```
@inproceedings{farmem-words23,
author = {Yelam, Anil and Grant, Stewart and Liu, Enze and Mysore, Radhika Niranjan and Aguilera, Marcos K. and Ousterhout, Amy and Snoeren, Alex C.},
title = {Limited Access: The Truth Behind Far Memory},
year = {2023},
isbn = {9798400702501},
publisher = {Association for Computing Machinery},
address = {New York, NY, USA},
url = {https://doi.org/10.1145/3605181.3626288},
doi = {10.1145/3605181.3626288},
pages = {37–43},
numpages = {7},
location = {Koblenz, Germany},
series = {WORDS '23}
}
```