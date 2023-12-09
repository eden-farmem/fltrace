# fltrace




#### Requirements
- Linux kernel 5.9 or higher (recently tested on 5.15)
- [jemalloc](https://github.com/jemalloc/jemalloc)
    ```
    ./deps.sh --force   # sets up jemalloc libs
    ```

#### Build
```
make clean
make

# if needed, set the following flags
make DEBUG=1      # run with (very) verbose logging
make SAFEMODE=1   # run with a bunch of safety checks
```

#### Run
```
env="LD_PRELOAD=./fltrace.so"               # the tool is an LD_PRELOADable library
env="$env FLTRACE_MAX_MEMORY_MB=10000"      # max memory the app would need (in MB)
env="$env FLTRACE_LOCAL_MEMORY_MB=1000"     # memory (in MB) that app has "locally"
env="$env FLTRACE_NHANDLERS=1"              # number of cores to run on (default: 1). 
                                            # More cores == faster tracing, but each core would output a separate trace file
env="$env FLTRACE_MAX_SAMPLES_PER_SEC=0"    # max samples per sec (default: 0, i.e., trace all faults)

$env <app> <app args>                       # run the app with the tool
```

#### Example
```
TODO
```

#### Acknowledgements
- Borrowed the [base](./base) library from [Shenango](https://github.com/shenango/shenango/tree/master/base)
- Hat tips to [@wantonsolutions](https://github.com/wantonsolutions) and [@alexliu0809](https://github.com/alexliu0809) for helping with testing

  
  
If you use this tool for your research, please consider citing our paper which introduced the tool:
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