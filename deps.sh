#!/bin/bash
set -e

#
# Sets up jemalloc dependency
#

SCRIPT_DIR=`dirname "$0"`
JEMALLOC_DIR=jemalloc

usage="Example: $1 [args] setup jemalloc \n
-f, --force \t force clean and setup everything\n
-h, --help \t this usage information message\n"

# parse cli
for i in "$@"
do
case $i in
    -f| --force)
    FORCE=1
    ;;

    -h|--help)
    echo -e $usage
    exit
    ;;

    *)                      # unknown option
    echo "Unknown Option: $i"
    echo -e $usage
    exit
    ;;
esac
done

pushd ${SCRIPT_DIR}

# clean
if [[ $FORCE ]];
then
    rm -rf ${JEMALLOC_DIR}
fi

# Initialize & setup jemalloc
if [ ! -d ${JEMALLOC_DIR} ]; then
    git submodule update --init ${JEMALLOC_DIR}
fi

# build
pushd ${JEMALLOC_DIR}
if [[ $FORCE ]]; then   rm -rf build;   fi
autoconf
mkdir -p build
pushd build
../configure --with-jemalloc-prefix=rmlib_je_ --config-cache --disable-cxx
make -j$(nproc)
popd

# save paths
JE_BUILD_DIR=`pwd`/build
echo "-L${JE_BUILD_DIR}/lib -Wl,-rpath,${JE_BUILD_DIR}/lib -ljemalloc" > je_libs
echo "${JE_BUILD_DIR}/lib/libjemalloc_pic.a" > je_static_libs
echo "-I${JE_BUILD_DIR}/include" > je_includes
    
popd
