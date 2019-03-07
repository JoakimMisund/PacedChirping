# Compilation and Loading
Simply running make should compile the module. Any error messages are likely due to either a kernel version mismatch or
missing library.

The module is loaded with 'make load', and unloaded with 'make unload'. Note that make load will fail if the module
is allready loaded.


# Usage
The modified iproute tc command found in /iproute2-4.13.0 has to be used to set and unset the modified RED QDisc.

## Example 
sudo TC_LIB_DIR=$(pwd)'/../iproute2-4.13.0/tc' ../iproute2-4.13.0/tc/tc qdisc add dev lo root red_new limit 100000 avpkt 1500
