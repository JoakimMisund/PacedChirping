# Compiling, loading and using

Will only compile on systems using the modified Linux 4.13 kernel for chirping.

compile:         make
load:            make load
unload:          make unload
Set default:     sysctl -w net.ipv4.tcp_congestion_control=chirping

There are two versions, corresponding to the two kernel versions. The version of the cc module and the kernel has to be the same.


# Versions (copied from root README.md)
- v1: Used in the thesis
- v2: Changed the code from operating in rate to operate in time gaps. Reduces the number of division done in the cc module and in the kernel. The algorithm is the same as in v2.
