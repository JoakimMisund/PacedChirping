# Compiling, loading and using

Will only compile on systems using the modified Linux 4.13 kernel for chirping.

compile:         make
load:            make load
unload:          make unload
Set default:     sysctl -w net.ipv4.tcp_congestion_control=chirping

There are two versions, corresponding to the two kernel versions. The version of the cc module and the kernel has to be the same.
