# Roadmap
This directory contains code for a RED-Qdisc that reports queue length using the
IP-ID field. The code is made for kernel version 4.13.16 and will probably not
run on the latest kernel.


Directory iproute2-4.13.0 contains the iproute2 toolset with changes required to load the modified RED-Qdisc.
Directory modified_red contains the code for the modified RED-Qdisc.
