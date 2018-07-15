# PacedChirping
Code developed during work on master thesis.

# Roadmap
Each subsection describes a directory.

## cc_module
Contains the TCP CC module code.

## iproute2-4.13.0
The whole iproute2 toolset with changes required to load the modified RED-Qdisc.
We have followed the answer to this StackOverflow question: https://stackoverflow.com/questions/26499631/how-to-add-a-new-qdisc-in-linux

## modified_red
The code for the modified RED-Qdisc.

## kernel
Contain kernel patch(es) for paced chirping and instructions on how to
compile and install it.

- Versions
-- v1: Used in the thesis
-- v2: Changed the code from operating in rate to operate in time gaps. Reduces the number of division done in the cc module and in the kernel.
