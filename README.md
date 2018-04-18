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
Contain kernel patch for paced chirping and instructions on how to
compile and install it. This takes some time and I do not guarantee that
it works for you, but it should.
