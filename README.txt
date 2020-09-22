README

Disassembler.py is a program that disassembles a .o binary file with x86 machine code using the linear sweep algorithm. It outputs the disassembled instructions and offsets to stdout. It is only able to disassemble instructions as indicated in the Programming Assignment 1 PDF for JHU EP 695.744 Fall 2020.  

To run this program, run:

python disassembler.py [-h] -i inputfile [-v]

-h will display help documentation
-i should be followed by the binary file to be disassembled
-v will trigger verbose mode

A sample assembly (.S) and binary (.o) file have been provided. To test these files, run:

python disassembler.py -i laurentest.o

The output of this function should match what is seen in laurentest.S. 