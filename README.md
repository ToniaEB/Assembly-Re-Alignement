# Assembly-Re-Alignement
This project evaluates how a linear sweep disassembler behaves when it starts disassembling from incorrect (misaligned) offsets in an ARM64 binary. The goal is to simulate realignment behavior and determine how many 4-byte instructions are decoded before either a valid instruction boundary is reached or decoding fails.

Contents

linear_sweep_simulation.py: Python script that simulates linear sweep disassembly.

instructions.txt: (Optional) A file containing exported valid instruction addresses from Ghidra.

linear_sweep_results.csv: Output of the simulation (optional).

How It Works

The ARM64 binary (e.g., curl.exe) is disassembled in Ghidra.

The valid instruction start addresses are extracted (manually or via script) and saved.

The Python script performs a sweep:

Starts at all possible offsets that are not valid instruction addresses

Simulates decoding instructions in 4-byte steps (ARM64)

Stops if realignment is achieved or after 25 instructions

Results are logged to terminal and optionally saved as CSV.

