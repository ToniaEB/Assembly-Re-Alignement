import pandas as pd

# Example ARM64 instruction addresses from your Ghidra disassembly
valid_addresses = [
    0x1400012e0, 0x1400012e4, 0x1400012e8, 0x1400012ec, 0x1400012f0,
    0x1400012f4, 0x1400012f8, 0x1400012fc, 0x140001300, 0x140001304,
    0x140001308, 0x14000130c, 0x140001310, 0x140001314, 0x140001318,
    0x14000131c, 0x140001320, 0x140001324, 0x140001328, 0x14000132c,
    0x140001330, 0x140001334, 0x140001338
]

# Convert to set for quick lookup
valid_set = set(valid_addresses)
min_addr = min(valid_set)
max_addr = max(valid_set)
max_steps = 25  # maximum sweep steps

# Run linear sweep simulation
results = []

for offset in range(min_addr, max_addr, 1):
    if offset in valid_set:
        continue  # skip real instruction starts

    steps = 0
    current = offset
    while steps < max_steps:
        if current in valid_set:
            results.append((offset, steps))
            break
        current += 4  # ARM64 instructions are 4 bytes
        steps += 1
    else:
        results.append((offset, None))  # never realigned

# Create and save result table
df = pd.DataFrame(results, columns=["Start Offset", "Steps to Realign"])
print(df)

# Optional: export to CSV
df.to_csv("linear_sweep_results.csv", index=False)
