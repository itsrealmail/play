# Парсер для masscan_output.txt, сохраняет результат в nmap_in.txt
import sys

def parse_masscan_lines(input_path, output_path):
    with open(input_path, "r") as fin, open(output_path, "w") as fout:
        for line in fin:
            line = line.strip()
            if not line or not line.startswith("open tcp"):
                continue
            parts = line.split()
            if len(parts) >= 4:
                port = parts[2]
                ip = parts[3]
                fout.write(f"{ip}:{port}\n")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 parse_masscan.py masscan_output.txt")
        sys.exit(1)
    input_file = sys.argv[1]
    output_file = "nmap_in.txt"
    parse_masscan_lines(input_file, output_file)
    print(f"Saved: {output_file}")