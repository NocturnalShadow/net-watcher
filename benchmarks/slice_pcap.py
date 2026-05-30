"""Write the first N packets of a classic pcap to a new pcap (for quick tests).

Copies the 24-byte global header verbatim and the first N record headers+data,
so the slice is a valid pcap the pipeline reads exactly like the original.

Usage:
    venv/Scripts/python benchmarks/slice_pcap.py <src.pcap> <dst.pcap> <N>
"""
import struct
import sys


def main():
    src, dst, n = sys.argv[1], sys.argv[2], int(sys.argv[3])
    with open(src, "rb") as f, open(dst, "wb") as out:
        gh = f.read(24)
        out.write(gh)
        count = 0
        while count < n:
            hdr = f.read(16)
            if len(hdr) < 16:
                break
            incl_len = struct.unpack("<I", hdr[8:12])[0]
            data = f.read(incl_len)
            if len(data) < incl_len:
                break
            out.write(hdr)
            out.write(data)
            count += 1
    print(f"Wrote {count} packets to {dst}")


if __name__ == "__main__":
    main()
