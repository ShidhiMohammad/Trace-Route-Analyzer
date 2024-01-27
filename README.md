# Trace Route Analyzer

This suite consists of a Python script and a helper module designed to analyze and interpret network packets, particularly focusing on trace route data.

## Files

- `p3Final.py`: The primary script that processes pcap files to analyze network packets. It identifies source and destination nodes, intermediate nodes, calculates round-trip times, and other statistics.
- `headers.py`: A helper module that defines classes for packet headers and various utilities for packet processing. It is used by `p3Final.py` for detailed packet analysis..

## Usage

To use the Trace Route Analyzer, ensure that both `p3Final.py` and `headers.py` are in the same directory.

Run the main script as follows:

python3 p3Final.py sample_trace_file.cap

Replace sample_trace_file.cap with the path to your pcap file.
