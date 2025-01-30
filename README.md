# Basic Sniffer Tool

## Overview

The Basic Sniffer Tool is a simple network packet sniffer written in Python. It captures and analyzes network packets at the Ethernet level, providing insights into the data being transmitted over the network. This tool is designed for educational purposes, helping users understand network protocols and packet structures.

## Features

- Captures live network packets using raw sockets
- Displays Ethernet frame details (MAC addresses and protocol)
- Analyzes IPv4 packets and displays relevant information
- Processes TCP segments and shows source/destination ports, sequence, and acknowledgment numbers
- Simple command-line interface

## Requirements

- Python 3.x
- No external libraries required (uses built-in `socket` and `struct` modules)

## Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/yourusername/basic-sniffer-tool.git
