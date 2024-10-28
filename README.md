### `README.md`

# Network Monitor

A simple network monitoring tool that captures and analyzes network packets using Scapy.

## Features

- Captures network packets and counts the number of packets between source and destination IPs.
- Displays total packets captured and packets per second.
- Lists the top 5 connections based on packet count.

## Requirements

To run this project, you need to have Python installed along with the following packages:

- Scapy

## Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/mnshchtri/Network-monitor.git
   cd Network-monitor
   ```

2. Install the required packages:
   ```bash
   pip install -r requirements.txt
   ```

## Usage

Run the script using:
```bash
python3 network_monitor.py
```

You can specify the duration for monitoring by passing an argument:
```bash
python3 network_monitor.py <duration>
```

## License

This project is licensed under the MIT License.
```

 `requirements.txt`
```plaintext
scapy
```

### Explanation
- The `README.md` provides an overview of the project, its features, installation instructions, and usage.
- The `requirements.txt` lists the necessary package (`scapy`) for the project. 

