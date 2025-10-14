# Design Document

## Overview

The packet-tracer is a command-line tool written in C that uses libpcap to capture and analyze IPv4 packets on a specified network interface. The program filters packets based on a target IP address and displays packet information in a simple, readable format to standard output.

## Architecture

### High-Level Architecture
```
Command Line Input → Argument Validation → Packet Capture → Packet Analysis → Output Display
```

### Core Components
1. **Argument Parser**: Validates IP address and network interface
2. **Packet Capture Engine**: Uses libpcap to capture packets
3. **Packet Analyzer**: Extracts and formats packet information
4. **Output Formatter**: Displays packet data in readable format
5. **Signal Handler**: Manages graceful shutdown

## Components and Interfaces

### 1. Main Program (`main()`)
- Parse command-line arguments
- Initialize packet capture
- Set up signal handlers
- Start packet capture loop
- Clean up resources on exit

### 2. Argument Validation Module
```c
int validate_ip_address(const char* ip_str);
int validate_network_interface(const char* interface);
void print_usage(const char* program_name);
```

### 3. Packet Capture Module
```c
pcap_t* initialize_capture(const char* interface, const char* target_ip);
void packet_handler(u_char* user_data, const struct pcap_pkthdr* header, const u_char* packet);
void cleanup_capture(pcap_t* handle);
```

### 4. Packet Analysis Module
```c
void analyze_ip_header(const u_char* packet);
void determine_traffic_direction(const char* src_ip, const char* dst_ip, const char* target_ip);
```

### 5. Signal Handler
```c
void signal_handler(int signal);
void setup_signal_handlers();
```

## Data Models

### Packet Information Structure
```c
struct ip_packet_info {
    struct timeval timestamp;
    char direction[10];       // "INBOUND" or "OUTBOUND"
    char src_ip[16];
    char dst_ip[16];
    uint8_t version;          // IP version (4)
    uint8_t header_length;    // IP header length
    uint8_t type_of_service;  // Type of service
    uint16_t total_length;    // Total packet length
    uint16_t identification;  // Identification
    uint16_t flags;           // Flags
    uint16_t fragment_offset; // Fragment offset
    uint8_t ttl;              // Time to live
    uint8_t protocol;         // Protocol (TCP=6, UDP=17, ICMP=1)
    uint16_t checksum;        // Header checksum
};
```

### Global State
```c
struct program_state {
    pcap_t* capture_handle;
    char target_ip[16];
    char interface[16];
    uint32_t packet_count;
    int running;
};
```

## Error Handling

### Input Validation Errors
- Invalid IP address format → Display error message and usage
- Invalid network interface → Display error message and exit
- Missing arguments → Display usage instructions

### Runtime Errors
- Insufficient privileges → Display clear error about sudo/root requirements
- Network interface not found → Display error and available interfaces
- Packet capture initialization failure → Display libpcap error message

### Signal Handling
- SIGINT (Ctrl+C) → Set running flag to false, display packet count summary, clean exit

## Testing Strategy

### Unit Testing
- IP address validation function testing
- Network interface validation testing
- Packet header parsing accuracy
- Traffic direction determination logic

### Integration Testing
- End-to-end packet capture with known traffic
- Signal handling verification
- Error condition testing (invalid inputs, permission issues)

### Manual Testing
- Test with various network interfaces (eth0, wlan0, lo)
- Test with different IP addresses (local, remote, broadcast)
- Test permission handling (run without sudo)
- Test graceful shutdown with Ctrl+C

## Implementation Details

### Packet Capture Filter
- Use libpcap filter: `host <target_ip>` to capture only relevant packets
- This automatically handles both inbound and outbound traffic

### Output Format
```
[TIMESTAMP] [DIRECTION] IP: src_ip -> dst_ip Protocol: protocol_name
  IP Header: version=4 header_len=20 tos=0 total_len=60 id=12345 flags=0x2 frag_offset=0 ttl=64 protocol=6 checksum=0x1234
```

### Dependencies
- libpcap-dev (packet capture library)
- Standard C library
- POSIX signal handling

### Build System
- Simple Makefile with libpcap linking
- Compiler flags: `-Wall -Wextra -std=c99`
- Link flags: `-lpcap`

## Performance Considerations

- Minimal packet processing overhead
- Direct output to stdout (no buffering)
- Efficient string formatting
- Single-threaded design for simplicity
- Memory management for continuous operation