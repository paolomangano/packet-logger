---
inclusion: always
---

# Technology Stack & Development Guidelines

## Core Technology Decisions
- **Language**: C (confirmed - use C99 standard)
- **Target Platform**: Linux systems only
- **Protocol Support**: IPv4 only (no IPv6 implementation needed)
- **Packet Capture**: Use libpcap library (preferred over raw sockets)
- **Build System**: Makefile-based compilation

## Code Style & Standards
- Follow C99 standard conventions
- Use snake_case for function and variable names
- Include proper error handling for all system calls
- Add descriptive comments for complex packet parsing logic
- Implement graceful shutdown with SIGINT handler
- Always validate user input (IP addresses, interface names)

## Architecture Patterns
- Single executable design (`packet-tracer`)
- Modular function organization:
  - `parse_arguments()` - Command-line validation
  - `validate_interface()` - Network interface checks
  - `setup_capture()` - libpcap initialization
  - `process_packet()` - Packet analysis callback
  - `cleanup_resources()` - Memory and handle cleanup
  - `signal_handler()` - Graceful shutdown

## Required Dependencies
- libpcap-dev (Ubuntu/Debian) or libpcap-devel (RHEL/CentOS)
- Standard C library with POSIX signal support

## Build Commands
```bash
# Standard build
make

# Debug build
make debug

# Clean build artifacts
make clean
```

## Testing Requirements
- Test with valid IPv4 addresses and network interfaces
- Test error handling for invalid inputs
- Verify graceful shutdown with Ctrl+C
- Test on different network interfaces (eth0, wlan0, etc.)

## Performance Guidelines
- Use efficient packet filtering with BPF (Berkeley Packet Filter)
- Minimize memory allocations in packet processing loop
- Avoid buffering - display packets in real-time
- Handle high packet rates without dropping packets

## Security Considerations
- Require root privileges for packet capture
- Validate all user inputs to prevent injection attacks
- Use safe string handling functions (strncpy, snprintf)
- Implement proper bounds checking for packet data access