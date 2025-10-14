# Requirements Document

## Introduction

This feature involves developing a command-line network packet interceptor and tracer named packet-tracer that captures and analyzes IP protocol (and only IP protocol) traffic having the IP address provided as input as source or destination and transiting from a specific network interface on local host, the second input. The program will run on Linux systems and provide packet analysis printed on standard output (1 line per packet), including timestamp, IP headers and traffic direction for network monitoring and debugging purposes. Only IPv4 is supported.

## Requirements

### Requirement 1

**User Story:** As a network administrator, I want to launch the program packet-tracer from a linux CLI specifying an IPv4 address and a local network interface for packet monitoring, so that I can start traffic analysis for a specific host or service.

#### Acceptance Criteria

1. WHEN the program is launched THEN the system SHALL accept an IPv4 address and a network interface identifier (a driver name followed by a unit number, for example eth0) as command-line arguments
2. WHEN an invalid IPv4 address format is provided THEN the system SHALL display an error message and exit gracefully
3. WHEN an invalid network interface identifier is provided THEN the system SHALL display an error message and exit gracefully
4. WHEN no IPv4 address and/or no network interface identifier are provided THEN the system SHALL display usage instructions 

### Requirement 2

**User Story:** As a network administrator, I want to launch the program packet-tracer to capture all IP packets having the input IPv4 address as source or destination, flowing from network interface provided as input, so that I can monitor bidirectional network communication.

#### Acceptance Criteria

1. WHEN the program starts THEN it SHALL capture all traffic of the network interface provided as input having as source or destination the IP address provided as input
2. WHEN the program starts monitoring THEN the system SHALL capture all outbound packets originating from the network interface provided as input and directed to the IP address provided as input
3. WHENEVER a packet is captured THEN all IP headers information and traffic direction (inbound/outbound) is printed to standard output using easy to read format specifying each header name
4. WHEN the program lacks sufficient permissions THEN the system SHALL display a clear error message about required privileges

### Requirement 3

**User Story:** As a network administrator, I want to gracefully stop packet capture, so that I can control when monitoring begins and ends.

#### Acceptance Criteria

1. WHEN the user sends a SIGINT signal (Ctrl+C) to packet-tracer  in execution THEN the system SHALL stop packet capture and exit cleanly
2. WHEN stopping capture THEN packet-tracer SHALL display a summary of total packets captured
3. WHEN exiting THEN packet-tracer SHALL properly clean up any allocated resources