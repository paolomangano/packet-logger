#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pcap.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <ifaddrs.h>
#include <errno.h>
#include <netinet/ip.h>
#include <netinet/in.h>
#include <sys/time.h>
#include <time.h>
#include <signal.h>

// Global variables for packet capture and program state
pcap_t* capture_handle = NULL;
char target_ip_address[16];
uint32_t packet_count = 0;
volatile int running = 1;

// Structure to hold IP packet information
struct ip_packet_info {
    struct timeval timestamp;
    char direction[10];       // "INBOUND" or "OUTBOUND"
    char src_ip[16];
    char dst_ip[16];
    uint8_t version;          // IP version (4)
    uint8_t header_length;    // IP header length in bytes
    uint8_t type_of_service;  // Type of service
    uint16_t total_length;    // Total packet length
    uint16_t identification;  // Identification
    uint16_t flags;           // Flags
    uint16_t fragment_offset; // Fragment offset
    uint8_t ttl;              // Time to live
    uint8_t protocol;         // Protocol (TCP=6, UDP=17, ICMP=1)
    uint16_t checksum;        // Header checksum
};

/**
 * Determine traffic direction based on source and destination IPs
 * Returns "INBOUND" if packet is coming to target IP, "OUTBOUND" if from target IP
 */
void determine_traffic_direction(const char* src_ip, const char* dst_ip, const char* target_ip, char* direction) {
    if (strcmp(src_ip, target_ip) == 0) {
        strcpy(direction, "OUTBOUND");
    } else if (strcmp(dst_ip, target_ip) == 0) {
        strcpy(direction, "INBOUND");
    } else {
        strcpy(direction, "UNKNOWN");
    }
}

/**
 * Get protocol name from protocol number
 */
const char* get_protocol_name(uint8_t protocol) {
    switch (protocol) {
        case 1: return "ICMP";
        case 6: return "TCP";
        case 17: return "UDP";
        default: return "OTHER";
    }
}

/**
 * Extract IP header information from captured packet
 * Fills the ip_packet_info structure with parsed header data
 */
void analyze_ip_header (const u_char* packet, const struct pcap_pkthdr* header, struct ip_packet_info* packet_info) {
    // Ethernet header is typically 14 bytes, skip to IP header
    const struct ip* ip_header = (struct ip*)(packet + 14);
    
    // Store timestamp with microsecond precision
    packet_info->timestamp = header->ts;
    
    // Extract source and destination IP addresses
    strcpy(packet_info->src_ip, inet_ntoa(ip_header->ip_src));
    strcpy(packet_info->dst_ip, inet_ntoa(ip_header->ip_dst));
    
    // Determine traffic direction
    determine_traffic_direction(packet_info->src_ip, packet_info->dst_ip, target_ip_address, packet_info->direction);
    
    // Extract IP header fields (BSD-style struct ip)
    packet_info->version = ip_header->ip_v;
    packet_info->header_length = ip_header->ip_hl * 4;  // IHL is in 4-byte words
    packet_info->type_of_service = ip_header->ip_tos;
    packet_info->total_length = ntohs(ip_header->ip_len);
    packet_info->identification = ntohs(ip_header->ip_id);
    packet_info->flags = (ntohs(ip_header->ip_off) & 0xE000) >> 13;
    packet_info->fragment_offset = ntohs(ip_header->ip_off) & 0x1FFF;
    packet_info->ttl = ip_header->ip_ttl;
    packet_info->protocol = ip_header->ip_p;
    packet_info->checksum = ntohs(ip_header->ip_sum);
}

/**
 * Display formatted packet information to standard output
 */
void display_packet_info(const struct ip_packet_info* packet_info) {
    // Format timestamp
    char timestamp_str[64];
    struct tm* tm_info = localtime(&packet_info->timestamp.tv_sec);
    snprintf(timestamp_str, sizeof(timestamp_str), "%02d:%02d:%02d.%06d",
             tm_info->tm_hour, tm_info->tm_min, tm_info->tm_sec, (int)packet_info->timestamp.tv_usec);
    
    // Display packet summary line
    printf("[%s] [%s] IP: %s -> %s Protocol: %s\n",
           timestamp_str,
           packet_info->direction,
           packet_info->src_ip,
           packet_info->dst_ip,
           get_protocol_name(packet_info->protocol));
    
    // Display detailed IP header information
    printf("  IP Header: version=%d header_len=%d tos=%d total_len=%d id=%d flags=0x%x frag_offset=%d ttl=%d protocol=%d checksum=0x%04x\n",
           packet_info->version,
           packet_info->header_length,
           packet_info->type_of_service,
           packet_info->total_length,
           packet_info->identification,
           packet_info->flags,
           packet_info->fragment_offset,
           packet_info->ttl,
           packet_info->protocol,
           packet_info->checksum);
}

/**
 * Packet handler callback function for libpcap
 * This function is called for each captured packet
 */
void packet_handler(u_char* user_data __attribute__((unused)), const struct pcap_pkthdr* header, const u_char* packet) {
    struct ip_packet_info packet_info;
    
    // Increment packet count for tracking
    packet_count++;
    
    // Analyze the IP header and extract information
    analyze_ip_header(packet, header, &packet_info);
    
    // Display the packet information
    display_packet_info(&packet_info);
}

void print_usage(const char* program_name) {
    printf("Usage: %s <IPv4_address> <network_interface>\n", program_name);
    printf("  IPv4_address      - Target IP address to monitor (e.g., 192.168.1.100)\n");
    printf("  network_interface - Network interface to capture from (e.g., eth0, wlan0)\n");
    printf("\nExample: %s 192.168.1.100 eth0\n", program_name);
}

/**
 * Validates IPv4 address format using inet_pton()
 * Returns 1 if valid, 0 if invalid
 */
int validate_ip_address(const char* ip_str) {
    struct sockaddr_in sa;
    int result = inet_pton(AF_INET, ip_str, &(sa.sin_addr));
    return result;
}

/**
 * Validates network interface by checking if it exists
 * Returns 1 if valid, 0 if invalid
 */
int validate_network_interface(const char* interface) {
    struct ifaddrs *ifaddrs_ptr, *ifa;
    int interface_found = 0;

    if (getifaddrs(&ifaddrs_ptr) == -1) {
        fprintf(stderr, "Error: Failed to get network interfaces: %s\n", strerror(errno));
        return 0;
    }

    for (ifa = ifaddrs_ptr; ifa != NULL; ifa = ifa->ifa_next) {
        if (ifa->ifa_addr == NULL) continue;
        
        if (strcmp(ifa->ifa_name, interface) == 0) {
            interface_found = 1;
            break;
        }
    }

    freeifaddrs(ifaddrs_ptr);
    return interface_found;
}

/**
 * Initialize libpcap capture handle for the specified interface and target IP
 * Returns pcap_t* handle on success, NULL on failure
 */
pcap_t* initialize_capture(const char* interface, const char* target_ip) {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle;
    struct bpf_program filter_program;
    char filter_expression[256];
    bpf_u_int32 net, mask;

    // Clear error buffer
    errbuf[0] = '\0';

    // Get network address and mask for the interface
    if (pcap_lookupnet(interface, &net, &mask, errbuf) == -1) {
        fprintf(stderr, "Warning: Could not get network info for interface %s: %s\n", interface, errbuf);
        net = 0;
        mask = 0;
    }

    // Open the interface for packet capture
    handle = pcap_open_live(interface, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Error: Could not open interface %s for packet capture: %s\n", interface, errbuf);
        
        // Check for common permission issues
        if (strstr(errbuf, "Operation not permitted") || strstr(errbuf, "Permission denied")) {
            fprintf(stderr, "Note: Packet capture requires elevated privileges. Try running with sudo:\n");
            fprintf(stderr, "      sudo %s\n", "packet-tracer");
        }
        return NULL;
    }

    // Create filter expression for target IP (both source and destination)
    snprintf(filter_expression, sizeof(filter_expression), "host %s", target_ip);

    // Compile the filter
    if (pcap_compile(handle, &filter_program, filter_expression, 0, net) == -1) {
        fprintf(stderr, "Error: Could not compile packet filter '%s': %s\n", 
                filter_expression, pcap_geterr(handle));
        pcap_close(handle);
        return NULL;
    }

    // Apply the filter
    if (pcap_setfilter(handle, &filter_program) == -1) {
        fprintf(stderr, "Error: Could not apply packet filter '%s': %s\n", 
                filter_expression, pcap_geterr(handle));
        pcap_freecode(&filter_program);
        pcap_close(handle);
        return NULL;
    }

    // Free the compiled filter program
    pcap_freecode(&filter_program);

    printf("Packet capture initialized successfully\n");
    printf("Filter: %s\n", filter_expression);
    printf("Listening on interface: %s\n", interface);

    return handle;
}

/**
 * Clean up packet capture handle and resources
 */
void cleanup_capture(pcap_t* handle) {
    if (handle != NULL) {
        pcap_close(handle);
        printf("Packet capture cleaned up\n");
    }
}

/**
 * Signal handler for graceful shutdown
 * Handles SIGINT (Ctrl+C) to stop packet capture cleanly
 */
void signal_handler(int signal) {
    if (signal == SIGINT) {
        printf("\n\nReceived SIGINT (Ctrl+C), stopping packet capture...\n");
        
        // Set running flag to false to stop capture loop
        running = 0;
        
        // Break the pcap_loop to stop packet capture
        if (capture_handle != NULL) {
            pcap_breakloop(capture_handle);
        }
        
        // Display packet count summary
        printf("Packet capture summary:\n");
        printf("Total packets captured: %u\n", packet_count);
        
        printf("packet-tracer stopped gracefully\n");
    }
}

/**
 * Set up signal handlers for graceful shutdown
 */
void setup_signal_handlers() {
    struct sigaction sa;
    
    // Initialize sigaction structure
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = signal_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;
    
    // Register SIGINT handler
    if (sigaction(SIGINT, &sa, NULL) == -1) {
        fprintf(stderr, "Error: Failed to set up SIGINT handler: %s\n", strerror(errno));
        exit(EXIT_FAILURE);
    }
    
    printf("Signal handlers set up successfully (Ctrl+C to stop)\n");
}

int main(int argc, char *argv[]) {
    // Check command-line arguments
    if (argc != 3) {
        if (argc == 1) {
            print_usage(argv[0]);
        } else {
            fprintf(stderr, "Error: Invalid number of arguments\n");
            print_usage(argv[0]);
        }
        return EXIT_FAILURE;
    }

    // Store command-line arguments
    const char* target_ip = argv[1];
    const char* interface = argv[2];
    
    // Store target IP in global variable for packet analysis
    strcpy(target_ip_address, target_ip);

    // Validate IPv4 address format
    if (!validate_ip_address(target_ip)) {
        fprintf(stderr, "Error: Invalid IPv4 address format: %s\n", target_ip);
        fprintf(stderr, "Please provide a valid IPv4 address (e.g., 192.168.1.100)\n");
        return EXIT_FAILURE;
    }

    // Validate network interface
    if (!validate_network_interface(interface)) {
        fprintf(stderr, "Error: Invalid network interface: %s\n", interface);
        fprintf(stderr, "Please provide a valid network interface (e.g., eth0, wlan0, lo)\n");
        fprintf(stderr, "Use 'ip link show' or 'ifconfig' to list available interfaces\n");
        return EXIT_FAILURE;
    }

    printf("packet-tracer starting...\n");
    printf("Target IP: %s\n", target_ip);
    printf("Interface: %s\n", interface);

    // Initialize packet capture (Task 3)
    capture_handle = initialize_capture(interface, target_ip);
    if (capture_handle == NULL) {
        fprintf(stderr, "Error: Failed to initialize packet capture\n");
        return EXIT_FAILURE;
    }

    // Set up signal handlers for graceful shutdown (Task 6)
    setup_signal_handlers();

    // Start packet capture loop (Task 7)
    printf("packet-tracer initialized successfully\n");
    printf("Starting packet capture... (Press Ctrl+C to stop)\n\n");
    
    // Main packet capture loop - this will run until interrupted by signal
    int result = pcap_loop(capture_handle, -1, packet_handler, NULL);
    
    if (result == -1) {
        fprintf(stderr, "Error: Packet capture loop failed: %s\n", pcap_geterr(capture_handle));
        cleanup_capture(capture_handle);
        return EXIT_FAILURE;
    } else if (result == -2) {
        // pcap_loop was interrupted by pcap_breakloop() (called from signal handler)
        printf("Packet capture loop interrupted\n");
    }
    
    // Clean up resources before exit
    cleanup_capture(capture_handle);
    
    return EXIT_SUCCESS;
}