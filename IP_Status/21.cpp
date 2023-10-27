#include <netinet/ip_icmp.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <unistd.h>
#include <iostream>
#include <cstdlib>
#include <cstring>

// Define the packet size used in the ICMP Echo Request
#define PACKET_SIZE 64

// Function to calculate the checksum
unsigned short calculateChecksum(unsigned short* buffer, int length) {
    unsigned long sum = 0;
    while (length > 1) {
        sum += *buffer++;
        length -= 2;
    }
    if (length == 1) {
        sum += *(unsigned char*)buffer;
    }
    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);
    return (unsigned short)(~sum);
}

int main(int argc, char* argv[]) {
    if (argc < 2) {
        std::cerr << "Please Enter IP Address : " << argv[0] << " <IP address>" << std::endl;
        return 1;
    }

    // Create raw socket for ICMP communication
    int sock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (sock < 0) {
        std::cerr << "Error creating socket" << std::endl;
        return 1;
    }

    char packet[PACKET_SIZE];
    memset(packet, 0, sizeof(packet));

    // Set up the ICMP header
    icmp* icmpHeader = (icmp*)packet;
    icmpHeader->icmp_type = ICMP_ECHO;
    icmpHeader->icmp_code = 0;
    icmpHeader->icmp_id = htons(getpid());
    icmpHeader->icmp_seq = htons(1);
    icmpHeader->icmp_cksum = 0;
    icmpHeader->icmp_cksum = calculateChecksum((unsigned short*)icmpHeader, sizeof(icmp));

    sockaddr_in destAddr;
    destAddr.sin_family = AF_INET;
    destAddr.sin_port = 0;
    inet_pton(AF_INET, argv[1], &(destAddr.sin_addr));

    // Send the ICMP Echo Request packet
    int bytesSent = sendto(sock, packet, sizeof(icmp), 0, (struct sockaddr*)&destAddr, sizeof(destAddr));
    if (bytesSent < 0) {
        std::cerr << "Error sending packet" << std::endl;
        return 1;
    }

    // Receive the ICMP Echo Reply packet
    char recvBuffer[PACKET_SIZE];
    sockaddr_in senderAddr;
    socklen_t senderLen = sizeof(senderAddr);
    int bytesReceived = recvfrom(sock, recvBuffer, sizeof(recvBuffer), 0, (struct sockaddr*)&senderAddr, &senderLen);
    if (bytesReceived < 0) {
        std::cerr << "Error receiving packet" << std::endl;
        return 1;
    }

    // Parse the received packet to extract information (e.g., round-trip time, TTL, etc.)
    ip* ipHeader = (ip*)recvBuffer;
    icmp* recvIcmpHeader = (icmp*)(recvBuffer + (ipHeader->ip_hl << 2));

    if (recvIcmpHeader->icmp_type == ICMP_ECHOREPLY) {
        std::cout << "Destination IP is active" << std::endl;
    } else {
        std::cout << "Destination IP is not active" << std::endl;
    }
    
    //std::cout << "Ping Reply from " << inet_ntoa(senderAddr.sin_addr)
          //<< ": seq=" << ntohs(recvIcmpHeader->icmp_seq)
          //<< " time=" << bytesReceived << "ms"
          //<< " ttl=" << ipHeader->ip_ttl
          //<< std::endl;
          
    // Close the socket
    close(sock);

    return 0;
}
