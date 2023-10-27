#include <netinet/ip_icmp.h>
#include <bits/stdc++.h>
#include <netinet/ip.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <ifaddrs.h>
#include <unistd.h>
#include <signal.h>
#include <fcntl.h>
#include <netdb.h>
#include <iostream>
#include <fstream>
#include <cstring>
#include <cstdlib>
#include <csignal>
#include <string>
#include <chrono>
#include <thread>
#include <cstdio>
#include <atomic>
#include <ctime>

#define PACKET_SIZE 64

volatile std::atomic<bool> stop_flag(false);
void signal_handler(int signal) 
{
    std::cout << "Stopping the program..." << std::endl;
    stop_flag.store(true);
}

bool sendStatus(int sockfd, bool status) 
{
    std::string response = (status) ? "Active" : "Inactive";
    ssize_t bytesSent = send(sockfd, response.c_str(), response.length(), 0);
    if (bytesSent <= 0) 
    {
        std::cerr << "Error sending response to client!" << std::endl;
        return false;
    }
    return true;
}

unsigned short calculateChecksum(unsigned short* buffer, int length) 
{
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

std::string getSelfIP() 
{
    struct ifaddrs* ifAddrStruct = NULL;
    struct ifaddrs* ifa = NULL;
    void* tmpAddrPtr = NULL;
    std::string selfIP = "";
    getifaddrs(&ifAddrStruct);
    for (ifa = ifAddrStruct; ifa != NULL; ifa = ifa->ifa_next) 
    {
        if (!ifa->ifa_addr) 
        {
            continue;
        }
        if (ifa->ifa_addr->sa_family == AF_INET) 
        {
            tmpAddrPtr = &((struct sockaddr_in*)ifa->ifa_addr)->sin_addr;
            char addressBuffer[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, tmpAddrPtr, addressBuffer, INET_ADDRSTRLEN);
            if (strcmp(ifa->ifa_name, "lo") != 0) 
            {
                selfIP = addressBuffer;
                break;
            }
        }
    }
    if (ifAddrStruct != NULL) 
    {
        freeifaddrs(ifAddrStruct);
    }
    return selfIP;
}

bool isIPActive(const std::string& ipAddress) 
{
    // Create raw socket for ICMP communication
    int sock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (sock < 0) 
    {
        std::cerr << "Error creating socket" << std::endl;
        return false;
    }
    int optval = 1;
    setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval));
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
    inet_pton(AF_INET, ipAddress.c_str(), &(destAddr.sin_addr));
    // Send the ICMP Echo Request packet
    int bytesSent = sendto(sock, packet, sizeof(icmp), 0, (struct sockaddr*)&destAddr, sizeof(destAddr));
    if (bytesSent < 0) 
    {
        std::cerr << "Error sending packet" << std::endl;
        return false;
    }
    // Receive the ICMP Echo Reply packet
    char recvBuffer[PACKET_SIZE];
    sockaddr_in senderAddr;
    socklen_t senderLen = sizeof(senderAddr);
    int bytesReceived = recvfrom(sock, recvBuffer, sizeof(recvBuffer), 0, (struct sockaddr*)&senderAddr, &senderLen);
    if (bytesReceived < 0) 
    {
        std::cerr << "Error receiving packet" << std::endl;
        return false;
    }
    // Parse the received packet to extract information (e.g., round-trip time, TTL, etc.)
    iphdr* ipHeader = (iphdr*)recvBuffer;
    icmp* recvIcmpHeader = (icmp*)(recvBuffer + (ipHeader->ihl << 2));
    if (strcmp(ipAddress.c_str(), getSelfIP().c_str()) == 0 || strcmp(ipAddress.c_str(), "127.0.0.1") == 0) 
    {
        return true;
    } 
    else if (recvIcmpHeader->icmp_type == ICMP_ECHOREPLY) 
    {
        return true;
    } 
    else 
    {
        return false;
    }
    // Close the socket
    close(sock);
}

void handleClient(int clientSockfd) 
{
    char clientIP[INET_ADDRSTRLEN];
    sockaddr_in clientAddr;
    socklen_t clientAddrLen = sizeof(clientAddr);
    getpeername(clientSockfd, reinterpret_cast<struct sockaddr*>(&clientAddr), &clientAddrLen);
    inet_ntop(AF_INET, &(clientAddr.sin_addr), clientIP, INET_ADDRSTRLEN);
    std::cout << "Connected to client " << clientIP << std::endl;
    std::string message;
    while (!stop_flag.load()) 
    {
        char buffer[1024];
        ssize_t bytesRead = recv(clientSockfd, buffer, sizeof(buffer), 0);
        if (bytesRead <= 0) 
        {
            std::cerr << "Error receiving message from client!" << std::endl;
            break;
        }
        message = std::string(buffer, bytesRead);
        std::cout << "Received message from client " << clientIP << ": " << message << std::endl;
        bool activeStatus = isIPActive(message);
        if (!sendStatus(clientSockfd, activeStatus)) 
        {
            std::cerr << "Error sending status to client!" << std::endl;
            break;
        }
    }
    close(clientSockfd);
    std::cout << "Connection closed with client " << clientIP << std::endl;
}


int main(int argc, char* argv[]) 
{
    if (argc < 2) 
    {
        std::cerr << "Enter First these details: " << argv[0] << " <Port Number>" << std::endl;
        return 1;
    }
    // Set up signal handling
    signal(SIGINT, signal_handler);
    int portNumber = std::stoi(argv[1]);
    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) 
    {
        std::cerr << "Error creating socket!" << std::endl;
        return 1;
    }
    sockaddr_in serverAddr;
    memset(&serverAddr, 0, sizeof(serverAddr));
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_port = htons(portNumber);
    serverAddr.sin_addr.s_addr = INADDR_ANY;
    if (bind(sockfd, reinterpret_cast<struct sockaddr*>(&serverAddr), sizeof(serverAddr)) < 0) 
    {
        std::cerr << "Error binding socket!" << std::endl;
        close(sockfd);
        return 1;
    }
    if (listen(sockfd, SOMAXCONN) < 0) 
    {
        std::cerr << "Error listening on socket!" << std::endl;
        close(sockfd);
        return 1;
    }
    std::cout << "Waiting for incoming connections... Just Wait Please" << std::endl;
    while (!stop_flag.load()) 
    {
        sockaddr_in clientAddr;
        socklen_t clientAddrLen = sizeof(clientAddr);
        int clientSockfd = accept(sockfd, reinterpret_cast<struct sockaddr*>(&clientAddr), &clientAddrLen);
        if (clientSockfd < 0) 
        {
            std::cerr << "Error accepting client connection!" << std::endl;
            continue;
        }
        char clientIP[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &(clientAddr.sin_addr), clientIP, INET_ADDRSTRLEN);
        std::cout << "Connected to client " << clientIP << std::endl;
        // Create a new thread to handle the communication with the client
        std::thread clientThread(handleClient, clientSockfd);
        clientThread.detach();
    }
    close(sockfd);
    return 0;
}

