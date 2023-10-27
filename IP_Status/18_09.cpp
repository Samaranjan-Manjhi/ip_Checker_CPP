#include <bits/stdc++.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <signal.h>
#include <fcntl.h>
#include <iostream>
#include <fstream>
#include <cstring>
#include <cstdlib>
#include <string>
#include <chrono>
#include <thread>
#include <cstdio>
#include <atomic>
#include <ctime>
#include <netinet/ip_icmp.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <unistd.h>
#include <iostream>
#include <cstdlib>
#include <cstring>
#include <ifaddrs.h>
#include <netdb.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#define PACKET_SIZE 64
std::atomic<bool> stop_flag(false);

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

void writeIPStatusToFile(const std::string& ipAddress, bool status) {
    std::ofstream outFile("/home/escan/edu/task/work/log/ip_status.log", std::ios_base::app);
    if (!outFile) 
    {
        std::cerr << "Error opening output file!" << std::endl;
        return;
    }
    std::time_t nowTime = std::time(nullptr);
    std::string statusStr = (status) ? "Active" : "Inactive";
    outFile << std::ctime(&nowTime) << "IP Address: " << ipAddress << " - Status: " << statusStr << std::endl;
    outFile.close();
    return;
}

void createDaemon(const std::string& ipAddress, int checkIntervalSeconds) 
{
    pid_t pid = fork();
    if (pid < 0) {
        perror("Error forking process");
        exit(EXIT_FAILURE);
    }
    if (pid > 0) {
        std::cout << "Daemon process started with PID: " << pid << std::endl;
        exit(EXIT_SUCCESS);
    }
    umask(0);
    if (setsid() < 0) {
        perror("Error creating new session");
        exit(EXIT_FAILURE);
    }
    close(STDIN_FILENO);
    close(STDOUT_FILENO);
    close(STDERR_FILENO);
    signal(SIGCHLD, SIG_IGN);
    while (true) {
        bool status = isIPActive(ipAddress);
        writeIPStatusToFile(ipAddress, status);
        std::this_thread::sleep_for(std::chrono::seconds(checkIntervalSeconds));
    }
}

void signal_handler(int signal) {
    std::cout << "Stopping the program..." << std::endl;
    exit(signal);
}

int main(int argc, char* argv[]) 
{
    if (argc < 2) {
        std::cerr << "Enter First these details: " << argv[0] << " <Port Number>" << std::endl;
        return 1;
    }
    int portNumber = std::stoi(argv[1]);
    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        std::cerr << "Error creating socket!" << std::endl;
        return 1;
    }
    int optval = 1;
    setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval));
    struct sockaddr_in serverAddr;
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_addr.s_addr = INADDR_ANY;
    serverAddr.sin_port = htons(portNumber);
    if (bind(sockfd, (struct sockaddr*)&serverAddr, sizeof(serverAddr)) < 0) {
        std::cerr << "Error binding socket!" << std::endl;
        close(sockfd);
        return 1;
    }
    if (listen(sockfd, 1) < 0) {
        std::cerr << "Error listening on socket!" << std::endl;
        close(sockfd);
        return 1;
    }
    std::cout << "Server listening on port " << portNumber << "..." << std::endl;
    std::signal(SIGINT, signal_handler);
    while (true) {
        int clientfd = accept(sockfd, NULL, NULL);
        if (clientfd < 0) {
            std::cerr << "Error accepting client connection!" << std::endl;
            continue;
        }
        char buffer[1024];
        memset(buffer, 0, sizeof(buffer));
        ssize_t bytesRead = recv(clientfd, buffer, sizeof(buffer), 0);
        if (bytesRead <= 0) {
            std::cerr << "Error receiving IP address from client!" << std::endl;
            close(clientfd);
            continue;
        }
        std::string ipAddress(buffer);
        bool status = isIPActive(ipAddress);
        writeIPStatusToFile(ipAddress, status);
        std::string response = (status) ? "Active" : "Inactive";
        ssize_t bytesSent = send(clientfd, response.c_str(), response.length(), 0);
        if (bytesSent <= 0) {
            std::cerr << "Error sending status to client!" << std::endl;
        }
        close(clientfd);
    }
    close(sockfd);
    std::cout << "Stopping the program..." << std::endl;
    return 0;
}
