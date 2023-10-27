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
#include <ctime>

volatile std::sig_atomic_t stop_flag = 0; 

bool checkStatus(int sockfd)
{
    char buffer[1024];
    while (true) 
    {
        std::cout << "Enter IP address to check status (or press Ctrl + C to exit): ";
        std::string ipAddress;
        std::getline(std::cin, ipAddress);
        if (stop_flag) 
        {
            std::cout << "Stopping the program..." << std::endl;
            return false;
        }
        ssize_t bytesSent = send(sockfd, ipAddress.c_str(), ipAddress.length(), 0);
        if (bytesSent <= 0) 
        {
            std::cerr << "Error sending IP address to server!" << std::endl;
            continue;
        }
        char responseBuffer[1024];
        memset(responseBuffer, 0, sizeof(responseBuffer));
        ssize_t bytesRead = recv(sockfd, responseBuffer, sizeof(responseBuffer), 0);
        if (bytesRead <= 0) 
        {
            std::cerr << "Error receiving status from server!" << std::endl;
            continue;
        }
        std::string response(responseBuffer);
        std::cout << "Status of IP address " << ipAddress << " is " << response << std::endl;
    }
    return true;
}

void signal_handler(int sig) 
{
    stop_flag = 1;
}

int main(int argc, char* argv[]) 
{
    if (argc < 2) 
    {
        std::cerr << "Enter First these details: " << argv[0] << " <Server IP Address> <Port Number>" << std::endl;
        return 1;
    }
    int portNumber = std::stoi(argv[2]);
    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) 
    {
        std::cerr << "Error creating socket!" << std::endl;
        return 1;
    }
    struct sockaddr_in serverAddr;
    memset(&serverAddr, 0, sizeof(serverAddr));
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_port = htons(portNumber);
    inet_pton(AF_INET, argv[1], &(serverAddr.sin_addr));
    if (connect(sockfd, reinterpret_cast<struct sockaddr*>(&serverAddr), sizeof(serverAddr)) < 0) 
    {
        std::cerr << "Error connecting to server!" << std::endl;
        close(sockfd);
        return 1;
    }
    std::signal(SIGINT, signal_handler);
    std::cout << "Connected to server " << argv[1] << " on port " << portNumber << std::endl;
    checkStatus(sockfd);
    close(sockfd);
    return 0;
}

