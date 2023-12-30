
# Firewall Configuration Management System

## Overview
This project is part of the "Operating Systems and Systems Programming" course at The University of Birmingham. It implements a client-server architecture for managing firewall configurations. The server program maintains a collection of firewall rules and processes requests from clients, while the client program allows users to send requests to the server and view responses.

## Description
The task involves writing two programs:
1. A server program that runs indefinitely, listening for client requests to manage firewall rules.
2. A client program that interacts with the server to add, check, delete, or list firewall rules.

## Features
- **Server Program**
  - Listens on a specified port.
  - Supports adding, checking, and deleting firewall rules.
  - Maintains a list of IP addresses and ports queried for each rule.
  - Returns appropriate responses based on request type.

- **Client Program**
  - Connects to the server program.
  - Sends requests to the server and displays returned results.
  - Supports various operations (add, check, delete, list rules).

## Installation
### Prerequisites
- GCC Compiler
- Linux environment

### Compiling
Compile the server and client programs using GCC:
```bash
gcc -o server server.c -lpthread
gcc -o client client.c
```

## Usage
### Starting the Server
```bash
./server <port>
```
### Running the Client
```bash
./client <ServerHost> <ServerPort> [A|C|D|L] [<IP Address> <Port>]
```
- 'A': Add a rule
- 'C': Check an IP address and port
- 'D': Delete a rule
- 'L': List rules

## Server Program
The server program (`server.c`) is designed to handle multiple client requests concurrently using threads. It listens on a specified TCP port and processes incoming client requests. Key functionalities include rule addition, deletion, query processing, and rule listing.

### Code Structure
- **Thread Management**: Uses `pthread` library for handling multiple client connections.
- **Rule Management**: Stores and manages firewall rules.
- **Request Processing**: Interprets client requests and provides appropriate responses.
- **Connection Handling**: Accepts and manages client connections.

## Client Program
The client program (`client.c`) interacts with the server to perform firewall rule management tasks. It connects to the server using TCP/IP and sends requests based on user input.

### Code Structure
- **Connection Setup**: Establishes a connection with the server.
- **User Input Handling**: Processes arguments for different operations.
- **Request Formation**: Creates and sends requests to the server.
- **Response Handling**: Displays the server's response to the user.
