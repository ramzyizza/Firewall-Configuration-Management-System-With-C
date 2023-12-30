#include <netdb.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#define MAX_BUF_SIZE 256

void displayError(char *errorMessage) {
    perror(errorMessage);
    exit(1);
}

int main(int argc, char *argv[]) {
    int socketFD, bytes;
    struct addrinfo settings, *servinfo, *p;
    char sendBuffer[MAX_BUF_SIZE];

    if (argc < 4) {
        fprintf(stderr,
                "Syntax: %s <Server Name> <Server Port> <A C D L> <IP Address>"
                "<Port>\n",
                argv[0]);
        exit(EXIT_FAILURE);
    }

    char operationType = argv[3][0];

    if ((operationType == 'A' || operationType == 'C' ||
         operationType == 'D') &&
        argc != 6) {
        fprintf(stderr,
                "Syntax: %s <Server Name> <Server Port> <A C D> "
                "<IP Address> <Port>\n",
                argv[0]);
        exit(EXIT_FAILURE);
    } else if (operationType == 'L' && argc != 4) {
        fprintf(stderr, "Syntax: %s <Server Name> <Server Port> L\n",
                argv[0]);
        exit(EXIT_FAILURE);
    } else if (!(operationType == 'A' || operationType == 'C' ||
                 operationType == 'D' || operationType == 'L')) {
        fprintf(stderr, "Invalid command\n");
        exit(EXIT_FAILURE);
    }

    memset(&settings, 0, sizeof(settings));
    settings.ai_family = AF_UNSPEC;      // Accept any IP version
    settings.ai_socktype = SOCK_STREAM;  // TCP socket type

    int status = getaddrinfo(argv[1], argv[2], &settings, &servinfo);
    if (status != 0) {
        fprintf(stderr, "Error in getaddrinfo: %s\n", gai_strerror(status));
        exit(EXIT_FAILURE);
    }

    for (p = servinfo; p != NULL; p = p->ai_next) {
        socketFD = socket(p->ai_family, p->ai_socktype, p->ai_protocol);
        if (socketFD == -1) continue;

        if (connect(socketFD, p->ai_addr, p->ai_addrlen) != -1) break;

        close(socketFD);
    }

    if (p == NULL) {
        fprintf(stderr, "Connection to server failed\n");
        exit(EXIT_FAILURE);
    }

    freeaddrinfo(servinfo);

    if (operationType == 'L') {
        snprintf(sendBuffer, MAX_BUF_SIZE, "L");
    } else {
        snprintf(sendBuffer, MAX_BUF_SIZE, "%c%s %s", operationType, argv[4],
                 argv[5]);
    }

    bytes = write(socketFD, sendBuffer, strlen(sendBuffer));
    if (bytes < 0) {
        displayError("ERROR: Unable to write to socket");
        exit(EXIT_FAILURE);
    }

    memset(sendBuffer, 0, MAX_BUF_SIZE);

    bytes = read(socketFD, sendBuffer, MAX_BUF_SIZE - 1);
    if (bytes < 0) {
        displayError("ERROR: Unable to read from socket");
        exit(EXIT_FAILURE);
    }

    printf("%s\n", sendBuffer);
    close(socketFD);
    return 0;
}