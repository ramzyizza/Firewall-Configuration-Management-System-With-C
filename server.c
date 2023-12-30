#include <ctype.h>
#include <netinet/in.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#define MAXBUFFERLEN 256
#define THREAD_IN_USE 0
#define THREAD_FINISHED 1
#define THREAD_AVAILABLE 2
#define THREADS_ALLOCATED 10

struct firewallRules_t *rules = NULL;
int rulesCount = 0;
int queriesCount = 0;
struct firewallRules_t *allRules = NULL;
struct firewallRules_t *allQueries = NULL;

struct threadArgs_t {
    int socketfdNew;
    int threadIndex;
};

int checkExecute = 0;
int returnVal = 0;
pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;

struct threadInfo_t {
    pthread_t infoPThread;
    pthread_attr_t attributes;
    int status;
};
struct threadInfo_t *serverThreads = NULL;
int noOfThreads = 0;
pthread_rwlock_t lockThread = PTHREAD_RWLOCK_INITIALIZER;
pthread_cond_t condThread = PTHREAD_COND_INITIALIZER;
pthread_mutex_t endLockThread = PTHREAD_MUTEX_INITIALIZER;

struct matchedQuery_t {
    int ipaddr[4];
    int port;
    struct matchedQuery_t *next;
};

struct matchedQuery_t *addQueryChecked(struct matchedQuery_t *head, int ipaddr[], int port) {
    struct matchedQuery_t *newQuery = (struct matchedQuery_t *)malloc(sizeof(struct matchedQuery_t));
    if (newQuery == NULL) {
        fprintf(stderr, "Failed to allocate memory for a new query.\n");
        return head;
    }

    for (int i = 0; i < 4; i++) {
        newQuery->ipaddr[i] = ipaddr[i];
    }
    newQuery->port = port;
    newQuery->next = head;
    return newQuery;
}

struct firewallRule_t {
    int ipaddr1[4];
    int ipaddr2[4];
    int port1;
    int port2;
    struct matchedQuery_t *matchedQueries;
};

struct firewallRules_t {
    struct firewallRule_t *query;
    struct firewallRule_t *rule;
    struct firewallRules_t *next;
};

struct firewallRules_Query {
    struct firewallRule_t *query;
    struct firewallRule_t *rule;
    struct firewallRules_t *next;
};

struct ruleErrors_t {
    char *line;
    struct ruleErrors_t *next;
};

struct firewallRules_t *addRulesAll(struct firewallRules_t *allRules, struct firewallRule_t *rule, bool isValid) {
    struct firewallRules_t *entryNew;

    entryNew = malloc(sizeof(struct firewallRules_t));
    if (!entryNew) return NULL;

    if (isValid) {
        entryNew->query = NULL;
        entryNew->rule = rule;
    } else {
        entryNew->query = rule;
        entryNew->rule = NULL;
    }

    entryNew->next = allRules;
    return entryNew;
}

char *rule2String(struct firewallRule_t *rule) {
    char *stringRule = malloc(100);
    if (!stringRule) return NULL;

    snprintf(stringRule, 100, "%d.%d.%d.%d-%d.%d.%d.%d %d-%d", rule->ipaddr1[0], rule->ipaddr1[1], rule->ipaddr1[2], rule->ipaddr1[3], rule->ipaddr2[0],
             rule->ipaddr2[1], rule->ipaddr2[2], rule->ipaddr2[3], rule->port1, rule->port2);

    return stringRule;
}

void displayIp(int *ipaddr) { printf("%d.%d.%d.%d", ipaddr[0], ipaddr[1], ipaddr[2], ipaddr[3]); }

void displayRule(struct firewallRule_t *rule) {
    printf("Rule: %d.%d.%d.%d", rule->ipaddr1[0], rule->ipaddr1[1], rule->ipaddr1[2], rule->ipaddr1[3]);
    if (rule->ipaddr2[0] != -1) {
        printf("-");
        displayIp(rule->ipaddr2);
    }
    printf(" %d", rule->port1);
    if (rule->port2 != -1) {
        printf("-");
        printf("%d", rule->port2);
    }
    printf("\n");
}

int ipAddressCompare(int *ipaddr1, int *ipaddr2) {
    int i;
    for (i = 0; i < 4; i++) {
        if (ipaddr1[i] > ipaddr2[i]) {
            return 1;
        } else if (ipaddr1[i] < ipaddr2[i]) {
            return -1;
        }
    }
    return 0;
}

char *parseIPaddress(int *ipaddr, char *text) {
    char *oldPos, *newPos;
    long int addr;
    int i;

    oldPos = text;
    for (i = 0; i < 4; i++) {
        if (oldPos == NULL || *oldPos < '0' || *oldPos > '9') {
            return NULL;
        }
        addr = strtol(oldPos, &newPos, 10);
        if (newPos == oldPos) {
            return NULL;
        }
        if ((addr < 0) || addr > 255) {
            ipaddr[0] = -1;
            return NULL;
        }
        if (i < 3) {
            if ((newPos == NULL) || (*newPos != '.')) {
                ipaddr[0] = -1;
                return NULL;
            } else
                newPos++;
        } else if ((newPos == NULL) || ((*newPos != ' ') && (*newPos != '-'))) {
            ipaddr[0] = -1;
            return NULL;
        }
        ipaddr[i] = addr;
        oldPos = newPos;
    }
    return newPos;
}

char *portParsing(int *port, char *text) {
    char *newPos;

    if ((text == NULL) || (*text < '0') || (*text > '9')) {
        return NULL;
    }
    *port = strtol(text, &newPos, 10);
    if (newPos == text) {
        *port = -1;
        return NULL;
    }
    if ((*port < 0) || (*port > 65535)) {
        *port = -1;
        return NULL;
    }
    return newPos;
}

int ruleCompare(const void *arg1, const void *arg2) {
    struct firewallRules_t *rule1, *rule2;

    rule1 = ((struct firewallRules_t *)arg1);
    rule2 = ((struct firewallRules_t *)arg2);
    if (rule1->rule->port1 < rule2->rule->port1) {
        return -1;
    } else if (rule1->rule->port1 > rule2->rule->port1) {
        return 1;
    } else
        return (ipAddressCompare(rule1->rule->ipaddr1, rule2->rule->ipaddr1));
}

struct firewallRule_t *ruleRead(char *line) {
    struct firewallRule_t *newRule;
    char *position;

    newRule = malloc(sizeof(struct firewallRule_t));
    position = parseIPaddress(newRule->ipaddr1, line);
    if ((position == NULL) || (newRule->ipaddr1[0] == -1)) {
        free(newRule);
        return NULL;
    }
    if (*position == '-') {
        position = parseIPaddress(newRule->ipaddr2, position + 1);
        if ((position == NULL) || (newRule->ipaddr2[0] == -1)) {
            free(newRule);
            return NULL;
        }

        if (ipAddressCompare(newRule->ipaddr1, newRule->ipaddr2) != -1) {
            free(newRule);
            return NULL;
        }
    } else {
        newRule->ipaddr2[0] = -1;
        newRule->ipaddr2[1] = -1;
        newRule->ipaddr2[2] = -1;
        newRule->ipaddr2[3] = -1;
    }
    if (*position != ' ') {
        free(newRule);
        return NULL;
    } else
        position++;
    position = portParsing(&(newRule->port1), position);
    if ((position == NULL) || (newRule->port1 == -1)) {
        free(newRule);
        return NULL;
    }
    if ((*position == '\n') || (*position == '\0')) {
        newRule->port2 = -1;
        return newRule;
    }
    if (*position != '-') {
        free(newRule);
        return NULL;
    }

    position++;
    position = portParsing(&(newRule->port2), position);
    if ((position == NULL) || (newRule->port2 == -1)) {
        free(newRule);
        return NULL;
    }
    if (newRule->port2 <= newRule->port1) {
        free(newRule);
        return NULL;
    }
    if ((*position == '\n') || (*position == '\0')) {
        return newRule;
    }
    free(newRule);
    return NULL;
}

struct ruleErrors_t *errorsAll = NULL;

struct firewallRules_t *ruleAdd(struct firewallRules_t *rules, struct firewallRule_t *rule) {
    struct firewallRules_t *newRule;
    newRule = malloc(sizeof(struct firewallRules_t));
    newRule->rule = rule;
    newRule->next = rules;
    return newRule;
}

struct firewallRules_t *queryAdd(struct firewallRules_t *queries, struct firewallRule_t *query, struct firewallRule_t *rule) {
    struct firewallRules_t *newQuery;

    newQuery = malloc(sizeof(struct firewallRules_t));
    if (!newQuery) return NULL;

    newQuery->query = query;
    newQuery->rule = rule;
    newQuery->next = queries;
    return newQuery;
}

bool ipAddressCheck(int *ipaddr1, int *ipaddr2, int *ipaddr) {
    int res;

    res = ipAddressCompare(ipaddr, ipaddr1);
    if (ipAddressCompare(ipaddr, ipaddr1) == 0)
        return true;
    else if (ipaddr2[0] == -1)
        return false;
    else if (res == -1)
        return false;
    else if (ipAddressCompare(ipaddr, ipaddr2) <= 0)
        return true;
    else
        return false;
}

int portCheck(int port1, int port2, int port) {
    if (port == port1) 
        return 0;
    else if (port < port1)
        return -1;
    else if (port2 == -1 || port > port2)
        return 1;
    else
        return 0;
}

bool connectCheck(struct firewallRules_t *rules, int *ipaddr, int port) {
    while (rules != NULL) {
        if (ipAddressCheck(rules->rule->ipaddr1, rules->rule->ipaddr2, ipaddr) && portCheck(rules->rule->port1, rules->rule->port2, port)) {
            return true;
        }
        rules = rules->next;
    }

    return false;
}

void error(char *msg) {
    perror(msg);
    exit(1);
};

void freeQueries(struct matchedQuery_t *matchedQueries) {
    struct matchedQuery_t *current = matchedQueries;
    while (current != NULL) {
        struct matchedQuery_t *next = current->next;
        free(current);
        current = next;
    }
}


bool rulesEqualCheck(struct firewallRule_t *rule1, struct firewallRule_t *rule2);
bool rulesEqualCheck(struct firewallRule_t *rule1, struct firewallRule_t *rule2) {
    if (ipAddressCompare(rule1->ipaddr1, rule2->ipaddr1) != 0) {
        return false;
    }

    if ((rule1->ipaddr2[0] != -1 && rule2->ipaddr2[0] != -1) && (ipAddressCompare(rule1->ipaddr2, rule2->ipaddr2) != 0)) {
        return false;
    } else if ((rule1->ipaddr2[0] == -1 && rule2->ipaddr2[0] != -1) || (rule1->ipaddr2[0] != -1 && rule2->ipaddr2[0] == -1)) {
        return false;
    }

    if (rule1->port1 != rule2->port1 || rule1->port2 != rule2->port2) {
        return false;
    }

    return true;
}

bool checkIsRule(struct firewallRules_t *rules, struct firewallRule_t *inputRule) {
    while (rules != NULL) {
        if (rulesEqualCheck(rules->rule, inputRule)) {
            return true;
        }
        rules = rules->next;
    }
    return false;
}

bool addRequestProcess(char *rule) {
    struct firewallRule_t *newRule;

    printf("%s\n", rule);
    newRule = ruleRead(rule);

    pthread_mutex_lock(&mutex);

    if (newRule != NULL) {
        rules = ruleAdd(rules, newRule);
        rulesCount++;
    }

    pthread_mutex_unlock(&mutex);

    return newRule != NULL;
}

int checkRequestProcess(char *ipAddress, char *port) {
    struct firewallRule_t *newRule;

    int size = strlen(ipAddress) + strlen(port) + 2;
    char *combined = (char *)malloc(size);
    if (!combined) {
        return -1;
    }
    snprintf(combined, size, "%s %s", ipAddress, port);

    newRule = ruleRead(combined);

    if (newRule == NULL) {
        return -1;
    }

    bool isPacketAccept = false;
    struct firewallRules_t *tmp = allRules;
    int res;

    while (tmp != NULL && !isPacketAccept) {
        res = portCheck(tmp->rule->port1, tmp->rule->port2, newRule->port1);
        if (res == 0) {
            isPacketAccept = ipAddressCheck(tmp->rule->ipaddr1, tmp->rule->ipaddr2, newRule->ipaddr1);
            allQueries = queryAdd(allQueries, newRule, tmp->rule);
            queriesCount++;
        }
        tmp = tmp->next;
    }

    if (isPacketAccept) {
        return 1;
    }
    return 0;
}

bool ruleDelete(struct firewallRules_t **rules, struct firewallRule_t *ruleToBeDeleted) {
    struct firewallRules_t *current = *rules, *prev = NULL;
    while (current != NULL) {
        if (rulesEqualCheck(current->rule, ruleToBeDeleted)) {
            if (prev) {
                prev->next = current->next;
            } else {
                *rules = current->next;
            }
            freeQueries(current->rule->matchedQueries);
            free(current->rule);
            free(current);
            return true;
        }
        prev = current;
        current = current->next;
    }
    return false;
}

void displayBufferRule(struct firewallRule_t *rule, char *buffer, int bufferSize) {
    snprintf(buffer, bufferSize, "%d.%d.%d.%d", rule->ipaddr1[0], rule->ipaddr1[1], rule->ipaddr1[2], rule->ipaddr1[3]);

    if (rule->ipaddr2[0] != -1) {
        char ip2[16];
        snprintf(ip2, sizeof(ip2), "-%d.%d.%d.%d", rule->ipaddr2[0], rule->ipaddr2[1], rule->ipaddr2[2], rule->ipaddr2[3]);
        strncat(buffer, ip2, bufferSize - strlen(buffer) - 1);
    }

    char ports[32];
    snprintf(ports, sizeof(ports), " %d", rule->port1);
    strncat(buffer, ports, bufferSize - strlen(buffer) - 1);

    if (rule->port2 != -1) {
        snprintf(ports, sizeof(ports), "-%d", rule->port2);  // Removed the newline here
        strncat(buffer, ports, bufferSize - strlen(buffer) - 1);
    }
}

void rulesFormat(struct firewallRules_t *rules, char *buffer, int bufferSize) {
    struct firewallRules_t *current = rules;
    char bufferTemp[256];
    bool isFirstRule = true;

    while (current != NULL) {
        if (!isFirstRule) {
            strncat(buffer, "\n", bufferSize - strlen(buffer) - 1);
        }

        snprintf(bufferTemp, sizeof(bufferTemp), "Rule: ");
        strncat(buffer, bufferTemp, bufferSize - strlen(buffer) - 1);

        displayBufferRule(current->rule, bufferTemp, sizeof(bufferTemp));
        strncat(buffer, bufferTemp, bufferSize - strlen(buffer) - 1);

        struct matchedQuery_t *query = current->rule->matchedQueries;
        while (query != NULL) {
            snprintf(bufferTemp, sizeof(bufferTemp), "\nQuery: %d.%d.%d.%d %d", query->ipaddr[0], query->ipaddr[1], query->ipaddr[2],
                     query->ipaddr[3], query->port);
            strncat(buffer, bufferTemp, bufferSize - strlen(buffer) - 1);
            query = query->next;
        }

        isFirstRule = false;
        current = current->next;
    }
}

void *clientProcess(void *args) {
    struct threadArgs_t *threadArgs;
    char buffer[MAXBUFFERLEN];
    int n;

    threadArgs = (struct threadArgs_t *)args;
    bzero(buffer, MAXBUFFERLEN);
    n = read(threadArgs->socketfdNew, buffer, MAXBUFFERLEN - 1);
    if (n < 0) error("ERROR reading from socket");

    char function = buffer[0];

    if (function == 'A') {
        char *rule = buffer + 1;

        if (addRequestProcess(rule)) {
            strcpy(buffer, "Rule added");
        } else {
            strcpy(buffer, "Invalid rule");
        }
    } else if (function == 'C') {
        int ipaddr[4], port;
        char *stringRemain = parseIPaddress(ipaddr, buffer + 1);

        if (stringRemain == NULL || ipaddr[0] == -1) {
            strcpy(buffer, "Illegal IP address specified or port specified");
        } else {
            while (*stringRemain == ' ') {
                stringRemain++;
            }
            stringRemain = portParsing(&port, stringRemain);
            if (stringRemain == NULL || *stringRemain != '\0' || port == -1) {
                strcpy(buffer, "Illegal port specified or port specified");
            } else {
                bool allowConnection = false;
                struct firewallRules_t *currRule = rules;
                while (currRule != NULL) {
                    if (ipAddressCheck(currRule->rule->ipaddr1, currRule->rule->ipaddr2, ipaddr) &&
                        portCheck(currRule->rule->port1, currRule->rule->port2, port) == 0) {
                        allowConnection = true;
                        break;
                    }
                    currRule = currRule->next;
                }

                if (allowConnection) {
                    strcpy(buffer, "Connection accepted");
                    struct matchedQuery_t *newQuery = malloc(sizeof(struct matchedQuery_t));
                    if (newQuery) {
                        memcpy(newQuery->ipaddr, ipaddr, sizeof(newQuery->ipaddr));
                        newQuery->port = port;
                        newQuery->next = currRule->rule->matchedQueries;
                        currRule->rule->matchedQueries = newQuery;
                    }
                } else {
                    strcpy(buffer, "Connection rejected");
                }
            }
        }
    }

    else if (function == 'D') {
        struct firewallRule_t *ruleToBeDeleted = ruleRead(buffer + 1);
        if (!ruleToBeDeleted) {
            strcpy(buffer, "Rule invalid");
        } else {
            if (ruleDelete(&rules, ruleToBeDeleted)) {
                strcpy(buffer, "Rule deleted");
            } else {
                strcpy(buffer, "Rule not found");
            }
            free(ruleToBeDeleted);
        }
    }

    else if (function == 'L') {
        pthread_mutex_lock(&mutex);
        char rulesBuffer[MAXBUFFERLEN] = "";
        rulesFormat(rules, rulesBuffer, sizeof(rulesBuffer));
        pthread_mutex_unlock(&mutex);

        strncpy(buffer, rulesBuffer, MAXBUFFERLEN - 1);
    }

    else {
        strcpy(buffer, "Illegal request");
    }

    n = write(threadArgs->socketfdNew, buffer, strlen(buffer));
    if (n < 0) error("ERROR writing to socket");

    serverThreads[threadArgs->threadIndex].status = THREAD_FINISHED;
    pthread_cond_signal(&condThread);

    close(threadArgs->socketfdNew);
    free(threadArgs);
    pthread_exit(&returnVal);
}

int findIndexThread() {
    int i, tmp;

    for (i = 0; i < noOfThreads; i++) {
        if (serverThreads[i].status == THREAD_AVAILABLE) {
            serverThreads[i].status = THREAD_IN_USE;
            return i;
        }
    }

    pthread_rwlock_wrlock(&lockThread);
    serverThreads = realloc(serverThreads, ((noOfThreads + THREADS_ALLOCATED) * sizeof(struct threadInfo_t)));
    noOfThreads = noOfThreads + THREADS_ALLOCATED;
    pthread_rwlock_unlock(&lockThread);
    if (serverThreads == NULL) {
        fprintf(stderr, "Memory allocation failed\n");
        exit(1);
    }

    for (tmp = i + 1; tmp < noOfThreads; tmp++) {
        serverThreads[tmp].status = THREAD_AVAILABLE;
    }
    serverThreads[i].status = THREAD_IN_USE;
    return i;
}

void *threadsWait(void *args) {
    int i, res;
    while (1) {
        pthread_mutex_lock(&endLockThread);
        pthread_cond_wait(&condThread, &endLockThread);
        pthread_mutex_unlock(&endLockThread);

        pthread_rwlock_rdlock(&lockThread);
        for (i = 0; i < noOfThreads; i++) {
            if (serverThreads[i].status == THREAD_FINISHED) {
                res = pthread_join(serverThreads[i].infoPThread, NULL);
                if (res != 0) {
                    fprintf(stderr, "thread joining failed, exiting\n");
                    exit(1);
                }
                serverThreads[i].status = THREAD_AVAILABLE;
            }
        }
        pthread_rwlock_unlock(&lockThread);
    }
}

int main(int argc, char *argv[]) {
    socklen_t clilen;
    int sockfd, portno;
    struct sockaddr_in6 serv_addr, cli_addr;
    int result;
    pthread_t waitInfo;
    pthread_attr_t waitAttributes;

    if (argc < 2) {
        fprintf(stderr, "ERROR, no port provided\n");
        exit(1);
    }

    sockfd = socket(AF_INET6, SOCK_STREAM, 0);
    if (sockfd < 0) error("ERROR opening socket");
    bzero((char *)&serv_addr, sizeof(serv_addr));
    portno = atoi(argv[1]);
    serv_addr.sin6_family = AF_INET6;
    serv_addr.sin6_addr = in6addr_any;
    serv_addr.sin6_port = htons(portno);

    if (bind(sockfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) error("ERROR on binding");

    listen(sockfd, 5);
    clilen = sizeof(cli_addr);

    if (pthread_attr_init(&waitAttributes)) {
        fprintf(stderr, "Creating initial thread attributes failed!\n");
        exit(1);
    }

    result = pthread_create(&waitInfo, &waitAttributes, threadsWait, NULL);
    if (result != 0) {
        fprintf(stderr, "Initial Thread creation failed!\n");
        exit(1);
    }

    while (1) {
        struct threadArgs_t *threadArgs;
        int threadIndex;

        threadArgs = malloc(sizeof(struct threadArgs_t));
        if (!threadArgs) {
            fprintf(stderr, "Memory allocation failed!\n");
            exit(1);
        }

        threadArgs->socketfdNew = accept(sockfd, (struct sockaddr *)&cli_addr, &clilen);
        if (threadArgs->socketfdNew < 0) error("ERROR on accept");

        threadIndex = findIndexThread();
        threadArgs->threadIndex = threadIndex;
        if (pthread_attr_init(&(serverThreads[threadIndex].attributes))) {
            fprintf(stderr, "Creating thread attributes failed!\n");
            exit(1);
        }

        result =
            pthread_create(&(serverThreads[threadIndex].infoPThread), &(serverThreads[threadIndex].attributes), clientProcess, (void *)threadArgs);
        if (result != 0) {
            fprintf(stderr, "Thread creation failed!\n");
            exit(1);
        }
    }
}