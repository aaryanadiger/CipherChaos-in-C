/* CipherChaos Simple: one C file, two consoles, three data structures.
   Windows only. XOR is a teaching example, not secure encryption. */
#define _CRT_SECURE_NO_WARNINGS
#include <winsock2.h>
#include <ws2tcpip.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <limits.h>
#ifdef _MSC_VER
#pragma comment(lib, "ws2_32.lib")
#endif

#define SIZE 256
#define BUCKETS 8
#define PORT 5057

typedef struct Message {
    int id, sample;
    char text[SIZE], status[12];
    struct Message *next;       /* Next message in history. */
    struct Message *hash_next;  /* Next message in this hash bucket. */
} Message;

typedef struct QueueNode {
    Message *message;           /* Shares the history record. */
    struct QueueNode *next;
} QueueNode;

Message *head = NULL, *tail = NULL, *table[BUCKETS] = {NULL};
QueueNode *front = NULL, *rear = NULL;
int next_id = 1;

/* Read a complete input line without overflowing the destination. */
int read_line(const char *prompt, char *text, int size) {
    int ch;
    printf("%s", prompt);
    fflush(stdout);
    if (!fgets(text, size, stdin)) return 0;
    if (!strchr(text, '\n') && !feof(stdin)) {
        while ((ch = getchar()) != '\n' && ch != EOF) {}
        puts("Input too long. Please try again.");
        text[0] = '\0';
        return 1;
    }
    text[strcspn(text, "\r\n")] = '\0';
    return 1;
}

int read_number(const char *prompt) {
    char text[32], extra;
    int number;
    if (!read_line(prompt, text, sizeof(text))) return 0;
    return sscanf(text, "%d %c", &number, &extra) == 1 ? number : -1;
}

/* HASH TABLE: ID modulo 8 chooses the bucket; collisions form a chain. */
Message *find_message(int id, int explain) {
    int bucket = id % BUCKETS;
    Message *message;
    if (id <= 0) return NULL;
    if (explain) printf("%d %% 8 = bucket %d\n", id, bucket);
    for (message = table[bucket]; message; message = message->hash_next) {
        if (explain) printf("Compare with ID %d\n", message->id);
        if (message->id == id) return message;
    }
    return NULL;
}

/* LINKED LIST: append at the tail, then index that same node. */
Message *add_history(int id, int sample, const char *text, const char *status) {
    int bucket = id % BUCKETS;
    Message *message = malloc(sizeof(Message));
    if (!message) return NULL;
    message->id = id;
    message->sample = sample;
    strcpy(message->text, text);
    strcpy(message->status, status);
    message->next = NULL;
    if (tail) tail->next = message;
    else head = message;
    tail = message;
    message->hash_next = table[bucket];
    table[bucket] = message;
    return message;
}

/* QUEUE: add at REAR, inspect/remove at FRONT. */
void enqueue_message(const char *text) {
    QueueNode *node = malloc(sizeof(QueueNode));
    Message *message;
    if (!node) { puts("Not enough memory."); return; }
    message = add_history(next_id, rand() % 4096, text, "Queued");
    if (!message) { free(node); puts("Not enough memory."); return; }
    ++next_id;
    node->message = message;
    node->next = NULL;
    if (rear) rear->next = node;
    else front = node;
    rear = node;
    printf("Enqueued ID %d. Simulated pendulum sample: %d\n", message->id, message->sample);
}

void dequeue_message(void) {
    QueueNode *old = front;
    if (!front) return;
    front = front->next;
    if (!front) rear = NULL;
    free(old); /* The message itself remains in history. */
}

void show_queue(void) {
    QueueNode *node;
    printf("FRONT -> ");
    for (node = front; node; node = node->next)
        printf("[%d: %s] -> ", node->message->id, node->message->text);
    puts("NULL (REAR is the last node)");
}

void show_history(void) {
    Message *message;
    puts("HEAD -> message -> next -> ... -> NULL");
    for (message = head; message; message = message->next)
        printf("ID %d | %s | %s\n", message->id, message->status, message->text);
    if (!head) puts("History is empty.");
}

void show_hash_table(void) {
    int bucket;
    Message *message;
    for (bucket = 0; bucket < BUCKETS; ++bucket) {
        printf("Bucket %d: ", bucket);
        for (message = table[bucket]; message; message = message->hash_next)
            printf("[%d] -> ", message->id);
        puts("NULL");
    }
}

/* BASIC ENCRYPTION: applying XOR twice with the same key restores the text. */
void xor_text(unsigned char *text, int length, int key) {
    int i;
    for (i = 0; i < length; ++i) text[i] ^= (unsigned char)key;
}

/* TCP may split data, so repeat send/recv until every byte is transferred. */
int transfer(SOCKET connection, char *data, int length, int sending) {
    int done = 0, count;
    while (done < length) {
        count = sending ? send(connection, data + done, length - done, 0)
                        : recv(connection, data + done, length - done, 0);
        if (count <= 0) return 0;
        done += count;
    }
    return 1;
}

void set_timeout(SOCKET connection) {
    DWORD timeout = 10000;
    setsockopt(connection, SOL_SOCKET, SO_RCVTIMEO, (const char *)&timeout, sizeof(timeout));
    setsockopt(connection, SOL_SOCKET, SO_SNDTIMEO, (const char *)&timeout, sizeof(timeout));
}

void send_messages(const char *ip, int key, int send_all) {
    SOCKET connection;
    struct sockaddr_in address = {0};
    unsigned char encrypted[SIZE];
    unsigned long header[3], reply;
    Message *message;
    int length, i;
    if (!front) { puts("Queue is empty."); return; }
    address.sin_family = AF_INET;
    address.sin_port = htons(PORT);
    if (inet_pton(AF_INET, ip, &address.sin_addr) != 1) { puts("Invalid IPv4 address."); return; }
    connection = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (connection == INVALID_SOCKET) { puts("Cannot create socket."); return; }
    set_timeout(connection);
    if (connect(connection, (struct sockaddr *)&address, sizeof(address)) == SOCKET_ERROR) {
        puts("Cannot connect. Start the receiver first. Queue unchanged.");
        closesocket(connection);
        return;
    }
    do {
        message = front->message;
        length = (int)strlen(message->text);
        memcpy(encrypted, message->text, (size_t)length);
        xor_text(encrypted, length, key);
        printf("ID %d encrypted bytes: ", message->id);
        for (i = 0; i < length; ++i) printf("%02X ", encrypted[i]);
        puts("");
        header[0] = htonl((unsigned long)message->id);
        header[1] = htonl((unsigned long)message->sample);
        header[2] = htonl((unsigned long)length);
        if (!transfer(connection, (char *)header, sizeof(header), 1) ||
            !transfer(connection, (char *)encrypted, length, 1) ||
            !transfer(connection, (char *)&reply, sizeof(reply), 0) ||
            ntohl(reply) != (unsigned long)message->id) {
            puts("No delivery confirmation. Front message kept for retry.");
            break;
        }
        strcpy(message->status, "Sent");
        printf("Delivered ID %d. Dequeue FRONT; history remains.\n", message->id);
        dequeue_message();
    } while (send_all && front);
    closesocket(connection);
}

SOCKET start_receiver(void) {
    struct sockaddr_in address = {0};
    SOCKET listener = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (listener == INVALID_SOCKET) return INVALID_SOCKET;
    address.sin_family = AF_INET;
    address.sin_port = htons(PORT);
    address.sin_addr.s_addr = htonl(INADDR_ANY);
    if (bind(listener, (struct sockaddr *)&address, sizeof(address)) == SOCKET_ERROR ||
        listen(listener, 5) == SOCKET_ERROR) {
        closesocket(listener);
        return INVALID_SOCKET;
    }
    return listener;
}

void receive_messages(SOCKET listener, int key) {
    SOCKET connection;
    unsigned long header[3], reply;
    unsigned long id, sample, length;
    unsigned char text[SIZE];
    Message *message;
    puts("Waiting for sender. Send a message from the other console now.");
    connection = accept(listener, NULL, NULL);
    if (connection == INVALID_SOCKET) { puts("Could not accept connection."); return; }
    set_timeout(connection);
    while (transfer(connection, (char *)header, sizeof(header), 0)) {
        id = ntohl(header[0]); sample = ntohl(header[1]); length = ntohl(header[2]);
        if (!id || id > INT_MAX || sample > 4095 || !length || length >= SIZE) break;
        if (!transfer(connection, (char *)text, (int)length, 0)) break;
        xor_text(text, (int)length, key);
        text[length] = '\0';
        message = find_message((int)id, 0);
        if (!message) message = add_history((int)id, (int)sample, (char *)text, "Received");
        reply = htonl(message && strcmp(message->text, (char *)text) == 0 ? id : 0);
        if (!transfer(connection, (char *)&reply, sizeof(reply), 1)) break;
        if (ntohl(reply)) printf("Received ID %lu | Decrypted: %s\n", id, text);
        else puts("Message rejected: ID conflict or insufficient memory.");
    }
    closesocket(connection);
}

int main(int argc, char **argv) {
    WSADATA winsock;
    SOCKET listener = INVALID_SOCKET;
    char ip[64] = "127.0.0.1", text[SIZE];
    Message *message, *next;
    int mode, choice, key, id;
    setvbuf(stdout, NULL, _IONBF, 0);
    if (WSAStartup(MAKEWORD(2, 2), &winsock)) return 1;
    srand((unsigned int)time(NULL));
    puts("CipherChaos Simple | C console demo | Basic XOR encryption");
    if (argc > 1 && strcmp(argv[1], "sender") == 0) mode = 1;
    else if (argc > 1 && strcmp(argv[1], "receiver") == 0) mode = 2;
    else mode = read_number("1 Sender, 2 Receiver, 0 Exit: ");
    if (mode != 1 && mode != 2) { WSACleanup(); return 0; }
    key = read_number("Shared XOR key (1-255; use the same key on both sides): ");
    if (key < 1 || key > 255) { puts("Invalid key."); WSACleanup(); return 1; }
    if (mode == 1) {
        if (!read_line("Receiver IPv4 address (Enter for 127.0.0.1): ", text, sizeof(text))) return 1;
        if (text[0]) {
            if (strlen(text) >= sizeof(ip)) { puts("Address too long."); WSACleanup(); return 1; }
            strcpy(ip, text);
        }
    } else {
        listener = start_receiver();
        if (listener == INVALID_SOCKET) { puts("Cannot listen on port 5057."); WSACleanup(); return 1; }
        puts("Receiver ready on TCP port 5057.");
    }
    for (;;) {
        puts("\n1 Show history | 2 Find ID | 3 Show hash table | 0 Exit");
        if (mode == 1) puts("4 Add message | 5 Show queue | 6 Send front | 7 Send all");
        else puts("4 Receive messages (wait for sender)");
        choice = read_number("Choice: ");
        if (choice == 0) break;
        if (choice == 1) show_history();
        else if (choice == 2) {
            id = read_number("Message ID: ");
            message = find_message(id, 1);
            if (message) printf("Found: %s | %s\n", message->status, message->text);
            else puts("Message not found.");
        } else if (choice == 3) show_hash_table();
        else if (choice == 4 && mode == 1) {
            if (!read_line("Message: ", text, sizeof(text))) break;
            if (text[0]) enqueue_message(text);
        } else if (choice == 4) receive_messages(listener, key);
        else if (choice == 5 && mode == 1) show_queue();
        else if ((choice == 6 || choice == 7) && mode == 1) send_messages(ip, key, choice == 7);
        else puts("Invalid choice.");
    }
    while (front) dequeue_message();
    for (message = head; message; message = next) { next = message->next; free(message); }
    if (listener != INVALID_SOCKET) closesocket(listener);
    WSACleanup();
    return 0;
}
