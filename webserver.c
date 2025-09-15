#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <time.h>
#include <errno.h>
#include <signal.h>
#include <sys/wait.h>
#include <pthread.h>

#define PORT 3000
#define BUFFER_SIZE 8192
#define MAX_PATH 512
#define MAX_HEADERS 20
#define MAX_HEADER_SIZE 512
#define MAX_CONNECTIONS 50

// HTTP Status Codes
#define HTTP_200 "200 OK"
#define HTTP_404 "404 Not Found"
#define HTTP_400 "400 Bad Request"
#define HTTP_500 "500 Internal Server Error"

// Connection tracking
typedef struct
{
    int client_fd;
    struct sockaddr_in client_addr;
    time_t connect_time;
} client_connection_t;

// MIME Types
typedef struct
{
    char *extension;
    char *mime_type;
} mime_type_t;

mime_type_t mime_types[] = {
    {".html", "text/html; charset=utf-8"},
    {".htm", "text/html; charset=utf-8"},
    {".css", "text/css; charset=utf-8"},
    {".js", "application/javascript; charset=utf-8"},
    {".json", "application/json; charset=utf-8"},
    {".png", "image/png"},
    {".jpg", "image/jpeg"},
    {".jpeg", "image/jpeg"},
    {".gif", "image/gif"},
    {".ico", "image/x-icon"},
    {".svg", "image/svg+xml"},
    {".txt", "text/plain; charset=utf-8"},
    {".pdf", "application/pdf"},
    {".zip", "application/zip"},
    {NULL, "application/octet-stream"}};

// HTTP Header structure
typedef struct
{
    char name[MAX_HEADER_SIZE];
    char value[MAX_HEADER_SIZE];
} http_header_t;

// HTTP Request structure
typedef struct
{
    char method[16];
    char path[MAX_PATH];
    char version[16];
    http_header_t headers[MAX_HEADERS];
    int header_count;
    char body[BUFFER_SIZE];
    int keep_alive;
} http_request_t;

// Function prototypes
int create_socket();
int bind_socket(int sockfd, int port);
int listen_socket(int sockfd);
void *handle_client_thread(void *arg);
void handle_client(int client_fd, struct sockaddr_in client_addr);
void parse_request(char *raw_request, http_request_t *request);
void send_response(int client_fd, char *status, char *content_type, char *body, size_t body_length, int keep_alive);
void send_file(int client_fd, char *filepath, int keep_alive);
void send_404(int client_fd, int keep_alive);
void send_400(int client_fd, int keep_alive);
void send_500(int client_fd, int keep_alive);
char *get_mime_type(char *filepath);
void get_current_time(char *buffer);
void url_decode(char *dst, const char *src);
void handle_sigchld(int sig);
void setup_socket_options(int sockfd);
int safe_send(int sockfd, const void *buf, size_t len);
int safe_send_file(int client_fd, int file_fd, size_t file_size);

// Global variables for graceful shutdown
volatile sig_atomic_t server_running = 1;

void handle_sigint(int sig)
{
    (void)sig;
    printf("\n[INFO] Received shutdown signal. Stopping server...\n");
    server_running = 0;
    exit(0);
}

// Create socket with error handling
int create_socket()
{
    int sockfd;

    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0)
    {
        perror("Socket creation failed");
        return -1;
    }

    // Set socket options for better performance and reliability
    setup_socket_options(sockfd);

    printf("[INFO] Socket created successfully (fd: %d)\n", sockfd);
    return sockfd;
}

// socket options
void setup_socket_options(int sockfd)
{
    int opt = 1;

    // Reuse address (prevents "Address already in use" error)
    if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0)
    {
        perror("Warning: setsockopt SO_REUSEADDR failed");
    }

    // Set socket buffer sizes
    int buffer_size = BUFFER_SIZE * 2;
    if (setsockopt(sockfd, SOL_SOCKET, SO_SNDBUF, &buffer_size, sizeof(buffer_size)) < 0)
    {
        perror("Warning: setsockopt SO_SNDBUF failed");
    }
    if (setsockopt(sockfd, SOL_SOCKET, SO_RCVBUF, &buffer_size, sizeof(buffer_size)) < 0)
    {
        perror("Warning: setsockopt SO_RCVBUF failed");
    }

    // Enable keep-alive
    if (setsockopt(sockfd, SOL_SOCKET, SO_KEEPALIVE, &opt, sizeof(opt)) < 0)
    {
        perror("Warning: setsockopt SO_KEEPALIVE failed");
    }
}

// Bind socket to address and port
int bind_socket(int sockfd, int port)
{
    struct sockaddr_in server_addr;

    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(port);

    if (bind(sockfd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0)
    {
        perror("Bind failed");
        return -1;
    }

    printf("[INFO] Socket bound to port %d\n", port);
    return 0;
}

// Listen for connections with backlog
int listen_socket(int sockfd)
{
    if (listen(sockfd, MAX_CONNECTIONS) < 0)
    {
        perror("Listen failed");
        return -1;
    }

    printf("[INFO] Server listening (max connections: %d)\n", MAX_CONNECTIONS);
    return 0;
}

// Thread function for handling clients
void *handle_client_thread(void *arg)
{
    client_connection_t *conn = (client_connection_t *)arg;
    handle_client(conn->client_fd, conn->client_addr);
    free(conn);
    return NULL;
}

// client handling with connection management
void handle_client(int client_fd, struct sockaddr_in client_addr)
{
    char buffer[BUFFER_SIZE];
    http_request_t request;
    int keep_connection = 1;

    printf("[INFO] Handling client %s:%d\n", inet_ntoa(client_addr.sin_addr), ntohs(client_addr.sin_port));

    while (keep_connection && server_running)
    {
        memset(buffer, 0, sizeof(buffer));
        memset(&request, 0, sizeof(request));

        // Read request with timeout
        ssize_t bytes_read = recv(client_fd, buffer, sizeof(buffer) - 1, 0);
        if (bytes_read <= 0)
        {
            if (bytes_read == 0)
            {
                printf("[INFO] Client disconnected normally\n");
            }
            else
            {
                printf("[ERROR] Failed to read from client: %s\n", strerror(errno));
            }
            break;
        }

        buffer[bytes_read] = '\0';
        printf("[DEBUG] Received %zd bytes\n", bytes_read);

        // Parse the HTTP request
        parse_request(buffer, &request);

        printf("[INFO] %s %s %s\n", request.method, request.path, request.version);

        // Check for keep-alive
        keep_connection = request.keep_alive;

        // Handle different HTTP methods
        if (strcmp(request.method, "GET") == 0 || strcmp(request.method, "HEAD") == 0)
        {
            // Normalize path
            if (strcmp(request.path, "/") == 0)
            {
                strcpy(request.path, "/index.html");
            }

            // Construct file path (remove leading slash)
            char filepath[MAX_PATH];
            snprintf(filepath, sizeof(filepath), ".%s", request.path);

            // URL decode
            char decoded_path[MAX_PATH];
            url_decode(decoded_path, filepath);
            strcpy(filepath, decoded_path);

            printf("[INFO] Serving file: %s\n", filepath);

            if (strcmp(request.method, "HEAD") == 0)
            {
                // HEAD request - send headers only
                struct stat file_stat;
                if (stat(filepath, &file_stat) == 0 && S_ISREG(file_stat.st_mode))
                {
                    char *mime_type = get_mime_type(filepath);
                    send_response(client_fd, HTTP_200, mime_type, NULL, file_stat.st_size, keep_connection);
                }
                else
                {
                    send_404(client_fd, keep_connection);
                }
            }
            else
            {
                // GET request - send full response
                send_file(client_fd, filepath, keep_connection);
            }
        }
        else if (strcmp(request.method, "POST") == 0)
        {
            char *response_body = "POST request received successfully";
            send_response(client_fd, HTTP_200, "text/plain", response_body, strlen(response_body), keep_connection);
        }
        else
        {
            send_400(client_fd, keep_connection);
            keep_connection = 0; // Close connection on bad request
        }

        // For HTTP/1.0 or if Connection: close, don't keep alive
        if (strstr(request.version, "1.0") || !keep_connection)
        {
            break;
        }
    }

    close(client_fd);
    printf("[INFO] Client connection closed\n");
}

// request parsing with keep-alive detection
void parse_request(char *raw_request, http_request_t *request)
{
    memset(request, 0, sizeof(http_request_t));
    request->keep_alive = 0; // Default to false

    char *line = strtok(raw_request, "\r\n");
    if (line == NULL)
    {
        return;
    }

    // Parse request line
    sscanf(line, "%15s %511s %15s", request->method, request->path, request->version);

    // Default to keep-alive for HTTP/1.1
    if (strstr(request->version, "1.1"))
    {
        request->keep_alive = 1;
    }

    // Parse headers
    request->header_count = 0;
    while ((line = strtok(NULL, "\r\n")) != NULL && strlen(line) > 0)
    {
        if (request->header_count >= MAX_HEADERS)
            break;

        char *colon = strchr(line, ':');
        if (colon != NULL)
        {
            *colon = '\0';
            strcpy(request->headers[request->header_count].name, line);

            // Skip whitespace after colon
            char *value = colon + 1;
            while (*value == ' ')
                value++;
            strcpy(request->headers[request->header_count].value, value);

            // Check for Connection header
            if (strcasecmp(line, "Connection") == 0)
            {
                if (strcasecmp(value, "close") == 0)
                {
                    request->keep_alive = 0;
                }
                else if (strcasecmp(value, "keep-alive") == 0)
                {
                    request->keep_alive = 1;
                }
            }

            request->header_count++;
        }
    }
}

// Safe send function with error handling
int safe_send(int sockfd, const void *buf, size_t len)
{
    size_t total_sent = 0;
    const char *data = (const char *)buf;

    while (total_sent < len)
    {
        ssize_t sent = send(sockfd, data + total_sent, len - total_sent, MSG_NOSIGNAL);
        if (sent <= 0)
        {
            if (errno == EAGAIN || errno == EWOULDBLOCK)
            {
                usleep(1000); // Brief pause
                continue;
            }
            return -1;
        }
        total_sent += sent;
    }
    return 0;
}

// response function with keep-alive support
void send_response(int client_fd, char *status, char *content_type, char *body, size_t body_length, int keep_alive)
{
    char response[BUFFER_SIZE];
    char time_str[128];

    get_current_time(time_str);

    int header_length = snprintf(response, sizeof(response),
                                 "HTTP/1.1 %s\r\n"
                                 "Date: %s\r\n"
                                 "Server: CustomWebServer/1.0\r\n"
                                 "Content-Type: %s\r\n"
                                 "Content-Length: %zu\r\n"
                                 "Connection: %s\r\n"
                                 "\r\n",
                                 status, time_str, content_type, body_length,
                                 keep_alive ? "keep-alive" : "close");

    // Send headers
    if (safe_send(client_fd, response, header_length) < 0)
    {
        printf("[ERROR] Failed to send headers\n");
        return;
    }

    // Send body if present
    if (body != NULL && body_length > 0)
    {
        if (safe_send(client_fd, body, body_length) < 0)
        {
            printf("[ERROR] Failed to send body\n");
        }
    }

    printf("[INFO] Sent response: %s (%zu bytes)\n", status, body_length);
}

// Safe file sending with error handling
int safe_send_file(int client_fd, int file_fd, size_t file_size)
{
    char file_buffer[BUFFER_SIZE];
    size_t total_sent = 0;

    while (total_sent < file_size)
    {
        ssize_t bytes_read = read(file_fd, file_buffer, sizeof(file_buffer));
        if (bytes_read <= 0)
        {
            if (bytes_read < 0)
            {
                printf("[ERROR] Failed to read file: %s\n", strerror(errno));
            }
            return -1;
        }

        if (safe_send(client_fd, file_buffer, bytes_read) < 0)
        {
            printf("[ERROR] Failed to send file data\n");
            return -1;
        }

        total_sent += bytes_read;
    }

    return 0;
}

// file sending
void send_file(int client_fd, char *filepath, int keep_alive)
{
    struct stat file_stat;

    if (stat(filepath, &file_stat) < 0)
    {
        printf("[ERROR] File not found: %s\n", filepath);
        send_404(client_fd, keep_alive);
        return;
    }

    if (!S_ISREG(file_stat.st_mode))
    {
        printf("[ERROR] Not a regular file: %s\n", filepath);
        send_404(client_fd, keep_alive);
        return;
    }

    int file_fd = open(filepath, O_RDONLY);
    if (file_fd < 0)
    {
        printf("[ERROR] Cannot open file: %s (%s)\n", filepath, strerror(errno));
        send_500(client_fd, keep_alive);
        return;
    }

    char *mime_type = get_mime_type(filepath);

    // Send response headers first
    send_response(client_fd, HTTP_200, mime_type, NULL, file_stat.st_size, keep_alive);

    // Then send file content
    if (safe_send_file(client_fd, file_fd, file_stat.st_size) < 0)
    {
        printf("[ERROR] Failed to send file: %s\n", filepath);
    }
    else
    {
        printf("[INFO] File sent successfully: %s (%lld bytes)\n",
               filepath, (long long)file_stat.st_size);
    }

    close(file_fd);
}

// error response functions with keep-alive support
void send_404(int client_fd, int keep_alive)
{
    char *body =
        "<!DOCTYPE html>"
        "<html><head><title>404 Not Found</title></head>"
        "<body><h1>404 Not Found</h1>"
        "<p>The requested resource was not found on this server.</p>"
        "</body></html>";

    send_response(client_fd, HTTP_404, "text/html", body, strlen(body), keep_alive);
}

void send_400(int client_fd, int keep_alive)
{
    char *body =
        "<!DOCTYPE html>"
        "<html><head><title>400 Bad Request</title></head>"
        "<body><h1>400 Bad Request</h1>"
        "<p>The request could not be understood by the server.</p>"
        "</body></html>";

    send_response(client_fd, HTTP_400, "text/html", body, strlen(body), keep_alive);
}

void send_500(int client_fd, int keep_alive)
{
    char *body =
        "<!DOCTYPE html>"
        "<html><head><title>500 Internal Server Error</title></head>"
        "<body><h1>500 Internal Server Error</h1>"
        "<p>The server encountered an internal error.</p>"
        "</body></html>";

    send_response(client_fd, HTTP_500, "text/html", body, strlen(body), keep_alive);
}

// get MIME type
char *get_mime_type(char *filepath)
{
    char *extension = strrchr(filepath, '.');
    if (extension == NULL)
    {
        return "application/octet-stream";
    }

    for (int i = 0; mime_types[i].extension != NULL; i++)
    {
        if (strcasecmp(extension, mime_types[i].extension) == 0)
        {
            return mime_types[i].mime_type;
        }
    }

    return "application/octet-stream";
}

// get current time in HTTP format
void get_current_time(char *buffer)
{
    time_t now = time(NULL);
    struct tm *gmt = gmtime(&now);
    strftime(buffer, 128, "%a, %d %b %Y %H:%M:%S GMT", gmt);
}

// URL decode function
void url_decode(char *dst, const char *src)
{
    char *d = dst;
    const char *s = src;
    char hex[3] = {0};

    while (*s)
    {
        if (*s == '%' && s[1] && s[2])
        {
            hex[0] = s[1];
            hex[1] = s[2];
            *d++ = (char)strtol(hex, NULL, 16);
            s += 3;
        }
        else if (*s == '+')
        {
            *d++ = ' ';
            s++;
        }
        else
        {
            *d++ = *s++;
        }
    }
    *d = '\0';
}

// signal handler for child processes
void handle_sigchld(int sig)
{
    (void)sig;
    while (waitpid(-1, NULL, WNOHANG) > 0)
        ;
}

// main server with threading
int main(int argc, char *argv[])
{
    int server_fd, client_fd;
    struct sockaddr_in client_addr;
    socklen_t client_len = sizeof(client_addr);
    int port = PORT;

    // Parse command line arguments
    if (argc > 1)
    {
        port = atoi(argv[1]);
        if (port <= 0 || port > 65535)
        {
            printf("Error: Invalid port number. Using default port %d.\n", PORT);
            port = PORT;
        }
    }

    printf("=== Custom Web Server ===\n");
    printf("[INFO] Using port: %d\n", port);

    // Install signal handlers
    signal(SIGCHLD, handle_sigchld);
    signal(SIGINT, handle_sigint);
    signal(SIGTERM, handle_sigint);
    signal(SIGPIPE, SIG_IGN); // Ignore broken pipe signals

    // Create and setup server socket
    server_fd = create_socket();
    if (server_fd < 0)
    {
        exit(EXIT_FAILURE);
    }

    if (bind_socket(server_fd, port) < 0)
    {
        close(server_fd);
        exit(EXIT_FAILURE);
    }

    if (listen_socket(server_fd) < 0)
    {
        close(server_fd);
        exit(EXIT_FAILURE);
    }

    printf("[INFO] Server started successfully. Visit http://localhost:%d\n", port);
    printf("[INFO] Features: Keep-alive connections, threading, error handling\n");
    printf("[INFO] Press Ctrl+C to stop the server\n\n");

    // Main server loop
    while (server_running)
    {
        client_fd = accept(server_fd, (struct sockaddr *)&client_addr, &client_len);
        if (client_fd < 0)
        {
            if (errno == EINTR)
                continue; // Interrupted by signal
            if (server_running)
            {
                perror("Accept failed");
            }
            continue;
        }

        printf("[INFO] New client connected from %s:%d\n",
               inet_ntoa(client_addr.sin_addr), ntohs(client_addr.sin_port));

        // Use threading for better performance
        client_connection_t *conn = malloc(sizeof(client_connection_t));
        if (conn)
        {
            conn->client_fd = client_fd;
            conn->client_addr = client_addr;
            conn->connect_time = time(NULL);

            pthread_t thread;
            if (pthread_create(&thread, NULL, handle_client_thread, conn) == 0)
            {
                pthread_detach(thread); // Don't wait for thread to finish
            }
            else
            {
                printf("[ERROR] Failed to create thread\n");
                handle_client(client_fd, client_addr);
                free(conn);
            }
        }
        else
        {
            // Fallback to direct handling if malloc fails
            handle_client(client_fd, client_addr);
        }
    }

    printf("[INFO] Server shutting down...\n");
    close(server_fd);
    return 0;
}