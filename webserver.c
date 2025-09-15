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
#include <zlib.h>

#define PORT 3000
#define BUFFER_SIZE 8192
#define MAX_PATH 512
#define MAX_HEADERS 20
#define MAX_HEADER_SIZE 512
#define MAX_CONNECTIONS 50

// HTTP Status Codes
#define HTTP_200 "200 OK"
#define HTTP_404 "404 Not Found"
#define HTTP_406 "406 Not Acceptable"
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
    {".html", "text/html"},
    {".htm", "text/html"},
    {".css", "text/css"},
    {".js", "application/javascript"},
    {".json", "application/json"},
    {".png", "image/png"},
    {".jpg", "image/jpeg"},
    {".jpeg", "image/jpeg"},
    {".gif", "image/gif"},
    {".ico", "image/x-icon"},
    {".svg", "image/svg+xml"},
    {".txt", "text/plain"},
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
    char accept[MAX_HEADER_SIZE];
    char accept_language[MAX_HEADER_SIZE];
    char accept_encoding[MAX_HEADER_SIZE];
    char accept_charset[MAX_HEADER_SIZE];
} http_request_t;

typedef struct
{
    char mime_type[64];
    char language[16];
    char encoding[16];
    float quality;
} accept_entry_t;

typedef struct
{
    char content_type[64];
    char language[16];
    char encoding[16];
    char charset[32];
    int should_compress;
} negotiated_content_t;

// Function prototypes
int create_socket();
int bind_socket(int sockfd, int port);
int listen_socket(int sockfd);
void *handle_client_thread(void *arg);
void handle_client(int client_fd, struct sockaddr_in client_addr);
void parse_request(char *raw_request, http_request_t *request);
void send_response(int client_fd, char *status, negotiated_content_t *content, char *body, size_t body_length, int keep_alive);
void send_file(int client_fd, char *filepath, int keep_alive, http_request_t *request);
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
float parse_quality(char *header_value, char *target_value);
negotiated_content_t negotiate_content(char *filepath, http_request_t *request);
int compress_gzip(const char *input, size_t input_len, char **output, size_t *output_len);
int should_compress_content(const char *content_type, size_t contnet_length);

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
                    negotiated_content_t content = negotiate_content(filepath, &request);
                    send_response(client_fd, HTTP_200, &content, NULL, file_stat.st_size, keep_connection);
                }
                else
                {
                    send_404(client_fd, keep_connection);
                }
            }
            else
            {
                // GET request - send full response
                send_file(client_fd, filepath, keep_connection, &request);
            }
        }
        else if (strcmp(request.method, "POST") == 0)
        {
            char *response_body = "POST request received successfully";
            negotiated_content_t post_content = {0};
            strcpy(post_content.content_type, "text/plain");
            strcpy(post_content.charset, "utf-8");
            send_response(client_fd, HTTP_200, &post_content, response_body, strlen(response_body), keep_connection);
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
            if (strcasecmp(line, "Accept") == 0)
            {
                strcpy(request->accept, value);
            }
            if (strcasecmp(line, "Accept-Language") == 0)
            {
                strcpy(request->accept_language, value);
            }
            if (strcasecmp(line, "Accept-Encoding") == 0)
            {
                strcpy(request->accept_encoding, value);
            }
            if (strcasecmp(line, "Accept-Charset") == 0)
            {
                strcpy(request->accept_charset, value);
            }
            request->header_count++;
        }
    }
}

float parse_quality(char *header_value, char *target_type)
{
    if (strlen(header_value) == 0)
    {
        return 1.0; // default if no accept header
    }

    char *header_copy = malloc(strlen(header_value) + 1);
    strcpy(header_copy, header_value);

    char *token = strtok(header_copy, ",");
    float best_quality = 0.0;

    while (token != NULL)
    {
        // trim whitespace
        while (*token == ' ')
        {
            token++;
        }

        char media_type[64] = {0};
        float quality = 1.0; // default quality
        // split on ; to separate media type from parameters
        char *semicolon = strchr(token, ';');
        if (semicolon != NULL)
        {
            *semicolon = '\0';
            strcpy(media_type, token);

            // parse quality parameter
            char *q_param = strstr(semicolon + 1, "q=");
            if (q_param != NULL)
            {
                quality = atof(q_param + 2);
            }
        }
        else
        {
            strcpy(media_type, token);
        }

        // check if this media type matches our target
        if (strcmp(media_type, target_type) == 0 ||
            strcmp(media_type, "*/*") == 0 ||
            (strstr(target_type, "/") && strncmp(media_type, target_type, strchr(target_type, '/') - target_type) == 0 &&
             strcmp(strchr(media_type, '/'), "/*") == 0))
        {
            if (quality > best_quality)
            {
                best_quality = quality;
            }
        }

        token = strtok(NULL, ",");
    }

    free(header_copy);
    return best_quality;
}

// main content negotiation function
negotiated_content_t negotiate_content(char *filepath, http_request_t *request)
{
    negotiated_content_t result = {0};
    strcpy(result.charset, "utf-8"); // default charset

    // get base MIME type from file extension
    char *base_mime = get_mime_type(filepath);
    strcpy(result.content_type, base_mime);

    printf("[DEBUG] File: %s, Base MIME: %s\n", filepath, base_mime);
    printf("[DEBUG] Accept header: '%s'\n", request->accept);

    // 1. content-type negotiation
    if (strlen(request->accept) > 0)
    {
        float quality = parse_quality(request->accept, base_mime);
        if (quality == 0)
        {
            // client does not accept this tpye, we should try alternatives but for now we can keep original - should be improved
            strcpy(result.content_type, "application/octet-stream");
        }
    }

    // 2. language negotiation (simplified)
    if (strlen(request->accept_language) > 0)
    {
        // check if we have language specific vestion
        char lang_filepath[MAX_PATH];
        // try common languages
        char *languages[] = {"en", "fr", "es", "de", NULL};
        for (int i = 0; languages[i] != NULL; i++)
        {
            float lang_quality = parse_quality(request->accept_language, languages[i]);
            if (lang_quality > 0.0)
            {
                // check if language specific path exists
                snprintf(lang_filepath, sizeof(lang_filepath), "%s.%s.html", filepath, languages[i]);
                struct stat lang_stat;
                if (stat(lang_filepath, &lang_stat) == 0)
                {
                    strcpy(result.language, languages[i]);
                    break;
                }
            }
        }
    }

    // 3. encoding negotiation
    if (strlen(request->accept_encoding) > 0)
    {
        // check for compression support
        if (parse_quality(request->accept_encoding, "gzip") > 0.0)
        {
            strcpy(result.encoding, "gzip");
            result.should_compress = 1;
        }
        else if (parse_quality(request->accept_encoding, "deflate") > 0.0)
        {
            strcpy(result.encoding, "deflate");
            result.should_compress = 1;
        }
    }

    // 4. charset negotiation
    if (strlen(request->accept_charset) > 0)
    {
        if (parse_quality(request->accept_charset, "utf-8") > 0.0)
        {
            strcpy(result.charset, "utf-8");
        }
        else if (parse_quality(request->accept_charset, "iso-8859-1") > 0.0)
        {
            strcpy(result.charset, "iso-8859-1");
        }
    }

    return result;
}

int compress_gzip(const char *input, size_t input_len, char **output, size_t *output_len)
{
    if (input == NULL || input_len == 0)
    {
        return -1;
    }

    // allocate output buffer: input size + 0.1% + 12 bytes;
    size_t max_output_len = input_len + (input_len * 0.001) + 12 + 18; // gzip header and footer
    *output = malloc(max_output_len);
    if (*output == NULL)
    {
        return -1;
    }

    z_stream strm;
    strm.zalloc = Z_NULL;
    strm.zfree = Z_NULL;
    strm.opaque = Z_NULL;

    // initialise for gzip format
    if (deflateInit2(&strm, Z_DEFAULT_COMPRESSION, Z_DEFLATED, 15 + 16, 8, Z_DEFAULT_STRATEGY) != Z_OK)
    {
        free(*output);
        return -1;
    }

    strm.next_in = (unsigned char *)input;
    strm.avail_in = input_len;
    strm.next_out = (unsigned char *)*output;
    strm.avail_out = max_output_len;

    // comptess
    if (deflate(&strm, Z_FINISH) != Z_STREAM_END)
    {
        deflateEnd(&strm);
        free(*output);
        return -1;
    }

    *output_len = max_output_len - strm.avail_out;
    deflateEnd(&strm);
    return 0;
}

// determine if the content should be compressed
int should_compress_content(const char *content_type, size_t content_length)
{
    // dont compress if it is below 1kb, the overhead not worth it
    if (content_length < 1024)
    {
        return 0;
    }

    // Don't compress already compressed formats
    if (strstr(content_type, "image/") ||
        strstr(content_type, "video/") ||
        strstr(content_type, "application/zip") ||
        strstr(content_type, "application/gzip") ||
        strstr(content_type, "application/pdf"))
    {
        return 0;
    }

    // Compress text-based formats
    if (strstr(content_type, "text/") ||
        strstr(content_type, "application/json") ||
        strstr(content_type, "application/javascript") ||
        strstr(content_type, "application/xml") ||
        strstr(content_type, "image/svg+xml"))
    {
        return 1;
    }

    return 0;
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
void send_response(int client_fd, char *status, negotiated_content_t *content, char *body, size_t body_length, int keep_alive)
{
    char response[BUFFER_SIZE];
    char time_str[128];
    char content_type_header[256];

    get_current_time(time_str);

    // build content type header with charset
    if (strlen(content->charset) > 0)
    {
        // Check if charset is already in content_type
        if (strstr(content->content_type, "charset=") == NULL)
        {
            snprintf(content_type_header, sizeof(content_type_header),
                     "%s; charset=%s", content->content_type, content->charset);
        }
        else
        {
            // Charset already present, use as-is
            strcpy(content_type_header, content->content_type);
        }
    }
    else
    {
        strcpy(content_type_header, content->content_type);
    }

    int header_length = snprintf(response, sizeof(response),
                                 "HTTP/1.1 %s\r\n"
                                 "Date: %s\r\n"
                                 "Server: CustomWebServer/1.0\r\n"
                                 "Content-Type: %s\r\n"
                                 "Content-Length: %zu\r\n"
                                 "Connection: %s\r\n",
                                 status,
                                 time_str, content_type_header, body_length,
                                 keep_alive ? "keep-alive" : "close");

    // add optional headers
    if (strlen(content->language) > 0)
    {
        char lang_header[64];
        snprintf(lang_header, sizeof(lang_header), "Content-Language: %s\r\n", content->language);
        strcat(response, lang_header);
        header_length += strlen(lang_header);
    }

    if (strlen(content->encoding) > 0)
    {
        char encoding_header[64];
        snprintf(encoding_header, sizeof(encoding_header), "Content-Encoding: %s\r\n", content->encoding);
        strcat(response, encoding_header);
        header_length += strlen(encoding_header);
    }

    // Add Vary header to indicate which request headers affect the response
    char vary_header[] = "Vary: Accept, Accept-Language, Accept-Encoding, Accept-Charset\r\n";
    strcat(response, vary_header);
    header_length += strlen(vary_header);

    // End headers
    strcat(response, "\r\n");
    header_length += 2;

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

    printf("[INFO] Sent negotiated response: %s (%zu bytes, %s)\n", status, body_length, content_type_header);
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

// file sending with content negotiation
void send_file(int client_fd, char *filepath, int keep_alive, http_request_t *request)
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

    // content negotiation
    negotiated_content_t content = negotiate_content(filepath, request);
    // Check if client accepts our content type
    if (strlen(request->accept) > 0)
    {
        float quality = parse_quality(request->accept, content.content_type);
        if (quality == 0.0)
        {
            // Send 406 Not Acceptable
            char *body =
                "<!DOCTYPE html><html><head><title>406 Not Acceptable</title></head>"
                "<body><h1>406 Not Acceptable</h1>"
                "<p>The requested resource cannot be provided in a format acceptable to your client.</p>"
                "</body></html>";
            negotiated_content_t content = {0};
            strcpy(content.content_type, "text/html");
            strcpy(content.charset, "utf-8");

            send_response(client_fd, HTTP_406, &content, body, strlen(body), keep_alive);
            return;
        }
    }

    int file_fd = open(filepath, O_RDONLY);
    if (file_fd < 0)
    {
        printf("[ERROR] Cannot open file: %s (%s)\n", filepath, strerror(errno));
        send_500(client_fd, keep_alive);
        return;
    }

    // check if we should actually compress the file
    int do_compression = content.should_compress && should_compress_content(content.content_type, file_stat.st_size);
    if (do_compression)
    {
        // read entire file into memory for compression
        char *file_content = malloc(file_stat.st_size);
        if (file_content == NULL)
        {
            printf("[ERROR] Failed to allocate memory for file compression\n");
            close(file_fd);
            send_500(client_fd, keep_alive);
            return;
        }

        if (read(file_fd, file_content, file_stat.st_size) != file_stat.st_size)
        {
            printf("[ERROR] Failed to read complete file for compression\n");
            free(file_content);
            close(file_fd);
            send_500(client_fd, keep_alive);
            return;
        }

        close(file_fd);

        // compress the content
        char *compressed_content;
        size_t compressed_size;

        if (compress_gzip(file_content, file_stat.st_size, &compressed_content, &compressed_size) == 0)
        {
            printf("[INFO] Compressed %s: %lld -> %zu bytes (%.1f%% reduction)\n", filepath, (long long)file_stat.st_size, compressed_size, 100.0 * (file_stat.st_size - compressed_size) / file_stat.st_size);

            // Send compressed response
            send_response(client_fd, HTTP_200, &content, compressed_content, compressed_size, keep_alive);

            free(compressed_content);
        }
        else
        {
            printf("[ERROR] Compression failed, sending uncompressed\n");
            // Fall back to uncompressed
            strcpy(content.encoding, "");
            content.should_compress = 0;
            send_response(client_fd, HTTP_200, &content, file_content, file_stat.st_size, keep_alive);
        }

        free(file_content);
    }
    else
    {
        // Send uncompressed file
        strcpy(content.encoding, "");
        content.should_compress = 0;

        // Send response headers first
        send_response(client_fd, HTTP_200, &content, NULL, file_stat.st_size, keep_alive);

        // Send file content in chunks
        if (safe_send_file(client_fd, file_fd, file_stat.st_size) < 0)
        {
            printf("[ERROR] Failed to send file: %s\n", filepath);
        }
        else
        {
            printf("[INFO] File sent uncompressed: %s (%lld bytes)\n", filepath, (long long)file_stat.st_size);
        }

        close(file_fd);
    }
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

    negotiated_content_t content = {0};
    strcpy(content.content_type, "text/html");
    strcpy(content.charset, "utf-8");

    send_response(client_fd, HTTP_404, &content, body, strlen(body), keep_alive);
}

void send_400(int client_fd, int keep_alive)
{
    char *body =
        "<!DOCTYPE html>"
        "<html><head><title>400 Bad Request</title></head>"
        "<body><h1>400 Bad Request</h1>"
        "<p>The request could not be understood by the server.</p>"
        "</body></html>";

    negotiated_content_t content = {0};
    strcpy(content.content_type, "text/html");
    strcpy(content.charset, "utf-8");

    send_response(client_fd, HTTP_400, &content, body, strlen(body), keep_alive);
}

void send_500(int client_fd, int keep_alive)
{
    char *body =
        "<!DOCTYPE html>"
        "<html><head><title>500 Internal Server Error</title></head>"
        "<body><h1>500 Internal Server Error</h1>"
        "<p>The server encountered an internal error.</p>"
        "</body></html>";

    negotiated_content_t content = {0};
    strcpy(content.content_type, "text/html");
    strcpy(content.charset, "utf-8");

    send_response(client_fd, HTTP_500, &content, body, strlen(body), keep_alive);
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