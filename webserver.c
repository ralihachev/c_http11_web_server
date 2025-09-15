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
#include <ctype.h>

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
    char params[10][2][256];
    int param_count;
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

typedef struct
{
    int enable_hsts;
    int enable_csp;
    int enable_xss_protection;
    int enable_content_type_options;
    int enable_frame_options;
    char frame_options[32];      // deny, same origin, allow-from
    char csp_policy[512];        // content security policy
    int hsts_max_age;            // in seconds
    int hsts_include_subdomains; // include subdomains directive
} security_headers_t;

typedef struct
{
    char client_ip[INET_ADDRSTRLEN];
    time_t window_start;
    int request_count;
    time_t last_request;
    int blocked_until;   // Temporary ban timestamp
    int violation_count; // Number of violations from this IP
} rate_limit_entry_t;

typedef struct
{
    int requests_per_window; // e.g., 100 requests
    int window_size;         // e.g., 60 seconds
    int ban_duration;        // e.g., 300 seconds (5 min ban)
    int max_entries;         // cache size limit
    int strict_mode;         // progressive penalties
    int burst_threshold;     // burst threshold (requests in 1 second)
    rate_limit_entry_t *entries;
    int entry_count;
    pthread_mutex_t mutex; // Mutex for thread-safe access
} rate_limit_config_t;

typedef enum
{
    RATE_LIMIT_ALLOW,
    RATE_LIMIT_WARN,
    RATE_LIMIT_BLOCK,
    RATE_LIMIT_BAN
} rate_limit_result_t;

typedef struct
{
    time_t window_start;
    int total_requests;
    int unique_ips;
    int blocked_requests;
    char top_offender[INET_ADDRSTRLEN];
    int top_offender_count;
} ddos_stats_t;

typedef enum
{
    SECURITY_ACTION_LOG,
    SECURITY_ACTION_BLOCK,
    SECURITY_ACTION_BAN
} security_action_t;

typedef struct
{
    char pattern[256];
    security_action_t action;
    char description[256];
    int ban_duration;   // if the action is ban
    int case_sensitive; // case sensitive matching
} security_rule_t;

typedef struct
{
    security_rule_t *rules;
    int rule_count;
    int max_rules;
    int enabled;
} security_filter_t;

typedef struct
{
    int blocked;
    int should_ban;
    int ban_duration;
    char threat_type[128];
    char matched_pattern[128];
} security_check_result_t;

// route handler function pointer
typedef struct api_response (*route_handler_t)(http_request_t *req, struct api_response *res);
// middleware function pointer
typedef int (*middleware_t)(http_request_t *req, struct api_response *res, void (*next)());

typedef struct
{
    char method[8]; // get, put, post, delete
    char path[256];
    route_handler_t handler;  // function to handle this route
    middleware_t *middleware; // array of middleware functions
    int middleware_count;
} route_t;

typedef struct
{
    route_t *routes;
    int route_count;
    int max_routes;
    middleware_t *global_middleware;
    int global_middleware_count;
} router_t;

typedef struct api_response
{
    int status_code;
    char headers[MAX_HEADERS][MAX_HEADER_SIZE];
    int header_count;
    char *body;
    size_t body_length;
    int json_mode;
} api_response_t;

typedef struct
{
    middleware_t *middleware_chain;
    int current_index;
    int total_count;
    http_request_t *req;
    api_response_t *res;
} middleware_context_t;

ddos_stats_t ddos_stats = {0};
rate_limit_config_t *global_rate_limit_config = NULL;
security_filter_t *global_security_filter = NULL;
router_t *api_router = NULL;

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
security_headers_t get_default_security_headers();
void add_security_headers(char *response_buffer, size_t buffer_size, int *header_length, security_headers_t *security_config, int is_https);
rate_limit_config_t *init_rate_limiting();
rate_limit_entry_t *find_or_create_entry(rate_limit_config_t *config, const char *client_ip);
rate_limit_result_t check_rate_limit(rate_limit_config_t *config, const char *client_ip);
int detect_ddos_pattern(rate_limit_config_t *config);
void send_rate_limit_response(int client_fd, const char *client_ip, int retry_after);
void send_ban_response(int client_fd, const char *client_ip, int ban_remaining);
void cleanup_rate_limiting(rate_limit_config_t *config);
security_filter_t *init_security_filter();
int add_security_rule(security_filter_t *filter, const char *pattern, security_action_t action, const char *description, int ban_duration, int case_sensitive);
security_check_result_t validate_request_security(security_filter_t *filter, const char *request_uri, const char *user_agent, const char *request_body);
int validate_file_path(const char *requested_path, char *safe_path, size_t safe_path_len);
void send_security_block_response(int client_fd, const char *threat_type);
router_t *create_router();
void add_route(router_t *router, const char *method, const char *path, route_handler_t handler);
void add_route_middleware(router_t *router, int route_index, middleware_t middleware);
void use_middleware(router_t *router, middleware_t middleware);
int match_route(const char *route_path, const char *request_path, char params[][256]);
route_t *find_route(router_t *router, const char *method, const char *path);
void next(middleware_context_t *ctx);
void execute_middleware_chain(middleware_t *chain, int count, http_request_t *req, api_response_t *res, route_handler_t final_handler);
void set_json_response(api_response_t *res, const char *json);
void setup_routes(router_t *router);
void handle_api_request(http_request_t *request, int client_fd, router_t *router);
void send_api_response(int client_fd, api_response_t *response);
char *get_param(http_request_t *request, const char *param_name);
void extract_url_params(const char *route_path, const char *request_path, http_request_t *request);
const char *get_status_text(int status_code);

// Global variables for graceful shutdown
volatile sig_atomic_t server_running = 1;

void handle_sigint(int sig)
{
    (void)sig;
    printf("\n[INFO] Received shutdown signal. Stopping server...\n");
    server_running = 0;
    cleanup_rate_limiting(global_rate_limit_config);
    exit(0);
}

void cleanup_rate_limiting(rate_limit_config_t *config)
{
    if (config)
    {
        pthread_mutex_destroy(&config->mutex);
        free(config->entries);
        free(config);
        printf("[INFO] Rate limiting cleanup completed\n");
    }
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
    // check limits before processing the request
    char client_ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &client_addr.sin_addr, client_ip, INET_ADDRSTRLEN);

    if (global_rate_limit_config)
    {
        rate_limit_result_t rate_result = check_rate_limit(global_rate_limit_config, client_ip);

        switch (rate_result)
        {
        case RATE_LIMIT_BAN:
        {
            // Find entry to get remaining ban time
            pthread_mutex_lock(&global_rate_limit_config->mutex);
            for (int i = 0; i < global_rate_limit_config->entry_count; i++)
            {
                if (strcmp(global_rate_limit_config->entries[i].client_ip, client_ip) == 0)
                {
                    int remaining = global_rate_limit_config->entries[i].blocked_until - time(NULL);
                    pthread_mutex_unlock(&global_rate_limit_config->mutex);
                    send_ban_response(client_fd, client_ip, remaining);
                    close(client_fd);
                    return;
                }
            }
            pthread_mutex_unlock(&global_rate_limit_config->mutex);
        }
        break;

        case RATE_LIMIT_BLOCK:
            send_rate_limit_response(client_fd, client_ip, global_rate_limit_config->window_size);
            close(client_fd);
            return;

        case RATE_LIMIT_WARN:
            printf("[INFO] Client %s approaching rate limit\n", client_ip);
            break;

        case RATE_LIMIT_ALLOW:
            break;
        }

        // check for DDoS patterns periodically
        static time_t last_ddos_check = 0;
        time_t now = time(NULL);
        if (now - last_ddos_check >= 30)
        { // Check every 30 seconds
            detect_ddos_pattern(global_rate_limit_config);
            last_ddos_check = now;
        }
    }

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

        // process security validation
        if (global_security_filter)
        {
            // Extract user agent from request headers
            char *user_agent = NULL;
            for (int i = 0; i < request.header_count; i++)
            {
                if (strcasecmp(request.headers[i].name, "User-Agent") == 0)
                {
                    user_agent = request.headers[i].value;
                    break;
                }
            }

            // Validate request for security threats
            security_check_result_t security_result = validate_request_security(
                global_security_filter, request.path, user_agent, request.body);

            if (security_result.blocked)
            {
                if (security_result.should_ban)
                {
                    // Add IP to rate limiting ban list
                    pthread_mutex_lock(&global_rate_limit_config->mutex);
                    rate_limit_entry_t *entry = find_or_create_entry(global_rate_limit_config, client_ip);
                    entry->blocked_until = time(NULL) + security_result.ban_duration;
                    entry->violation_count += 10; // Heavy penalty for security violations
                    pthread_mutex_unlock(&global_rate_limit_config->mutex);

                    send_ban_response(client_fd, client_ip, security_result.ban_duration);
                }
                else
                {
                    send_security_block_response(client_fd, security_result.threat_type);
                }
                close(client_fd);
                return;
            }
        }

        // Check for keep-alive
        keep_connection = request.keep_alive;

        if (strncmp(request.path, "/api/", 5) == 0)
        {
            // Handle API request
            handle_api_request(&request, client_fd, api_router);
        }
        else
        {
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

                // Validate and sanitize file path
                char safe_filepath[MAX_PATH];
                if (validate_file_path(request.path, safe_filepath, sizeof(safe_filepath)) < 0)
                {
                    send_security_block_response(client_fd, "PATH_TRAVERSAL");
                    close(client_fd);
                    return;
                }

                // Use safe_filepath instead of original request.path for file operations
                strcpy(filepath, safe_filepath);
                printf("[INFO] Serving safe file: %s\n", filepath);

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

// default security configuration
security_headers_t get_default_security_headers()
{
    security_headers_t headers = {0};

    // enable basic security headers
    headers.enable_xss_protection = 1;
    headers.enable_content_type_options = 1;
    headers.enable_frame_options = 1;
    strcpy(headers.frame_options, "SAMEORIGIN");

    // basic csp - allows same origin, inline styles, but restricts scripts
    strcpy(headers.csp_policy, "default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self'");
    headers.enable_csp = 1;

    // hsts disabled by default - only enable with HTTPS
    headers.enable_hsts = 0;
    headers.hsts_max_age = 31536000; // 1 year
    headers.hsts_include_subdomains = 0;

    return headers;
}

void add_security_headers(char *response_buffer, size_t buffer_size, int *header_length, security_headers_t *security_config, int is_https)
{
    char temp_header[256];

    // prevent mime type sniffing
    if (security_config->enable_content_type_options)
    {
        strcpy(temp_header, "X-Content-Type-Options: nosniff\r\n");
        if (strlen(response_buffer) + strlen(temp_header) < buffer_size)
        {
            strcat(response_buffer, temp_header);
            *header_length += strlen(temp_header);
        }
    }

    // prevent clickjacking
    if (security_config->enable_frame_options)
    {
        snprintf(temp_header, sizeof(temp_header), "X-Frame-Options: %s\r\n",
                 security_config->frame_options);
        if (strlen(response_buffer) + strlen(temp_header) < buffer_size)
        {
            strcat(response_buffer, temp_header);
            *header_length += strlen(temp_header);
        }
    }

    // enable xss filtering
    if (security_config->enable_xss_protection)
    {
        strcpy(temp_header, "X-XSS-Protection: 1; mode=block\r\n");
        if (strlen(response_buffer) + strlen(temp_header) < buffer_size)
        {
            strcat(response_buffer, temp_header);
            *header_length += strlen(temp_header);
        }
    }

    // prevent xss and injection attacks
    if (security_config->enable_csp && strlen(security_config->csp_policy) > 0)
    {
        snprintf(temp_header, sizeof(temp_header), "Content-Security-Policy: %s\r\n", security_config->csp_policy);
        if (strlen(response_buffer) + strlen(temp_header) < buffer_size)
        {
            strcat(response_buffer, temp_header);
            *header_length += strlen(temp_header);
        }
    }

    // only for HTTPS connections
    if (security_config->enable_hsts && is_https)
    {
        if (security_config->hsts_include_subdomains)
        {
            snprintf(temp_header, sizeof(temp_header), "Strict-Transport-Security: max-age=%d; includeSubDomains\r\n", security_config->hsts_max_age);
        }
        else
        {
            snprintf(temp_header, sizeof(temp_header), "Strict-Transport-Security: max-age=%d\r\n", security_config->hsts_max_age);
        }
        if (strlen(response_buffer) + strlen(temp_header) < buffer_size)
        {
            strcat(response_buffer, temp_header);
            *header_length += strlen(temp_header);
        }
    }

    // additional security headers
    strcpy(temp_header, "Referrer-Policy: strict-origin-when-cross-origin\r\n");
    if (strlen(response_buffer) + strlen(temp_header) < buffer_size)
    {
        strcat(response_buffer, temp_header);
        *header_length += strlen(temp_header);
    }

    strcpy(temp_header, "X-Permitted-Cross-Domain-Policies: none\r\n");
    if (strlen(response_buffer) + strlen(temp_header) < buffer_size)
    {
        strcat(response_buffer, temp_header);
        *header_length += strlen(temp_header);
    }
}

rate_limit_config_t *init_rate_limiting()
{
    rate_limit_config_t *config = malloc(sizeof(rate_limit_config_t));
    if (!config)
    {
        return NULL;
    }

    // default configuration - moderate protection
    config->requests_per_window = 60;
    config->window_size = 60;
    config->ban_duration = 300;
    config->max_entries = 1000; // track up to 1000 ips
    config->strict_mode = 1;    // enable progressive penalties
    config->burst_threshold = 100;

    config->entries = malloc(sizeof(rate_limit_entry_t) * config->max_entries);
    if (!config->entries)
    {
        free(config);
        return NULL;
    }

    config->entry_count = 0;
    // initialise mutex for thread safety
    if (pthread_mutex_init(&config->mutex, NULL) != 0)
    {
        free(config->entries);
        free(config);
        return NULL;
    }

    memset(config->entries, 0, sizeof(rate_limit_entry_t) * config->max_entries);

    printf("[INFO] Rate limiting initialized: %d req/%ds, %ds ban\n", config->requests_per_window, config->window_size, config->ban_duration);

    return config;
}

// find or create rate limit entry for an IP
rate_limit_entry_t *find_or_create_entry(rate_limit_config_t *config, const char *client_ip)
{
    time_t now = time(NULL);

    // first, look for an existing entry
    for (int i = 0; i < config->entry_count; i++)
    {
        if (strcmp(config->entries[i].client_ip, client_ip) == 0)
        {
            return &config->entries[i];
        }
    }

    // if we have room, create a new entry
    if (config->entry_count < config->max_entries)
    {
        rate_limit_entry_t *entry = &config->entries[config->entry_count];
        strcpy(entry->client_ip, client_ip);
        entry->window_start = now;
        entry->request_count = 0;
        entry->last_request = 0;
        entry->blocked_until = 0;
        entry->violation_count = 0;
        config->entry_count++;
        return entry;
    }

    // cache full - find oldest entry to replace (LRU eviction)
    rate_limit_entry_t *oldest = &config->entries[0];
    for (int i = 1; i < config->max_entries; i++)
    {
        if (config->entries[i].last_request < oldest->last_request)
        {
            oldest = &config->entries[i];
        }
    }

    // Replace oldest entry
    strcpy(oldest->client_ip, client_ip);
    oldest->window_start = now;
    oldest->request_count = 0;
    oldest->last_request = 0;
    oldest->blocked_until = 0;
    oldest->violation_count = 0;

    return oldest;
}

// main rate limiting check function
rate_limit_result_t check_rate_limit(rate_limit_config_t *config, const char *client_ip)
{
    if (!config || !client_ip)
    {
        return RATE_LIMIT_ALLOW;
    }

    pthread_mutex_lock(&config->mutex);

    time_t now = time(NULL);
    rate_limit_entry_t *entry = find_or_create_entry(config, client_ip);

    // check if ip is currently banned
    if (entry->blocked_until > now)
    {
        pthread_mutex_unlock(&config->mutex);
        printf("[SECURITY] Blocked request from banned IP: %s (ban expires in %lds)\n", client_ip, entry->blocked_until - now);
        return RATE_LIMIT_BAN;
    }

    // reset window if expired
    if (now - entry->window_start >= config->window_size)
    {
        entry->window_start = now;
        entry->request_count = 0;
    }

    // check for burst (too many requests in 1 second)
    if (entry->last_request > 0 && (now - entry->last_request == 0))
    {
        // multiple requests in same second - count them
        static int same_second_count = 0;
        same_second_count++;

        if (same_second_count > config->burst_threshold)
        {
            entry->violation_count++;
            entry->blocked_until = now + (config->ban_duration * entry->violation_count);

            pthread_mutex_unlock(&config->mutex);
            printf("[SECURITY] Burst detected from %s: %d requests/second (banned for %ds)\n", client_ip, same_second_count, config->ban_duration * entry->violation_count);
            return RATE_LIMIT_BAN;
        }
    }
    else
    {
        // Reset burst counter for new second
        static int same_second_count = 0;
    }

    entry->last_request = now;
    entry->request_count++;

    // Check if limit exceeded
    if (entry->request_count > config->requests_per_window)
    {
        entry->violation_count++;

        if (config->strict_mode)
        {
            // Progressive penalties: longer bans for repeat offenders
            int penalty_multiplier = (entry->violation_count > 5) ? 5 : entry->violation_count;
            entry->blocked_until = now + (config->ban_duration * penalty_multiplier);

            pthread_mutex_unlock(&config->mutex);
            printf("[SECURITY] Rate limit exceeded by %s: %d/%d requests (banned for %ds, violation #%d)\n", client_ip, entry->request_count, config->requests_per_window, config->ban_duration * penalty_multiplier, entry->violation_count);
            return RATE_LIMIT_BLOCK;
        }
        else
        {
            // Simple mode: just block this request
            pthread_mutex_unlock(&config->mutex);
            printf("[SECURITY] Rate limit exceeded by %s: %d/%d requests\n", client_ip, entry->request_count, config->requests_per_window);
            return RATE_LIMIT_BLOCK;
        }
    }

    // Warn when approaching limit (80% of limit)
    if (entry->request_count > (config->requests_per_window * 0.8))
    {
        pthread_mutex_unlock(&config->mutex);
        printf("[WARNING] IP %s approaching rate limit: %d/%d requests\n", client_ip, entry->request_count, config->requests_per_window);
        return RATE_LIMIT_WARN;
    }

    pthread_mutex_unlock(&config->mutex);
    return RATE_LIMIT_ALLOW;
}

int detect_ddos_pattern(rate_limit_config_t *config)
{
    time_t now = time(NULL);

    // reset stats window every minute
    if (now - ddos_stats.window_start >= 60)
    {
        ddos_stats.window_start = now;
        ddos_stats.total_requests = 0;
        ddos_stats.unique_ips = 0;
        ddos_stats.blocked_requests = 0;
        ddos_stats.top_offender_count = 0;
        strcpy(ddos_stats.top_offender, "");
    }

    pthread_mutex_lock(&config->mutex);

    // count active IPs and find top offender
    int active_ips = 0;
    int max_requests = 0;

    for (int i = 0; i < config->entry_count; i++)
    {
        rate_limit_entry_t *entry = &config->entries[i];

        if (now - entry->window_start < 60)
        {
            // active in last minute
            active_ips++;

            if (entry->request_count > max_requests)
            {
                max_requests = entry->request_count;
                strcpy(ddos_stats.top_offender, entry->client_ip);
                ddos_stats.top_offender_count = entry->request_count;
            }

            if (entry->blocked_until > now)
            {
                ddos_stats.blocked_requests++;
            }
        }
    }

    ddos_stats.unique_ips = active_ips;
    pthread_mutex_unlock(&config->mutex);

    // DDoS detection criteria
    int ddos_detected = 0;

    // criteria 1: Too many unique IPs hitting server simultaneously
    if (active_ips > 50)
    {
        printf("[ALERT] Potential DDoS: %d unique IPs active\n", active_ips);
        ddos_detected = 1;
    }

    // criteria 2: High percentage of blocked requests
    if (ddos_stats.blocked_requests > 10)
    {
        printf("[ALERT] Potential DDoS: %d blocked requests in last minute\n", ddos_stats.blocked_requests);
        ddos_detected = 1;
    }

    // criteria 3: Single IP with excessive requests
    if (ddos_stats.top_offender_count > config->requests_per_window * 3)
    {
        printf("[ALERT] Potential DDoS: IP %s made %d requests\n", ddos_stats.top_offender, ddos_stats.top_offender_count);
        ddos_detected = 1;
    }

    return ddos_detected;
}

void send_rate_limit_response(int client_fd, const char *client_ip, int retry_after)
{
    char *body =
        "<!DOCTYPE html>"
        "<html><head><title>429 Too Many Requests</title></head>"
        "<body><h1>429 Too Many Requests</h1>"
        "<p>You have exceeded the rate limit. Please slow down your requests.</p>"
        "<p>Try again in <span id='countdown'></span> seconds.</p>"
        "<script>"
        "let seconds = %d;"
        "function updateCountdown() {"
        "  document.getElementById('countdown').textContent = seconds;"
        "  if (seconds > 0) { seconds--; setTimeout(updateCountdown, 1000); }"
        "}"
        "updateCountdown();"
        "</script>"
        "</body></html>";

    char response_body[1024];
    snprintf(response_body, sizeof(response_body), body, retry_after);

    char response[BUFFER_SIZE];
    char time_str[128];
    get_current_time(time_str);

    int header_length = snprintf(response, sizeof(response),
                                 "HTTP/1.1 429 Too Many Requests\r\n"
                                 "Date: %s\r\n"
                                 "Server: CustomWebServer/1.0\r\n"
                                 "Content-Type: text/html; charset=utf-8\r\n"
                                 "Content-Length: %zu\r\n"
                                 "Retry-After: %d\r\n"
                                 "Connection: close\r\n"
                                 "\r\n",
                                 time_str, strlen(response_body), retry_after);

    safe_send(client_fd, response, header_length);
    safe_send(client_fd, response_body, strlen(response_body));

    printf("[INFO] Sent 429 response to %s (retry after %ds)\n", client_ip, retry_after);
}

// Send ban response for severely rate-limited IPs
void send_ban_response(int client_fd, const char *client_ip, int ban_remaining)
{
    char *body =
        "<!DOCTYPE html>"
        "<html><head><title>403 Forbidden - Temporary Ban</title></head>"
        "<body><h1>403 Forbidden</h1>"
        "<p>Your IP address has been temporarily banned due to excessive requests.</p>"
        "<p>Ban will be lifted in %d seconds.</p>"
        "<p>Please respect the server's rate limits.</p>"
        "</body></html>";

    char response_body[1024];
    snprintf(response_body, sizeof(response_body), body, ban_remaining);

    char response[BUFFER_SIZE];
    char time_str[128];
    get_current_time(time_str);

    int header_length = snprintf(response, sizeof(response),
                                 "HTTP/1.1 403 Forbidden\r\n"
                                 "Date: %s\r\n"
                                 "Server: CustomWebServer/1.0\r\n"
                                 "Content-Type: text/html; charset=utf-8\r\n"
                                 "Content-Length: %zu\r\n"
                                 "Connection: close\r\n"
                                 "\r\n",
                                 time_str, strlen(response_body));

    safe_send(client_fd, response, header_length);
    safe_send(client_fd, response_body, strlen(response_body));

    printf("[INFO] Sent 403 ban response to %s (%ds remaining)\n", client_ip, ban_remaining);
}

// initialise security filter with common patterns
security_filter_t *init_security_filter()
{
    security_filter_t *filter = malloc(sizeof(security_filter_t));
    if (!filter)
        return NULL;

    filter->max_rules = 50;
    filter->rules = malloc(sizeof(security_rule_t) * filter->max_rules);
    if (!filter->rules)
    {
        free(filter);
        return NULL;
    }

    filter->rule_count = 0;
    filter->enabled = 1;

    // SQL Injection patterns
    add_security_rule(filter, "union.*select", SECURITY_ACTION_BLOCK, "SQL Injection - UNION SELECT", 0, 0);
    add_security_rule(filter, "insert.*into", SECURITY_ACTION_BLOCK, "SQL Injection - INSERT INTO", 0, 0);
    add_security_rule(filter, "update.*set", SECURITY_ACTION_BLOCK, "SQL Injection - UPDATE SET", 0, 0);
    add_security_rule(filter, "delete.*from", SECURITY_ACTION_BLOCK, "SQL Injection - DELETE FROM", 0, 0);
    add_security_rule(filter, "drop.*table", SECURITY_ACTION_BAN, "SQL Injection - DROP TABLE", 3600, 0);
    add_security_rule(filter, "exec.*sp_", SECURITY_ACTION_BLOCK, "SQL Injection - Stored Procedure", 0, 0);
    add_security_rule(filter, ".*'.*or.*'.*=.*'", SECURITY_ACTION_BLOCK, "SQL Injection - OR clause", 0, 0);
    add_security_rule(filter, ".*'.*and.*'.*=.*'", SECURITY_ACTION_BLOCK, "SQL Injection - AND clause", 0, 0);
    add_security_rule(filter, ".*--.*", SECURITY_ACTION_LOG, "SQL Comment", 0, 0);
    add_security_rule(filter, ".*/\\*.*\\*/", SECURITY_ACTION_LOG, "SQL Block Comment", 0, 0);

    // Path Traversal patterns
    add_security_rule(filter, "\\.\\./", SECURITY_ACTION_BLOCK, "Path Traversal - Unix", 0, 1);
    add_security_rule(filter, "\\.\\.\\\\/", SECURITY_ACTION_BLOCK, "Path Traversal - Windows", 0, 1);
    add_security_rule(filter, "%2e%2e%2f", SECURITY_ACTION_BLOCK, "Path Traversal - URL Encoded", 0, 0);
    add_security_rule(filter, "%2e%2e/", SECURITY_ACTION_BLOCK, "Path Traversal - Partial URL Encoded", 0, 0);
    add_security_rule(filter, "..%2f", SECURITY_ACTION_BLOCK, "Path Traversal - Mixed Encoding", 0, 0);
    add_security_rule(filter, "%c0%ae%c0%ae/", SECURITY_ACTION_BLOCK, "Path Traversal - Double URL Encoded", 0, 0);
    add_security_rule(filter, "/etc/passwd", SECURITY_ACTION_BAN, "Path Traversal - System File Access", 1800, 0);
    add_security_rule(filter, "/etc/shadow", SECURITY_ACTION_BAN, "Path Traversal - Password File", 1800, 0);
    add_security_rule(filter, "/proc/", SECURITY_ACTION_BLOCK, "Path Traversal - Proc filesystem", 0, 0);

    // Script Injection patterns
    add_security_rule(filter, "<script", SECURITY_ACTION_BLOCK, "XSS - Script Tag", 0, 0);
    add_security_rule(filter, "</script>", SECURITY_ACTION_BLOCK, "XSS - Script End Tag", 0, 0);
    add_security_rule(filter, "javascript:", SECURITY_ACTION_BLOCK, "XSS - JavaScript Protocol", 0, 0);
    add_security_rule(filter, "vbscript:", SECURITY_ACTION_BLOCK, "XSS - VBScript Protocol", 0, 0);
    add_security_rule(filter, "onload=", SECURITY_ACTION_BLOCK, "XSS - OnLoad Event", 0, 0);
    add_security_rule(filter, "onerror=", SECURITY_ACTION_BLOCK, "XSS - OnError Event", 0, 0);
    add_security_rule(filter, "onclick=", SECURITY_ACTION_BLOCK, "XSS - OnClick Event", 0, 0);
    add_security_rule(filter, "eval\\(", SECURITY_ACTION_BLOCK, "Script Injection - Eval", 0, 0);
    add_security_rule(filter, "document\\.cookie", SECURITY_ACTION_BLOCK, "XSS - Cookie Theft", 0, 0);
    add_security_rule(filter, "document\\.write", SECURITY_ACTION_BLOCK, "XSS - Document Write", 0, 0);
    add_security_rule(filter, "alert\\(", SECURITY_ACTION_LOG, "XSS - Alert Box", 0, 0);
    add_security_rule(filter, "prompt\\(", SECURITY_ACTION_LOG, "XSS - Prompt Box", 0, 0);
    add_security_rule(filter, "confirm\\(", SECURITY_ACTION_LOG, "XSS - Confirm Box", 0, 0);

    // Command Injection patterns
    add_security_rule(filter, "system\\(", SECURITY_ACTION_BAN, "Command Injection - System", 3600, 0);
    add_security_rule(filter, "exec\\(", SECURITY_ACTION_BAN, "Command Injection - Exec", 3600, 0);
    add_security_rule(filter, "passthru\\(", SECURITY_ACTION_BAN, "Command Injection - Passthru", 3600, 0);
    add_security_rule(filter, "shell_exec", SECURITY_ACTION_BAN, "Command Injection - Shell Exec", 3600, 0);
    add_security_rule(filter, "\\|\\|", SECURITY_ACTION_BLOCK, "Command Injection - OR operator", 0, 1);
    add_security_rule(filter, "&&", SECURITY_ACTION_BLOCK, "Command Injection - AND operator", 0, 1);
    add_security_rule(filter, ";.*rm.*", SECURITY_ACTION_BAN, "Command Injection - Remove command", 3600, 0);
    add_security_rule(filter, ";.*cat.*", SECURITY_ACTION_BLOCK, "Command Injection - Cat command", 0, 0);

    // Data URI and File inclusion
    add_security_rule(filter, "data:text/html", SECURITY_ACTION_BLOCK, "Data URI XSS", 0, 0);
    add_security_rule(filter, "data:application/javascript", SECURITY_ACTION_BLOCK, "Data URI Script", 0, 0);
    add_security_rule(filter, "file://", SECURITY_ACTION_BLOCK, "Local File Inclusion", 0, 0);
    add_security_rule(filter, "php://", SECURITY_ACTION_BLOCK, "PHP Stream Wrapper", 0, 0);

    printf("[INFO] Security filter initialized with %d rules\n", filter->rule_count);
    return filter;
}

int add_security_rule(security_filter_t *filter, const char *pattern, security_action_t action, const char *description, int ban_duration, int case_sensitive)
{
    if (!filter || filter->rule_count >= filter->max_rules)
    {
        return -1;
    }

    security_rule_t *rule = &filter->rules[filter->rule_count];
    strncpy(rule->pattern, pattern, sizeof(rule->pattern) - 1);
    rule->pattern[sizeof(rule->pattern) - 1] = '\0';

    strncpy(rule->description, description, sizeof(rule->description) - 1);
    rule->description[sizeof(rule->description) - 1] = '\0';

    rule->action = action;
    rule->ban_duration = ban_duration;
    rule->case_sensitive = case_sensitive;

    filter->rule_count++;
    return 0;
}

// simple pattern matching (basic regex-like functionality)
int pattern_match(const char *text, const char *pattern, int case_sensitive)
{
    if (!text || !pattern)
    {
        return 0;
    }

    char *text_copy = strdup(text);
    char *pattern_copy = strdup(pattern);

    if (!text_copy || !pattern_copy)
    {
        free(text_copy);
        free(pattern_copy);
        return 0;
    }

    // Convert to lowercase if case insensitive
    if (!case_sensitive)
    {
        for (int i = 0; text_copy[i]; i++)
        {
            text_copy[i] = tolower(text_copy[i]);
        }
        for (int i = 0; pattern_copy[i]; i++)
        {
            pattern_copy[i] = tolower(pattern_copy[i]);
        }
    }

    // Simple wildcard matching and basic regex
    int match = 0;

    // Check for exact substring match first
    if (strstr(text_copy, pattern_copy))
    {
        match = 1;
    }
    // Handle basic regex patterns
    else if (strchr(pattern_copy, '\\'))
    {
        // Simple regex handling - convert \\( to (, \\. to ., etc.
        char *regex_pattern = malloc(strlen(pattern_copy) + 1);
        if (regex_pattern)
        {
            int j = 0;
            for (int i = 0; pattern_copy[i]; i++)
            {
                if (pattern_copy[i] == '\\' && pattern_copy[i + 1])
                {
                    i++; // Skip backslash
                    regex_pattern[j++] = pattern_copy[i];
                }
                else
                {
                    regex_pattern[j++] = pattern_copy[i];
                }
            }
            regex_pattern[j] = '\0';

            if (strstr(text_copy, regex_pattern))
            {
                match = 1;
            }
            free(regex_pattern);
        }
    }

    free(text_copy);
    free(pattern_copy);
    return match;
}

security_check_result_t validate_request_security(security_filter_t *filter, const char *request_uri, const char *user_agent, const char *request_body)
{
    security_check_result_t result = {0};

    if (!filter || !filter->enabled)
    {
        return result;
    }

    // Combine all request data for scanning
    size_t total_len = strlen(request_uri) + (user_agent ? strlen(user_agent) : 0) + (request_body ? strlen(request_body) : 0) + 10;

    char *combined_data = malloc(total_len);
    if (!combined_data)
    {
        return result;
    }

    snprintf(combined_data, total_len, "%s %s %s", request_uri, user_agent ? user_agent : "", request_body ? request_body : "");

    // check against all security rules
    for (int i = 0; i < filter->rule_count; i++)
    {
        security_rule_t *rule = &filter->rules[i];

        if (pattern_match(combined_data, rule->pattern, rule->case_sensitive))
        {
            strcpy(result.threat_type, rule->description);
            strcpy(result.matched_pattern, rule->pattern);

            switch (rule->action)
            {
            case SECURITY_ACTION_LOG:
                printf("[SECURITY] Suspicious pattern detected: %s in request from URI: %s\n", rule->description, request_uri);
                break;

            case SECURITY_ACTION_BLOCK:
                printf("[SECURITY] Blocked malicious request: %s - Pattern: %s\n", rule->description, rule->pattern);
                result.blocked = 1;
                break;

            case SECURITY_ACTION_BAN:
                printf("[SECURITY] Malicious request detected - BANNING: %s - Pattern: %s\n", rule->description, rule->pattern);
                result.blocked = 1;
                result.should_ban = 1;
                result.ban_duration = rule->ban_duration;
                break;
            }

            // Stop at first match for efficiency
            break;
        }
    }

    free(combined_data);
    return result;
}

// validate and sanitize file paths
int validate_file_path(const char *requested_path, char *safe_path, size_t safe_path_len)
{
    if (!requested_path || !safe_path)
    {
        return -1;
    }

    // Remove leading slash if present
    const char *path = requested_path;
    if (path[0] == '/')
    {
        path++;
    }

    // decode the path first
    char decoded_path[MAX_PATH];
    url_decode(decoded_path, path);

    // Check for path traversal attempts
    if (strstr(decoded_path, "..") ||
        strstr(decoded_path, "%2e%2e") ||
        strstr(decoded_path, "%c0%ae") ||
        decoded_path[0] == '/' ||
        strstr(decoded_path, "\\"))
    {

        printf("[SECURITY] Path traversal attempt detected: %s\n", decoded_path);
        return -1;
    }

    // Check for system file access attempts
    const char *forbidden_paths[] = {
        "etc/passwd", "etc/shadow", "etc/hosts",
        "proc/", "sys/", "dev/", "var/log/",
        "boot/", "root/", "home/",
        ".ssh/", ".bash_history", ".env",
        "config", "settings", "database",
        NULL};

    for (int i = 0; forbidden_paths[i]; i++)
    {
        if (strstr(decoded_path, forbidden_paths[i]))
        {
            printf("[SECURITY] Forbidden path access attempt: %s\n", decoded_path);
            return -1;
        }
    }

    // Ensure path stays within document root
    char normalized_path[MAX_PATH];
    snprintf(normalized_path, sizeof(normalized_path), "./%s", decoded_path);

    // Additional validation: ensure file extension is allowed
    const char *allowed_extensions[] = {
        ".html", ".htm", ".css", ".js", ".json", ".txt", ".png",
        ".jpg", ".jpeg", ".gif", ".ico", ".svg", ".pdf", ".zip",
        NULL};

    char *extension = strrchr(decoded_path, '.');
    if (extension)
    {
        int allowed = 0;
        for (int i = 0; allowed_extensions[i]; i++)
        {
            if (strcasecmp(extension, allowed_extensions[i]) == 0)
            {
                allowed = 1;
                break;
            }
        }
        if (!allowed)
        {
            printf("[SECURITY] Forbidden file extension: %s\n", extension);
            return -1;
        }
    }

    strncpy(safe_path, normalized_path, safe_path_len - 1);
    safe_path[safe_path_len - 1] = '\0';

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
    char response[BUFFER_SIZE * 2]; // double the buffer size for security headers
    char time_str[128];
    char content_type_header[256];

    // get security configuration
    security_headers_t security_config = get_default_security_headers();

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

    // Add security headers
    add_security_headers(response, sizeof(response), &header_length, &security_config, 0); // 0 = HTTP (not HTTPS)
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

void send_security_block_response(int client_fd, const char *threat_type)
{
    char *body =
        "<!DOCTYPE html>"
        "<html><head><title>403 Forbidden - Security Policy Violation</title></head>"
        "<body><h1>403 Forbidden</h1>"
        "<p>Your request has been blocked by our security policy.</p>"
        "<p>Threat detected: %s</p>"
        "<p>If you believe this is an error, please contact the administrator.</p>"
        "</body></html>";

    char response_body[1024];
    snprintf(response_body, sizeof(response_body), body, threat_type);

    char response[BUFFER_SIZE];
    char time_str[128];
    get_current_time(time_str);

    int header_length = snprintf(response, sizeof(response),
                                 "HTTP/1.1 403 Forbidden\r\n"
                                 "Date: %s\r\n"
                                 "Server: CustomWebServer/1.0\r\n"
                                 "Content-Type: text/html; charset=utf-8\r\n"
                                 "Content-Length: %zu\r\n"
                                 "Connection: close\r\n"
                                 "\r\n",
                                 time_str, strlen(response_body));

    safe_send(client_fd, response, header_length);
    safe_send(client_fd, response_body, strlen(response_body));

    printf("[INFO] Sent 403 security block response - Threat: %s\n", threat_type);
}

// router & middleware handlers

// initialise router
router_t *create_router()
{
    router_t *router = malloc(sizeof(router_t));
    router->routes = malloc(sizeof(route_t) * 100);
    router->route_count = 0;
    router->max_routes = 100;
    router->global_middleware = malloc(sizeof(middleware_t) * 10);
    router->global_middleware_count = 0;
    return router;
}

// add route
void add_route(router_t *router, const char *method, const char *path, route_handler_t handler)
{
    if (router->route_count >= router->max_routes)
    {
        return;
    }

    route_t *route = &router->routes[router->route_count];
    strcpy(route->method, method);
    strcpy(route->path, path);
    route->handler = handler;
    route->middleware = NULL;
    route->middleware_count = 0;
    router->route_count++;
}

// add middleware to specific route
void add_route_middleware(router_t *router, int route_index, middleware_t middleware)
{
    route_t *route = &router->routes[route_index];
    if (route->middleware == NULL)
    {
        route->middleware = malloc(sizeof(middleware_t) * 10);
        route->middleware_count = 0;
    }
    route->middleware[route->middleware_count++] = middleware;
}

// add global middleware
void use_middleware(router_t *router, middleware_t middleware)
{
    router->global_middleware[router->global_middleware_count++] = middleware;
}

// simple path matching (supports :id parameters)
int match_route(const char *route_path, const char *request_path, char params[][256])
{
    // Skip leading slashes
    const char *route_start = route_path;
    const char *request_start = request_path;

    if (route_start[0] == '/')
        route_start++;
    if (request_start[0] == '/')
        request_start++;

    char *route_copy = strdup(route_start);
    char *request_copy = strdup(request_start);

    // Use strtok_r for thread-safe tokenization
    char *route_saveptr, *request_saveptr;
    char *route_token = strtok_r(route_copy, "/", &route_saveptr);
    char *request_token = strtok_r(request_copy, "/", &request_saveptr);
    int param_count = 0;

    while (route_token && request_token)
    {
        if (route_token[0] == ':')
        {
            // Parameter - store value
            strcpy(params[param_count], request_token);
            param_count++;
        }
        else if (strcmp(route_token, request_token) != 0)
        {
            free(route_copy);
            free(request_copy);
            return 0; // No match
        }

        route_token = strtok_r(NULL, "/", &route_saveptr);
        request_token = strtok_r(NULL, "/", &request_saveptr);
    }

    int result = (route_token == NULL && request_token == NULL);

    free(route_copy);
    free(request_copy);
    return result;
}
// find matching route
route_t *find_route(router_t *router, const char *method, const char *path)
{
    char params[10][256]; // Store URL parameters

    for (int i = 0; i < router->route_count; i++)
    {
        route_t *route = &router->routes[i];

        if (strcmp(route->method, method) == 0)
        {
            if (match_route(route->path, path, params))
            {
                return route;
            }
        }
    }
    return NULL;
}

// next function for middleware chain
void next(middleware_context_t *ctx)
{
    ctx->current_index++;
    if (ctx->current_index < ctx->total_count)
    {
        middleware_t current = ctx->middleware_chain[ctx->current_index];
        current(ctx->req, ctx->res, (void (*)())next);
    }
}

// Execute middleware chain
void execute_middleware_chain(middleware_t *chain, int count, http_request_t *req, api_response_t *res, route_handler_t final_handler)
{
    middleware_context_t ctx = {
        .middleware_chain = chain,
        .current_index = -1,
        .total_count = count,
        .req = req,
        .res = res};

    // Start middleware chain
    next(&ctx);

    // Execute final handler if all middleware passed
    if (ctx.current_index >= count)
    {
        final_handler(req, res);
    }
}

void set_json_response(api_response_t *res, const char *json)
{
    res->json_mode = 1;
    res->body = strdup(json);
    res->body_length = strlen(json);
    res->status_code = 200;
    sprintf(res->headers[res->header_count++], "Content-Type: application/json");
}

api_response_t get_users(http_request_t *req, api_response_t *res)
{
    set_json_response(res, "{\"users\": [{\"id\": 1, \"name\": \"John\"}, {\"id\": 2, \"name\": \"Jane\"}]}");
    return *res;
}

int cors_middleware(http_request_t *req, api_response_t *res, void (*next)())
{
    sprintf(res->headers[res->header_count++], "Access-Control-Allow-Origin: *");
    sprintf(res->headers[res->header_count++], "Access-Control-Allow-Methods: GET, POST, PUT, DELETE");
    sprintf(res->headers[res->header_count++], "Access-Control-Allow-Headers: Content-Type, Authorization");
    next();
    return 1;
}

int logging_middleware(http_request_t *req, api_response_t *res, void (*next)())
{
    time_t now = time(NULL);
    printf("[%s] %s %s\n", ctime(&now), req->method, req->path);
    next();
    return 1;
}

void setup_routes(router_t *router)
{
    // Global middleware
    // use_middleware(router, cors_middleware);
    // use_middleware(router, logging_middleware);

    // API routes
    add_route(router, "GET", "/api/users", get_users);
}

void handle_api_request(http_request_t *request, int client_fd, router_t *router)
{
    api_response_t response = {0};
    char params[10][256] = {0}; // For URL parameters

    // Initialize response
    response.status_code = 404;
    response.header_count = 0;
    response.body = NULL;
    response.json_mode = 0;

    // Find matching route
    route_t *route = find_route(router, request->method, request->path);

    if (route)
    {
        // Extract URL parameters and add to request
        extract_url_params(route->path, request->path, request);

        // Build middleware chain (global + route-specific)
        middleware_t full_chain[20];
        int chain_count = 0;

        // Add global middleware
        for (int i = 0; i < router->global_middleware_count; i++)
        {
            full_chain[chain_count++] = router->global_middleware[i];
        }

        // Add route-specific middleware
        for (int i = 0; i < route->middleware_count; i++)
        {
            full_chain[chain_count++] = route->middleware[i];
        }

        // Execute middleware chain + handler
        execute_middleware_chain(full_chain, chain_count, request, &response, route->handler);
    }
    else
    {
        // 404 for API routes
        response.status_code = 404;
        set_json_response(&response, "{\"error\": \"API route not found\"}");
    }

    // Send response
    send_api_response(client_fd, &response);

    // Cleanup
    if (response.body)
    {
        free(response.body);
    }
}

const char *get_status_text(int status_code)
{
    switch (status_code)
    {
    case 200:
        return "OK";
    case 201:
        return "Created";
    case 204:
        return "No Content";
    case 304:
        return "Not Modified";
    case 400:
        return "Bad Request";
    case 401:
        return "Unauthorized";
    case 403:
        return "Forbidden";
    case 404:
        return "Not Found";
    case 405:
        return "Method Not Allowed";
    case 406:
        return "Not Acceptable";
    case 429:
        return "Too Many Requests";
    case 500:
        return "Internal Server Error";
    case 501:
        return "Not Implemented";
    case 502:
        return "Bad Gateway";
    case 503:
        return "Service Unavailable";
    default:
        return "Unknown";
    }
}

void extract_url_params(const char *route_path, const char *request_path, http_request_t *request)
{
    char *route_copy = strdup(route_path);
    char *request_copy = strdup(request_path);

    char *route_token = strtok(route_copy, "/");
    char *request_token = strtok(request_copy, "/");
    request->param_count = 0;

    while (route_token && request_token)
    {
        if (route_token[0] == ':')
        {
            // Found parameter
            strcpy(request->params[request->param_count][0], route_token + 1); // Skip ':'
            strcpy(request->params[request->param_count][1], request_token);
            request->param_count++;
        }

        route_token = strtok(NULL, "/");
        request_token = strtok(NULL, "/");
    }

    free(route_copy);
    free(request_copy);
}

// Helper to get parameter value
char *get_param(http_request_t *request, const char *param_name)
{
    for (int i = 0; i < request->param_count; i++)
    {
        if (strcmp(request->params[i][0], param_name) == 0)
        {
            return request->params[i][1];
        }
    }
    return NULL;
}

void send_api_response(int client_fd, api_response_t *response)
{
    char response_buffer[BUFFER_SIZE];
    const char *status_text = get_status_text(response->status_code);

    // Build response headers
    int header_len = snprintf(response_buffer, sizeof(response_buffer),
                              "HTTP/1.1 %d %s\r\n"
                              "Server: CustomWebServer/1.0\r\n"
                              "Connection: keep-alive\r\n",
                              response->status_code, status_text);

    // Add custom headers
    for (int i = 0; i < response->header_count; i++)
    {
        header_len += snprintf(response_buffer + header_len,
                               sizeof(response_buffer) - header_len,
                               "%s\r\n", response->headers[i]);
    }

    // Add content length if body exists
    if (response->body && response->body_length > 0)
    {
        header_len += snprintf(response_buffer + header_len,
                               sizeof(response_buffer) - header_len,
                               "Content-Length: %zu\r\n", response->body_length);
    }

    // End headers
    header_len += snprintf(response_buffer + header_len,
                           sizeof(response_buffer) - header_len, "\r\n");

    // Send headers
    send(client_fd, response_buffer, header_len, 0);

    // Send body if exists
    if (response->body && response->body_length > 0)
    {
        send(client_fd, response->body, response->body_length, 0);
    }
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

    // Initialize rate limiting at server startup
    global_rate_limit_config = init_rate_limiting();
    if (!global_rate_limit_config)
    {
        printf("[ERROR] Failed to initialize rate limiting\n");
        exit(EXIT_FAILURE);
    }

    // In main function, after rate limiting initialization:
    global_security_filter = init_security_filter();
    if (!global_security_filter)
    {
        printf("[ERROR] Failed to initialize security filter\n");
        exit(EXIT_FAILURE);
    }

    // Initialize API router
    api_router = create_router();
    setup_routes(api_router);

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