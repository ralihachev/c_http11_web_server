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
#include <regex.h>

#define PORT 3000
#define BUFFER_SIZE 8192
#define MAX_PATH 512
#define MAX_HEADERS 20
#define MAX_HEADER_SIZE 512
#define MAX_CONNECTIONS 50
#define MAX_COMPRESSION_FILE_SIZE (5 * 1024 * 1024) // 5MB limit for compression
#define MAX_THREADS 100                             // Maximum number of concurrent threads

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
    {".xml", "application/xml"},
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
    time_t blocked_until; // Temporary ban timestamp
    int violation_count;  // Number of violations from this IP
    int burst_count;
    time_t burst_second;
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
    int ban_duration;       // if the action is ban
    int case_sensitive;     // case sensitive matching
    regex_t compiled_regex; // cached compiled regex pattern
    int regex_compiled;     // flag to track if regex is compiled
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

// Memory Pool Structures for Performance Optimization
typedef struct memory_pool_block
{
    void *data;
    int in_use;
    struct memory_pool_block *next;
} memory_pool_block_t;

typedef struct
{
    size_t block_size;
    int pool_size;
    int blocks_allocated;
    int blocks_in_use;
    memory_pool_block_t *free_list;
    pthread_mutex_t mutex;
} memory_pool_t;

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

// Global memory pools
memory_pool_t *connection_pool = NULL;

// Thread management for resource exhaustion protection
static volatile int active_thread_count = 0;
static pthread_mutex_t thread_count_mutex = PTHREAD_MUTEX_INITIALIZER;

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
void url_decode(char *dst, const char *src, size_t dst_size);
void handle_sigchld(int sig);
void setup_socket_options(int sockfd);
int safe_send(int sockfd, const void *buf, size_t len);
int safe_send_file(int client_fd, int file_fd, size_t file_size);
float parse_quality(char *header_value, char *target_value);
negotiated_content_t negotiate_content(char *filepath, http_request_t *request);
int compress_gzip(const char *input, size_t input_len, char **output, size_t *output_len);
int should_compress_content(const char *content_type, size_t content_length);
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
void cleanup_security_filter(security_filter_t *filter);
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

// Memory pool management functions
memory_pool_t *create_memory_pool(size_t block_size, int pool_size);
void *pool_allocate(memory_pool_t *pool);
void pool_deallocate(memory_pool_t *pool, void *ptr);
void destroy_memory_pool(memory_pool_t *pool);

// Global variables for graceful shutdown
volatile sig_atomic_t server_running = 1;

void handle_sigint(int sig)
{
    (void)sig;
    // Only async-signal-safe operations allowed in signal handlers
    // Just set the flag - cleanup will happen in main loop
    server_running = 0;
}

void cleanup_rate_limiting(rate_limit_config_t *config)
{
    if (config)
    {
        pthread_mutex_destroy(&config->mutex);
        if (config->entries)
        {
            free(config->entries);
            config->entries = NULL; // Prevent double-free
        }
        free(config);
        printf("[INFO] Rate limiting cleanup completed\n");
    }
}

// Memory Pool Implementation for Performance Optimization
memory_pool_t *create_memory_pool(size_t block_size, int pool_size)
{
    memory_pool_t *pool = malloc(sizeof(memory_pool_t));
    if (!pool)
        return NULL;

    pool->block_size = block_size;
    pool->pool_size = pool_size;
    pool->blocks_allocated = 0;
    pool->blocks_in_use = 0;
    pool->free_list = NULL;

    if (pthread_mutex_init(&pool->mutex, NULL) != 0)
    {
        free(pool);
        return NULL;
    }

    // Pre-allocate pool blocks
    for (int i = 0; i < pool_size; i++)
    {
        memory_pool_block_t *block = malloc(sizeof(memory_pool_block_t));
        if (!block)
            break;

        block->data = malloc(block_size);
        if (!block->data)
        {
            free(block);
            break;
        }

        block->in_use = 0;
        block->next = pool->free_list;
        pool->free_list = block;
        pool->blocks_allocated++;
    }

    printf("[INFO] Memory pool created: %d blocks of %zu bytes each\n",
           pool->blocks_allocated, block_size);
    return pool;
}

void *pool_allocate(memory_pool_t *pool)
{
    if (!pool)
        return NULL;

    pthread_mutex_lock(&pool->mutex);

    if (!pool->free_list)
    {
        pthread_mutex_unlock(&pool->mutex);
        return NULL; // Pool exhausted
    }

    memory_pool_block_t *block = pool->free_list;
    pool->free_list = block->next;
    block->in_use = 1;
    block->next = NULL;
    pool->blocks_in_use++;

    pthread_mutex_unlock(&pool->mutex);
    return block->data;
}

void pool_deallocate(memory_pool_t *pool, void *ptr)
{
    if (!pool || !ptr)
        return;

    pthread_mutex_lock(&pool->mutex);

    // Find the block that contains this data
    memory_pool_block_t *current = pool->free_list;
    memory_pool_block_t *prev = NULL;

    // Check free list first (shouldn't find it here)
    while (current)
    {
        if (current->data == ptr)
        {
            // This is an error - double free
            pthread_mutex_unlock(&pool->mutex);
            printf("[ERROR] Double free detected in memory pool\n");
            return;
        }
        prev = current;
        current = current->next;
    }

    // Search through all allocated blocks to find the one to free
    // In a real implementation, we'd maintain a separate list of allocated blocks
    // For simplicity, we'll create a new block structure
    memory_pool_block_t *block = malloc(sizeof(memory_pool_block_t));
    if (!block)
    {
        pthread_mutex_unlock(&pool->mutex);
        return;
    }

    block->data = ptr;
    block->in_use = 0;
    block->next = pool->free_list;
    pool->free_list = block;
    pool->blocks_in_use--;

    pthread_mutex_unlock(&pool->mutex);
}

void destroy_memory_pool(memory_pool_t *pool)
{
    if (!pool)
        return;

    pthread_mutex_lock(&pool->mutex);

    memory_pool_block_t *current = pool->free_list;
    while (current)
    {
        memory_pool_block_t *next = current->next;
        free(current->data);
        free(current);
        current = next;
    }

    pool->free_list = NULL;
    pool->blocks_allocated = 0;
    pool->blocks_in_use = 0;

    pthread_mutex_unlock(&pool->mutex);
    pthread_mutex_destroy(&pool->mutex);
    free(pool);

    printf("[INFO] Memory pool destroyed\n");
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

    // Set socket timeouts to prevent hanging connections
    struct timeval timeout;
    timeout.tv_sec = 30; // 30 second timeout
    timeout.tv_usec = 0;

    if (setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) < 0)
    {
        perror("Warning: setsockopt SO_RCVTIMEO failed");
    }

    if (setsockopt(sockfd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout)) < 0)
    {
        perror("Warning: setsockopt SO_SNDTIMEO failed");
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

    // Extract values locally to avoid use-after-free
    int client_fd = conn->client_fd;
    struct sockaddr_in client_addr = conn->client_addr;

    // Free the connection structure immediately after copying data
    if (connection_pool)
    {
        pool_deallocate(connection_pool, conn);
    }
    else
    {
        free(conn);
    }

    // Handle the client using local copies
    handle_client(client_fd, client_addr);

    // Decrement active thread count when thread is about to exit
    pthread_mutex_lock(&thread_count_mutex);
    active_thread_count--;
    pthread_mutex_unlock(&thread_count_mutex);

    return NULL;
}

// client handling with connection management
void handle_client(int client_fd, struct sockaddr_in client_addr)
{
    char client_ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &client_addr.sin_addr, client_ip, INET_ADDRSTRLEN);

    if (global_rate_limit_config)
    {
        rate_limit_result_t rate_result = check_rate_limit(global_rate_limit_config, client_ip);

        switch (rate_result)
        {
        case RATE_LIMIT_BAN:
        {
            pthread_mutex_lock(&global_rate_limit_config->mutex);
            for (int i = 0; i < global_rate_limit_config->entry_count; i++)
            {
                if (strcmp(global_rate_limit_config->entries[i].client_ip, client_ip) == 0)
                {
                    int remaining = (int)(global_rate_limit_config->entries[i].blocked_until - time(NULL));
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

        static time_t last_ddos_check = 0;
        time_t now = time(NULL);
        if (now - last_ddos_check >= 30)
        {
            detect_ddos_pattern(global_rate_limit_config);
            last_ddos_check = now;
        }
    }

    char buffer[BUFFER_SIZE];
    http_request_t request;
    int keep_connection = 1;

    printf("[INFO] Handling client %s:%d\n", inet_ntoa(client_addr.sin_addr), ntohs(client_addr.sin_port));

    // Resolve docroot once per client connection (fail early if docroot missing)
    char docroot[MAX_PATH];
    if (!realpath("./client", docroot))
    {
        printf("[ERROR] Failed to resolve document root directory\n");
        send_500(client_fd, 0);
        close(client_fd);
        return;
    }

    while (keep_connection && server_running)
    {
        memset(buffer, 0, sizeof(buffer));
        memset(&request, 0, sizeof(request));

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

        parse_request(buffer, &request);

        // security validation
        if (global_security_filter)
        {
            char *user_agent = NULL;
            for (int i = 0; i < request.header_count; i++)
            {
                if (strcasecmp(request.headers[i].name, "User-Agent") == 0)
                {
                    user_agent = request.headers[i].value;
                    break;
                }
            }

            security_check_result_t security_result = validate_request_security(
                global_security_filter, request.path, user_agent, request.body);

            if (security_result.blocked)
            {
                if (security_result.should_ban)
                {
                    if (global_rate_limit_config)
                    {
                        pthread_mutex_lock(&global_rate_limit_config->mutex);
                        rate_limit_entry_t *entry = find_or_create_entry(global_rate_limit_config, client_ip);
                        if (entry)
                        {
                            entry->blocked_until = time(NULL) + security_result.ban_duration;
                            entry->violation_count += 10;
                        }
                        else
                        {
                            printf("[ERROR] Failed to create rate limit entry for security ban: %s\n", client_ip);
                        }
                        pthread_mutex_unlock(&global_rate_limit_config->mutex);
                    }
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

        keep_connection = request.keep_alive;

        if (strcmp(request.method, "GET") == 0 || strcmp(request.method, "HEAD") == 0)
        {
            printf("[INFO] received request path: %s\n", request.path);

            // Build a relative path under docroot WITHOUT duplicating "client/"
            // relative_path never contains "client/" prefix
            char relative_path[MAX_PATH] = {0};

            // Special routing (maps to files inside docroot)
            if (strcmp(request.path, "/") == 0)
            {
                snprintf(relative_path, sizeof(relative_path), "index.html");
            }
            else if (strcmp(request.path, "/about") == 0)
            {
                snprintf(relative_path, sizeof(relative_path), "about.html");
            }
            else if (strcmp(request.path, "/blog") == 0 || strcmp(request.path, "/blog/") == 0)
            {
                snprintf(relative_path, sizeof(relative_path), "blog.html");
            }
            else if (strncmp(request.path, "/blog/", 6) == 0)
            {
                // /blog/post -> dist/blog/post.html
                char tmp[MAX_PATH];
                snprintf(tmp, sizeof(tmp), "dist/blog/%s.html", request.path + 6);
                snprintf(relative_path, sizeof(relative_path), "%s", tmp);
            }
            else if (strcmp(request.path, "/sitemap.xml") == 0)
            {
                snprintf(relative_path, sizeof(relative_path), "sitemap.xml");
            }
            else
            {
                // Generic: strip leading slash
                const char *p = request.path;
                if (*p == '/')
                    p++;

                // If the incoming path starts with "client/" remove that prefix.
                if (strncmp(p, "client/", 7) == 0)
                    p += 7;

                // copy remaining into relative_path (prevent overflow)
                snprintf(relative_path, sizeof(relative_path), "%s", p);
            }

            // Use secure path validation function
            char safe_file_path[MAX_PATH];
            int validation_result = validate_file_path(relative_path, safe_file_path, sizeof(safe_file_path));

            if (validation_result == -1)
            {
                // Path traversal attempt detected - log to server only
                printf("[SECURITY] Path traversal attempt blocked\n");
                send_security_block_response(client_fd, "PATH_TRAVERSAL");
                close(client_fd);
                return;
            }
            else if (validation_result != 0)
            {
                // Other validation error (buffer overflow, etc.) - generic message
                printf("[SECURITY] Path validation failed\n");
                send_500(client_fd, keep_connection);
                if (!keep_connection)
                    break;
                continue;
            }

            printf("[INFO] Serving safe file: %s\n", safe_file_path);

            if (strcmp(request.method, "HEAD") == 0)
            {
                struct stat file_stat;
                if (stat(safe_file_path, &file_stat) == 0 && S_ISREG(file_stat.st_mode))
                {
                    negotiated_content_t content = negotiate_content(safe_file_path, &request);
                    send_response(client_fd, HTTP_200, &content, NULL, file_stat.st_size, keep_connection);
                }
                else
                {
                    send_404(client_fd, keep_connection);
                }
            }
            else
            {
                send_file(client_fd, safe_file_path, keep_connection, &request);
            }
        }
        else if (strcmp(request.method, "POST") == 0)
        {
            char *response_body = "POST request received successfully";
            negotiated_content_t post_content = {0};
            snprintf(post_content.content_type, sizeof(post_content.content_type), "%s", "text/plain");
            snprintf(post_content.charset, sizeof(post_content.charset), "%s", "utf-8");

            send_response(client_fd, HTTP_200, &post_content, response_body, strlen(response_body), keep_connection);
        }
        else
        {
            send_400(client_fd, keep_connection);
            keep_connection = 0;
        }

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

            // Validate header name (basic checks)
            if (strlen(line) == 0 || strlen(line) > MAX_HEADER_SIZE - 1)
            {
                continue; // Skip invalid header names
            }

            snprintf(request->headers[request->header_count].name, sizeof(request->headers[request->header_count].name), "%s", line);

            // Skip whitespace after colon
            char *value = colon + 1;
            while (*value == ' ')
                value++;

            // Validate header value length
            if (strlen(value) > MAX_HEADER_SIZE - 1)
            {
                continue; // Skip oversized header values
            }

            snprintf(request->headers[request->header_count].value, sizeof(request->headers[request->header_count].value), "%s", value);

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
                snprintf(request->accept, sizeof(request->accept), "%s", value);
            }
            if (strcasecmp(line, "Accept-Language") == 0)
            {
                snprintf(request->accept_language, sizeof(request->accept_language), "%s", value);
            }
            if (strcasecmp(line, "Accept-Encoding") == 0)
            {
                snprintf(request->accept_encoding, sizeof(request->accept_encoding), "%s", value);
            }
            if (strcasecmp(line, "Accept-Charset") == 0)
            {
                snprintf(request->accept_charset, sizeof(request->accept_charset), "%s", value);
            }
            request->header_count++;
        }
    }
}

float parse_quality(char *header_value, char *target_type)
{
    if (!header_value || strlen(header_value) == 0)
    {
        return 1.0; // default if no accept header
    }

    size_t len = strlen(header_value);

    // Prevent excessive memory allocation - limit header size to reasonable maximum
    const size_t MAX_HEADER_LENGTH = BUFFER_SIZE; // 8KB should be sufficient for Accept headers
    if (len > MAX_HEADER_LENGTH)
    {
        printf("[SECURITY] Rejecting oversized header: %zu bytes (max: %zu)\n", len, MAX_HEADER_LENGTH);
        return 0.0; // reject oversized headers
    }

    // Use stack allocation for small headers, fallback to malloc for large ones
    char stack_buffer[4096]; // 4KB stack buffer for most common cases
    char *header_copy;
    int use_stack = (len < sizeof(stack_buffer));

    if (use_stack)
    {
        header_copy = stack_buffer;
    }
    else
    {
        header_copy = malloc(len + 1);
        if (!header_copy)
        {
            return 0.0; // allocation failed, safest fallback
        }
    }

    snprintf(header_copy, len + 1, "%s", header_value);

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
        float quality = 1.0f; // default quality

        // split on ; to separate media type from parameters
        char *semicolon = strchr(token, ';');
        if (semicolon != NULL)
        {
            *semicolon = '\0';
            snprintf(media_type, sizeof(media_type), "%s", token);

            // parse quality parameter
            char *q_param = strstr(semicolon + 1, "q=");
            if (q_param != NULL)
            {
                quality = (float)atof(q_param + 2);
            }
        }
        else
        {
            snprintf(media_type, sizeof(media_type), "%s", token);
        }

        // check if this media type matches our target
        if (strcmp(media_type, target_type) == 0 ||
            strcmp(media_type, "*/*") == 0 ||
            (strstr(target_type, "/") &&
             strncmp(media_type, target_type, strchr(target_type, '/') - target_type) == 0 &&
             strcmp(strchr(media_type, '/'), "/*") == 0))
        {
            if (quality > best_quality)
            {
                best_quality = quality;
            }
        }

        token = strtok(NULL, ",");
    }

    // Only free if we used malloc
    if (!use_stack)
    {
        free(header_copy);
    }
    return best_quality;
}

// main content negotiation function
negotiated_content_t negotiate_content(char *filepath, http_request_t *request)
{
    negotiated_content_t result = {0};
    snprintf(result.charset, sizeof(result.charset), "%s", "utf-8");

    // get base MIME type from file extension
    char *base_mime = get_mime_type(filepath);
    snprintf(result.content_type, sizeof(result.content_type), "%s", base_mime);

    printf("[DEBUG] File: %s, Base MIME: %s\n", filepath, base_mime);
    printf("[DEBUG] Accept header: '%s'\n", request->accept);

    // 1. content-type negotiation
    if (strlen(request->accept) > 0)
    {
        float quality = parse_quality(request->accept, base_mime);
        if (quality == 0)
        {
            // client does not accept this tpye, we should try alternatives but for now we can keep original - should be improved
            snprintf(result.content_type, sizeof(result.content_type), "%s", "application/octet-stream");
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
                    snprintf(result.language, sizeof(result.language), "%s", languages[i]);
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
            snprintf(result.encoding, sizeof(result.encoding), "%s", "gzip");
            result.should_compress = 1;
        }
        else if (parse_quality(request->accept_encoding, "deflate") > 0.0)
        {
            snprintf(result.encoding, sizeof(result.encoding), "%s", "deflate");
            result.should_compress = 1;
        }
    }

    // 4. charset negotiation
    if (strlen(request->accept_charset) > 0)
    {
        if (parse_quality(request->accept_charset, "utf-8") > 0.0)
        {
            snprintf(result.charset, sizeof(result.charset), "%s", "utf-8");
        }
        else if (parse_quality(request->accept_charset, "iso-8859-1") > 0.0)
        {
            snprintf(result.charset, sizeof(result.charset), "%s", "iso-8859-1");
        }
    }

    return result;
}

int compress_gzip(const char *input, size_t input_len, char **output, size_t *output_len)
{
    if (input == NULL || input_len == 0 || output == NULL || output_len == NULL)
    {
        return -1;
    }

    // Initialize output pointer to NULL for safety
    *output = NULL;
    *output_len = 0;

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
        *output = NULL;
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
        *output = NULL;
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
    snprintf(headers.frame_options, sizeof(headers.frame_options), "%s", "SAMEORIGIN");

    // basic csp - allows same origin, inline styles, but restricts scripts
    /*strcpy(headers.csp_policy,
           "default-src 'self'; "
           "img-src 'self' https: data:; "
           "style-src 'self' https: 'unsafe-inline'; "
           "script-src 'self' https://www.googletagmanager.com https://www.google-analytics.com 'sha256-CixLfa7WgyJXPMQDCl15d/FBZpN8gUqAInEA45xlO9o=';");*/
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
        snprintf(temp_header, sizeof(temp_header), "%s", "X-Content-Type-Options: nosniff\r\n");
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
        snprintf(temp_header, sizeof(temp_header), "%s", "X-XSS-Protection: 1; mode=block\r\n");

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
    snprintf(temp_header, sizeof(temp_header), "%s", "Referrer-Policy: strict-origin-when-cross-origin\r\n");

    if (strlen(response_buffer) + strlen(temp_header) < buffer_size)
    {
        strcat(response_buffer, temp_header);
        *header_length += strlen(temp_header);
    }

    snprintf(temp_header, sizeof(temp_header), "%s", "X-Permitted-Cross-Domain-Policies: none\r\n");

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
    config->requests_per_window = 600;
    config->window_size = 600;
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
// CRITICAL: This function MUST only be called while holding the config mutex
// The caller is responsible for mutex synchronization
rate_limit_entry_t *find_or_create_entry(rate_limit_config_t *config, const char *client_ip)
{
    if (!config || !client_ip)
    {
        return NULL;
    }

    time_t now = time(NULL);

    // Validate that entry_count is within bounds (defense against corruption)
    if (config->entry_count < 0 || config->entry_count > config->max_entries)
    {
        printf("[CRITICAL] Rate limiting corruption detected: entry_count=%d, max=%d\n",
               config->entry_count, config->max_entries);
        config->entry_count = 0; // Reset to safe state
    }

    // first, look for an existing entry
    for (int i = 0; i < config->entry_count; i++)
    {
        if (strcmp(config->entries[i].client_ip, client_ip) == 0)
        {
            // Update last_request time for LRU tracking
            config->entries[i].last_request = now;
            return &config->entries[i];
        }
    }

    // if we have room, create a new entry
    if (config->entry_count < config->max_entries)
    {
        int entry_index = config->entry_count; // Capture index before increment
        rate_limit_entry_t *entry = &config->entries[entry_index];

        // Initialize entry safely
        memset(entry, 0, sizeof(rate_limit_entry_t));
        snprintf(entry->client_ip, sizeof(entry->client_ip), "%s", client_ip);
        entry->window_start = now;
        entry->last_request = now;
        entry->request_count = 0;
        entry->blocked_until = 0;
        entry->violation_count = 0;
        entry->burst_count = 0;
        entry->burst_second = 0;

        // Increment entry_count AFTER initialization to prevent race conditions
        config->entry_count++;
        return entry;
    }

    // cache full - find oldest entry to replace (LRU eviction)
    // Find entry with oldest last_request time
    rate_limit_entry_t *oldest = &config->entries[0];
    for (int i = 1; i < config->max_entries; i++)
    {
        if (config->entries[i].last_request < oldest->last_request)
        {
            oldest = &config->entries[i];
        }
    }

    // Safely replace oldest entry - clear all fields first
    memset(oldest, 0, sizeof(rate_limit_entry_t));
    snprintf(oldest->client_ip, sizeof(oldest->client_ip), "%s", client_ip);
    oldest->window_start = now;
    oldest->last_request = now;
    oldest->request_count = 0;
    oldest->blocked_until = 0;
    oldest->violation_count = 0;
    oldest->burst_count = 0;
    oldest->burst_second = 0;

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

    // Double-check that we have the lock (defensive programming)
    if (pthread_mutex_trylock(&config->mutex) == 0)
    {
        // This should never happen - if trylock succeeds, we didn't have the lock
        printf("[CRITICAL] Rate limiting mutex not held properly!\n");
        pthread_mutex_unlock(&config->mutex); // Release the extra lock
        pthread_mutex_unlock(&config->mutex); // Release the original lock
        return RATE_LIMIT_ALLOW;
    }

    rate_limit_entry_t *entry = find_or_create_entry(config, client_ip);

    // Check if entry creation/lookup failed
    if (!entry)
    {
        pthread_mutex_unlock(&config->mutex);
        printf("[ERROR] Failed to find or create rate limit entry for IP: %s\n", client_ip);
        return RATE_LIMIT_ALLOW; // Fail open for availability
    }

    // check if IP is currently banned
    if (entry->blocked_until > now)
    {
        pthread_mutex_unlock(&config->mutex);
        printf("[SECURITY] Blocked request from banned IP: %s (ban expires in %lds)\n",
               client_ip, entry->blocked_until - now);
        return RATE_LIMIT_BAN;
    }

    // reset window if expired
    if (now - entry->window_start >= config->window_size)
    {
        entry->window_start = now;
        entry->request_count = 0;
        entry->burst_count = 0;
        entry->burst_second = 0;
    }

    // burst detection (too many requests in the same second)
    if (entry->burst_second == now)
    {
        entry->burst_count++;
        if (entry->burst_count > config->burst_threshold)
        {
            entry->violation_count++;
            entry->blocked_until = now + (config->ban_duration * entry->violation_count);

            pthread_mutex_unlock(&config->mutex);
            printf("[SECURITY] Burst detected from %s: %d requests/second (banned for %ds)\n",
                   client_ip, entry->burst_count,
                   config->ban_duration * entry->violation_count);
            return RATE_LIMIT_BAN;
        }
    }
    else
    {
        entry->burst_second = now;
        entry->burst_count = 1;
    }

    entry->last_request = now;
    entry->request_count++;

    // Check if limit exceeded
    if (entry->request_count > config->requests_per_window)
    {
        entry->violation_count++;

        if (config->strict_mode)
        {
            // Progressive penalties
            int penalty_multiplier = (entry->violation_count > 5) ? 5 : entry->violation_count;
            entry->blocked_until = now + (config->ban_duration * penalty_multiplier);

            pthread_mutex_unlock(&config->mutex);
            printf("[SECURITY] Rate limit exceeded by %s: %d/%d requests "
                   "(banned for %ds, violation #%d)\n",
                   client_ip, entry->request_count, config->requests_per_window,
                   config->ban_duration * penalty_multiplier, entry->violation_count);
            return RATE_LIMIT_BLOCK;
        }
        else
        {
            pthread_mutex_unlock(&config->mutex);
            printf("[SECURITY] Rate limit exceeded by %s: %d/%d requests\n",
                   client_ip, entry->request_count, config->requests_per_window);
            return RATE_LIMIT_BLOCK;
        }
    }

    // Warn when approaching limit (80%)
    if (entry->request_count > (config->requests_per_window * 0.8))
    {
        pthread_mutex_unlock(&config->mutex);
        printf("[WARNING] IP %s approaching rate limit: %d/%d requests\n",
               client_ip, entry->request_count, config->requests_per_window);
        return RATE_LIMIT_WARN;
    }

    pthread_mutex_unlock(&config->mutex);
    return RATE_LIMIT_ALLOW;
}

// Protects all ddos_stats updates with the same mutex used for rate-limit entries.
int detect_ddos_pattern(rate_limit_config_t *config)
{
    if (!config)
        return 0;

    time_t now = time(NULL);
    int window = (config->window_size > 0) ? config->window_size : 60;

    // EMA smoothing state — persists across calls (thread-safe with static mutex)
    static double ema_active_ips = 0.0;
    static double ema_blocked = 0.0;
    static pthread_mutex_t ema_mutex = PTHREAD_MUTEX_INITIALIZER;
    const double alpha = 0.30; // smoothing factor (0..1). Larger = more responsive.

    int ddos_detected = 0;

    // Hold the mutex for the whole read/update of ddos_stats to avoid races
    pthread_mutex_lock(&config->mutex);

    // Reset stats window when it elapses (protected by mutex)
    if (now - ddos_stats.window_start >= window)
    {
        ddos_stats.window_start = now;
        ddos_stats.total_requests = 0;
        ddos_stats.unique_ips = 0;
        ddos_stats.blocked_requests = 0;
        ddos_stats.top_offender_count = 0;
        ddos_stats.top_offender[0] = '\0';
    }

    // Local accumulators
    int active_ips = 0;
    int max_requests = 0;
    int blocked_requests = 0;
    int total_requests = 0;
    char top_offender_local[INET_ADDRSTRLEN] = "";

    for (int i = 0; i < config->entry_count; i++)
    {
        rate_limit_entry_t *entry = &config->entries[i];

        if (now - entry->window_start < window)
        {
            active_ips++;
            total_requests += entry->request_count;

            if (entry->request_count > max_requests)
            {
                max_requests = entry->request_count;
                snprintf(top_offender_local, sizeof(top_offender_local), "%s", entry->client_ip);
            }

            if (entry->blocked_until > now)
                blocked_requests++;
        }
    }

    // Commit local values to shared ddos_stats while still holding lock
    ddos_stats.total_requests = total_requests;
    ddos_stats.unique_ips = active_ips;
    ddos_stats.blocked_requests = blocked_requests;
    ddos_stats.top_offender_count = max_requests;
    if (top_offender_local[0] != '\0')
        snprintf(ddos_stats.top_offender, sizeof(ddos_stats.top_offender), "%s", top_offender_local);

    pthread_mutex_unlock(&config->mutex);

    // Update EMA smoothing with proper thread synchronization
    pthread_mutex_lock(&ema_mutex);
    double current_ema_active_ips = alpha * (double)active_ips + (1.0 - alpha) * ema_active_ips;
    double current_ema_blocked = alpha * (double)blocked_requests + (1.0 - alpha) * ema_blocked;

    // Update the static variables
    ema_active_ips = current_ema_active_ips;
    ema_blocked = current_ema_blocked;
    pthread_mutex_unlock(&ema_mutex);

    // Detection thresholds (tweak as needed)
    const int unique_ips_hard_threshold = 50; // old behavior threshold
    const int blocked_hard_threshold = 10;    // old behavior threshold
    const int top_offender_multiplier = 3;    // same as before

    // Criterion 1: too many unique IPs — use EMA to avoid very short spikes
    if (current_ema_active_ips > (double)unique_ips_hard_threshold)
    {
        printf("[ALERT] Potential DDoS (smoothed): EMA active IPs=%.1f (raw=%d)\n", current_ema_active_ips, active_ips);
        ddos_detected = 1;
    }

    // Criterion 2: high number of blocked requests (smoothed)
    if (current_ema_blocked > (double)blocked_hard_threshold)
    {
        printf("[ALERT] Potential DDoS (smoothed): EMA blocked reqs=%.1f (raw=%d)\n", current_ema_blocked, blocked_requests);
        ddos_detected = 1;
    }

    // Criterion 3: single IP making excessive requests (raw check — keep strict)
    if (ddos_stats.top_offender_count > config->requests_per_window * top_offender_multiplier)
    {
        printf("[ALERT] Potential DDoS: IP %s made %d requests\n",
               ddos_stats.top_offender, ddos_stats.top_offender_count);
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
    rule->regex_compiled = 0; // Initialize as not compiled

    filter->rule_count++;
    return 0;
}

// Legacy pattern match function (still needed for some cases)
int pattern_match(const char *text, const char *pattern, int case_sensitive)
{
    if (!text || !pattern)
        return 0;

    regex_t regex;
    int flags = REG_NOSUB | REG_EXTENDED;
    if (!case_sensitive)
        flags |= REG_ICASE;

    if (regcomp(&regex, pattern, flags) != 0)
        return 0;

    int ret = regexec(&regex, text, 0, NULL, 0);
    regfree(&regex);

    return (ret == 0);
}

// Optimized pattern match using cached regex
int cached_pattern_match(const char *text, security_rule_t *rule)
{
    if (!text || !rule)
        return 0;

    // Compile regex if not already compiled
    if (!rule->regex_compiled)
    {
        int flags = REG_NOSUB | REG_EXTENDED;
        if (!rule->case_sensitive)
            flags |= REG_ICASE;

        if (regcomp(&rule->compiled_regex, rule->pattern, flags) != 0)
        {
            printf("[WARNING] Failed to compile regex pattern: %s\n", rule->pattern);
            return 0;
        }
        rule->regex_compiled = 1;
    }

    // Execute the cached regex
    return (regexec(&rule->compiled_regex, text, 0, NULL, 0) == 0);
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

    // Use stack allocation for small requests, fallback to malloc for large ones
    char stack_buffer[8192]; // 8KB stack buffer for most requests
    char *combined_data;
    int use_stack = (total_len < sizeof(stack_buffer));

    if (use_stack)
    {
        combined_data = stack_buffer;
    }
    else
    {
        combined_data = malloc(total_len + 1);
        if (!combined_data)
        {
            return result;
        }
    }

    snprintf(combined_data, total_len + 1, "%s %s %s", request_uri, user_agent ? user_agent : "", request_body ? request_body : "");

    // check against all security rules
    for (int i = 0; i < filter->rule_count; i++)
    {
        security_rule_t *rule = &filter->rules[i];

        if (cached_pattern_match(combined_data, rule))
        {
            snprintf(result.threat_type, sizeof(result.threat_type), "%s", rule->description);

            snprintf(result.matched_pattern, sizeof(result.matched_pattern), "%s", rule->pattern);

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

    // Only free if we used malloc
    if (!use_stack)
    {
        free(combined_data);
    }
    return result;
}

// Replaces previous validate_file_path. It returns 0 on success and fills safe_path
// (safe_path will be a canonical path under docroot even if the file doesn't exist).
// Returns -1 for path traversal/invalid, -2 for other errors (like buffer overflow).
int validate_file_path(const char *requested_path, char *safe_path, size_t safe_path_len)
{
    if (!requested_path || !safe_path)
        return -1;

    // URL-decode iteratively to handle double/triple encoding attacks
    char decoded[MAX_PATH];
    char temp_buffer[MAX_PATH];

    // Start with the original path
    strncpy(decoded, requested_path, sizeof(decoded) - 1);
    decoded[sizeof(decoded) - 1] = '\0';

    // Decode up to 3 times to handle multiple levels of encoding
    for (int decode_round = 0; decode_round < 3; decode_round++)
    {
        // Copy current state to temp buffer
        strncpy(temp_buffer, decoded, sizeof(temp_buffer) - 1);
        temp_buffer[sizeof(temp_buffer) - 1] = '\0';

        // Decode into decoded buffer
        url_decode(decoded, temp_buffer, sizeof(decoded));

        // If no change occurred, we're done decoding
        if (strcmp(decoded, temp_buffer) == 0)
        {
            break;
        }

        printf("[SECURITY] Multiple URL decoding round %d: %s\n", decode_round + 1, decoded);
    }

    // Strip leading '/' characters so we join onto docroot cleanly
    char *p = decoded;
    while (*p == '/')
        p++;

    // Normalize path (resolve ., ..) WITHOUT touching filesystem
    char normalized[MAX_PATH];
    int norm_ret = normalize_path(p, normalized, sizeof(normalized));
    if (norm_ret == -1)
    {
        // traversal attempt detected - log to server only, no details to client
        printf("[SECURITY] Path traversal attempt detected from client\n");
        return -1;
    }
    else if (norm_ret != 0)
    {
        printf("[SECURITY] Path normalization failed (err=%d)\n", norm_ret);
        return -2;
    }

    // Get canonical docroot (realpath of ./client)
    char docroot[MAX_PATH];
    if (!realpath("./client", docroot))
    {
        printf("[ERROR] Failed to resolve document root directory\n");
        return -2;
    }

    // If normalized is empty -> means client requested "/", map to index later
    char candidate[MAX_PATH];
    if (normalized[0] == '\0')
    {
        // point to docroot alone
        snprintf(candidate, sizeof(candidate), "%s", docroot);
    }
    else
    {
        // join docroot and normalized path
        snprintf(candidate, sizeof(candidate), "%s/%s", docroot, normalized);
    }

    // Confirm candidate path starts with docroot (should be by construction, but double-check)
    if (strncmp(candidate, docroot, strlen(docroot)) != 0)
    {
        printf("[SECURITY] Path escapes document root after join\n");
        return -1;
    }

    // Optional: check extension whitelist (the original code used resolved path for ext)
    const char *ext = strrchr(candidate, '.');
    if (!ext)
    {
        // no extension -> allow (could be a directory or index)
        // We'll let send_file/stat handle directory vs file
    }
    else
    {
        const char *allowed[] = {".html", ".htm", ".css", ".js", ".json", ".txt",
                                 ".png", ".jpg", ".jpeg", ".gif", ".ico", ".svg",
                                 ".pdf", ".zip", ".xml", ".webp", NULL};
        int ok = 0;
        for (int i = 0; allowed[i]; i++)
        {
            if (strcasecmp(ext, allowed[i]) == 0)
            {
                ok = 1;
                break;
            }
        }
        if (!ok)
        {
            printf("[SECURITY] Forbidden file extension requested\n");
            return -1;
        }
    }

    // Return candidate (may or may not exist). send_file/stat will return 404 if missing.
    if (strlen(candidate) >= safe_path_len)
    {
        return -2;
    }
    snprintf(safe_path, safe_path_len, "%s", candidate);
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
        if (sent < 0)
        {
            if (errno == EAGAIN || errno == EWOULDBLOCK)
            {
                usleep(1000); // Brief pause then retry
                continue;
            }
            // Fatal send error — log for debugging
            perror("[ERROR] send() failed");
            return -1;
        }
        else if (sent == 0)
        {
            // Unexpected, treat as error
            fprintf(stderr, "[ERROR] send() returned 0\n");
            return -1;
        }

        total_sent += (size_t)sent;
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
            snprintf(content_type_header, sizeof(content_type_header), "%s", content->content_type);
        }
    }
    else
    {
        snprintf(content_type_header, sizeof(content_type_header), "%s", content->content_type);
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
    if (request->accept[0] != '\0')
    {
        float quality = parse_quality(request->accept, content.content_type);
        if (quality == 0.0f)
        {
            // Send 406 Not Acceptable
            const char *body =
                "<!DOCTYPE html><html><head><title>406 Not Acceptable</title></head>"
                "<body><h1>406 Not Acceptable</h1>"
                "<p>The requested resource cannot be provided in a format acceptable to your client.</p>"
                "</body></html>";
            negotiated_content_t c = {0};
            snprintf(c.content_type, sizeof(c.content_type), "%s", "text/html");
            snprintf(c.charset, sizeof(c.charset), "%s", "utf-8");

            send_response(client_fd, HTTP_406, &c, (char *)body, strlen(body), keep_alive);
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

    size_t fsize = (size_t)file_stat.st_size;
    int do_compression = content.should_compress && should_compress_content(content.content_type, fsize);

    if (do_compression)
    {
        // Security: Check file size limit for compression to prevent memory exhaustion
        if (fsize > MAX_COMPRESSION_FILE_SIZE)
        {
            printf("[SECURITY] File too large for compression: %zu bytes (max: %d bytes)\n",
                   fsize, MAX_COMPRESSION_FILE_SIZE);

            // Disable compression for large files, serve uncompressed
            content.encoding[0] = '\0';
            content.should_compress = 0;
            do_compression = 0;

            // Continue to serve the file uncompressed below
        }
    }

    if (do_compression)
    {
        // Read entire file into memory for compression (robust loop)
        char *file_content = (char *)malloc(fsize);
        if (file_content == NULL)
        {
            printf("[ERROR] Failed to allocate memory for file compression (%zu bytes)\n", fsize);
            close(file_fd);
            send_500(client_fd, keep_alive);
            return;
        }

        size_t total_read = 0;
        while (total_read < fsize)
        {
            ssize_t n = read(file_fd, file_content + total_read, fsize - total_read);
            if (n < 0)
            {
                if (errno == EINTR)
                    continue; // retry on interrupt
                if (errno == EAGAIN)
                {
                    usleep(1000);
                    continue;
                } // brief backoff
                perror("[ERROR] File read failed");
                free(file_content);
                close(file_fd);
                send_500(client_fd, keep_alive);
                return;
            }
            if (n == 0)
            {
                // Unexpected EOF
                printf("[ERROR] Unexpected EOF while reading file for compression\n");
                free(file_content);
                close(file_fd);
                send_500(client_fd, keep_alive);
                return;
            }
            total_read += (size_t)n;
        }

        close(file_fd);

        // Compress the content
        char *compressed_content = NULL;
        size_t compressed_size = 0;

        if (compress_gzip(file_content, fsize, &compressed_content, &compressed_size) == 0)
        {
            printf("[INFO] Compressed %s: %lld -> %zu bytes (%.1f%% reduction)\n",
                   filepath, (long long)fsize, compressed_size,
                   fsize ? (100.0 * (fsize - compressed_size) / fsize) : 0.0);

            send_response(client_fd, HTTP_200, &content, compressed_content, compressed_size, keep_alive);

            // Always free compressed content after use
            if (compressed_content)
            {
                free(compressed_content);
                compressed_content = NULL;
            }
        }
        else
        {
            printf("[ERROR] Compression failed, sending uncompressed\n");

            // Defensive: Free compressed_content if it was allocated but compression failed
            if (compressed_content)
            {
                free(compressed_content);
                compressed_content = NULL;
            }

            content.encoding[0] = '\0'; // clear encoding
            content.should_compress = 0;

            send_response(client_fd, HTTP_200, &content, file_content, fsize, keep_alive);
        }

        free(file_content);
    }
    else
    {
        // Send uncompressed file
        content.encoding[0] = '\0';
        content.should_compress = 0;

        // Send headers first (with known Content-Length)
        send_response(client_fd, HTTP_200, &content, NULL, fsize, keep_alive);

        // Stream file content in chunks
        if (safe_send_file(client_fd, file_fd, fsize) < 0)
        {
            printf("[ERROR] Failed to send file: %s\n", filepath);
            // We already sent headers; best we can do is close the socket after this function returns
        }
        else
        {
            printf("[INFO] File sent uncompressed: %s (%lld bytes)\n", filepath, (long long)fsize);
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
    snprintf(content.content_type, sizeof(content.content_type), "%s", "text/html");
    snprintf(content.charset, sizeof(content.charset), "%s", "utf-8");

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
    snprintf(content.content_type, sizeof(content.content_type), "%s", "text/html");
    snprintf(content.charset, sizeof(content.charset), "%s", "utf-8");

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
    snprintf(content.content_type, sizeof(content.content_type), "%s", "text/html");
    snprintf(content.charset, sizeof(content.charset), "%s", "utf-8");

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
    snprintf(response_body, sizeof(response_body), body, "%s", threat_type);

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

// URL decode function with bounds checking
void url_decode(char *dst, const char *src, size_t dst_size)
{
    if (!dst || !src || dst_size == 0)
        return;

    char *d = dst;
    const char *s = src;
    char hex[3] = {0};
    size_t written = 0;

    while (*s && written < dst_size - 1) // Leave space for null terminator
    {
        if (*s == '%' && s[1] && s[2])
        {
            // Validate hex digits before conversion
            if (isxdigit(s[1]) && isxdigit(s[2]))
            {
                hex[0] = s[1];
                hex[1] = s[2];
                *d++ = (char)strtol(hex, NULL, 16);
                written++;
                s += 3;
            }
            else
            {
                // Invalid hex encoding - copy as literal
                *d++ = *s++;
                written++;
            }
        }
        else if (*s == '+')
        {
            *d++ = ' ';
            written++;
            s++;
        }
        else
        {
            *d++ = *s++;
            written++;
        }
    }
    *d = '\0'; // Always null terminate
}
// signal handler for child processes
void handle_sigchld(int sig)
{
    (void)sig;
    while (waitpid(-1, NULL, WNOHANG) > 0)
        ;
}

// Cleanup compiled regex patterns in security filter
void cleanup_security_filter(security_filter_t *filter)
{
    if (!filter)
        return;

    for (int i = 0; i < filter->rule_count; i++)
    {
        security_rule_t *rule = &filter->rules[i];
        if (rule->regex_compiled)
        {
            regfree(&rule->compiled_regex);
            rule->regex_compiled = 0;
        }
    }

    if (filter->rules)
    {
        free(filter->rules);
        filter->rules = NULL;
    }
    free(filter);
    printf("[INFO] Security filter cleanup completed\n");
}

// Normalize a path string (no filesystem calls).
// - input: e.g. "foo/../bar//baz/./file.txt" or "/foo/bar"
// - out: normalized path without a leading slash, e.g. "bar/baz/file.txt"
// Returns 0 on success, -1 on traversal/invalid, -2 on overflow.
static int normalize_path(const char *input, char *out, size_t outlen)
{
    if (!input || !out)
        return -1;

    // Work on a writable copy
    char tmp[MAX_PATH];
    size_t in_len = strlen(input);
    if (in_len >= sizeof(tmp))
        return -2;
    strncpy(tmp, input, sizeof(tmp));
    tmp[sizeof(tmp) - 1] = '\0';

    // Remove any leading slashes for consistent joining later
    char *p = tmp;
    while (*p == '/')
        p++;

    // Split by '/', use small stack for segments
    const char *segv[128];
    int segc = 0;
    char *tok = strtok(p, "/");
    while (tok)
    {
        if (strcmp(tok, ".") == 0)
        {
            // skip
        }
        else if (strcmp(tok, "..") == 0)
        {
            if (segc == 0)
            {
                // Trying to go above document root -> traversal
                return -1;
            }
            segc--; // pop one segment
        }
        else if (tok[0] != '\0')
        {
            if (segc < (int)(sizeof(segv) / sizeof(segv[0])))
            {
                segv[segc++] = tok;
            }
            else
            {
                return -2; // too many segments
            }
        }
        tok = strtok(NULL, "/");
    }

    // join back
    size_t used = 0;
    if (segc == 0)
    {
        // root index
        if (outlen < 2)
            return -2;
        out[0] = '\0'; // empty means docroot
        return 0;
    }

    for (int i = 0; i < segc; i++)
    {
        size_t need = strlen(segv[i]) + 1; // plus '/' or '\0'
        if (i > 0)
            need++; // for separator
        if (used + need >= outlen)
            return -2;

        if (i > 0)
        {
            out[used++] = '/';
        }
        size_t seglen = strlen(segv[i]);
        memcpy(out + used, segv[i], seglen);
        used += seglen;
    }
    out[used] = '\0';
    return 0;
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
        printf("[WARNING] Failed to initialize rate limiting - running without rate limits\n");
    }

    // initialise security filters
    global_security_filter = init_security_filter();
    if (!global_security_filter)
    {
        printf("[WARNING] Failed to initialize security filter - running without security filtering\n");
    }

    // Initialize memory pools for performance optimization
    connection_pool = create_memory_pool(sizeof(client_connection_t), 100);
    if (!connection_pool)
    {
        printf("[WARNING] Failed to initialize connection memory pool - using malloc/free\n");
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
        // Use select() to make accept() interruptible
        fd_set read_fds;
        struct timeval timeout;

        FD_ZERO(&read_fds);
        FD_SET(server_fd, &read_fds);

        // Check for new connections every 1 second
        timeout.tv_sec = 1;
        timeout.tv_usec = 0;

        int select_result = select(server_fd + 1, &read_fds, NULL, NULL, &timeout);

        if (select_result < 0)
        {
            if (errno == EINTR)
                continue; // Interrupted by signal - check server_running
            perror("Select failed");
            break;
        }

        if (select_result == 0)
        {
            // Timeout - check if we should still be running
            continue;
        }

        if (!server_running)
        {
            break; // Server shutdown requested
        }

        // Accept the connection
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

        // Check thread limit to prevent resource exhaustion
        pthread_mutex_lock(&thread_count_mutex);
        int current_threads = active_thread_count;
        pthread_mutex_unlock(&thread_count_mutex);

        if (current_threads >= MAX_THREADS)
        {
            printf("[SECURITY] Thread limit reached (%d/%d) - handling client directly\n",
                   current_threads, MAX_THREADS);
            // Handle client directly without creating new thread
            handle_client(client_fd, client_addr);
            continue;
        }

        // Use threading for better performance
        client_connection_t *conn = connection_pool ? pool_allocate(connection_pool) : malloc(sizeof(client_connection_t));
        if (conn)
        {
            conn->client_fd = client_fd;
            conn->client_addr = client_addr;
            conn->connect_time = time(NULL);

            // Increment thread count before creating thread
            pthread_mutex_lock(&thread_count_mutex);
            active_thread_count++;
            pthread_mutex_unlock(&thread_count_mutex);

            pthread_t thread;
            int thread_result = pthread_create(&thread, NULL, handle_client_thread, conn);
            if (thread_result == 0)
            {
                pthread_detach(thread); // Don't wait for thread to finish
            }
            else
            {
                // Thread creation failed - decrement counter
                pthread_mutex_lock(&thread_count_mutex);
                active_thread_count--;
                pthread_mutex_unlock(&thread_count_mutex);

                printf("[ERROR] Failed to create thread: %s (error code: %d)\n",
                       strerror(thread_result), thread_result);
                handle_client(client_fd, client_addr);
                if (connection_pool)
                {
                    pool_deallocate(connection_pool, conn);
                }
                else
                {
                    free(conn);
                }
            }
        }
        else
        {
            // Fallback to direct handling if malloc fails
            handle_client(client_fd, client_addr);
        }
    }

    printf("[INFO] Server shutting down...\n");

    // Cleanup resources
    if (global_rate_limit_config)
    {
        cleanup_rate_limiting(global_rate_limit_config);
        global_rate_limit_config = NULL;
    }

    if (global_security_filter)
    {
        cleanup_security_filter(global_security_filter);
        global_security_filter = NULL;
    }

    if (connection_pool)
    {
        destroy_memory_pool(connection_pool);
        connection_pool = NULL;
    }

    close(server_fd);
    return 0;
}