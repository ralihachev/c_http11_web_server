# Custom C Web Server

A high-performance HTTP/1.1 web server implementation written from scratch in C, featuring multi-threading, keep-alive connections, and comprehensive error handling.

## Features

- **HTTP/1.1 Protocol Support**: Full implementation with keep-alive connections
- **Multi-threaded Architecture**: Concurrent client handling using POSIX threads
- **MIME Type Detection**: Automatic content-type detection for various file formats
- **Robust Error Handling**: Proper HTTP status codes (200, 404, 400, 500)
- **Security Features**: URL decoding, path validation, and signal handling
- **Performance Optimizations**: Socket options tuning and efficient file serving

## Architecture Overview

The server is organized into several logical layers:

### 1. Network Layer (`webserver.c:111-190`)
- **Socket Management**: Creation, binding, and listening with proper error handling
- **Connection Handling**: Accept incoming connections with configurable backlog
- **Socket Options**: Buffer size optimization, address reuse, and keep-alive settings

### 2. Threading Layer (`webserver.c:192-199`, `webserver.c:651-694`)
- **Thread Pool**: Dynamic thread creation for each client connection
- **Resource Management**: Automatic cleanup and thread detachment
- **Concurrency Control**: Thread-safe operations with proper synchronization

### 3. HTTP Protocol Layer (`webserver.c:304-359`)
- **Request Parsing**: Complete HTTP request line and header processing
- **Keep-Alive Detection**: Connection persistence based on HTTP version and headers
- **Method Support**: GET, HEAD, and POST method handling

### 4. MIME Type System (`webserver.c:44-59`, `webserver.c:536-553`)
- **Content Type Detection**: File extension to MIME type mapping
- **Supported Formats**: 
  - Web: HTML, CSS, JavaScript, JSON
  - Images: PNG, JPEG, GIF, SVG, ICO
  - Documents: PDF, ZIP, plain text
  - Default: application/octet-stream

### 5. File Serving Layer (`webserver.c:453-496`)
- **File System Access**: Safe file operations with proper validation
- **Content Delivery**: Efficient file reading and transmission
- **Error Handling**: File not found, permission, and I/O error management

### 6. Response Generation Layer (`webserver.c:385-533`)
- **HTTP Response Format**: Standards-compliant response headers and body
- **Status Code Management**: Appropriate error responses with HTML content
- **Safe Transmission**: Partial send handling and network error recovery

### 7. Utility Layer (`webserver.c:555-598`)
- **URL Decoding**: Percent-encoding and plus-space conversion
- **Time Formatting**: HTTP-compliant GMT timestamp generation
- **Signal Handling**: Graceful shutdown and process cleanup

## Project Structure

```
c_web_server/
├── webserver.c       # Main server implementation (699 lines)
├── webserver         # Compiled binary
├── index.html        # Default homepage with server info
├── test.html         # Test page with POST form
├── style.css         # Styling for web pages
├── script.js         # Client-side JavaScript
└── data.json         # JSON test data
```

## Configuration Constants

| Constant | Value | Purpose |
|----------|-------|---------|
| `PORT` | 3000 | Default server port |
| `BUFFER_SIZE` | 8192 | I/O buffer size |
| `MAX_PATH` | 512 | Maximum file path length |
| `MAX_HEADERS` | 20 | Maximum HTTP headers per request |
| `MAX_HEADER_SIZE` | 512 | Maximum header value size |
| `MAX_CONNECTIONS` | 50 | Listen queue backlog |

## Data Structures

### `http_request_t`
Complete HTTP request representation with method, path, version, headers, and body.

### `client_connection_t`
Client connection tracking with socket descriptor, address, and timestamp.

### `mime_type_t`
File extension to MIME type mapping structure.

### `http_header_t`
Individual HTTP header with name-value pairs.

## Compilation

```bash
gcc -o webserver webserver.c -pthread
```

## Usage

### Basic Usage
```bash
./webserver
```
Server starts on port 3000: http://localhost:3000

### Custom Port
```bash
./webserver 8080
```
Server starts on specified port: http://localhost:8080

### Graceful Shutdown
Press `Ctrl+C` to stop the server gracefully.

## Supported HTTP Methods

- **GET**: Retrieve files from the server
- **HEAD**: Get response headers without body content
- **POST**: Send data to server (basic acknowledgment response)

## Error Handling

The server provides comprehensive error responses:

- **400 Bad Request**: Malformed HTTP requests
- **404 Not Found**: Missing files or resources
- **500 Internal Server Error**: Server-side errors (file I/O, etc.)

## Performance Features

- **Keep-Alive Connections**: Reduces connection overhead for multiple requests
- **Multi-threading**: Concurrent handling of multiple clients
- **Optimized Socket Options**: Enhanced buffer sizes and connection reuse
- **Efficient File I/O**: Chunked reading and safe transmission protocols

## Security Considerations

- URL decoding prevents path traversal attacks
- File type validation ensures only regular files are served
- Signal handling prevents zombie processes
- Broken pipe signals are properly ignored
- Input validation on all user-provided data

## Test Files

The project includes several test files to demonstrate functionality:

- `index.html`: Homepage showcasing server capabilities
- `test.html`: Form testing with POST method support
- `style.css`: CSS styling demonstration
- `script.js`: JavaScript file serving
- `data.json`: JSON content type handling

## HTTP Protocol Compliance Analysis

This server implements **4 out of 7** core HTTP protocol layers (~60-70% compliance):

### ✅ **Implemented Layers**
- ~~**HTTP Message Layer** (`webserver.c:304-359`)~~ - Request/response parsing, headers, body handling
- ~~**HTTP Method Layer** (`webserver.c:241-290`)~~ - GET, HEAD, POST support with validation
- ~~**HTTP Status Layer** (`webserver.c:499-533`)~~ - 200, 400, 404, 500 status codes
- ~~**Connection Management** (`webserver.c:238-297`)~~ - HTTP/1.1 keep-alive, persistent connections

### 🔄 **Partially Implemented**
- **Content-Type Layer** - ~~MIME detection~~ but missing content negotiation
- **HTTP Headers** - ~~Basic parsing/generation~~ but missing advanced headers

### ❌ **Missing Layers**
- [ ] **Content Encoding Layer** - Compression (gzip, deflate), chunked transfer
- [ ] **Caching Layer** - Cache-Control, ETag, Last-Modified, conditional requests
- [ ] **Security/Auth Layer** - HTTPS/TLS, authentication, CORS, security headers

### 🚧 **Future Enhancement Opportunities**
- [ ] Range requests for partial content (`Range: bytes=0-1023`)
- [ ] Content negotiation (`Accept`, `Accept-Language` headers)  
- [ ] Request/response compression for bandwidth optimization
- [ ] Conditional requests (`If-Modified-Since`, `If-None-Match`)
- [ ] WebSocket upgrade capability
- [ ] HTTP/2 or HTTP/3 protocol support
- [ ] SSL/TLS encryption layer
- [ ] Authentication mechanisms (Basic, Digest, Bearer)
- [ ] CORS headers for cross-origin requests
- [ ] Security headers (HSTS, CSP, X-Frame-Options)

## Technical Implementation Notes

- Uses POSIX threads (`pthread`) for concurrency
- Implements proper HTTP/1.1 keep-alive semantics
- Handles partial sends for large files
- Graceful error recovery and client disconnection
- Standards-compliant HTTP response formatting
- GMT timezone for all HTTP date headers

This web server demonstrates low-level network programming concepts, HTTP protocol implementation, and system programming best practices in C.