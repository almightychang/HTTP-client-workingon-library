#ifndef __HTTPC_API_H
#define __HTTPC_API_H


#define HTTP_POST   "POST"
#define HTTP_PUT    "PUT"
#define HTTP_GET    "GET"

#define HTTPC_REQ_BASIC \
"%s %s HTTP/1.1\r\n" /* REQ, URI */ \
"User-Agent: lwIP\r\n" \
"Content-Type: application/json\r\n" /* Content-Type */ \
"Accept: */*\r\n" \
"Content-Length: %d\r\n\r\n" /* Content-Length */ \

#define HTTPC_REQ_HOST \
"%s %s HTTP/1.1\r\n" /* REQ, URI */ \
"Host: %s\r\n" \
"User-Agent: lwIP\r\n" \
"Content-Type: application/json\r\n" \
"Accept: */*\r\n" \
"Content-Length: %d\r\n\r\n" /* Content-Length */ \


#endif /* __HTTPC_API_H */
