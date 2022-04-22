#include "httpc.h"


typedef enum ehttpc_parse_state {
    HTTPC_PARSE_WAIT_FIRST_LINE = 0,
    HTTPC_PARSE_WAIT_HEADERS,
    HTTPC_PARSE_RX_DATA
} httpc_parse_state_t;

typedef struct _httpc_state {
    struct altcp_pcb* pcb;
    ip_addr_t remote_addr;
    u16_t remote_port;
    int timeout_ticks;
    struct pbuf *request;
    struct pbuf *rx_hdrs;
    u16_t rx_http_version;
    u16_t rx_status;
    altcp_recv_fn recv_fn;
    const httpc_connection_t *conn_settings;
    void* callback_arg;
    u32_t rx_content_len;
    u32_t hdr_content_len;
    httpc_parse_state_t parse_state;
} httpc_state_t;


/*
http_parse_response_status :
    - Parse start-line of HTTP response header
    - Pass http version, status, status string
    - Return ERR_OK if valid
*/
static err_t
http_parse_response_status(struct pbuf *p, u16_t *http_version, u16_t *http_status, u16_t *http_status_str_offset)
{
    u16_t end1 = pbuf_memfind(p, "\r\n", 2, 0);
    if(end1 == 0xFFFF) return ERR_VAL;

    /* Search HTTP/x.y segment */
    u16_t space1, space2;
    space1 = pbuf_memfind(p, " ", 1, 0);
    if(space1 == 0xFFFF) return ERR_VAL;

    /* Parse HTTP/x.y format in segment 1 */
    if(pbuf_memcmp(p, 0, "HTTP/", 5) != 0) return ERR_VAL;
    if(pbuf_get_at(p, 6) != '.') return ERR_VAL;

    /* Parse HTTP/x.y version */
    u16_t version = pbuf_get_at(p, 5) - '0';
    version <<= 8;
    version |= pbuf_get_at(p, 7) - '0';
    *http_version = version;

    /* Parse HTTP status number */
    char status_num[10];
    size_t status_num_len;
    space2 = pbuf_memfind(p, " ", 1, space1 + 1);
    if(space2 != 0xFFFF)
    {
        *http_status_str_offset = space2 + 1;
        status_num_len = space2 - space1 - 1;
    }
    else
    {
        status_num_len = end1 - space1 - 1;
    }

    memset(status_num, 0, sizeof(status_num));
    if(pbuf_copy_partial(p, status_num, (u16_t)status_num_len, space1 + 1) == status_num_len)
    {
        int status = atoi(status_num);
        if ((status > 0) && (status <= 0xFFFF))
        {
            *http_status = (u16_t)status;
            return ERR_OK;
        }
    }

    return ERR_VAL;
}

/*
http_wait_headers :
    - Check all headers are received
    - Pass length and content-length if available
    - Return ERR_OK if all headers are received and valid
*/
static err_t
http_wait_headers(struct pbuf *p, u32_t *content_length, u16_t *total_header_len)
{
    /* Check all headers are received */
    u16_t end1 = pbuf_memfind(p, "\r\n\r\n", 4, 0);
    if (end1 >= (0xFFFF - 2)) return ERR_VAL;

    /* Check if we have a content length (@todo: case insensitive?) */
    u16_t content_len_hdr;
    *content_length = HTTPC_CONTENT_LEN_INVALID;
    *total_header_len = end1 + 4;

    content_len_hdr = pbuf_memfind(p, "Content-Length: ", 16, 0);
    if(content_len_hdr != 0xFFFF)
    {
        u16_t content_len_line_end = pbuf_memfind(p, "\r\n", 2, content_len_hdr);
        if(content_len_line_end != 0xFFFF)
        {
            char content_len_num[16];
            u16_t content_len_num_len = (u16_t)(content_len_line_end - content_len_hdr - 16);
            memset(content_len_num, 0, sizeof(content_len_num));
            if(pbuf_copy_partial(p, content_len_num, content_len_num_len, content_len_hdr + 16)
                == content_len_num_len)
            {
                int len = atoi(content_len_num);
                if ((len >= 0) && ((u32_t)len < HTTPC_CONTENT_LEN_INVALID))
                {
                    *content_length = (u32_t)len;
                }
            }
        }
    }
    return ERR_OK;
}
