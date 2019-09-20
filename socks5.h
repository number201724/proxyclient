#ifndef _SOCKS5_H_
#define _SOCKS5_H_

#pragma pack(1)

// socks5 version
#define SOCKS5_VERSION 0x05

// socks5 reserved
#define SOCKS5_RSV 0x00

// socks5 auth method
#define SOCKS5_AUTH_NOAUTH 0x00
#define SOCKS5_AUTH_USERNAMEPASSWORD 0x02
#define SOCKS5_AUTH_NOACCEPTABLE 0xff

struct socks5_method_req
{
    uint8_t ver;
    uint8_t nmethods;
    // uint8_t methods[0];
};

struct socks5_method_res
{
    uint8_t ver;
    uint8_t method;
};

// socks5 command
#define SOCKS5_CMD_CONNECT 0x01
#define SOCKS5_CMD_BIND 0x02
#define SOCKS5_CMD_UDPASSOCIATE 0x03

// socks5 address type
#define SOCKS5_ADDRTYPE_IPV4 0x01
#define SOCKS5_ADDRTYPE_DOMAIN 0x03
#define SOCKS5_ADDRTYPE_IPV6 0x04

struct socks5_ipv4_addr
{
    uint32_t ip;
    uint16_t port;
};

struct socks5_ipv6_addr
{
    unsigned char ip[16];
    uint16_t port;
};

struct socks5_request
{
    uint8_t ver;
    uint8_t cmd;
    uint8_t rsv;
    uint8_t addrtype;
};

// socks5 response status
#define SOCKS5_RESPONSE_SUCCESS 0x00
#define SOCKS5_RESPONSE_SERVER_FAILURE 0x01
#define SOCKS5_RESPONSE_CONNECTION_NOT_ALLOWED 0x02
#define SOCKS5_RESPONSE_NETWORK_UNREACHABLE 0x03
#define SOCKS5_RESPONSE_HOST_UNREACHABLE 0x04
#define SOCKS5_RESPONSE_CONNECTION_REFUSED 0x05
#define SOCKS5_RESPONSE_TTL_EXPIRED 0x06
#define SOCKS5_RESPONSE_COMMAND_NOT_SUPPORTED 0x07
#define SOCKS5_RESPONSE_ADDRTYPE_NOT_SUPPORTED 0x08

struct socks5_response
{
    uint8_t ver;
    uint8_t rep;
    uint8_t rsv;
    uint8_t addrtype;
};

#define SOCKS5_AUTH_USERNAMEPASSWORD_VER 0x01

#define SOCKS5_AUTH_USERNAMEPASSWORD_MAX_LEN 256
struct socks5_userpass_req
{
    uint8_t ver;
    uint8_t ulen;
    char username[SOCKS5_AUTH_USERNAMEPASSWORD_MAX_LEN];
    uint8_t plen;
    char password[SOCKS5_AUTH_USERNAMEPASSWORD_MAX_LEN];
};

#define SOCKS5_AUTH_USERNAMEPASSWORD_STATUS_OK 0x00
#define SOCKS5_AUTH_USERNAMEPASSWORD_STATUS_FAIL 0x01
struct socks5_userpass_res
{
    uint8_t ver;
    uint8_t status;
};

#pragma pack()

#define SOCKS5_ALLOW_TCP (1 << 0)
#define SOCKS5_ALLOW_UDP (1 << 1)
class socks5_server;

struct domainaddr
{
    char domain[256];
    uint16_t port;
};

typedef union  {
    struct sockaddr_in v4;
    struct sockaddr_in6 v6;
    struct domainaddr domain;
} socks5_addr;

#define SOCKS5_CONN_STAGE_EXMETHOD 0
#define SOCKS5_CONN_STAGE_EXHOST 1
#define SOCKS5_CONN_STAGE_CONNECTING 2
#define SOCKS5_CONN_STAGE_CONNECTED 3
#define SOCKS5_CONN_STAGE_STREAM 4
#define SOCKS5_CONN_STAGE_CLOSING 5
#define SOCKS5_CONN_STAGE_CLOSED 6

class socks5_client
{
public:
    socks5_client(sock_t fd);
    ~socks5_client();

    uint64_t guid;
    RakNet::SignaledEvent event;

    ringbuffer incoming_buffers;
    ringbuffer outgoing_buffers;
    sock_t sock;
    int stage;
    std::mutex lock;

    int resp_status;

    int bnd_addrtype;
    socks5_addr bnd_addr;

    int remote_addrtype;
    socks5_addr remote_addr;
};

class socks5_server
{
public:
    socks5_server();
    ~socks5_server();

    bool start(const char *host, unsigned short port, int flags = SOCKS5_ALLOW_TCP | SOCKS5_ALLOW_UDP);
    void tcp_client_proc(std::shared_ptr<socks5_client> client);
    void accept_thrd_proc();
    void udp_thrd_proc();
    sock_t _tcp_fd;
    sock_t _udp_fd;
};

#endif