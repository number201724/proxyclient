#ifndef _SOCKS5_H_
#define _SOCKS5_H_

#define SOCKS5_ALLOW_TCP (1 << 0)
#define SOCKS5_ALLOW_UDP (1 << 1)
class socks5_server;

struct domainaddr
{
    char domain[256];
    uint16_t port;
};

typedef union {
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

class packet
{
public:
    packet(void *_data, size_t _len);
    ~packet();

    void *data;
    size_t len;
};

class socks5_client
{
public:
    socks5_client(sock_t fd);
    ~socks5_client();

    uint64_t guid;
    RakNet::SignaledEvent event;
    ringbuffer incoming_buffers;
    std::queue<packet *> outgoing_buffers;
    sock_t sock;
    int stage;
    unsigned char resp_status;
    unsigned char bnd_addrtype;
    socks5_addr bnd_addr;
    unsigned char remote_addrtype;
    socks5_addr remote_addr;

    void lock();
    void unlock();

private:
    std::mutex _lock;
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