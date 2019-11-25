#ifndef _SOCKS5_H_
#define _SOCKS5_H_

#define SOCKS5_ALLOW_TCP (1 << 0)
#define SOCKS5_ALLOW_UDP (1 << 1)
class socks5_server;

class reference_object
{
public:
    reference_object()
    {
        _refcnt = 1;
    }
    virtual ~reference_object() {}
    virtual int64_t addref()
    {
#ifdef _WIN32
		return InterlockedIncrement64(&_refcnt);
#else
		return __sync_add_and_fetch(&_refcnt, 1);
#endif
    }

    virtual int64_t release()
    {
#ifdef _WIN32
		int64_t refcnt = InterlockedDecrement64(&_refcnt);
#else
		int64_t refcnt = __sync_sub_and_fetch(&_refcnt, 1);
#endif
        if (refcnt == 0)
        {
            delete this;
        }

        return refcnt;
    }

public:
    int64_t _refcnt;
};

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
class socks5_tcp_reader;
class socks5_tcp_close;
class socks5_tcp_shutdown;
class socks5_tcp_timeout;

class socks5_client : public reference_object
{
private:
    virtual ~socks5_client();

public:
    socks5_client();

    uint64_t guid;
    ringbuffer incoming_buffers;
    int stage;
    unsigned char resp_status;
    unsigned char bnd_addrtype;
    socks5_addr bnd_addr;
    unsigned char remote_addrtype;
    socks5_addr remote_addr;
    socks5_tcp_reader *reader;
    socks5_tcp_close *close;
    socks5_tcp_shutdown *shutdown;
    socks5_tcp_timeout *timeout;
    uv_tcp_t sock;
    bool remote_close;

    static void connect_event(socks5_client *client);
};

class socks5_tcp_timeout
{
public:
    socks5_tcp_timeout(socks5_client *_client, int timeout, int repeat);
    virtual ~socks5_tcp_timeout();
    virtual void callback() = 0;

    void stop();

    static void close_cb(uv_handle_t *handle);
    static void timer_cb(uv_timer_t *handle);
    socks5_client *client;

private:
    void close();

    uv_timer_t timer;
};

class socks5_tcp_connect_timeout : public socks5_tcp_timeout
{
public:
    socks5_tcp_connect_timeout(socks5_client *_client, int timeout, int repeat) : socks5_tcp_timeout(_client, timeout, repeat)
    {
    }
    virtual void callback();
};

class socks5_tcp_close
{
public:
    socks5_tcp_close(socks5_client *_client);
    ~socks5_tcp_close();
    static void close_cb(uv_handle_t *handle);
    static void close(socks5_client *client, bool forcemode = false);
    socks5_client *client;
};

class socks5_tcp_shutdown
{
public:
    socks5_tcp_shutdown(socks5_client *_client);
    ~socks5_tcp_shutdown();
    static void shutdown_cb(uv_shutdown_t *req, int status);
    static void shutdown(socks5_client *client);

    socks5_client *client;
    uv_shutdown_t req;
};

class socks5_tcp_reader
{
public:
    socks5_tcp_reader(socks5_client *client);
    ~socks5_tcp_reader();

    static int begin_read(socks5_client *_client);

    static void alloc_cb(uv_handle_t *handle,
                         size_t suggested_size,
                         uv_buf_t *buf);
    static void read_cb(uv_stream_t *stream,
                        ssize_t nread,
                        const uv_buf_t *buf);

    socks5_client *client;
    char buf[0x10000];
};

class socks5_tcp_sender
{
public:
    socks5_tcp_sender(socks5_client *_client, void *data, size_t len);
    ~socks5_tcp_sender();

    static void write(socks5_client *_client, void *data, size_t len);
    static void write_cb(uv_write_t *req, int status);
    socks5_client *client;
    uv_write_t request;
    uv_buf_t buf;
};

class socks5_server
{
public:
    socks5_server();
    ~socks5_server();

    void start(const char *host, unsigned short port, int flags = SOCKS5_ALLOW_TCP | SOCKS5_ALLOW_UDP);

    static void connection_cb(uv_stream_t *server, int status);

    uv_tcp_t _tcp;
};

#endif
