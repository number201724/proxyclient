#include "defs.h"
#include "ringbuffer.h"
#include "socks5.h"
#include "tunnel.h"

extern RakNet::RakPeerInterface *rakPeer;

extern Tunnel tunnel;

packet::packet(void *_data, size_t _len)
{
    len = _len;
    data = malloc(_len);
    memcpy(data, _data, len);
}

packet::~packet()
{
    if (data)
    {
        free(data);
    }
}

socks5_tcp_close::socks5_tcp_close(socks5_client *_client) : client(_client)
{
    client->addref();
}

socks5_tcp_close::~socks5_tcp_close()
{
    client->release();
}

void socks5_tcp_close::close_cb(uv_handle_t *handle)
{
    socks5_client *client = (socks5_client *)handle->data;

    if(client->reader)
    {
        delete client->reader;
        client->reader = nullptr;
    }

    socks5_tcp_close *close = client->close;
    client->close = nullptr;
    delete close;
}

void socks5_tcp_close::close(socks5_client *client, bool doclose)
{
    if (client->stage < SOCKS5_CONN_STAGE_CLOSING)
        doclose=true;

    if(doclose)
    {
        if (!client->remote_close)
        {
            tunnel.send_close(client);
        }

        if (client->reader)
        {
            uv_read_stop((uv_stream_t *)&client->sock);
        }

        client->stage = SOCKS5_CONN_STAGE_CLOSED;
        client->close = new socks5_tcp_close(client);
        uv_close((uv_handle_t *)&client->sock, close_cb);

        tunnel.unlink_client(client);
    }
}

socks5_tcp_shutdown::socks5_tcp_shutdown(socks5_client *_client) : client(_client)
{
    client->addref();
}

socks5_tcp_shutdown::~socks5_tcp_shutdown()
{
    client->release();
}
void socks5_tcp_shutdown::shutdown_cb(uv_shutdown_t *req, int status)
{
    socks5_tcp_shutdown *pshutdown = (socks5_tcp_shutdown *)req->data;
    socks5_client *client = pshutdown->client;
    socks5_tcp_close::close(client, true);
    delete pshutdown;
}

void socks5_tcp_shutdown::shutdown(socks5_client *client)
{
    if (client->stage < SOCKS5_CONN_STAGE_CLOSING)
    {
        client->stage = SOCKS5_CONN_STAGE_CLOSING;
        socks5_tcp_shutdown *pshutdown = new socks5_tcp_shutdown(client);
        pshutdown->req.data = pshutdown;
        int code = uv_shutdown(&pshutdown->req, (uv_stream_t *)&client->sock, shutdown_cb);
        if (code)
        {
            socks5_tcp_close::close(client);
            delete pshutdown;
        }
    }
}

socks5_tcp_sender::socks5_tcp_sender(socks5_client *_client, void *data, size_t len) : client(_client)
{
    if (len == 0)
    {
        exit(EXIT_FAILURE);
    }
    buf.base = new char[len];
    buf.len = len;

    memcpy(buf.base, data, len);
    client->addref();
}

socks5_tcp_sender::~socks5_tcp_sender()
{
    if (buf.base)
    {
        delete[] buf.base;
    }

    client->release();
}

void socks5_tcp_sender::write_cb(uv_write_t *req, int status)
{
    socks5_tcp_sender *request = (socks5_tcp_sender *)req->data;
    delete request;
}

void socks5_tcp_sender::write(socks5_client *_client, void *data, size_t len)
{
    if (_client->stage < SOCKS5_CONN_STAGE_CLOSING)
    {
        if (len == 0)
        {
            _client->remote_close = true;
            socks5_tcp_shutdown::shutdown(_client);
            return;
        }

        socks5_tcp_sender *sender = new socks5_tcp_sender(_client, data, len);
        sender->request.data = sender;
        int code = uv_write(&sender->request, (uv_stream_t *)&_client->sock, &sender->buf, 1, write_cb);
        if (code != 0)
        {
            printf("write fail:%d\n", code);
            delete sender;
        }
    }
}

socks5_tcp_timeout::socks5_tcp_timeout(socks5_client *_client, int timeout, int repeat)
{
    client = _client;
    client->addref();
    timer.data = this;
    uv_timer_init(uv_default_loop(), &timer);
    uv_timer_start(&timer, timer_cb, timeout, repeat);
}

socks5_tcp_timeout::~socks5_tcp_timeout()
{
    client->release();
}

void socks5_tcp_timeout::stop()
{
    uv_timer_stop(&timer);
    uv_close((uv_handle_t *)&timer, close_cb);
}

void socks5_tcp_timeout::timer_cb(uv_timer_t *handle)
{
    socks5_tcp_timeout *ptimeout = (socks5_tcp_timeout *)handle->data;
    ptimeout->callback();
}

void socks5_tcp_timeout::close_cb(uv_handle_t *handle)
{
    socks5_tcp_timeout *ptimeout = (socks5_tcp_timeout *)handle->data;
    ptimeout->client->timeout = nullptr;
    delete ptimeout;
}

void socks5_tcp_connect_timeout::callback()
{
    socks5_client::connect_event(client);
    client->timeout = nullptr;
    stop();
}

socks5_tcp_reader::socks5_tcp_reader(socks5_client *_client) : client(_client)
{
    client->addref();
}

socks5_tcp_reader::~socks5_tcp_reader()
{
    client->release();
}

int socks5_tcp_reader::begin_read(socks5_client *client)
{
    socks5_tcp_reader *reader = new socks5_tcp_reader(client);
    client->reader = reader;
    return uv_read_start((uv_stream_t *)&client->sock, socks5_tcp_reader::alloc_cb, socks5_tcp_reader::read_cb);
}

void socks5_tcp_reader::alloc_cb(uv_handle_t *handle,
                                 size_t suggested_size,
                                 uv_buf_t *buf)
{
    socks5_client *__client = (socks5_client *)handle->data;
    buf->base = __client->reader->buf;
    buf->len = sizeof(__client->reader->buf);
}
void socks5_tcp_reader::read_cb(uv_stream_t *stream,
                                ssize_t nread,
                                const uv_buf_t *buf)
{
    unsigned char message[1024];
    socks5_client *client = (socks5_client *)stream->data;
    socks5_tcp_reader *reader = client->reader;

    if (nread == UV_EOF || nread == UV_ECANCELED)
    {
        client->reader = nullptr;
        socks5_tcp_close::close(client);
        delete reader;

        return;
    }

    if (nread < 0)
    {
        client->reader = nullptr;
        socks5_tcp_close::close(client);
        delete reader;
        return;
    }

    if (client->stage == SOCKS5_CONN_STAGE_STREAM)
    {
        tunnel.send_stream(client, buf->base, nread);
        return;
    }

    if (!client->incoming_buffers.queue(buf->base, nread))
    {
        client->reader = nullptr;
        socks5_tcp_close::close(client);
        delete reader;
        return;
    }

    while (true)
    {
        if (client->stage == SOCKS5_CONN_STAGE_EXMETHOD)
        {
            if (client->incoming_buffers.size() < sizeof(struct socks5_method_req))
            {
                return;
            }

            struct socks5_method_req method;
            if (!client->incoming_buffers.front(&method, sizeof(method)))
            {
                return;
            }

            if (method.ver != SOCKS5_VERSION)
            {
                printf("invalid socks5 version: SOCKS5_CONN_STAGE_EXMETHOD [%d]\n", method.ver);
                client->reader = nullptr;
                socks5_tcp_close::close(client);
                delete reader;
                return;
            }

            struct socks5_method_req *method_req = (struct socks5_method_req *)&message;

            if (!client->incoming_buffers.deque(method_req, sizeof(struct socks5_method_req) + method.nmethods))
                return;

            uint8_t *methods = (uint8_t *)&method_req[1];

            bool noauth_supported = false;

            for (int i = 0; i < method_req->nmethods; i++)
            {
                if (methods[i] == SOCKS5_AUTH_NOAUTH)
                {
                    noauth_supported = true;
                    break;
                }
            }

            struct socks5_method_res reply = {SOCKS5_VERSION, SOCKS5_AUTH_NOACCEPTABLE};

            if (noauth_supported)
            {
                reply.method = SOCKS5_AUTH_NOAUTH;
            }

            socks5_tcp_sender::write(client, &reply, sizeof(reply));

            if (reply.method == SOCKS5_AUTH_NOACCEPTABLE)
            {
                socks5_tcp_shutdown::shutdown(client);
                return;
            }

            client->stage = SOCKS5_CONN_STAGE_EXHOST;
        }

        if (client->stage == SOCKS5_CONN_STAGE_EXHOST)
        {
            if (client->incoming_buffers.size() < sizeof(struct socks5_request))
            {
                return;
            }

            struct socks5_request request;
            if (!client->incoming_buffers.front(&request, sizeof(request)))
            {
                return;
            }

            if (request.ver != SOCKS5_VERSION)
            {
                printf("invalid socks5 version: SOCKS5_CONN_STAGE_EXHOST [%d]\n", request.ver);
                client->reader = nullptr;
                socks5_tcp_close::close(client);
                delete reader;
                return;
            }

            if (request.cmd == SOCKS5_CMD_CONNECT)
            {

                client->resp_status = SOCKS5_RESPONSE_SERVER_FAILURE;
                if (request.addrtype == SOCKS5_ADDRTYPE_IPV4)
                {
                    struct socks5_ipv4_addr addr = {0};

                    if (client->incoming_buffers.size() < sizeof(struct socks5_request) + sizeof(struct socks5_ipv4_addr))
                    {
                        return;
                    }

                    client->incoming_buffers.pop(sizeof(struct socks5_request));
                    client->incoming_buffers.deque(&addr, sizeof(addr));

                    memcpy(&client->remote_addr.v4.sin_addr, &addr.ip, sizeof(addr.ip));
                    client->remote_addr.v4.sin_port = addr.port;
                    client->remote_addrtype = request.addrtype;
                    client->bnd_addrtype = client->remote_addrtype;
                    client->bnd_addr = client->remote_addr;
                    client->stage = SOCKS5_CONN_STAGE_CONNECTING;


                    tunnel.link_client(client);
                    tunnel.request_connect(client);

                }
                else if (request.addrtype == SOCKS5_ADDRTYPE_IPV6)
                {
                    struct socks5_ipv6_addr addr = {0};

                    if (client->incoming_buffers.size() < sizeof(struct socks5_request) + sizeof(struct socks5_ipv6_addr))
                    {
                        return;
                    }

                    client->incoming_buffers.pop(sizeof(struct socks5_request));
                    client->incoming_buffers.deque(&addr, sizeof(addr));

                    memcpy(&client->remote_addr.v6.sin6_addr, &addr.ip, sizeof(addr.ip));
                    client->remote_addr.v4.sin_port = addr.port;
                    client->remote_addrtype = request.addrtype;
                    client->bnd_addrtype = client->remote_addrtype;
                    client->bnd_addr = client->remote_addr;
                    client->stage = SOCKS5_CONN_STAGE_CONNECTING;

                    tunnel.link_client(client);
                    tunnel.request_connect(client);
                }
                else if (request.addrtype == SOCKS5_ADDRTYPE_DOMAIN)
                {
                    struct
                    {
                        struct socks5_request request;
                        unsigned char len;
                    } domain_header;

                    uint16_t port;

                    if (client->incoming_buffers.size() < sizeof(domain_header))
                    {
                        return;
                    }

                    client->incoming_buffers.front(&domain_header, sizeof(domain_header));

                    if (client->incoming_buffers.size() < sizeof(domain_header) + domain_header.len + sizeof(uint16_t))
                    {
                        return;
                    }

                    client->incoming_buffers.pop(sizeof(domain_header));
                    client->incoming_buffers.deque(&client->remote_addr.domain, domain_header.len);
                    client->incoming_buffers.deque(&port, sizeof(port));
                    client->remote_addr.domain.domain[domain_header.len] = 0;
                    client->remote_addr.domain.port = port;
                    client->remote_addrtype = request.addrtype;
                    client->bnd_addrtype = client->remote_addrtype;
                    client->bnd_addr = client->remote_addr;
                    client->stage = SOCKS5_CONN_STAGE_CONNECTING;

                    tunnel.link_client(client);
                    tunnel.request_connect(client);
                }
                else
                {
                    client->reader = nullptr;
                    socks5_tcp_close::close(client);
                    delete reader;
                    return;
                }

                //check if connect successfully
                if (client->stage == SOCKS5_CONN_STAGE_CONNECTING || client->stage == SOCKS5_CONN_STAGE_CONNECTED)
                {
                    client->timeout = new socks5_tcp_connect_timeout(client, 20000, 0);
                    return;
                }
            }

            if (request.cmd == SOCKS5_CMD_BIND)
            {
                printf("SOCKS5_CMD_BIND\n");
            }

            if (request.cmd == SOCKS5_CMD_UDPASSOCIATE)
            {
                printf("SOCKS5_CMD_UDPASSOCIATE\n");
            }

            continue;
        }

        if (client->stage == SOCKS5_CONN_STAGE_STREAM)
        {
            if (!client->incoming_buffers.empty())
            {
                unsigned char tempbuf[FRAGMENT_LEN];
                int len = (int)client->incoming_buffers.size();
                client->incoming_buffers.deque(tempbuf, client->incoming_buffers.size());
                tunnel.send_stream(client, tempbuf, len);
            }
        }

        break;
    }
}

socks5_client::socks5_client()
{
    remote_close = false;
    guid = rakPeer->Get64BitUniqueRandomNumber();
    reader = nullptr;
    close = nullptr;
    shutdown = nullptr;
    timeout = nullptr;
}

socks5_client::~socks5_client()
{
}

void socks5_client::connect_event(socks5_client *client)
{
    char message[512];

    struct socks5_response *reply = (struct socks5_response *)&message;
    reply->ver = SOCKS5_VERSION;
    reply->rep = client->resp_status;
    reply->rsv = 0;
    reply->addrtype = client->bnd_addrtype;

    size_t len = sizeof(struct socks5_response);

    if (reply->addrtype == SOCKS5_ADDRTYPE_IPV4)
    {
        memcpy(&message[4], &client->bnd_addr.v4.sin_addr, sizeof(client->bnd_addr.v4.sin_addr));
        memcpy(&message[8], &client->bnd_addr.v4.sin_port, sizeof(client->bnd_addr.v4.sin_port));

        len += sizeof(client->bnd_addr.v4.sin_addr) + sizeof(client->bnd_addr.v4.sin_port);
    }

    if (reply->addrtype == SOCKS5_ADDRTYPE_IPV6)
    {
        memcpy(&message[4], &client->bnd_addr.v6.sin6_addr, sizeof(client->bnd_addr.v6.sin6_addr));
        memcpy(&message[4 + sizeof(client->bnd_addr.v6.sin6_addr)], &client->bnd_addr.v6.sin6_port, sizeof(client->bnd_addr.v6.sin6_port));
        len += sizeof(client->bnd_addr.v6.sin6_addr) + sizeof(client->bnd_addr.v6.sin6_port);
    }

    if (reply->addrtype == SOCKS5_ADDRTYPE_DOMAIN)
    {
        message[4] = strlen(client->bnd_addr.domain.domain);
        memcpy(&message[5], client->bnd_addr.domain.domain, message[4]);

        len += sizeof(char) + message[4];
    }

    socks5_tcp_sender::write(client, reply, len);

    if (client->stage != SOCKS5_CONN_STAGE_CONNECTED)
    {
        socks5_tcp_shutdown::shutdown(client);
        return;
    }

    client->stage = SOCKS5_CONN_STAGE_STREAM;

    if (!client->incoming_buffers.empty())
    {
        unsigned char tempbuf[FRAGMENT_LEN];
        int len = (int)client->incoming_buffers.size();
        client->incoming_buffers.deque(tempbuf, client->incoming_buffers.size());
        tunnel.send_stream(client, tempbuf, len);
    }
}

socks5_server::socks5_server()
{
}

socks5_server::~socks5_server()
{
}

void socks5_server::connection_cb(uv_stream_t *server, int status)
{
    int code;
    if (status == UV_ECANCELED)
    {
        return;
    }

    socks5_client *client = new socks5_client();

    if (client == nullptr)
    {
        printf("new socks5_client failed\n");
        exit(EXIT_FAILURE);
    }

    if (status != 0)
    {
        printf("connection_cb status != 0\n");
        exit(EXIT_FAILURE);
    }

    code = uv_tcp_init(uv_default_loop(), &client->sock);
    if (code != 0)
    {
        printf("connection_cb uv_tcp_init failed\n");
        exit(EXIT_FAILURE);
    }

    client->sock.data = client;

    code = uv_accept(server, (uv_stream_t *)&client->sock);
    if (code != 0)
    {
        printf("connection_cb uv_accept failed\n");
        exit(EXIT_FAILURE);
    }

    client->stage = SOCKS5_CONN_STAGE_EXMETHOD;

    code = socks5_tcp_reader::begin_read(client);
    if (code != 0)
    {
        printf("connection_cb begin_read failed\n");
        exit(EXIT_FAILURE);
    }

    client->release();
}

void socks5_server::start(const char *host, unsigned short port, int flags)
{
    int code;
    char str_port[32];
    struct addrinfo hints;
    struct addrinfo *pres;
    struct sockaddr_in addr;

    memset(&hints, 0, sizeof(struct addrinfo));
    hints.ai_family = AF_UNSPEC;
    hints.ai_flags = AI_PASSIVE;
    hints.ai_protocol = 0;
    hints.ai_socktype = 0;

    code = uv_tcp_init(uv_default_loop(), &_tcp);

    if (code)
    {
        printf("tcp init failed.\n");
        exit(EXIT_FAILURE);
    }

    sprintf(str_port, "%d", port);
    code = getaddrinfo(host, str_port, &hints, &pres);
    if (code != 0)
    {
        printf("socks5 server getaddrinfo failed...\n");
        exit(EXIT_FAILURE);
    }

    for (auto p = pres; p != nullptr; p = p->ai_next)
    {
        if (p->ai_addr->sa_family == AF_INET)
        {
            addr = *(struct sockaddr_in *)p->ai_addr;
            break;
        }
    }

    freeaddrinfo(pres);

    code = uv_tcp_bind(&_tcp, (struct sockaddr *)&addr, sizeof(addr));
    if (code)
    {
        printf("tcp bind faield.\n");
        exit(EXIT_FAILURE);
    }

    _tcp.data = this;
    code = uv_listen((uv_stream_t *)&_tcp, SOMAXCONN, connection_cb);

    if (code)
    {
        printf("tcp listen faield.\n");
        exit(EXIT_FAILURE);
    }
}
