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

socks5_client::socks5_client(sock_t fd)
{
    sock = fd;
    guid = rakPeer->Get64BitUniqueRandomNumber();
    event.InitEvent();
}

socks5_client::~socks5_client()
{
    event.CloseEvent();
}

void socks5_client::lock()
{
    _lock.lock();
}

void socks5_client::unlock()
{
    _lock.unlock();
}

socks5_server::socks5_server()
{
}

socks5_server::~socks5_server()
{
}

void socks5_server::tcp_client_proc(std::shared_ptr<socks5_client> client)
{
    unsigned char buf[4096];
    int len;
    int nfds;
    fd_set readfds, writefds, exceptfds;
    struct timeval timeout;

    client->stage = SOCKS5_CONN_STAGE_EXMETHOD;

    timeout.tv_sec = 0;
    timeout.tv_usec = 0;
    while (true)
    {
        FD_ZERO(&readfds);
        FD_ZERO(&writefds);
        FD_ZERO(&exceptfds);

        FD_SET(client->sock, &readfds);

        client->lock();
        if (!client->outgoing_buffers.empty())
        {
            FD_SET(client->sock, &writefds);
        }
        client->unlock();

        FD_SET(client->sock, &exceptfds);

        nfds = client->sock + 1;

        select(nfds, &readfds, &writefds, &exceptfds, &timeout);

        if (FD_ISSET(client->sock, &exceptfds))
        {
            printf("socket closed.\n");
            break;
        }

        if (FD_ISSET(client->sock, &writefds))
        {
            packet *sendpacket = nullptr;

            client->lock();

            if (!client->outgoing_buffers.empty())
            {
                sendpacket = client->outgoing_buffers.front();
                client->outgoing_buffers.pop();
            }

            client->unlock();

            if (sendpacket)
            {
                len = send(client->sock, sendpacket->data, sendpacket->len, 0);

                delete sendpacket;
            }

            // printf("send packets\n");
        }

        if (FD_ISSET(client->sock, &readfds))
        {
            len = recv(client->sock, buf, sizeof(buf), 0);
            if (len <= 0)
            {
                break;
            }

            if (client->stage == SOCKS5_CONN_STAGE_STREAM)
            {
                tunnel.send_stream(client, buf, len);
                continue;
            }

            if (!client->incoming_buffers.queue(buf, len))
            {
                printf("incoming_buffers overflow\n");
                break;
            }

        readnext:

            if (client->stage == SOCKS5_CONN_STAGE_EXMETHOD)
            {
                if (client->incoming_buffers.size() < sizeof(struct socks5_method_req))
                {
                    continue;
                }

                struct socks5_method_req method;
                if (!client->incoming_buffers.front(&method, sizeof(method)))
                {
                    continue;
                }

                if (method.ver != SOCKS5_VERSION)
                {
                    printf("invalid socks5 version: SOCKS5_CONN_STAGE_EXMETHOD [%d]\n", method.ver);
                    break;
                }

                struct socks5_method_req *method_req = (struct socks5_method_req *)&buf;

                if (!client->incoming_buffers.deque(method_req, sizeof(struct socks5_method_req) + method.nmethods))
                    continue;

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

                send(client->sock, &reply, sizeof(reply), 0);

                if (reply.method == SOCKS5_AUTH_NOACCEPTABLE)
                {
                    shutdown(client->sock, SHUT_WR);
                    break;
                }

                client->stage = SOCKS5_CONN_STAGE_EXHOST;

                goto readnext;
            }

            if (client->stage == SOCKS5_CONN_STAGE_EXHOST)
            {
                if (client->incoming_buffers.size() < sizeof(struct socks5_request))
                {
                    continue;
                }

                struct socks5_request request;
                if (!client->incoming_buffers.front(&request, sizeof(request)))
                {
                    continue;
                }

                if (request.ver != SOCKS5_VERSION)
                {
                    printf("invalid socks5 version: SOCKS5_CONN_STAGE_EXHOST [%d]\n", request.ver);
                    break;
                }

                if (request.cmd == SOCKS5_CMD_CONNECT)
                {

                    client->resp_status = SOCKS5_RESPONSE_SERVER_FAILURE;
                    if (request.addrtype == SOCKS5_ADDRTYPE_IPV4)
                    {
                        struct socks5_ipv4_addr addr = {0};

                        if (client->incoming_buffers.size() < sizeof(struct socks5_request) + sizeof(struct socks5_ipv4_addr))
                        {
                            continue;
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
                            continue;
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
                            continue;
                        }

                        client->incoming_buffers.front(&domain_header, sizeof(domain_header));

                        if (client->incoming_buffers.size() < sizeof(domain_header) + domain_header.len + sizeof(uint16_t))
                        {
                            continue;
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
                        printf("SOCKS5_ADDRTYPE_UNKNOWN\n");
                        break;
                    }

                    //check if connect successfully
                    if (client->stage == SOCKS5_CONN_STAGE_CONNECTING || client->stage == SOCKS5_CONN_STAGE_CONNECTED)
                    {
                        client->event.WaitOnEvent(5000);
                        struct socks5_response *reply = (struct socks5_response *)buf;
                        reply->ver = SOCKS5_VERSION;
                        reply->rep = client->resp_status;
                        reply->rsv = 0;
                        reply->addrtype = client->bnd_addrtype;

                        len = sizeof(struct socks5_response);

                        printf("reply->addrtype:%d\n", reply->addrtype);

                        if (reply->addrtype == SOCKS5_ADDRTYPE_IPV4)
                        {
                            memcpy(&buf[4], &client->bnd_addr.v4.sin_addr, sizeof(client->bnd_addr.v4.sin_addr));
                            memcpy(&buf[8], &client->bnd_addr.v4.sin_port, sizeof(client->bnd_addr.v4.sin_port));

                            len += sizeof(client->bnd_addr.v4.sin_addr) + sizeof(client->bnd_addr.v4.sin_port);
                        }

                        if (reply->addrtype == SOCKS5_ADDRTYPE_IPV6)
                        {
                            memcpy(&buf[4], &client->bnd_addr.v6.sin6_addr, sizeof(client->bnd_addr.v6.sin6_addr));
                            memcpy(&buf[4 + sizeof(client->bnd_addr.v6.sin6_addr)], &client->bnd_addr.v6.sin6_port, sizeof(client->bnd_addr.v6.sin6_port));
                            len += sizeof(client->bnd_addr.v6.sin6_addr) + sizeof(client->bnd_addr.v6.sin6_port);
                        }

                        if (reply->addrtype == SOCKS5_ADDRTYPE_DOMAIN)
                        {
                            buf[4] = strlen(client->bnd_addr.domain.domain);
                            memcpy(&buf[5], client->bnd_addr.domain.domain, buf[4]);

                            len += sizeof(char) + buf[4];
                        }

                        send(client->sock, buf, len, 0);

                        if (client->stage != SOCKS5_CONN_STAGE_CONNECTED)
                        {
                            shutdown(client->sock, SHUT_RDWR);
                            break;
                        }

                        client->stage = SOCKS5_CONN_STAGE_STREAM;
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

                goto readnext;
            }

            if (client->stage == SOCKS5_CONN_STAGE_STREAM)
            {
                if (!client->incoming_buffers.empty())
                {
                    unsigned char tempbuf[FRAGMENT_LEN];
                    len = (int)client->incoming_buffers.size();
                    client->incoming_buffers.deque(tempbuf, client->incoming_buffers.size());
                    tunnel.send_stream(client, tempbuf, len);
                }
            }
        }
    }

    tunnel.unlink_client(client);
    if (client->sock != -1)
    {
        close(client->sock);
        client->sock = -1;
    }
}

void socks5_server::accept_thrd_proc()
{
    sock_t sock;
    while (true)
    {
        sock = accept(_tcp_fd, nullptr, 0);
        if (sock <= 0)
        {
            printf("accept failed\n");
            exit(EXIT_FAILURE);
        }

        socks5_client *pclient = new socks5_client(sock);

        if (pclient == nullptr)
        {
            printf("new socks5_client failed\n");
            exit(EXIT_FAILURE);
        }

        std::shared_ptr<socks5_client> client(pclient);
        std::thread(&socks5_server::tcp_client_proc, this, client).detach();
    }
}

void socks5_server::udp_thrd_proc()
{
    int len;
    unsigned char buf[4096];
    struct sockaddr_in remote_addr;
    socklen_t addr_len;

    while (true)
    {
        addr_len = sizeof(remote_addr);

        len = recvfrom(_udp_fd, buf, sizeof(buf), 0, (struct sockaddr *)&remote_addr, &addr_len);
        if (len > 0)
        {
            printf("udp packet:%d\n", len);
        }
    }
}
bool socks5_server::start(const char *host, unsigned short port, int flags)
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

    sprintf(str_port, "%d", port);
    code = getaddrinfo(host, str_port, &hints, &pres);
    if (code != 0)
    {
        printf("socks5 server getaddrinfo failed...\n");
        return false;
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

    _tcp_fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (_tcp_fd == -1)
    {

        printf("socks5 server create tcp socket failed.\n");
        return false;
    }

    _udp_fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (_udp_fd == -1)
    {
        close(_tcp_fd);
        printf("socks5 server create udp socket failed.\n");
        return false;
    }

    code = bind(_tcp_fd, (struct sockaddr *)&addr, sizeof(addr));
    if (code != 0)
    {
        printf("socks5 server bind tcp socket failed.\n");
        close(_tcp_fd);
        close(_udp_fd);

        return false;
    }
    code = bind(_udp_fd, (struct sockaddr *)&addr, sizeof(addr));
    if (code != 0)
    {
        printf("socks5 server bind udp socket failed.\n");
        close(_tcp_fd);
        close(_udp_fd);

        return false;
    }

    code = listen(_tcp_fd, SOMAXCONN);
    if (code != 0)
    {
        printf("socks5 server listen tcp socket failed.\n");
        close(_tcp_fd);
        close(_udp_fd);

        return false;
    }

    std::thread udp_thread(&socks5_server::udp_thrd_proc, this);
    std::thread accept_thread(&socks5_server::accept_thrd_proc, this);

    udp_thread.detach();
    accept_thread.detach();
    return true;
}