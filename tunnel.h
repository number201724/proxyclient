#ifndef _TUNNEL_H_
#define _TUNNEL_H_

class socks5_client;

enum TunnelStage
{
    TUNNEL_STAGE_NOT_CONNECTED,
    TUNNEL_STAGE_CONNECTING,
    TUNNEL_STAGE_CONNECTED
};

class Tunnel
{
public:
    Tunnel();
    ~Tunnel();

    void on_frame();
    void handle_packet(RakNet::Packet *p);
    void connection_packet(void *data, size_t length);

    void setup(const char *proxy_server_host, uint16_t proxy_server_port, const char *key);

    void update_connection_state();
    /**
     *  link socks5 client connection to socket map
     **/
    void link_client(socks5_client *client);

    /**
     *  unlink socks5 client connection from socket map
     **/
    void unlink_client(socks5_client *client);

    /**
     * send connect request to proxy server 
     **/
    void request_connect(socks5_client *client);

    void send(socks5_client *client, RakNet::BitStream &packet, PacketReliability reliability = RELIABLE_ORDERED, PacketPriority priority = MEDIUM_PRIORITY);
    void send_stream(socks5_client *client, void *data, size_t len);
    void send_close(socks5_client *client);

    int _stage;
    std::vector<socks5_client *> _connecting_requests;
    std::unordered_map<uint64_t, socks5_client *> _socks5_clientmap;

    unsigned char password[32];
    const char *_proxy_server_host;
    uint16_t _proxy_server_port;
};

#endif