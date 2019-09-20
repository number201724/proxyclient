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
    
    void setup(const char *proxy_server_host, uint16_t proxy_server_port, const char *key);

    void update_connection_state();
    /**
     *  link socks5 client connection to socket map
     **/
    void link_client(std::shared_ptr<socks5_client> &client);

    /**
     *  unlink socks5 client connection from socket map
     **/
    void unlink_client(std::shared_ptr<socks5_client> &client);

    /**
     * send connect request to proxy server 
     **/
    void request_connect(std::shared_ptr<socks5_client> &client);

    void send(std::shared_ptr<socks5_client> &client, RakNet::BitStream &packet);
    void send_stream(std::shared_ptr<socks5_client> &client);

    int _stage;
    std::mutex _lock;
    std::vector<std::shared_ptr<socks5_client>> _connecting_requests;
    std::unordered_map<uint64_t, std::shared_ptr<socks5_client>> _socks5_clientmap;

    unsigned char password[32];
    const char *_proxy_server_host;
    uint16_t _proxy_server_port;

};

#endif