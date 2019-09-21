#include "defs.h"
#include "tunnel.h"
#include "ringbuffer.h"
#include "socks5.h"

extern RakNet::RakPeerInterface *rakPeer;

unsigned char GetPacketIdentifier(RakNet::Packet *p);
unsigned char *GetPacketData(RakNet::Packet *p);
size_t GetPacketLength(RakNet::Packet *p);

Tunnel::Tunnel()
{
    _stage = TUNNEL_STAGE_NOT_CONNECTED;
    _proxy_server_host = "";
}

Tunnel::~Tunnel()
{
}

void dump_bytes(void *data, size_t len)
{
    unsigned char *buf = (unsigned char *)data;
    for (size_t i = 0; i < len; i++)
    {
        printf("%02X", buf[i]);
    }

    printf("\n");
}

void Tunnel::setup(const char *proxy_server_host, uint16_t proxy_server_port, const char *key)
{
    SHA256_CTX sha256;
    int len = strlen(key);

    SHA256_Init(&sha256);
    SHA256_Update(&sha256, key, len);
    SHA256_Final(password, &sha256);

    printf("password:");
    dump_bytes(password, 32);

    _proxy_server_host = proxy_server_host;
    _proxy_server_port = proxy_server_port;
}

void Tunnel::connection_packet(void *data, size_t length)
{
    unsigned char identifier;
    uint64_t guid;
    uint8_t nonce[8];
    RakNet::BitStream reader((unsigned char *)data, (const unsigned int)length, false);

    printf("connection_packet\n");

    reader.IgnoreBytes(sizeof(unsigned char));
    if (!reader.Read(nonce))
        return;

    unsigned char *encrypted_data = reader.GetData() + BITS_TO_BYTES(reader.GetReadOffset());
    size_t encrypted_length = BITS_TO_BYTES(reader.GetNumberOfUnreadBits());

    s20_crypt(password, S20_KEYLEN_256, nonce, 0, encrypted_data, encrypted_length);

    if (!reader.Read(identifier))
        return;

    if (!reader.Read(guid))
    {
        return;
    }

    printf("identifier:%d\n", identifier);
    _lock.lock();

    auto iterator = _socks5_clientmap.find(guid);
    if (iterator == _socks5_clientmap.end())
    {
        _lock.unlock();
        return;
    }

    auto client = iterator->second;

    _lock.unlock();

    if (identifier == ID_S2C_TCP_CONNECT)
    {
        client->lock();

        if (reader.Read(client->resp_status) && reader.Read(client->bnd_addrtype))
        {
            printf("client->resp_status:%d\n", client->resp_status);
            printf("client->bnd_addrtype:%d\n", client->bnd_addrtype);

            switch (client->bnd_addrtype)
            {
            case SOCKS5_ADDRTYPE_IPV4:
            {
                if (reader.Read(client->remote_addr.v4.sin_addr) && reader.Read(client->remote_addr.v4.sin_port))
                {
                }
                break;
            }
            case SOCKS5_ADDRTYPE_IPV6:
            {
                if (reader.Read(client->remote_addr.v6.sin6_addr) && reader.Read(client->remote_addr.v6.sin6_port))
                {
                }
                break;
            }
            case SOCKS5_ADDRTYPE_DOMAIN:
            {
                RakNet::RakString domain;

                if (reader.Read(domain) && reader.Read(client->remote_addr.domain.port))
                {
                }

                break;
            }

            default:
                break;
            }
        }
        if (client->resp_status == SOCKS5_RESPONSE_SUCCESS)
        {
            client->stage = SOCKS5_CONN_STAGE_CONNECTED;
        }
        client->event.SetEvent();
        client->unlock();
    }

    if (identifier == ID_A2A_TCP_STREAM)
    {
        encrypted_data = reader.GetData() + BITS_TO_BYTES(reader.GetReadOffset());
        encrypted_length = BITS_TO_BYTES(reader.GetNumberOfUnreadBits());

        client->lock();

        client->outgoing_buffers.push(new packet(encrypted_data,encrypted_length ));
        client->unlock();

        client->event.SetEvent();
    }
}

void Tunnel::handle_packet(RakNet::Packet *p)
{
    unsigned char packetIdentifier;
    unsigned char *data;
    size_t length;

    packetIdentifier = GetPacketIdentifier(p);
    data = GetPacketData(p);
    length = GetPacketLength(p);

    switch (packetIdentifier)
    {
    case ID_DISCONNECTION_NOTIFICATION:
    case ID_CONNECTION_BANNED: // Banned from this server
    case ID_CONNECTION_ATTEMPT_FAILED:
    case ID_NO_FREE_INCOMING_CONNECTIONS:
    case ID_INVALID_PASSWORD:
    case ID_CONNECTION_LOST:
        _stage = TUNNEL_STAGE_NOT_CONNECTED;
        printf("connect to server falled.\n");
        break;
    case ID_ALREADY_CONNECTED:
    case ID_CONNECTION_REQUEST_ACCEPTED:
        _stage = TUNNEL_STAGE_CONNECTED;
        // This tells the client they have connected
        printf("connection request accepted to %s with GUID %s\n", p->systemAddress.ToString(true), p->guid.ToString());
        break;
    case ID_USER_PACKET_ENUM:
        connection_packet(data, length);
        break;
    default:
        break;
    }
}

void Tunnel::update_connection_state()
{
    if (_stage == TUNNEL_STAGE_NOT_CONNECTED)
    {
        if (RakNet::CONNECTION_ATTEMPT_STARTED == rakPeer->Connect(_proxy_server_host, _proxy_server_port, NULL, 0))
        {
            _stage = TUNNEL_STAGE_CONNECTING;
            printf("connecting to proxy server %s:%d....\n", _proxy_server_host, _proxy_server_port);
        }
    }
}

void Tunnel::send(std::shared_ptr<socks5_client> &client, RakNet::BitStream &packet, PacketReliability reliability, PacketPriority priority)
{
    RakNet::BitStream encrypted_packet;
    uint8_t nonce[8];

    *(uint64_t *)&nonce = rakPeer->Get64BitUniqueRandomNumber();
    s20_crypt(password, S20_KEYLEN_256, nonce, 0, packet.GetData(), packet.GetNumberOfBytesUsed());

    encrypted_packet.Write((unsigned char)ID_USER_PACKET_ENUM);
    encrypted_packet.Write(nonce);
    encrypted_packet.Write(packet);

    char orderingChannel = client->guid % 32; //PacketPriority::NUMBER_OF_ORDERED_STREAMS
    rakPeer->Send(&encrypted_packet, priority, reliability, orderingChannel, RakNet::UNASSIGNED_SYSTEM_ADDRESS, true);
}

void Tunnel::on_frame()
{
    _lock.lock();

    update_connection_state();

    if (_stage != TUNNEL_STAGE_CONNECTED)
    {
        for (size_t i = 0; i < _connecting_requests.size(); i++)
        {
            auto &client = _connecting_requests[i];

            client->stage = SOCKS5_CONN_STAGE_CONNECTING;
            client->resp_status = SOCKS5_RESPONSE_SERVER_FAILURE;
            client->event.SetEvent();
        }

        _connecting_requests.clear();
    }
    else
    {
        for (size_t i = 0; i < _connecting_requests.size(); i++)
        {
            std::shared_ptr<socks5_client> &client = _connecting_requests[i];

            RakNet::BitStream serializer;
            serializer.Write((unsigned char)ID_C2S_TCP_CONNECT);
            serializer.Write(client->guid);
            serializer.Write((unsigned char)client->remote_addrtype);

            if (client->remote_addrtype == SOCKS5_ADDRTYPE_IPV4)
            {
                serializer.Write(client->remote_addr.v4.sin_addr);
                serializer.Write(client->remote_addr.v4.sin_port);
            }

            if (client->remote_addrtype == SOCKS5_ADDRTYPE_IPV6)
            {
                serializer.Write(client->remote_addr.v6.sin6_addr);
                serializer.Write(client->remote_addr.v6.sin6_port);
            }

            if (client->remote_addrtype == SOCKS5_ADDRTYPE_DOMAIN)
            {
                serializer.Write(client->remote_addr.domain.domain);
                serializer.Write(client->remote_addr.domain.port);
            }

            send(client, serializer, RELIABLE, IMMEDIATE_PRIORITY);
        }

        _connecting_requests.clear();
    }

    _lock.unlock();
}

void Tunnel::request_connect(std::shared_ptr<socks5_client> &client)
{
    _lock.lock();

    if (_stage != TUNNEL_STAGE_CONNECTED)
    {
        client->stage = SOCKS5_CONN_STAGE_CONNECTING;
        client->resp_status = SOCKS5_RESPONSE_SERVER_FAILURE;
        client->event.SetEvent();

        _lock.unlock();
        return;
    }

    _connecting_requests.push_back(client);
    _lock.unlock();
}

void Tunnel::link_client(std::shared_ptr<socks5_client> &client)
{
    _lock.lock();
    _socks5_clientmap[client->guid] = client;
    _lock.unlock();
}

void Tunnel::unlink_client(std::shared_ptr<socks5_client> &client)
{
    _lock.lock();

    auto iterator = _socks5_clientmap.find(client->guid);
    if (iterator == _socks5_clientmap.end())
    {
        _lock.unlock();
        return;
    }

    _socks5_clientmap.erase(iterator);
    _lock.unlock();
}

void Tunnel::send_stream(std::shared_ptr<socks5_client> &client, void *data, size_t len)
{
    size_t totalsize = client->incoming_buffers.size();

    RakNet::BitStream serializer;
    serializer.Write((unsigned char)ID_A2A_TCP_STREAM);
    serializer.Write(client->guid);
    serializer.Write((char *)data, len);

    send(client, serializer);
}