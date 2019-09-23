#include "defs.h"
#include "tunnel.h"
#include "ringbuffer.h"
#include "socks5.h"

extern RakNet::RakPeerInterface *rakPeer;

unsigned char GetPacketIdentifier(RakNet::Packet *p);
unsigned char *GetPacketData(RakNet::Packet *p);
size_t GetPacketLength(RakNet::Packet *p);

static uint32_t crc32_tab[] = {
    0x00000000, 0x77073096, 0xee0e612c, 0x990951ba, 0x076dc419, 0x706af48f,
    0xe963a535, 0x9e6495a3, 0x0edb8832, 0x79dcb8a4, 0xe0d5e91e, 0x97d2d988,
    0x09b64c2b, 0x7eb17cbd, 0xe7b82d07, 0x90bf1d91, 0x1db71064, 0x6ab020f2,
    0xf3b97148, 0x84be41de, 0x1adad47d, 0x6ddde4eb, 0xf4d4b551, 0x83d385c7,
    0x136c9856, 0x646ba8c0, 0xfd62f97a, 0x8a65c9ec, 0x14015c4f, 0x63066cd9,
    0xfa0f3d63, 0x8d080df5, 0x3b6e20c8, 0x4c69105e, 0xd56041e4, 0xa2677172,
    0x3c03e4d1, 0x4b04d447, 0xd20d85fd, 0xa50ab56b, 0x35b5a8fa, 0x42b2986c,
    0xdbbbc9d6, 0xacbcf940, 0x32d86ce3, 0x45df5c75, 0xdcd60dcf, 0xabd13d59,
    0x26d930ac, 0x51de003a, 0xc8d75180, 0xbfd06116, 0x21b4f4b5, 0x56b3c423,
    0xcfba9599, 0xb8bda50f, 0x2802b89e, 0x5f058808, 0xc60cd9b2, 0xb10be924,
    0x2f6f7c87, 0x58684c11, 0xc1611dab, 0xb6662d3d, 0x76dc4190, 0x01db7106,
    0x98d220bc, 0xefd5102a, 0x71b18589, 0x06b6b51f, 0x9fbfe4a5, 0xe8b8d433,
    0x7807c9a2, 0x0f00f934, 0x9609a88e, 0xe10e9818, 0x7f6a0dbb, 0x086d3d2d,
    0x91646c97, 0xe6635c01, 0x6b6b51f4, 0x1c6c6162, 0x856530d8, 0xf262004e,
    0x6c0695ed, 0x1b01a57b, 0x8208f4c1, 0xf50fc457, 0x65b0d9c6, 0x12b7e950,
    0x8bbeb8ea, 0xfcb9887c, 0x62dd1ddf, 0x15da2d49, 0x8cd37cf3, 0xfbd44c65,
    0x4db26158, 0x3ab551ce, 0xa3bc0074, 0xd4bb30e2, 0x4adfa541, 0x3dd895d7,
    0xa4d1c46d, 0xd3d6f4fb, 0x4369e96a, 0x346ed9fc, 0xad678846, 0xda60b8d0,
    0x44042d73, 0x33031de5, 0xaa0a4c5f, 0xdd0d7cc9, 0x5005713c, 0x270241aa,
    0xbe0b1010, 0xc90c2086, 0x5768b525, 0x206f85b3, 0xb966d409, 0xce61e49f,
    0x5edef90e, 0x29d9c998, 0xb0d09822, 0xc7d7a8b4, 0x59b33d17, 0x2eb40d81,
    0xb7bd5c3b, 0xc0ba6cad, 0xedb88320, 0x9abfb3b6, 0x03b6e20c, 0x74b1d29a,
    0xead54739, 0x9dd277af, 0x04db2615, 0x73dc1683, 0xe3630b12, 0x94643b84,
    0x0d6d6a3e, 0x7a6a5aa8, 0xe40ecf0b, 0x9309ff9d, 0x0a00ae27, 0x7d079eb1,
    0xf00f9344, 0x8708a3d2, 0x1e01f268, 0x6906c2fe, 0xf762575d, 0x806567cb,
    0x196c3671, 0x6e6b06e7, 0xfed41b76, 0x89d32be0, 0x10da7a5a, 0x67dd4acc,
    0xf9b9df6f, 0x8ebeeff9, 0x17b7be43, 0x60b08ed5, 0xd6d6a3e8, 0xa1d1937e,
    0x38d8c2c4, 0x4fdff252, 0xd1bb67f1, 0xa6bc5767, 0x3fb506dd, 0x48b2364b,
    0xd80d2bda, 0xaf0a1b4c, 0x36034af6, 0x41047a60, 0xdf60efc3, 0xa867df55,
    0x316e8eef, 0x4669be79, 0xcb61b38c, 0xbc66831a, 0x256fd2a0, 0x5268e236,
    0xcc0c7795, 0xbb0b4703, 0x220216b9, 0x5505262f, 0xc5ba3bbe, 0xb2bd0b28,
    0x2bb45a92, 0x5cb36a04, 0xc2d7ffa7, 0xb5d0cf31, 0x2cd99e8b, 0x5bdeae1d,
    0x9b64c2b0, 0xec63f226, 0x756aa39c, 0x026d930a, 0x9c0906a9, 0xeb0e363f,
    0x72076785, 0x05005713, 0x95bf4a82, 0xe2b87a14, 0x7bb12bae, 0x0cb61b38,
    0x92d28e9b, 0xe5d5be0d, 0x7cdcefb7, 0x0bdbdf21, 0x86d3d2d4, 0xf1d4e242,
    0x68ddb3f8, 0x1fda836e, 0x81be16cd, 0xf6b9265b, 0x6fb077e1, 0x18b74777,
    0x88085ae6, 0xff0f6a70, 0x66063bca, 0x11010b5c, 0x8f659eff, 0xf862ae69,
    0x616bffd3, 0x166ccf45, 0xa00ae278, 0xd70dd2ee, 0x4e048354, 0x3903b3c2,
    0xa7672661, 0xd06016f7, 0x4969474d, 0x3e6e77db, 0xaed16a4a, 0xd9d65adc,
    0x40df0b66, 0x37d83bf0, 0xa9bcae53, 0xdebb9ec5, 0x47b2cf7f, 0x30b5ffe9,
    0xbdbdf21c, 0xcabac28a, 0x53b39330, 0x24b4a3a6, 0xbad03605, 0xcdd70693,
    0x54de5729, 0x23d967bf, 0xb3667a2e, 0xc4614ab8, 0x5d681b02, 0x2a6f2b94,
    0xb40bbe37, 0xc30c8ea1, 0x5a05df1b, 0x2d02ef8d};

uint32_t
crc32(uint32_t crc, const void *buf, uint32_t size)
{
    const uint8_t *p;

    p = (const uint8_t *)buf;
    crc = crc ^ ~0U;

    while (size--)
        crc = crc32_tab[(crc ^ *p++) & 0xFF] ^ (crc >> 8);

    return crc ^ ~0U;
}

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

    struct packet_header *header = (struct packet_header *)data;

    unsigned char *encrypted_data = (unsigned char *)&header[1];
    size_t encrypted_length = length - sizeof(struct packet_header);
    uint32_t ncrc = crc32(0, encrypted_data, encrypted_length);
    RakNet::BitStream reader(encrypted_data, encrypted_length, false);

    s20_crypt(password, S20_KEYLEN_256, header->nonce, 0, encrypted_data, encrypted_length);

    struct stream_header *sheader = (struct stream_header *)&header[1];

    identifier = sheader->id;
    guid = sheader->guid;

    reader.IgnoreBytes(9);

    auto iterator = _socks5_clientmap.find(guid);
    if (iterator == _socks5_clientmap.end())
    {
        return;
    }

    auto client = iterator->second;

    if (identifier == ID_S2C_TCP_CONNECT)
    {
        if (reader.Read((char *)&client->resp_status, 1) && reader.Read((char *)&client->bnd_addrtype, 1))
        {
            switch (client->bnd_addrtype)
            {
            case SOCKS5_ADDRTYPE_IPV4:
            {
                if (reader.Read((char *)&client->bnd_addr.v4.sin_addr, 4) && reader.Read((char *)&client->bnd_addr.v4.sin_port, 2))
                {
                }
                break;
            }
            case SOCKS5_ADDRTYPE_IPV6:
            {
                if (reader.Read((char *)&client->bnd_addr.v6.sin6_addr, 16) && reader.Read((char *)&client->bnd_addr.v6.sin6_port, 2))
                {
                }
                break;
            }
            case SOCKS5_ADDRTYPE_DOMAIN:
            {
                RakNet::RakString domain;

                if (reader.Read(domain) && reader.Read((char *)&client->bnd_addr.domain.port, 2))
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

        if (client->timeout)
        {
            client->timeout->stop();
        }

        socks5_client::connect_event(client);
    }

    if (identifier == ID_A2A_TCP_STREAM)
    {
        encrypted_data = (unsigned char *)&sheader[1];
        encrypted_length = length - (sizeof(struct stream_header) + sizeof(struct packet_header));

        uint32_t crc2 = crc32(0, encrypted_data, encrypted_length);

        if (crc2 != sheader->crc)
        {
            printf("bad crc\n");
            return;
        }

        socks5_tcp_sender::write(client, encrypted_data, encrypted_length);
    }

    if (identifier == ID_A2A_TCP_CLOSE)
    {
        socks5_tcp_close::close(client);
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
    case ID_ALREADY_CONNECTED:
        _stage = TUNNEL_STAGE_NOT_CONNECTED;
        printf("connect to server falled.\n");
        break;
    
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

void Tunnel::send(socks5_client *client, RakNet::BitStream &packet, PacketReliability reliability, PacketPriority priority)
{
    RakNet::BitStream encrypted_packet;
    uint8_t nonce[8];

    *(uint64_t *)&nonce = rakPeer->Get64BitUniqueRandomNumber();
    s20_crypt(password, S20_KEYLEN_256, nonce, 0, packet.GetData(), packet.GetNumberOfBytesUsed());

    encrypted_packet.Write((unsigned char)ID_USER_PACKET_ENUM);
    encrypted_packet.WriteAlignedBytes((unsigned char *)nonce, 8);
    encrypted_packet.WriteAlignedBytes(packet.GetData(), packet.GetNumberOfBytesUsed());

    char orderingChannel = client->guid % 32; //PacketPriority::NUMBER_OF_ORDERED_STREAMS
    rakPeer->Send(&encrypted_packet, priority, reliability, orderingChannel, RakNet::UNASSIGNED_SYSTEM_ADDRESS, true);
}

void Tunnel::on_frame()
{
    update_connection_state();

    if (_stage != TUNNEL_STAGE_CONNECTED)
    {
        for (size_t i = 0; i < _connecting_requests.size(); i++)
        {
            auto &client = _connecting_requests[i];

            client->stage = SOCKS5_CONN_STAGE_CONNECTING;
            client->resp_status = SOCKS5_RESPONSE_SERVER_FAILURE;
        }

        _connecting_requests.clear();
    }
    else
    {
        for (size_t i = 0; i < _connecting_requests.size(); i++)
        {
            socks5_client *client = _connecting_requests[i];

            RakNet::BitStream serializer;
            unsigned char id = ID_C2S_TCP_CONNECT;
            serializer.WriteAlignedBytes((unsigned char *)&id, 1);
            serializer.WriteAlignedBytes((unsigned char *)&client->guid, 8);
            serializer.WriteAlignedBytes((unsigned char *)&client->remote_addrtype, 1);

            if (client->remote_addrtype == SOCKS5_ADDRTYPE_IPV4)
            {
                serializer.WriteAlignedBytes((unsigned char *)&client->remote_addr.v4.sin_addr, 4);
                serializer.WriteAlignedBytes((unsigned char *)&client->remote_addr.v4.sin_port, 2);
            }

            if (client->remote_addrtype == SOCKS5_ADDRTYPE_IPV6)
            {
                serializer.WriteAlignedBytes((unsigned char *)&client->remote_addr.v6.sin6_addr, 16);
                serializer.WriteAlignedBytes((unsigned char *)&client->remote_addr.v6.sin6_port, 2);
            }

            if (client->remote_addrtype == SOCKS5_ADDRTYPE_DOMAIN)
            {
                serializer.Write(client->remote_addr.domain.domain);
                serializer.WriteAlignedBytes((unsigned char *)&client->remote_addr.domain.port, 2);
            }

            send(client, serializer, RELIABLE, HIGH_PRIORITY);
            client->release();
        }

        _connecting_requests.clear();
    }
}

void Tunnel::request_connect(socks5_client *client)
{
    if (_stage != TUNNEL_STAGE_CONNECTED)
    {
        client->stage = SOCKS5_CONN_STAGE_CONNECTING;
        client->resp_status = SOCKS5_RESPONSE_SERVER_FAILURE;
        return;
    }

    client->addref();
    _connecting_requests.push_back(client);
}

void Tunnel::link_client(socks5_client *client)
{
    _socks5_clientmap[client->guid] = client;
    client->addref();
}

void Tunnel::unlink_client(socks5_client *client)
{
    auto iterator = _socks5_clientmap.find(client->guid);
    if (iterator == _socks5_clientmap.end())
    {
        return;
    }

    _socks5_clientmap.erase(iterator);
    client->release();
}

void Tunnel::send_stream(socks5_client *client, void *data, size_t len)
{
    size_t totalsize = client->incoming_buffers.size();

    RakNet::BitStream serializer;
    unsigned char id = ID_A2A_TCP_STREAM;
    serializer.WriteAlignedBytes((unsigned char *)&id, sizeof(id));
    serializer.WriteAlignedBytes((unsigned char *)&client->guid, 8);
    uint32_t crc = crc32(0, data, len);
    serializer.WriteAlignedBytes((unsigned char *)&crc, 4);
    serializer.WriteAlignedBytes((unsigned char *)data, len);

    send(client, serializer);

}
void Tunnel::send_close(socks5_client *client)
{
    RakNet::BitStream serializer;
    unsigned char id = ID_A2A_TCP_CLOSE;

    serializer.WriteAlignedBytes((unsigned char *)&id, sizeof(id));
    serializer.WriteAlignedBytes((unsigned char *)&client->guid, 8);

    send(client, serializer);
}