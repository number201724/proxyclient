#include "defs.h"
#include "ringbuffer.h"
#include "socks5.h"
#include "tunnel.h"

socks5_server socks5;

RakNet::RakPeerInterface *rakPeer;
Tunnel tunnel;

#define HOST "127.0.0.1"
#define PORT 27015

// Copied from Multiplayer.cpp
// If the first byte is ID_TIMESTAMP, then we want the 5th byte
// Otherwise we want the 1st byte
unsigned char GetPacketIdentifier(RakNet::Packet *p)
{
    if (p == 0)
        return 255;

    if ((unsigned char)p->data[0] == ID_TIMESTAMP)
    {
        RakAssert(p->length > sizeof(RakNet::MessageID) + sizeof(RakNet::Time));
        return (unsigned char)p->data[sizeof(RakNet::MessageID) + sizeof(RakNet::Time)];
    }
    else
        return (unsigned char)p->data[0];
}

unsigned char *GetPacketData(RakNet::Packet *p)
{
    if ((unsigned char)p->data[0] == ID_TIMESTAMP)
    {
        RakAssert(p->length > sizeof(RakNet::MessageID) + sizeof(RakNet::Time));
        return &p->data[sizeof(RakNet::MessageID) + sizeof(RakNet::Time)];
    }
    else
        return &p->data[0];
}

size_t GetPacketLength(RakNet::Packet *p)
{
    if ((unsigned char)p->data[0] == ID_TIMESTAMP)
    {
        RakAssert(p->length > sizeof(RakNet::MessageID) + sizeof(RakNet::Time));
        return p->length - (sizeof(RakNet::MessageID) + sizeof(RakNet::Time));
    }
    else
        return p->length;
}

#define ID_C2S_TCP_CONNECT (ID_USER_PACKET_ENUM + 0)

int main(int argc, char *argv[])
{
    rakPeer = RakNet::RakPeerInterface::GetInstance();
    rakPeer->SetTimeoutTime(10000, RakNet::UNASSIGNED_SYSTEM_ADDRESS);
    rakPeer->AllowConnectionResponseIPMigration(false);
    rakPeer->SetOccasionalPing(true);

    RakNet::SocketDescriptor socketDescriptor[1];

    RakNet::StartupResult rs = rakPeer->Startup(8, socketDescriptor, 1);

    if (rs != RakNet::StartupResult::RAKNET_STARTED)
    {
        printf("rakPeer::Startup failed error:%d\n", rs);
        exit(EXIT_FAILURE);
    }

    tunnel.setup("127.0.0.1", 27015, "WDNMDNMSL");

    if (!socks5.start("0.0.0.0", 1080))
    {
        printf("socks5 server start failed\n");
        exit(EXIT_FAILURE);
    }

    while (true)
    {
        RakNet::Packet *p;

        for (p = rakPeer->Receive(); p; rakPeer->DeallocatePacket(p), p = rakPeer->Receive())
        {
            tunnel.handle_packet(p);
        }

        tunnel.on_frame();

        std::this_thread::sleep_for(std::chrono::milliseconds(30));
    }

    return 0;
}