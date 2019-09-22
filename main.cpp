#include "defs.h"
#include "ringbuffer.h"
#include "socks5.h"
#include "tunnel.h"

socks5_server socks5;

RakNet::RakPeerInterface *rakPeer;
Tunnel tunnel;

#define HOST "127.0.0.1"
#define PORT 27015

uv_timer_t debugtimer;
int alloc_cnt =0;

static void ontimer(uv_timer_t *timer)
{
    printf("tcp usecount:%lu  allocnt:%d\n", tunnel._socks5_clientmap.size(),alloc_cnt);
}

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
uv_timer_t udp_timer;

static void udp_packet_update(uv_timer_t *timer)
{
    RakNet::Packet *p;

    for (p = rakPeer->Receive(); p; rakPeer->DeallocatePacket(p), p = rakPeer->Receive())
    {
        tunnel.handle_packet(p);
    }

    tunnel.on_frame();
}
int main(int argc, char *argv[])
{
    signal(SIGPIPE, SIG_IGN);
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

    tunnel.setup("47.56.166.112", 27015, "WDNMDNMSL");

    socks5.start("0.0.0.0", 1080);
    uv_timer_init(uv_default_loop(), &debugtimer);
    uv_timer_start(&debugtimer, ontimer, 5000, 5000);
    uv_timer_init(uv_default_loop(), &udp_timer);
    uv_timer_start(&udp_timer, udp_packet_update, 10, 10);

    uv_run(uv_default_loop(), UV_RUN_DEFAULT);
    return 0;
}
