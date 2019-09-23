#ifndef _PROTOCOL_H_
#define _PROTOCOL_H_


#pragma pack(1)

// socks5 version
#define SOCKS5_VERSION 0x05

// socks5 reserved
#define SOCKS5_RSV 0x00

// socks5 auth method
#define SOCKS5_AUTH_NOAUTH 0x00
#define SOCKS5_AUTH_USERNAMEPASSWORD 0x02
#define SOCKS5_AUTH_NOACCEPTABLE 0xff

struct socks5_method_req
{
    uint8_t ver;
    uint8_t nmethods;
    // uint8_t methods[0];
};

struct socks5_method_res
{
    uint8_t ver;
    uint8_t method;
};

// socks5 command
#define SOCKS5_CMD_CONNECT 0x01
#define SOCKS5_CMD_BIND 0x02
#define SOCKS5_CMD_UDPASSOCIATE 0x03

// socks5 address type
#define SOCKS5_ADDRTYPE_IPV4 0x01
#define SOCKS5_ADDRTYPE_DOMAIN 0x03
#define SOCKS5_ADDRTYPE_IPV6 0x04

struct socks5_ipv4_addr
{
    uint32_t ip;
    uint16_t port;
};

struct socks5_ipv6_addr
{
    unsigned char ip[16];
    uint16_t port;
};

struct socks5_request
{
    uint8_t ver;
    uint8_t cmd;
    uint8_t rsv;
    uint8_t addrtype;
};

// socks5 response status
#define SOCKS5_RESPONSE_SUCCESS 0x00
#define SOCKS5_RESPONSE_SERVER_FAILURE 0x01
#define SOCKS5_RESPONSE_CONNECTION_NOT_ALLOWED 0x02
#define SOCKS5_RESPONSE_NETWORK_UNREACHABLE 0x03
#define SOCKS5_RESPONSE_HOST_UNREACHABLE 0x04
#define SOCKS5_RESPONSE_CONNECTION_REFUSED 0x05
#define SOCKS5_RESPONSE_TTL_EXPIRED 0x06
#define SOCKS5_RESPONSE_COMMAND_NOT_SUPPORTED 0x07
#define SOCKS5_RESPONSE_ADDRTYPE_NOT_SUPPORTED 0x08

struct socks5_response
{
    uint8_t ver;
    uint8_t rep;
    uint8_t rsv;
    uint8_t addrtype;
};

#define SOCKS5_AUTH_USERNAMEPASSWORD_VER 0x01

#define SOCKS5_AUTH_USERNAMEPASSWORD_MAX_LEN 256
struct socks5_userpass_req
{
    uint8_t ver;
    uint8_t ulen;
    char username[SOCKS5_AUTH_USERNAMEPASSWORD_MAX_LEN];
    uint8_t plen;
    char password[SOCKS5_AUTH_USERNAMEPASSWORD_MAX_LEN];
};

#define SOCKS5_AUTH_USERNAMEPASSWORD_STATUS_OK 0x00
#define SOCKS5_AUTH_USERNAMEPASSWORD_STATUS_FAIL 0x01
struct socks5_userpass_res
{
    uint8_t ver;
    uint8_t status;
};


#pragma pack()

#define ID_C2S_TCP_CONNECT 0x01
#define ID_S2C_TCP_CONNECT 0x02
#define ID_A2A_TCP_STREAM  0x03
#define ID_A2A_TCP_CLOSE  0x04


#pragma pack(push,1)
struct packet_header
{
    unsigned char id;
    unsigned char nonce[8];
};
struct stream_header
{
    unsigned char id;
    uint64_t guid;
    uint32_t crc;
};
#pragma pack(pop)


#endif