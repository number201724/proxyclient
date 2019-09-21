#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <alloca.h>
#include <assert.h>

#include <thread>
#include <mutex>
#include <vector>
#include <list>
#include <queue>
#include <unordered_map>
#include "protocol.h"
#include <unistd.h>
#include <algorithm>

#include "salsa20.h"
#include <openssl/sha.h>

#ifdef _WIN32
#include <WinSock2.h>
#include <Windows.h>
typedef SOCKET sock_t;
#else
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netdb.h>
#include <sys/time.h>
#include <sys/select.h>
typedef int sock_t;
#endif



#include "MessageIdentifiers.h"
#include "RakPeerInterface.h"
#include "RakNetStatistics.h"
#include "RakNetTypes.h"
#include "BitStream.h"
#include "RakSleep.h"
#include "PacketLogger.h"
#include "SignaledEvent.h"
#include "protocol.h"