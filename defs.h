#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#ifndef _WIN32
#include <alloca.h>
#endif
#include <assert.h>
#include <uv.h>


#include <vector>
#include <list>
#include <queue>
#include <unordered_map>
#ifndef _WIN32
#include <unistd.h>
#endif
#include <algorithm>
#include <openssl/sha.h>

#include "protocol.h"
#include "salsa20.h"
#include "MessageIdentifiers.h"
#include "RakPeerInterface.h"
#include "RakNetStatistics.h"
#include "RakNetTypes.h"
#include "BitStream.h"
#include "RakSleep.h"
#include "PacketLogger.h"
#include "SignaledEvent.h"