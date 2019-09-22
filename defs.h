#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <alloca.h>
#include <assert.h>
#include <uv.h>


#include <vector>
#include <list>
#include <queue>
#include <unordered_map>
#include <unistd.h>
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