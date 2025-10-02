#include "main.h"

unsigned char decrBuffer[4096];

unsigned char sampDecrTable[256] = {
    0xB4,0x62,0x07,0xE5,0x9D,0xAF,0x63,0xDD,0xE3,0xD0,0xCC,0xFE,0xDC,0xDB,0x6B,0x2E,
    0x6A,0x40,0xAB,0x47,0xC9,0xD1,0x53,0xD5,0x20,0x91,0xA5,0x0E,0x4A,0xDF,0x18,0x89,
    0xFD,0x6F,0x25,0x12,0xB7,0x13,0x77,0x00,0x65,0x36,0x6D,0x49,0xEC,0x57,0x2A,0xA9,
    0x11,0x5F,0xFA,0x78,0x95,0xA4,0xBD,0x1E,0xD9,0x79,0x44,0xCD,0xDE,0x81,0xEB,0x09,
    0x3E,0xF6,0xEE,0xDA,0x7F,0xA3,0x1A,0xA7,0x2D,0xA6,0xAD,0xC1,0x46,0x93,0xD2,0x1B,
    0x9C,0xAA,0xD7,0x4E,0x4B,0x4D,0x4C,0xF3,0xB8,0x34,0xC0,0xCA,0x88,0xF4,0x94,0xCB,
    0x04,0x39,0x30,0x82,0xD6,0x73,0xB0,0xBF,0x22,0x01,0x41,0x6E,0x48,0x2C,0xA8,0x75,
    0xB1,0x0A,0xAE,0x9F,0x27,0x80,0x10,0xCE,0xF0,0x29,0x28,0x85,0x0D,0x05,0xF7,0x35,
    0xBB,0xBC,0x15,0x06,0xF5,0x60,0x71,0x03,0x1F,0xEA,0x5A,0x33,0x92,0x8D,0xE7,0x90,
    0x5B,0xE9,0xCF,0x9E,0xD3,0x5D,0xED,0x31,0x1C,0x0B,0x52,0x16,0x51,0x0F,0x86,0xC5,
    0x68,0x9B,0x21,0x0C,0x8B,0x42,0x87,0xFF,0x4F,0xBE,0xC8,0xE8,0xC7,0xD4,0x7A,0xE0,
    0x55,0x2F,0x8A,0x8E,0xBA,0x98,0x37,0xE4,0xB2,0x38,0xA1,0xB6,0x32,0x83,0x3A,0x7B,
    0x84,0x3C,0x61,0xFB,0x8C,0x14,0x3D,0x43,0x3B,0x1D,0xC3,0xA2,0x96,0xB3,0xF8,0xC4,
    0xF2,0x26,0x2B,0xD8,0x7C,0xFC,0x23,0x24,0x66,0xEF,0x69,0x64,0x50,0x54,0x59,0xF1,
    0xA0,0x74,0xAC,0xC6,0x7D,0xB5,0xE6,0xE2,0xC2,0x7E,0x67,0x17,0x5E,0xE1,0xB9,0x3F,
    0x6C,0x70,0x08,0x99,0x45,0x56,0x76,0xF9,0x9A,0x97,0x19,0x72,0x5C,0x02,0x8F,0x58
};

enum PacketEnumeration {
    ID_INTERNAL_PING = 6, ID_PING = 7, ID_PING_OPEN_CONNECTIONS = 8, ID_CONNECTED_PONG = 9,
    ID_REQUEST_STATIC_DATA = 10, ID_CONNECTION_REQUEST = 11, ID_AUTH_KEY = 12, ID_BROADCAST_PINGS = 14,
    ID_SECURED_CONNECTION_RESPONSE = 15, ID_SECURED_CONNECTION_CONFIRMATION = 16, ID_RPC_MAPPING = 17,
    ID_SET_RANDOM_NUMBER_SEED = 19, ID_RPC = 20, ID_RPC_REPLY = 21, ID_DETECT_LOST_CONNECTIONS = 23,
    ID_OPEN_CONNECTION_REQUEST = 24, ID_OPEN_CONNECTION_REPLY = 25, ID_OPEN_CONNECTION_COOKIE = 26,
    ID_RSA_PUBLIC_KEY_MISMATCH = 28, ID_CONNECTION_ATTEMPT_FAILED = 29, ID_NEW_INCOMING_CONNECTION = 30,
    ID_NO_FREE_INCOMING_CONNECTIONS = 31, ID_DISCONNECTION_NOTIFICATION = 32, ID_CONNECTION_LOST = 33,
    ID_CONNECTION_REQUEST_ACCEPTED = 34, ID_CONNECTION_BANNED = 36, ID_INVALID_PASSWORD = 37,
    ID_MODIFIED_PACKET = 38, ID_PONG = 39, ID_TIMESTAMP = 40, ID_RECEIVED_STATIC_DATA = 41,
    ID_REMOTE_DISCONNECTION_NOTIFICATION = 42, ID_REMOTE_CONNECTION_LOST = 43,
    ID_REMOTE_NEW_INCOMING_CONNECTION = 44, ID_REMOTE_EXISTING_CONNECTION = 45,
    ID_REMOTE_STATIC_DATA = 46, ID_ADVERTISE_SYSTEM = 55,
    ID_PLAYER_SYNC = 207, ID_MARKERS_SYNC = 208, ID_UNOCCUPIED_SYNC = 209, ID_TRAILER_SYNC = 210,
    ID_PASSENGER_SYNC = 211, ID_SPECTATOR_SYNC = 212, ID_AIM_SYNC = 203, ID_VEHICLE_SYNC = 200,
    ID_RCON_COMMAND = 201, ID_RCON_RESPONCE = 202, ID_WEAPONS_UPDATE = 204, ID_STATS_UPDATE = 205,
    ID_BULLET_SYNC = 206
};

std::map<int, std::string> packetNames = {
    {6,"ID_INTERNAL_PING"},{7,"ID_PING"},{8,"ID_PING_OPEN_CONNECTIONS"},{9,"ID_CONNECTED_PONG"},
    {10,"ID_REQUEST_STATIC_DATA"},{11,"ID_CONNECTION_REQUEST"},{12,"ID_AUTH_KEY"},{14,"ID_BROADCAST_PINGS"},
    {15,"ID_SECURED_CONNECTION_RESPONSE"},{16,"ID_SECURED_CONNECTION_CONFIRMATION"},{17,"ID_RPC_MAPPING"},
    {19,"ID_SET_RANDOM_NUMBER_SEED"},{20,"ID_RPC"},{21,"ID_RPC_REPLY"},{23,"ID_DETECT_LOST_CONNECTIONS"},
    {24,"ID_OPEN_CONNECTION_REQUEST"},{25,"ID_OPEN_CONNECTION_REPLY"},{26,"ID_OPEN_CONNECTION_COOKIE"},
    {28,"ID_RSA_PUBLIC_KEY_MISMATCH"},{29,"ID_CONNECTION_ATTEMPT_FAILED"},{30,"ID_NEW_INCOMING_CONNECTION"},
    {31,"ID_NO_FREE_INCOMING_CONNECTIONS"},{32,"ID_DISCONNECTION_NOTIFICATION"},{33,"ID_CONNECTION_LOST"},
    {34,"ID_CONNECTION_REQUEST_ACCEPTED"},{36,"ID_CONNECTION_BANNED"},{37,"ID_INVALID_PASSWORD"},
    {38,"ID_MODIFIED_PACKET"},{39,"ID_PONG"},{40,"ID_TIMESTAMP"},{41,"ID_RECEIVED_STATIC_DATA"},
    {42,"ID_REMOTE_DISCONNECTION_NOTIFICATION"},{43,"ID_REMOTE_CONNECTION_LOST"},{44,"ID_REMOTE_NEW_INCOMING_CONNECTION"},
    {45,"ID_REMOTE_EXISTING_CONNECTION"},{46,"ID_REMOTE_STATIC_DATA"},{55,"ID_ADVERTISE_SYSTEM"},
    {200,"ID_VEHICLE_SYNC"},{201,"ID_RCON_COMMAND"},{202,"ID_RCON_RESPONCE"},{203,"ID_AIM_SYNC"},
    {204,"ID_WEAPONS_UPDATE"},{205,"ID_STATS_UPDATE"},{206,"ID_BULLET_SYNC"},{207,"ID_PLAYER_SYNC"},
    {208,"ID_MARKERS_SYNC"},{209,"ID_UNOCCUPIED_SYNC"},{210,"ID_TRAILER_SYNC"},{211,"ID_PASSENGER_SYNC"},
    {212,"ID_SPECTATOR_SYNC"}
};

void hexdump(const unsigned char* data, int len) {
    for (int i = 0; i < len; ++i) {
        if (i && (i % 16) == 0) std::cout << "\n";
        std::cout << std::hex << std::setw(2) << std::setfill('0') << (int)data[i] << " ";
    }
    std::cout << std::dec << "\n";
}

bool unKyretardizedatagram(unsigned char* buf, int len, int port) {
    if (len <= 1) return false;
    unsigned char bChecksumEncr = buf[0];
    int dataLen = len - 1;
    if (dataLen > (int)sizeof(decrBuffer)) return false;
    memcpy(decrBuffer, buf + 1, dataLen);

    unsigned char bPort = (unsigned char)(port ^ 0xCC);
    int unk = 0;
    for (int i = 0; i < dataLen; ++i) {
        if (!unk) {
            decrBuffer[i] = (unsigned char)(unk ^ decrBuffer[i]);
            unk++;
        }
        else {
            decrBuffer[i] = (unsigned char)(bPort ^ decrBuffer[i]);
            unk--;
        }
        decrBuffer[i] = sampDecrTable[decrBuffer[i]];
    }

    unsigned char bChecksum = 0;
    for (int i = 0; i < dataLen; ++i) {
        unsigned char bData = decrBuffer[i];
        bChecksum ^= (bData & 0xAA);
    }

    return bChecksum == bChecksumEncr;
}

int main(int argc, char* argv[]) {
    if (argc < 3) {
        std::cout << "usage: " << argv[0] << " <remote_ip> <remote_port> [listen_ip] [listen_port]\n";
        return 1;
    }
    const char* remoteIp = argv[1];
    int remotePort = std::stoi(argv[2]);
    const char* listenIp = (argc >= 4) ? argv[3] : "0.0.0.0";
    int listenPort = (argc >= 5) ? std::stoi(argv[4]) : remotePort;

    WSADATA wsa;
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
        std::cerr << "WSAStartup failed\n"; return 1;
    }

    SOCKET s = socket(AF_INET, SOCK_DGRAM, 0);
    if (s == INVALID_SOCKET) { std::cerr << "socket failed: " << WSAGetLastError() << "\n"; WSACleanup(); return 1; }

    sockaddr_in local{};
    local.sin_family = AF_INET;
    inet_pton(AF_INET, listenIp, &local.sin_addr);
    local.sin_port = htons(listenPort);
    if (bind(s, (sockaddr*)&local, sizeof(local)) == SOCKET_ERROR) {
        std::cerr << "bind failed: " << WSAGetLastError() << "\n"; closesocket(s); WSACleanup(); return 1;
    }

    // remote addr struct
    sockaddr_in remote{};
    remote.sin_family = AF_INET;
    inet_pton(AF_INET, remoteIp, &remote.sin_addr);
    remote.sin_port = htons(remotePort);

    std::cout << "Proxy listening on " << listenIp << ":" << listenPort << " -> forwarding to " << remoteIp << ":" << remotePort << "\n";

    // map clientAddr -> last active time (to forward server responses)
    struct ClientInfo {
        sockaddr_in addr;
        std::chrono::steady_clock::time_point last;
    };
    std::vector<ClientInfo> clients; // small list, linear search ok

    const int BUF_SZ = 65536;
    unsigned char buf[BUF_SZ];
    sockaddr_in src{};
    int srcLen = sizeof(src);

    while (true) {
        // recvfrom: receives both client->proxy and server->proxy packets (we distinguish by source IP)
        int recvLen = recvfrom(s, (char*)buf, BUF_SZ, 0, (sockaddr*)&src, &srcLen);
        if (recvLen == SOCKET_ERROR) {
            std::cerr << "recvfrom error: " << WSAGetLastError() << "\n";
            break;
        }

        char srcStr[INET_ADDRSTRLEN], dstStr[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &src.sin_addr, srcStr, sizeof(srcStr));
        // decide direction
        bool fromServer = (src.sin_addr.s_addr == remote.sin_addr.s_addr && src.sin_port == remote.sin_port);
        if (!fromServer) {
            // Packet from client -> forward to server
            std::cout << ">>> CLIENT -> SERVER from " << srcStr << ":" << ntohs(src.sin_port) << "  len=" << recvLen << "\n";
            std::cout << "pkt dump hex:\n"; hexdump(buf, recvLen);

            // record client as active
            bool found = false;
            for (auto& c : clients) {
                if (c.addr.sin_addr.s_addr == src.sin_addr.s_addr && c.addr.sin_port == src.sin_port) {
                    c.last = std::chrono::steady_clock::now();
                    found = true; break;
                }
            }
            if (!found) {
                ClientInfo ci; ci.addr = src; ci.last = std::chrono::steady_clock::now();
                clients.push_back(ci);
                std::cout << "[INFO] new client registered: " << srcStr << ":" << ntohs(src.sin_port) << "\n";
            }

            // forward to remote server (send original payload unchanged)
            int sent = sendto(s, (const char*)buf, recvLen, 0, (sockaddr*)&remote, sizeof(remote));
            if (sent == SOCKET_ERROR) {
                std::cerr << "sendto to remote failed: " << WSAGetLastError() << "\n";
            }
            else {
                std::cout << "[FWD] -> server (" << sent << " bytes)\n";
            }

            // try decrypt (client->server payload)
            if (unKyretardizedatagram(buf, recvLen, ntohs(src.sin_port))) {
                int id = (unsigned char)decrBuffer[0];
                std::cout << "[DECRYPTED CLIENT->SERVER] ID=" << id;
                if (packetNames.count(id)) std::cout << " (" << packetNames[id] << ")";
                std::cout << "\ndecrypted pkt dump hex:\n"; hexdump(decrBuffer, recvLen - 1);
            }
            else {
                std::cout << "[NOT ENCRYPTED or checksum mismatch]\n";
            }

        }
        else {
            // Packet from server -> forward to most recent client (or to all clients)
            char serverSrc[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &src.sin_addr, serverSrc, sizeof(serverSrc));
            std::cout << "<<< SERVER -> PROXY from " << serverSrc << ":" << ntohs(src.sin_port) << "  len=" << recvLen << "\n";
            std::cout << "pkt dump hex:\n"; hexdump(buf, recvLen);

            // prune old clients (e.g., older than 30s)
            auto now = std::chrono::steady_clock::now();
            clients.erase(std::remove_if(clients.begin(), clients.end(),
                [&](const ClientInfo& c) { return std::chrono::duration_cast<std::chrono::seconds>(now - c.last).count() > 60; }),
                clients.end());

            if (clients.empty()) {
                std::cout << "[WARN] No clients known — dropping server packet\n";
            }
            else {
                // choose most recent client
                auto it = std::max_element(clients.begin(), clients.end(), [](const ClientInfo& a, const ClientInfo& b) {
                    return a.last < b.last;
                    });
                sockaddr_in destClient = it->addr;
                char destStr[INET_ADDRSTRLEN];
                inet_ntop(AF_INET, &destClient.sin_addr, destStr, sizeof(destStr));
                int destPort = ntohs(destClient.sin_port);

                // forward to client
                int sent = sendto(s, (const char*)buf, recvLen, 0, (sockaddr*)&destClient, sizeof(destClient));
                if (sent == SOCKET_ERROR) {
                    std::cerr << "sendto to client failed: " << WSAGetLastError() << "\n";
                }
                else {
                    std::cout << "[FWD] -> client " << destStr << ":" << destPort << " (" << sent << " bytes)\n";
                }

                // try decrypt server->client payload (port = server src port)
                if (unKyretardizedatagram(buf, recvLen, ntohs(src.sin_port))) {
                    int id = (unsigned char)decrBuffer[0];
                    std::cout << "[DECRYPTED SERVER->CLIENT] ID=" << id;
                    if (packetNames.count(id)) std::cout << " (" << packetNames[id] << ")";
                    std::cout << "\ndecrypted pkt dump hex:\n"; hexdump(decrBuffer, recvLen - 1);
                }
                else {
                    std::cout << "[NOT ENCRYPTED or checksum mismatch]\n";
                }
            }
        }

        // small housekeeping: reset srclen for next recvfrom
        srcLen = sizeof(src);
    }

    closesocket(s);
    WSACleanup();
    return 0;
}
