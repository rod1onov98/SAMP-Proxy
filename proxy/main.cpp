#include <winsock2.h>
#include <ws2tcpip.h>
#include <iostream>
#include <string>
#include <map>
#include <vector>
#include <algorithm>
#include <chrono>
#include <iomanip>
#include <cstring>
#include <bitset>

#pragma comment(lib, "Ws2_32.lib")

unsigned char decrBuffer[4096];

unsigned char sampDecrTable[256] =
{
    0xB4, 0x62, 0x07, 0xE5, 0x9D, 0xAF, 0x63, 0xDD, 0xE3, 0xD0, 0xCC, 0xFE, 0xDC, 0xDB, 0x6B, 0x2E,
    0x6A, 0x40, 0xAB, 0x47, 0xC9, 0xD1, 0x53, 0xD5, 0x20, 0x91, 0xA5, 0x0E, 0x4A, 0xDF, 0x18, 0x89,
    0xFD, 0x6F, 0x25, 0x12, 0xB7, 0x13, 0x77, 0x00, 0x65, 0x36, 0x6D, 0x49, 0xEC, 0x57, 0x2A, 0xA9,
    0x11, 0x5F, 0xFA, 0x78, 0x95, 0xA4, 0xBD, 0x1E, 0xD9, 0x79, 0x44, 0xCD, 0xDE, 0x81, 0xEB, 0x09,
    0x3E, 0xF6, 0xEE, 0xDA, 0x7F, 0xA3, 0x1A, 0xA7, 0x2D, 0xA6, 0xAD, 0xC1, 0x46, 0x93, 0xD2, 0x1B,
    0x9C, 0xAA, 0xD7, 0x4E, 0x4B, 0x4D, 0x4C, 0xF3, 0xB8, 0x34, 0xC0, 0xCA, 0x88, 0xF4, 0x94, 0xCB,
    0x04, 0x39, 0x30, 0x82, 0xD6, 0x73, 0xB0, 0xBF, 0x22, 0x01, 0x41, 0x6E, 0x48, 0x2C, 0xA8, 0x75,
    0xB1, 0x0A, 0xAE, 0x9F, 0x27, 0x80, 0x10, 0xCE, 0xF0, 0x29, 0x28, 0x85, 0x0D, 0x05, 0xF7, 0x35,
    0xBB, 0xBC, 0x15, 0x06, 0xF5, 0x60, 0x71, 0x03, 0x1F, 0xEA, 0x5A, 0x33, 0x92, 0x8D, 0xE7, 0x90,
    0x5B, 0xE9, 0xCF, 0x9E, 0xD3, 0x5D, 0xED, 0x31, 0x1C, 0x0B, 0x52, 0x16, 0x51, 0x0F, 0x86, 0xC5,
    0x68, 0x9B, 0x21, 0x0C, 0x8B, 0x42, 0x87, 0xFF, 0x4F, 0xBE, 0xC8, 0xE8, 0xC7, 0xD4, 0x7A, 0xE0,
    0x55, 0x2F, 0x8A, 0x8E, 0xBA, 0x98, 0x37, 0xE4, 0xB2, 0x38, 0xA1, 0xB6, 0x32, 0x83, 0x3A, 0x7B,
    0x84, 0x3C, 0x61, 0xFB, 0x8C, 0x14, 0x3D, 0x43, 0x3B, 0x1D, 0xC3, 0xA2, 0x96, 0xB3, 0xF8, 0xC4,
    0xF2, 0x26, 0x2B, 0xD8, 0x7C, 0xFC, 0x23, 0x24, 0x66, 0xEF, 0x69, 0x64, 0x50, 0x54, 0x59, 0xF1,
    0xA0, 0x74, 0xAC, 0xC6, 0x7D, 0xB5, 0xE6, 0xE2, 0xC2, 0x7E, 0x67, 0x17, 0x5E, 0xE1, 0xB9, 0x3F,
    0x6C, 0x70, 0x08, 0x99, 0x45, 0x56, 0x76, 0xF9, 0x9A, 0x97, 0x19, 0x72, 0x5C, 0x02, 0x8F, 0x58
};

enum pkt_ids
{
    ID_INTERNAL_PING = 6,
    ID_PING,
    ID_PING_OPEN_CONNECTIONS,
    ID_CONNECTED_PONG,
    ID_REQUEST_STATIC_DATA,
    ID_CONNECTION_REQUEST,
    ID_AUTH_KEY,
    ID_BROADCAST_PINGS = 14,
    ID_SECURED_CONNECTION_RESPONSE,
    ID_SECURED_CONNECTION_CONFIRMATION,
    ID_RPC_MAPPING,
    ID_SET_RANDOM_NUMBER_SEED = 19,
    ID_RPC,
    ID_RPC_REPLY,
    ID_DETECT_LOST_CONNECTIONS = 23,
    ID_OPEN_CONNECTION_REQUEST,
    ID_OPEN_CONNECTION_REPLY,
    ID_OPEN_CONNECTION_COOKIE,
    ID_RSA_PUBLIC_KEY_MISMATCH = 28,
    ID_CONNECTION_ATTEMPT_FAILED,
    ID_NEW_INCOMING_CONNECTION = 30,
    ID_NO_FREE_INCOMING_CONNECTIONS = 31,
    ID_DISCONNECTION_NOTIFICATION,
    ID_CONNECTION_LOST,
    ID_CONNECTION_REQUEST_ACCEPTED,
    ID_CONNECTION_BANNED = 36,
    ID_INVALID_PASS,
    ID_MODIFIED_PACKET,
    ID_PONG,
    ID_TIMESTAMP,
    ID_RECEIVED_STATIC_DATA,
    ID_REMOTE_DISCONNECTION_NOTIFICATION,
    ID_REMOTE_CONNECTION_LOST,
    ID_REMOTE_NEW_INCOMING_CONNECTION,
    ID_REMOTE_EXISTING_CONNECTION,
    ID_REMOTE_STATIC_DATA,
    ID_ADVERTISE_SYSTEM = 55,

    ID_PLAYER_SYNC = 207,
    ID_MARKERS_SYNC = 208,
    ID_UNOCCUPIED_SYNC = 209,
    ID_TRAILER_SYNC = 210,
    ID_PASSENGER_SYNC = 211,
    ID_SPECTATOR_SYNC = 212,
    ID_AIM_SYNC = 203,
    ID_VEHICLE_SYNC = 200,
    ID_RCON_COMMAND = 201,
    ID_RCON_RESPONCE = 202,
    ID_WEAPONS_UPDATE = 204,
    ID_STATS_UPDATE = 205,
    ID_BULLET_SYNC = 206,
    ID_USER_INTERFACE_SYNC = 252
};

std::map<int, std::string> pkt_names = {
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

class BitStream {
private:
    const unsigned char* data;
    size_t size;
    size_t readOffset;
    size_t bitOffset;

public:
    BitStream(const unsigned char* buf, size_t len)
        : data(buf), size(len), readOffset(0), bitOffset(0) {
    }

    bool Read(uint8_t& value) {
        if (readOffset >= size) return false;
        value = data[readOffset++];
        return true;
    }

    bool Read(uint16_t& value) {
        if (readOffset + 1 >= size) return false;
        value = (data[readOffset] << 8) | data[readOffset + 1];
        readOffset += 2;
        return true;
    }

    bool Read(uint32_t& value) {
        if (readOffset + 3 >= size) return false;
        value = (data[readOffset] << 24) | (data[readOffset + 1] << 16) |
            (data[readOffset + 2] << 8) | data[readOffset + 3];
        readOffset += 4;
        return true;
    }

    bool Read(float& value) {
        if (readOffset + 3 >= size) return false;
        uint32_t temp = (data[readOffset] << 24) | (data[readOffset + 1] << 16) |
            (data[readOffset + 2] << 8) | data[readOffset + 3];
        memcpy(&value, &temp, sizeof(float));
        readOffset += 4;
        return true;
    }

    bool ReadBits(uint8_t& value, int bits) {
        if (bits > 8 || readOffset >= size) return false;

        if (bitOffset == 0) {
            value = (data[readOffset] >> (8 - bits)) & ((1 << bits) - 1);
            bitOffset = bits;
        }
        else {
            int remainingBits = 8 - bitOffset;
            if (bits <= remainingBits) {
                value = (data[readOffset] >> (remainingBits - bits)) & ((1 << bits) - 1);
                bitOffset += bits;
                if (bitOffset == 8) {
                    readOffset++;
                    bitOffset = 0;
                }
            }
            else {
                uint8_t firstPart = data[readOffset] & ((1 << remainingBits) - 1);
                readOffset++;
                if (readOffset >= size) return false;
                uint8_t secondPart = (data[readOffset] >> (8 - (bits - remainingBits))) & ((1 << (bits - remainingBits)) - 1);
                value = (firstPart << (bits - remainingBits)) | secondPart;
                bitOffset = bits - remainingBits;
            }
        }
        return true;
    }

    size_t GetReadOffset() const { return readOffset; }
    size_t GetNumberOfUnreadBits() const { return (size - readOffset) * 8 - bitOffset; }
    void Reset() { readOffset = 0; bitOffset = 0; }
};

void hexdump(const unsigned char* data, int len) {
    for (int i = 0; i < len; ++i) {
        if (i && (i % 16) == 0) std::cout << "\n";
        std::cout << std::hex << std::setw(2) << std::setfill('0') << (int)data[i] << " ";
    }
    std::cout << std::dec << "\n";
}

bool samp_decrypt(unsigned char* buf, int len, int port, int unk) {
    unsigned char bChecksumEncr = buf[0];

    len--;
    memcpy(&decrBuffer, (char*)(buf + 1), len);

    unsigned char bPort = port ^ 0xCC;
    for (int i = 0; i < len; i++)
    {
        if (!unk)
        {
            decrBuffer[i] = unk ^ decrBuffer[i];
            unk++;

        }
        else
        {
            decrBuffer[i] = bPort ^ decrBuffer[i];
            unk--;
        }

        decrBuffer[i] = sampDecrTable[decrBuffer[i]];
    }

    unsigned char bChecksum = 0;
    for (int i = 0; i < len; i++)
    {
        unsigned char bData = decrBuffer[i];
        bChecksum ^= (bData & 0xAA);
    }

    memcpy(buf, &decrBuffer, len);

    if (bChecksum != bChecksumEncr) {
        printf("Checksum mismatch: %d != %d\n", bChecksum, bChecksumEncr);
        return false;
    }
    return true;
}

void onfootsync(const unsigned char* data, int len, bool fromServer) {
    if (len < 2) return;

    BitStream bs(data, len);
    uint8_t syncId;
    if (!bs.Read(syncId)) return;

    std::cout << "[PLAYER SYNC] ";

    if (!fromServer) {
        // client -> server
        uint16_t leftright, updown, keys;
        float pos_x, pos_y, pos_z, quat_x, quat_y, quat_z, quat_w;
        uint8_t health, armour, weapon, specialaction;
        float vel_x, vel_y, vel_z, surf_x, surf_y, surf_z;
        uint16_t surf_flags;
        uint32_t anim;

        if (bs.Read(leftright) && bs.Read(updown) && bs.Read(keys) &&
            bs.Read(pos_x) && bs.Read(pos_y) && bs.Read(pos_z) &&
            bs.Read(quat_x) && bs.Read(quat_y) && bs.Read(quat_z) && bs.Read(quat_w) &&
            bs.Read(health) && bs.Read(armour) && bs.Read(weapon) && bs.Read(specialaction) &&
            bs.Read(vel_x) && bs.Read(vel_y) && bs.Read(vel_z) &&
            bs.Read(surf_x) && bs.Read(surf_y) && bs.Read(surf_z) &&
            bs.Read(surf_flags) && bs.Read(anim)) {

            std::cout << "Pos: (" << pos_x << ", " << pos_y << ", " << pos_z << ") ";
            std::cout << "Health: " << (int)health << " Armour: " << (int)armour << " ";
            std::cout << "Weapon: " << (int)weapon << " Keys: 0x" << std::hex << keys << std::dec;
        }
    }
    else {
        // server -> client
        uint16_t playerid;
        if (bs.Read(playerid)) {
            std::cout << "PlayerID: " << playerid << " ";
        }

        std::cout << "(server sync data)";
    }
    std::cout << "\n";
}

void vehsync(const unsigned char* data, int len, bool fromServer) {
    if (len < 2) return;

    BitStream bs(data, len);
    uint8_t syncId;
    if (!bs.Read(syncId)) return;

    std::cout << "[VEHICLE SYNC] ";

    if (!fromServer) {
        // client -> server
        uint16_t vehicleid, leftright, updown, keys;
        float quat_x, quat_y, quat_z, quat_w, pos_x, pos_y, pos_z;
        float vel_x, vel_y, vel_z, health;
        uint8_t player_health, player_armour, weapon, siren, landinggear;
        uint16_t trailer;
        uint32_t hydra;

        if (bs.Read(vehicleid) && bs.Read(leftright) && bs.Read(updown) && bs.Read(keys) &&
            bs.Read(quat_x) && bs.Read(quat_y) && bs.Read(quat_z) && bs.Read(quat_w) &&
            bs.Read(pos_x) && bs.Read(pos_y) && bs.Read(pos_z) &&
            bs.Read(vel_x) && bs.Read(vel_y) && bs.Read(vel_z) &&
            bs.Read(health) && bs.Read(player_health) && bs.Read(player_armour) &&
            bs.Read(weapon) && bs.Read(siren) && bs.Read(landinggear) &&
            bs.Read(trailer) && bs.Read(hydra)) {

            std::cout << "VehicleID: " << vehicleid << " ";
            std::cout << "pos: (" << pos_x << ", " << pos_y << ", " << pos_z << ") ";
            std::cout << "health: " << health << " PlayerHP: " << (int)player_health;
        }
    }
    else {
        // server -> client
        uint16_t playerid, vehicleid;
        if (bs.Read(playerid) && bs.Read(vehicleid)) {
            std::cout << "PlayerID: " << playerid << " VehicleID: " << vehicleid << " ";
        }
        std::cout << "(server sync data)";
    }
    std::cout << "\n";
}

void aimsync(const unsigned char* data, int len, bool fromServer) {
    if (len < 2) return;

    BitStream bs(data, len);
    uint8_t syncId;
    if (!bs.Read(syncId)) return;

    std::cout << "[AIM SYNC] ";

    if (fromServer) {
        uint16_t playerid;
        if (bs.Read(playerid)) {
            std::cout << "PlayerID: " << playerid << " ";
        }
    }

    uint8_t cam_mode;
    float angle_x, angle_y, angle_z, pos_x, pos_y, pos_z, aim_z;

    if (bs.Read(cam_mode) && bs.Read(angle_x) && bs.Read(angle_y) && bs.Read(angle_z) &&
        bs.Read(pos_x) && bs.Read(pos_y) && bs.Read(pos_z) && bs.Read(aim_z)) {

        std::cout << "cam: " << (int)cam_mode << " ";
        std::cout << "angle: (" << angle_x << ", " << angle_y << ", " << angle_z << ") ";
        std::cout << "pos: (" << pos_x << ", " << pos_y << ", " << pos_z << ")";
    }
    std::cout << "\n";
}

void bulletsync(const unsigned char* data, int len, bool fromServer) {
    if (len < 2) return;

    BitStream bs(data, len);
    uint8_t syncId;
    if (!bs.Read(syncId)) return;

    std::cout << "[BULLET SYNC] ";

    if (fromServer) {
        uint16_t playerid;
        if (bs.Read(playerid)) {
            std::cout << "PlayerID: " << playerid << " ";
        }
    }

    uint8_t type;
    uint16_t id;
    float origin_x, origin_y, origin_z, target_x, target_y, target_z;

    if (bs.Read(type) && bs.Read(id) &&
        bs.Read(origin_x) && bs.Read(origin_y) && bs.Read(origin_z) &&
        bs.Read(target_x) && bs.Read(target_y) && bs.Read(target_z)) {

        std::cout << "type: " << (int)type << " ID: " << id << " ";
        std::cout << "origin: (" << origin_x << ", " << origin_y << ", " << origin_z << ") ";
        std::cout << "target: (" << target_x << ", " << target_y << ", " << target_z << ")";
    }
    std::cout << "\n";
}

void statssync(const unsigned char* data, int len, bool fromServer) {
    if (len < 2) return;

    BitStream bs(data, len);
    uint8_t syncId;
    if (!bs.Read(syncId)) return;

    std::cout << "[STATS UPDATE] ";

    if (!fromServer) {
        uint32_t money, drunk;
        if (bs.Read(money) && bs.Read(drunk)) {
            std::cout << "money: " << money << " drunk: " << drunk;
        }
    }
    std::cout << "\n";
}

void allsync(const unsigned char* data, int len, int packetId, bool fromServer) {
    switch (packetId) {
    case ID_PLAYER_SYNC:
        onfootsync(data, len, fromServer);
        break;
    case ID_VEHICLE_SYNC:
        vehsync(data, len, fromServer);
        break;
    case ID_AIM_SYNC:
        aimsync(data, len, fromServer);
        break;
    case ID_BULLET_SYNC:
        bulletsync(data, len, fromServer);
        break;
    case ID_STATS_UPDATE:
        statssync(data, len, fromServer);
        break;
    case ID_MARKERS_SYNC:
        std::cout << "[MARKERS SYNC]\n";
        break;
    case ID_UNOCCUPIED_SYNC:
        std::cout << "[UNOCCUPIED VEHICLE SYNC]\n";
        break;
    case ID_PASSENGER_SYNC:
        std::cout << "[PASSENGER SYNC]\n";
        break;
    case ID_TRAILER_SYNC:
        std::cout << "[TRAILER SYNC]\n";
        break;
    case ID_SPECTATOR_SYNC:
        std::cout << "[SPECTATOR SYNC]\n";
        break;
    case ID_WEAPONS_UPDATE:
        std::cout << "[WEAPONS UPDATE]\n";
        break;
    default:
        if (packetId >= 200 && packetId <= 212) {
            std::cout << "[SYNC PACKET " << packetId << "]\n";
        }
        break;
    }
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

    std::cout << "listening on " << listenIp << ":" << listenPort << " -> forwarding to " << remoteIp << ":" << remotePort << "\n";

    // map clientaddr -> last active time (to forward server responses)
    struct ClientInfo {
        sockaddr_in addr;
        std::chrono::steady_clock::time_point last;
    };
    std::vector<ClientInfo> clients;

    const int BUF_SZ = 65536;
    unsigned char buf[BUF_SZ];
    sockaddr_in src{};
    int srcLen = sizeof(src);

    while (true) {
        int recvLen = recvfrom(s, (char*)buf, BUF_SZ, 0, (sockaddr*)&src, &srcLen);
        if (recvLen == SOCKET_ERROR) {
            std::cerr << "recvfrom error: " << WSAGetLastError() << "\n";
            break;
        }

        char srcStr[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &src.sin_addr, srcStr, sizeof(srcStr));

        bool fromServer = (src.sin_addr.s_addr == remote.sin_addr.s_addr && src.sin_port == remote.sin_port);

        if (!fromServer) {
            // packet from client -> forward to server
            std::cout << ">>> c->s from " << srcStr << ":" << ntohs(src.sin_port) << "  len=" << recvLen << "\n";

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
                std::cout << "[info] new client registered: " << srcStr << ":" << ntohs(src.sin_port) << "\n";
            }

            // forward to remote server
            int sent = sendto(s, (const char*)buf, recvLen, 0, (sockaddr*)&remote, sizeof(remote));
            if (sent == SOCKET_ERROR) {
                std::cerr << "sendto to remote failed: " << WSAGetLastError() << "\n";
            }
            else {
                std::cout << "[fdw] -> server (" << sent << " bytes)\n";
            }

            // try decrypt and analyze
            if (samp_decrypt(buf, recvLen, ntohs(src.sin_port), 0)) {
                int id = (unsigned char)decrBuffer[0];
                std::cout << "[decr c->s] id=" << id;
                if (pkt_names.count(id)) std::cout << " (" << pkt_names[id] << ")";
                std::cout << "\n";

                // sync analysis from client
                allsync(decrBuffer + 1, recvLen - 1, id, false);

                std::cout << "decrypted pkt dump:\n";
                hexdump(decrBuffer, recvLen - 1);
            }
            else {
                std::cout << "checksum mismatch\n";
            }

        }
        else {
            // packet from server -> forward to most recent client
            char serverSrc[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &src.sin_addr, serverSrc, sizeof(serverSrc));
            std::cout << "<<< server->proxy from " << serverSrc << ":" << ntohs(src.sin_port) << "  len=" << recvLen << "\n";

            // prune old clients
            auto now = std::chrono::steady_clock::now();
            clients.erase(std::remove_if(clients.begin(), clients.end(),
                [&](const ClientInfo& c) { return std::chrono::duration_cast<std::chrono::seconds>(now - c.last).count() > 60; }),
                clients.end());

            if (clients.empty()) {
                std::cout << "[WARNING] no clients known dropping server packet\n";
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
                    std::cout << "[fwd] -> client " << destStr << ":" << destPort << " (" << sent << " bytes)\n";
                }

                // try decrypt and analyze server->client payload
                if (samp_decrypt(buf, recvLen, ntohs(src.sin_port), 0)) {
                    int id = (unsigned char)decrBuffer[0];
                    std::cout << "[decr s->c] ID=" << id;
                    if (pkt_names.count(id)) std::cout << " (" << pkt_names[id] << ")";
                    std::cout << "\n";

                    // sync analysis from server
                    allsync(decrBuffer + 1, recvLen - 1, id, true);

                    std::cout << "decrypted pkt dump:\n";
                    hexdump(decrBuffer, recvLen - 1);
                }
                else {
                    std::cout << "checksum mismatch\n";
                }
            }
        }

        std::cout << "---\n";
        srcLen = sizeof(src);
    }

    closesocket(s);
    WSACleanup();
    return 0;
}
