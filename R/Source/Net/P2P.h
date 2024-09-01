#pragma once

#include <cstdint>

#include "Utils.h"
#include "Macros.h"
#include "NetImports.h"

namespace R::Net::P2P {

    inline const int MAX_PACKAGE_LENGTH = 40;
    inline const int SECURITY_HEADER_LENGTH = 23;
    inline const char* SECURITY_HEADER = "0sdFGeVi3ItN1qwsHp3mcDF";
    inline const int UUID_LENGTH = 5;

    // Client-Server data flags
    enum ClientServerHeaderFlags {
        // Type of the lobby public/private
        ClientServerHeaderFlags_Public = 1 << 5,  // 00100000
        // Type of the action we are trying create/connect/disconnect/peersConnectSuccess
        ClientServerHeaderFlags_Bit1 = 1 << 7,  // 10000000
        ClientServerHeaderFlags_Bit2 = 1 << 6,  // 01000000
    };

    // Server-Client data flags
    enum ServerClientHeaderFlags {
        // action type send uuid/connect
        ServerClientHeaderFlags_Action = 1 << 7,  // 10000000
    };

    enum class LobbyPrivacyType {
        Private,
        Public
    };

    enum class ClientActionType {
        Create,
        Connect,
        Disconnect,
        PeerConnectSuccess
    };

    enum ServerActionType {
        Connect,
        SendUUID,
    };

    inline bool isValidAuthedRequest(Buffer& buffer) {
        return Utils::isInRange(buffer.size, SECURITY_HEADER_LENGTH + 1, MAX_PACKAGE_LENGTH) && strncmp(buffer.ini, SECURITY_HEADER, SECURITY_HEADER_LENGTH) == 0;
    }

    inline Buffer createSecuredBuffer() {
        auto buffer = Buffer(SECURITY_HEADER_LENGTH);

        buffer.write(SECURITY_HEADER, SECURITY_HEADER_LENGTH);

        return buffer;
    }

    inline uint8_t getProtocolHeader(Buffer& buffer) {
        return buffer.ini[SECURITY_HEADER_LENGTH];
    }

    inline Buffer getPayload(Buffer& buffer) {
        auto payloadBuffer = Buffer(buffer.size);
        auto headerSize = SECURITY_HEADER_LENGTH + 1;

        payloadBuffer.write(buffer.ini + headerSize, buffer.size - headerSize);

        return payloadBuffer;
    }

    // start Client section

    inline uint8_t createClientProtocolHeader(LobbyPrivacyType lobbyType, ClientActionType clientActionType) {
        uint8_t headerFlags = 0;
        if (lobbyType == LobbyPrivacyType::Public) {
            R::Utils::setFlag(headerFlags, ClientServerHeaderFlags_Public);
        }
        switch (clientActionType) {
            case ClientActionType::Connect:  // 11
                R::Utils::setFlag(headerFlags, ClientServerHeaderFlags_Bit1);
                R::Utils::setFlag(headerFlags, ClientServerHeaderFlags_Bit2);
                break;
            case ClientActionType::Create:  // 10
                R::Utils::setFlag(headerFlags, ClientServerHeaderFlags_Bit1);
                break;
            case ClientActionType::Disconnect:  // 01
                R::Utils::setFlag(headerFlags, ClientServerHeaderFlags_Bit2);
                break;
            case ClientActionType::PeerConnectSuccess:  // 00
                break;
        }

        return headerFlags;
    }

    inline Buffer createClientBuffer(LobbyPrivacyType lobbyType, ClientActionType action) {
        auto buffer = createSecuredBuffer();
        auto headerFlags = createClientProtocolHeader(lobbyType, action);

        buffer.write(headerFlags);

        return buffer;
    }

    inline Buffer createClientPeersConnectSuccessBuffer() {
        return createClientBuffer(LobbyPrivacyType::Private, ClientActionType::PeerConnectSuccess);
    }

    inline Buffer createClientDisconnectBuffer() {
        return createClientBuffer(LobbyPrivacyType::Private, ClientActionType::Disconnect);
    }

    inline Buffer createClientCreateLobbyBuffer(LobbyPrivacyType privacyType, uint32_t port) {
        auto buffer = createClientBuffer(privacyType, ClientActionType::Create);

        buffer.write(htonl(port));

        return buffer;
    }

    inline Buffer createClientPublicConnectBuffer(uint32_t port) {
        auto buffer = createClientBuffer(LobbyPrivacyType::Public, ClientActionType::Connect);

        buffer.write(htonl(port));

        return buffer;
    }

    inline Buffer createClientPrivateConnectBuffer(std::string& uuid, uint32_t port) {
        auto buffer = createClientBuffer(LobbyPrivacyType::Private, ClientActionType::Connect);

        buffer.write(htonl(port));
        buffer.write(uuid.c_str(), UUID_LENGTH);

        return buffer;
    }

    inline ClientActionType getClientActionTypeFromHeaderByte(uint8_t headerByte) {
        bool isBit1Set = R::Utils::isFlagSet(headerByte, ClientServerHeaderFlags::ClientServerHeaderFlags_Bit1);
        bool isBit2Set = R::Utils::isFlagSet(headerByte, ClientServerHeaderFlags::ClientServerHeaderFlags_Bit2);

        if (isBit1Set) {
            if (isBit2Set) {
                return ClientActionType::Connect;  // 11 = connect
            } else {
                return ClientActionType::Create;  // 10 = createLobby
            }
        } else {
            if (isBit2Set) {
                return ClientActionType::Disconnect;  // 01 = disconnect
            } else {
                return ClientActionType::PeerConnectSuccess;  // 00 = peersConnectSuccess
            }
        }
    }

    inline LobbyPrivacyType getLobbyPrivacyTypeFromHeaderByte(uint8_t headerByte) {
        if (R::Utils::isFlagSet(headerByte, ClientServerHeaderFlags::ClientServerHeaderFlags_Public)) {
            return LobbyPrivacyType::Public;
        }
        return LobbyPrivacyType::Private;
    }

    // end Client secion

    // start Server secion

    struct ServerConnectPayload {
        in_addr ipAddress;
        uint16_t port;
        uint32_t delay;

        void Print() {
            RLog("Other peer's information:\n");
            RLog("Peer Port: %d\n", this->port);
            RLog("Peer IP Address: %s\n", inet_ntoa({this->ipAddress}));
            RLog("Peer delay: %i\n", this->delay);
        }
    };

    inline uint8_t createServerProtocolHeader(ServerActionType serverActionType) {
        uint8_t headerFlags = 0;
        if (serverActionType == ServerActionType::Connect) {
            R::Utils::setFlag(headerFlags, ClientServerHeaderFlags_Bit1);  // 1
        }

        return headerFlags;
    }

    inline Buffer createServerConnectBuffer(uint32_t ipAddress, uint16_t port, uint32_t delay) {
        auto buffer = createSecuredBuffer();
        auto headerFlags = createServerProtocolHeader(ServerActionType::Connect);

        buffer.write(headerFlags);
        buffer.write(ipAddress);
        buffer.write(port);
        buffer.write(delay);

        return buffer;
    }

    inline Buffer createServerSendUUIDBuffer(std::string& uuid) {
        auto buffer = createSecuredBuffer();
        auto headerFlags = createServerProtocolHeader(ServerActionType::SendUUID);

        buffer.write(headerFlags);
        buffer.write(uuid.c_str(), UUID_LENGTH);

        return buffer;
    }

    inline ServerActionType getServerActionTypeFromHeaderByte(uint8_t headerByte) {
        if (R::Utils::isFlagSet(headerByte, ServerClientHeaderFlags::ServerClientHeaderFlags_Action)) {
            return ServerActionType::Connect;
        }
        return ServerActionType::SendUUID;
    }

    inline std::string getUUIDFromSendUUIDBuffer(Buffer& buffer) {
        auto protocolHeader = getProtocolHeader(buffer);
        auto actionType = getServerActionTypeFromHeaderByte(protocolHeader);

        if (actionType != ServerActionType::SendUUID)
            return "";

        auto payload = getPayload(buffer);
        return std::string(payload.ini, UUID_LENGTH);
    }

    inline ServerConnectPayload getPayloadFromServerConnectBuffer(Buffer& buffer) {
        auto protocolHeader = getProtocolHeader(buffer);
        auto actionType = getServerActionTypeFromHeaderByte(protocolHeader);

        if (actionType != ServerActionType::Connect)
            return {0, 0, 0};  // empty/error

        auto payload = getPayload(buffer);

        auto ipAddress = payload.read<in_addr>(0);
        auto port = payload.read<uint16_t>(4);
        auto delay = payload.read<uint32_t>(6);

        return {ipAddress, ntohs(port), ntohl(delay)};
    }

    // end Server secion

}  // namespace R::Net::P2P