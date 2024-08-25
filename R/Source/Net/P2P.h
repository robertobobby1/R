#pragma once

#include <cstdint>

#include "Utils.h"
#include "Macros.h"

namespace R::Net::P2P {
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

    enum LobbyPrivacyType {
        Private,
        Public
    };

    enum ClientActionType {
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
        return Utils::isInRange(buffer.size, 24, 29) && strncmp(buffer.ini, SECURITY_HEADER, SECURITY_HEADER_LENGTH) == 0;
    }

    inline Buffer createSecuredBuffer() {
        auto buffer = Buffer(SECURITY_HEADER_LENGTH);

        buffer.write(SECURITY_HEADER, SECURITY_HEADER_LENGTH);

        return buffer;
    }

    inline uint8_t getProtocolHeader(Buffer& buffer) {
        return buffer.ini[SECURITY_HEADER_LENGTH];
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

    inline Buffer createClientCreateLobbyBuffer(LobbyPrivacyType privacyType) {
        return createClientBuffer(privacyType, ClientActionType::Create);
    }

    inline Buffer createClientPublicConnectBuffer() {
        return createClientBuffer(LobbyPrivacyType::Public, ClientActionType::Connect);
    }

    inline Buffer createClientPrivateConnectBuffer(std::string& uuid) {
        auto buffer = createClientBuffer(LobbyPrivacyType::Private, ClientActionType::Connect);

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

    inline uint8_t createServerProtocolHeader(ServerActionType serverActionType) {
        uint8_t headerFlags = 0;
        if (serverActionType == ServerActionType::SendUUID) {
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
        auto headerFlags = createServerProtocolHeader(ServerActionType::Connect);

        buffer.write(headerFlags);
        buffer.write(uuid.c_str(), UUID_LENGTH);

        return buffer;
    }

    inline ServerActionType getServerActionTypeFromHeaderByte(uint8_t headerByte) {
        if (R::Utils::isFlagSet(headerByte, ServerClientHeaderFlags::ServerClientHeaderFlags_Action)) {
            return ServerActionType::SendUUID;
        }
        return ServerActionType::Connect;
    }

    // end Server secion

}  // namespace R::Net::P2P