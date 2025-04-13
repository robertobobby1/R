# PeerClient

## Description

This is a c++ header only library that contains many useful and simple common utils used throughout many projects. It also contains the basics used for the P2P protocol implemented for the repositories PeerClient and PeerServer. You can find the definition for this underneath.

## Usage

To be able to use this in your c++ projects you just need to include R.h, you can find this file under Inlcude/

## Protocol - Server-Client

##### All request contain

- 23 bytes of security
- 1 byte for protocol header:
  - B1 | B2 | B3 | B4 | B5 | B6 | B7 | B8
  - B1 & B2 => Action, possible values are:
    - 00 = peersConnectSuccess
    - 01 = disconnect
    - 10 = createLobby
    - 11 = connect
  - B3 => LobbyPrivacyType, possible values are:
    - 0 = Private
    - 1 = Public

#### Create request includes nothing else

#### Disconnect request includes nothing else

#### Peers connect success request includes nothing else

#### Connect request also includes:

- 5 bytes game hash

## Protocol - Client-Server

#### All responses contain

- 23 bytes of security
- 1 byte for protocol header:
  - B1 | B2 | B3 | B4 | B5 | B6 | B7 | B8
  - B1 => Action, posible values are:
    - 0 => send uuid
    - 1 => connect

#### Connect request also includes:

- 4 bytes for the ipAddress of the other peer
- 2 bytes for the port of the other peer
- 4 bytes for the delay of the other peer

#### Send uuid request also includes:

- 5 bytes for game hash

#### Disclaimer:

- if B1 | B2 | B3 | B4 | B5 | B6 | B7 | B8 are all set to 0 then it is a Keep Alive package
