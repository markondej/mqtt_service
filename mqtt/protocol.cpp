#include "protocol.hpp"
#include <chrono>
#include <atomic>
#include <thread>
#include <regex>
#ifdef _WIN32
#define _WIN32_WINNT 0x0601
#include <ws2tcpip.h>
#else
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <fcntl.h>
#include <netdb.h>
#include <cstring>
#include <climits>
#endif

#ifndef TCPSERVER_RECV_BUFFER_LENGTH
#define TCPSERVER_RECV_BUFFER_LENGTH 1024
#endif

#define TCPSERVER_SERVER_NOP_DELAY 1000
#define TCPSERVER_CLIENT_NOP_DELAY 1000

#ifdef _WIN32
#define TCPSERVER_SOCKET SOCKET
#define TCPSERVER_SOCKET_ERROR SOCKET_ERROR
#define TCPSERVER_CLOSESOCKET closesocket
#else
#define TCPSERVER_SOCKET int
#define TCPSERVER_SOCKET_ERROR -1
#define TCPSERVER_CLOSESOCKET close
#endif

#ifndef MQTT_BUFFER_MAX_LENGTH
#define MQTT_BUFFER_MAX_LENGTH 8 * 1024 * 1024
#endif

#define MQTT_CONTROL_PACKET_TYPE_CONNECT 1
#define MQTT_CONTROL_PACKET_TYPE_CONNACK 2
#define MQTT_CONTROL_PACKET_TYPE_PUBLISH 3
#define MQTT_CONTROL_PACKET_TYPE_PUBACK 4
#define MQTT_CONTROL_PACKET_TYPE_PUBREC 5
#define MQTT_CONTROL_PACKET_TYPE_PUBREL 6
#define MQTT_CONTROL_PACKET_TYPE_PUBCOMP 7
#define MQTT_CONTROL_PACKET_TYPE_SUBSCRIBE 8
#define MQTT_CONTROL_PACKET_TYPE_SUBACK 9
#define MQTT_CONTROL_PACKET_TYPE_UNSUBSCRIBE 10
#define MQTT_CONTROL_PACKET_TYPE_UNSUBACK 11
#define MQTT_CONTROL_PACKET_TYPE_PINGREQ 12
#define MQTT_CONTROL_PACKET_TYPE_PINGRESP 13
#define MQTT_CONTROL_PACKET_TYPE_DISCONNECT 14

#define MQTT_REQUIRED_FLAGS_CONNECT 0x0
#define MQTT_REQUIRED_FLAGS_CONNACK 0x0
#define MQTT_REQUIRED_FLAGS_PUBACK 0x0
#define MQTT_REQUIRED_FLAGS_PUBREC 0x0
#define MQTT_REQUIRED_FLAGS_PUBREL 0x2
#define MQTT_REQUIRED_FLAGS_PUBCOMP 0x0
#define MQTT_REQUIRED_FLAGS_SUBSCRIBE 0x2
#define MQTT_REQUIRED_FLAGS_SUBACK 0x0
#define MQTT_REQUIRED_FLAGS_UNSUBSCRIBE 0x2
#define MQTT_REQUIRED_FLAGS_UNSUBACK 0x0
#define MQTT_REQUIRED_FLAGS_PINGREQ 0x0
#define MQTT_REQUIRED_FLAGS_PINGRESP 0x0
#define MQTT_REQUIRED_FLAGS_DISCONNECT 0x0

#define MQTT_PUBLISH_FLAG_DUP 0x8
#define MQTT_PUBLISH_FLAG_QOS1 0x2
#define MQTT_PUBLISH_FLAG_QOS2 0x4
#define MQTT_PUBLISH_FLAG_RETAIN 0x1

#define MQTT_CONNECT_PROTOCOL_NAME "MQTT"
#define MQTT_CONNECT_PROTOCOL_LEVEL 0x04

#define MQTT_CONNECT_FLAG_USER_NAME 0x80
#define MQTT_CONNECT_FLAG_PASSWORD 0x40
#define MQTT_CONNECT_FLAG_WILL_RETAIN 0x20
#define MQTT_CONNECT_FLAG_WILL_QOS1 0x08
#define MQTT_CONNECT_FLAG_WILL_QOS2 0x10
#define MQTT_CONNECT_FLAG_WILL_FLAG 0x04
#define MQTT_CONNECT_FLAG_CLEAN_SESSION 0x02

#define MQTT_CONNACK_FLAG_SESSION_PRESENT 0x01
#define MQTT_CONNACK_RETURN_CODE_ACCEPTED 0x00
#define MQTT_CONNACK_RETURN_CODE_REFUSED_PROTOCOL 0x01
#define MQTT_CONNACK_RETURN_CODE_REFUSED_CLIENT_ID 0x02
#define MQTT_CONNACK_RETURN_CODE_REFUSED_UNAVAILABLE 0x03
#define MQTT_CONNACK_RETURN_CODE_REFUSED_BAD_CREDENTIALS 0x04
#define MQTT_CONNACK_RETURN_CODE_REFUSED_UNAUTHORIZED 0x05

#define MQTT_SUBACK_RETURN_CODE_SUCCESS_QOS_0 0x00
#define MQTT_SUBACK_RETURN_CODE_SUCCESS_QOS_1 0x01
#define MQTT_SUBACK_RETURN_CODE_SUCCESS_QOS_2 0x02
#define MQTT_SUBACK_RETURN_CODE_FAILURE 0x80

#if (defined _WIN32 && defined _MSC_VER)
#pragma comment(lib, "ws2_32.lib")
#endif

namespace mqtt {
#ifdef _WIN32
    class WinSock {
    public:
        WinSock(const WinSock &) = delete;
        WinSock(WinSock &&) = delete;
        virtual ~WinSock() {
            WSACleanup();
        }
        WinSock &operator=(const WinSock &) = delete;
        static WinSock &Initialize() {
            static WinSock instance;
            return instance;
        }
    private:
        WinSock() {
            WSADATA wsaData;
            int error = WSAStartup(MAKEWORD(2, 2), &wsaData);
            if (error != NO_ERROR) {
                throw std::runtime_error("Cannot initialize WinSock!");
            }
            if ((LOBYTE(wsaData.wVersion) != 2) || (HIBYTE(wsaData.wVersion) != 2)) {
                WSACleanup();
                throw std::runtime_error("Cannot initialize WinSock!");
            }
        }
    };

#endif
    class AddressIP {
    public:
        enum class Type {
            IPv4,
            IPv6,
            Unknown
        };
        AddressIP() {
            address = reinterpret_cast<sockaddr *>(new sockaddr_in);
            std::memset(address, 0, sizeof(sockaddr_in));
            (reinterpret_cast<sockaddr_in *>(address))->sin_family = AF_INET;
        }
        AddressIP(const std::string &address, Type type = Type::Unknown) : AddressIP() {
            auto init = [&](Type type) {
                switch (type) {
                case Type::IPv6:
                    this->address = reinterpret_cast<sockaddr *>(new sockaddr_in6);
                    std::memset(this->address, 0, sizeof(sockaddr_in6));
                    (reinterpret_cast<sockaddr_in6 *>(this->address))->sin6_family = AF_INET6;
                    if (inet_pton(AF_INET6, address.c_str(), &(reinterpret_cast<sockaddr_in6 *>(this->address))->sin6_addr) <= 0) {
                        delete this->address;
                        throw std::runtime_error("Incorrect IPv6 address provided!");
                    }
                    break;
                case Type::IPv4:
                default:
                    this->address = reinterpret_cast<sockaddr *>(new sockaddr_in);
                    std::memset(this->address, 0, sizeof(sockaddr_in));
                    (reinterpret_cast<sockaddr_in *>(this->address))->sin_family = AF_INET;
                    if (inet_pton(AF_INET, address.c_str(), &(reinterpret_cast<sockaddr_in *>(this->address))->sin_addr) <= 0) {
                        delete this->address;
                        throw std::runtime_error("Incorrect IPv4 address provided!");
                    }
                }
            };
            bool resolve = true;
            if ((type != Type::Unknown) && IsCorrect(address, type)) {
                init(type);
                resolve = false;
            } else if (type == Type::Unknown) {
                if (IsCorrect(address, Type::IPv4)) {
                    init(Type::IPv4);
                    resolve = false;
                } else if (IsCorrect(address, Type::IPv6)) {
                    init(Type::IPv6);
                    resolve = false;
                }
            }
            if (resolve) {
                Resolve(address, type);
            }
        }
        AddressIP(const std::string &address, uint16_t port, Type type = Type::Unknown) : AddressIP(address, type) {
            SetPort(port);
        }
        AddressIP(unsigned long address) : AddressIP() {
            (reinterpret_cast<sockaddr_in *>(this->address))->sin_addr.s_addr = htonl(address);
        }
        AddressIP(unsigned long address, uint16_t port) : AddressIP(address) {
            SetPort(port);
        }
        AddressIP(const AddressIP &source) {
            switch (source.GetType()) {
            case Type::IPv6:
                address = reinterpret_cast<sockaddr *>(new sockaddr_in6);
                std::memcpy(address, source.address, sizeof(sockaddr_in6));
                break;
            case Type::IPv4:
            default:
                address = reinterpret_cast<sockaddr *>(new sockaddr_in);
                std::memcpy(address, source.address, sizeof(sockaddr_in));
            }
        }
        AddressIP(AddressIP &&source) {
            address = source.address;
            source.address = reinterpret_cast<sockaddr *>(new sockaddr_in);
            std::memset(source.address, 0, sizeof(sockaddr_in));
            (reinterpret_cast<sockaddr_in *>(source.address))->sin_family = AF_INET;
        }
        virtual ~AddressIP() {
            delete address;
        }
        AddressIP &operator=(const AddressIP &source) {
            delete address;
            switch (source.GetType()) {
            case Type::IPv6:
                address = reinterpret_cast<sockaddr *>(new sockaddr_in6);
                std::memcpy(address, source.address, sizeof(sockaddr_in6));
                break;
            case Type::IPv4:
            default:
                address = reinterpret_cast<sockaddr *>(new sockaddr_in);
                std::memcpy(address, source.address, sizeof(sockaddr_in));
            }
            return *this;
        }
        AddressIP &operator=(AddressIP &&source) {
            delete address;
            address = source.address;
            source.address = reinterpret_cast<sockaddr *>(new sockaddr_in);
            std::memset(source.address, 0, sizeof(sockaddr_in));
            (reinterpret_cast<sockaddr_in *>(source.address))->sin_family = AF_INET;
            return *this;
        }
        AddressIP &Resolve(const std::string &address, Type type = Type::IPv4) {
#ifdef _WIN32
            WinSock::Initialize();
#endif
            addrinfo hints;
            std::memset(&hints, 0, sizeof(addrinfo));
            hints.ai_family = AF_UNSPEC;
            hints.ai_socktype = SOCK_STREAM;
            hints.ai_protocol = IPPROTO_TCP;

            addrinfo *result = NULL;
            if (getaddrinfo(address.c_str(), NULL, &hints, &result) == 0) {
                for (addrinfo *ptr = result; ptr != NULL; ptr = ptr->ai_next) {
                    switch (ptr->ai_family) {
                    case AF_INET:
                        if ((type != Type::IPv4) && (type != Type::Unknown)) {
                            break;
                        }
                        delete this->address;
                        this->address = reinterpret_cast<sockaddr *>(new sockaddr_in);
                        std::memcpy(this->address, ptr->ai_addr, sizeof(sockaddr_in));
                        freeaddrinfo(result);
                        type = Type::IPv4;
                        return *this;
                    case AF_INET6:
                        if ((type != Type::IPv6) && (type != Type::Unknown)) {
                            break;
                        }
                        delete this->address;
                        this->address = reinterpret_cast<sockaddr *>(new sockaddr_in6);
                        std::memcpy(this->address, ptr->ai_addr, sizeof(sockaddr_in6));
                        freeaddrinfo(result);
                        type = Type::IPv6;
                        return *this;
                    default:
                        break;
                    }
                }
                freeaddrinfo(result);
            }
            throw std::runtime_error("Cannot resolve address: " + address);
        }
        operator std::string() const {
            char buffer[INET6_ADDRSTRLEN];
            switch (GetType()) {
            case Type::IPv6:
                if (inet_ntop(AF_INET6, &(reinterpret_cast<sockaddr_in6 *>(address))->sin6_addr, buffer, INET6_ADDRSTRLEN) != NULL) {
                    return std::string(buffer);
                }
                throw std::runtime_error("Cannot convert IPv6 address structure");
            case Type::IPv4:
            default:
                if (inet_ntop(AF_INET, &(reinterpret_cast<sockaddr_in *>(address))->sin_addr, buffer, INET6_ADDRSTRLEN) != NULL) {
                    return std::string(buffer);
                }
                throw std::runtime_error("Cannot convert IPv4 address structure");
            }
        }
        void SetPort(uint16_t port) {
            switch (GetType()) {
            case Type::IPv6:
                (reinterpret_cast<sockaddr_in6 *>(address))->sin6_port = htons(port);
                break;
            case Type::IPv4:
            default:
                (reinterpret_cast<sockaddr_in *>(address))->sin_port = htons(port);
            }
        }
        uint16_t GetPort() const {
            switch (GetType()) {
            case Type::IPv6:
                return (reinterpret_cast<sockaddr_in6 *>(address))->sin6_port;
                break;
            case Type::IPv4:
            default:
                return (reinterpret_cast<sockaddr_in *>(address))->sin_port;
            }
        }
        Type GetType() const {
            switch (address->sa_family) {
            case AF_INET6:
                return Type::IPv6;
            case AF_INET:
            default:
                return Type::IPv4;
            }
        }
        sockaddr *GetSockAddr() const {
            return address;
        }
#ifdef _WIN32
        int GetSockAddrLength() const {
#else
        socklen_t GetSockAddrLength() const {
#endif
            switch (GetType()) {
            case Type::IPv6:
                return sizeof(sockaddr_in6);
            case Type::IPv4:
            default:
                return sizeof(sockaddr_in);
            }
        }
        static inline bool IsCorrect(const std::string &address, Type type = Type::IPv4) {
            return (type == Type::IPv4) ?
                std::regex_match(address, std::regex("^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$")) :
                std::regex_match(address, std::regex("^(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))$"));
        }
        static int GetFamily(Type type) {
            switch (type) {
            case Type::IPv6:
                return AF_INET6;
            case Type::IPv4:
            default:
                return AF_INET;
            }
        }
    private:
        sockaddr *address;
    };

    class TCPServer {
    public:
        struct Event {
            uint64_t connectionId;
            AddressIP address;
            enum class Type {
                Connected,
                Disconnected,
                None
            } type;
        };
        struct InputStream {
            uint8_t *data;
            unsigned length;
        };
        struct OutputStream : public InputStream {
            unsigned consumed;
            bool disconnect;
        };
        using EventHandler = std::function<void(const Event &connection, const InputStream &input, OutputStream &output)>;
        TCPServer() : enabled(false) { }
        TCPServer(const TCPServer &) = delete;
        TCPServer(TCPServer &&) = delete;
        TCPServer &operator=(const TCPServer &) = delete;
        void SetHandler(const EventHandler &handler) {
            std::lock_guard<std::mutex> lock(access);
            this->handler = handler;
        }
        void Enable(const std::string address, uint16_t port, uint32_t maxConn = 64) {
            std::lock_guard<std::mutex> lock(access);
#ifdef _WIN32
            WinSock::Initialize();
#endif
            AddressIP server(address, port);

            TCPSERVER_SOCKET conn, sock;
#ifdef _WIN32
            if ((sock = socket(AddressIP::GetFamily(server.GetType()), SOCK_STREAM, IPPROTO_TCP)) == INVALID_SOCKET) {
#else
            if ((sock = socket(AddressIP::GetFamily(server.GetType()), SOCK_STREAM, IPPROTO_TCP)) == TCPSERVER_SOCKET_ERROR) {
#endif
                throw std::runtime_error("Cannot enable service (socket error)");
            }

            auto setNonBlock = [](TCPSERVER_SOCKET sock) -> bool {
#ifdef _WIN32
                unsigned long mode = 1;
                if (ioctlsocket(sock, FIONBIO, &mode) != NO_ERROR) {
#else
                int flags = fcntl(sock, F_GETFL, 0);
                if ((flags == -1) || fcntl(sock, F_SETFL, flags | O_NONBLOCK) == -1) {
#endif
                    return false;
                }
                return true;
            };

            if (!setNonBlock(sock)) {
                TCPSERVER_CLOSESOCKET(sock);
                throw std::runtime_error("Cannot enable service (ioctlsocket error)");
            }

            int enable = 1;
            if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, reinterpret_cast<char *>(&enable), sizeof(enable)) == TCPSERVER_SOCKET_ERROR) {
                TCPSERVER_CLOSESOCKET(sock);
                throw std::runtime_error("Cannot enable service (setsockopt error)");
            }

            if (bind(sock, server.GetSockAddr(), server.GetSockAddrLength()) == TCPSERVER_SOCKET_ERROR) {
                TCPSERVER_CLOSESOCKET(sock);
                throw std::runtime_error("Cannot enable service (bind error)");
            }

            if (listen(sock, maxConn) == TCPSERVER_SOCKET_ERROR) {
                TCPSERVER_CLOSESOCKET(sock);
                throw std::runtime_error("Cannot enable service (listen error)");
            }

            enabled = true;
            uint64_t id = ULLONG_MAX;
            auto getNextId = [&]() -> uint64_t {
                for (uint64_t nextId = id + 1; nextId != id; nextId++) {
                    auto client = clients.begin();
                    while (client != clients.end()) {
                        if ((*client)->GetConnectionId() == nextId) {
                            break;
                        }
                        client++;
                    }
                    if (client == clients.end()) {
                        id = nextId;
                        return id;
                    }
                }
                throw std::runtime_error("Cannot generate connection identifier");
            };

            while (enabled) {
                AddressIP client(server);
#ifdef _WIN32
                int length = client.GetSockAddrLength();
#else
                socklen_t length = client.GetSockAddrLength();
#endif
                if ((UpdateClients() >= maxConn) ||
#ifdef _WIN32
                    ((conn = accept(sock, client.GetSockAddr(), &length)) == INVALID_SOCKET)
#else
                    ((conn = accept(sock, client.GetSockAddr(), &length)) == TCPSERVER_SOCKET_ERROR)
#endif
                ) {
                    std::this_thread::sleep_for(std::chrono::microseconds(TCPSERVER_SERVER_NOP_DELAY));
                    continue;
                }
                if (!setNonBlock(conn) || (handler == nullptr)) {
                    TCPSERVER_CLOSESOCKET(conn);
                    continue;
                }
                try {
                    clients.push_back(new Client(conn, client, getNextId(), handler));
                } catch (...) {
#ifdef _WIN32
                    shutdown(conn, SD_BOTH);
#else
                    shutdown(conn, SHUT_RDWR);
#endif
                    TCPSERVER_CLOSESOCKET(conn);
                }
            }

            for (Client *client : clients) {
                client->Disable();
            }

            while (UpdateClients()) {
                std::this_thread::sleep_for(std::chrono::microseconds(TCPSERVER_SERVER_NOP_DELAY));
            }

            TCPSERVER_CLOSESOCKET(sock);
        }
        void Disable() {
            enabled = false;
        }
        bool IsEnabled() const {
            return enabled;
        }
    private:
        unsigned UpdateClients() {
            unsigned enabled = 0;
            for (auto client = clients.begin(); client != clients.end();) {
                if (!(*client)->IsEnabled()) {
                    delete *client;
                    client = clients.erase(client);
                } else {
                    enabled++;
                    client++;
                }
            }
            return enabled;
        };
        class Client {
        public:
            Client(TCPSERVER_SOCKET sock, const AddressIP &address, uint64_t connectionId, EventHandler &handler) : enabled(true), connectionId(connectionId) {
                thread = std::thread(ClientThread, this, sock, address, handler);
            }
            Client(const Client &) = delete;
            Client(Client &&) = delete;
            Client &operator=(const Client &) = delete;
            virtual ~Client() {
                Disable();
            }
            void Disable() {
                enabled = false;
                if (thread.joinable()) {
                    thread.join();
                }
            }
            inline bool IsEnabled() const {
                return enabled;
            }
            uint64_t GetConnectionId() const {
                return connectionId;
            }
        private:
            static void ClientThread(Client *instance, TCPSERVER_SOCKET sock, const AddressIP &address, EventHandler handler) noexcept {
                Event event = { instance->connectionId, address, Event::Type::Connected };
                InputStream input = { new uint8_t[TCPSERVER_RECV_BUFFER_LENGTH], 0 };
                OutputStream output; output.data = nullptr; output.disconnect = false;
                bool disconnected = false;
                while ((event.type == Event::Type::Connected) || instance->enabled) {
                    if (output.data != nullptr) {
                        int bytes = send(sock, reinterpret_cast<char *>(output.data), output.length, 0);
                        delete[] output.data; output.data = nullptr; output.length = 0;
                        if (bytes == TCPSERVER_SOCKET_ERROR) {
                            disconnected = true;
                            instance->enabled = false;
                            break;
                        }
                    } else if (!input.length && (event.type != Event::Type::Connected) && !output.disconnect) {
                        std::this_thread::sleep_for(std::chrono::microseconds(TCPSERVER_CLIENT_NOP_DELAY));
                    }
                    if (output.disconnect) {
                        instance->enabled = false;
                        break;
                    }
                    int bytes = recv(sock, reinterpret_cast<char *>(&input.data[input.length]), TCPSERVER_RECV_BUFFER_LENGTH - input.length, 0);
#ifdef _WIN32
                    if ((bytes == 0) || ((bytes == TCPSERVER_SOCKET_ERROR) && (WSAGetLastError() != WSAEWOULDBLOCK))) {
#else
                    if ((bytes == 0) || ((bytes == TCPSERVER_SOCKET_ERROR) && ((errno != EWOULDBLOCK) && (errno != EAGAIN)))) {
#endif
                        disconnected = true;
                        instance->enabled = false;
                        if (event.type != Event::Type::Connected) {
                            break;
                        }
                    }
                    input.length += (bytes != TCPSERVER_SOCKET_ERROR) ? bytes : 0;
                    try {
                        output.consumed = input.length; output.disconnect = false;
                        handler(event, input, output);
                        std::memcpy(input.data, &input.data[output.consumed], input.length - output.consumed);
                        input.length -= output.consumed;
                    } catch (...) {
                        instance->enabled = false;
                        break;
                    }
                    event.type = Event::Type::None;
                }
#ifdef _WIN32
                shutdown(sock, SD_BOTH);
#else
                shutdown(sock, SHUT_RDWR);
#endif
                TCPSERVER_CLOSESOCKET(sock);

                event.type = Event::Type::Disconnected;
                if (output.data != nullptr) {
                    delete[] output.data; output.data = nullptr; output.length = 0;
                }
                try {
                    output.consumed = input.length; output.disconnect = true;
                    handler(event, input, output);
                    if (output.data != nullptr) {
                        delete[] output.data;
                    }
                } catch (...) { }
                delete[] input.data;
            }
            std::thread thread;
            std::atomic_bool enabled;
            std::atomic_uint64_t connectionId;
        };
        EventHandler handler;
        std::vector<Client *> clients;
        std::atomic_bool enabled;
        std::mutex access;
    };

    DisconnectException::DisconnectException()
        : reason("Client disconnected") {
    }

    DisconnectException::DisconnectException(const std::string &reason)
        : reason(reason) {
    }

    const char *DisconnectException::what() const noexcept {
        return reason.c_str();
    };

    const char *NoPacketException::what() const noexcept {
        return "No MQTT packet";
    };

    class Packet {
    public:
        Packet() = delete;
        Packet(uint8_t packetType, uint8_t flags, const std::vector<uint8_t> &data) : packetType(packetType), flags(flags), data(data) {
            uint32_t remLenValue = static_cast<uint32_t>(data.size());
            do {
                uint32_t nextRemLenVal = remLenValue >> 7;
                remLen.insert(remLen.end(), (remLenValue & 0x7F) | (nextRemLenVal ? 0x80 : 0x00));
                remLenValue = nextRemLenVal;
            } while (remLenValue);
            if (remLen.size() > 4) {
                throw NoPacketException();
            }
        }
        Packet(const uint8_t *stream, uint32_t length) {
            if (length < 2) {
                throw NoPacketException();
            }
            packetType = stream[0] >> 4;
            flags = stream[0] & 0x0F;
            uint8_t remLenSize = 1;
            uint32_t remLenValue = stream[1] & 0x7F;
            unsigned multiplier = 0x80;
            while (stream[remLenSize] & 0x80) {
                remLenSize++;
                if (remLenSize > 4) {
                    throw std::invalid_argument("MQTT packet Remaining Length value malformed");
                }
                if (length <= remLenSize) {
                    throw NoPacketException();
                }
                remLenValue += (stream[remLenSize] & 0x7F) * multiplier;
                multiplier = multiplier << 7;
            }
            remLen.resize(remLenSize);
            std::memcpy(remLen.data(), &stream[1], remLenSize);
            if (length < 1 + remLenSize + remLenValue) {
                throw NoPacketException();
            }
            data.resize(remLenValue);
            std::memcpy(data.data(), &stream[1 + remLenSize], remLenValue);
        }
        uint8_t GetPacketType() const {
            return packetType;
        }
        uint8_t GetFlags() const {
            return flags;
        }
        const std::vector<uint8_t> &GetData() const {
            return data;
        }
        uint32_t GetSize() const {
            return static_cast<uint32_t>(data.size() + remLen.size() + 1);
        }
        operator std::vector<uint8_t>() const {
            std::vector<uint8_t> stream;
            stream.push_back((packetType << 4) | (flags & 0x0F));
            stream.insert(stream.end(), remLen.begin(), remLen.end());
            stream.insert(stream.end(), data.begin(), data.end());
            return stream;
        }
        static std::vector<Packet> feedList(std::vector<uint8_t> &stream) {
            unsigned consumed = 0;
            std::vector<Packet> packets;
            while (true) {
                try {
                    packets.push_back(Packet(&(stream.data()[consumed]), static_cast<unsigned>(stream.size() - consumed)));
                    consumed += std::prev(packets.end())->GetSize();
                } catch (NoPacketException &) {
                    std::memcpy(stream.data(), &(stream.data()[consumed]), consumed);
                    stream.resize(stream.size() - consumed);
                    return packets;
                } catch (...) {
                    throw;
                }
            }
        }
    private:
        uint8_t packetType, flags;
        std::vector<uint8_t> remLen;
        std::vector<uint8_t> data;
    };

    class String {
    public:
        String() : string() { }
        String(const std::string &string) : string(string) { }
        String(const uint8_t *stream, uint32_t length) {
            if (length < 2) {
                throw std::invalid_argument("Cannot create MQTT string from stream, data stream to short");
            }
            uint16_t size = (stream[0] << 8) | stream[1];
            if (length < static_cast<unsigned>(size + 2)) {
                throw std::invalid_argument("Cannot create MQTT string from stream, data stream to short");
            }
            string.resize(size);
            for (unsigned i = 0; i < size; i++) {
                string[i] = stream[i + 2];
            }
        }
        operator std::vector<uint8_t>() const {
            std::vector<uint8_t> stream;
            stream.resize(GetSize());
            stream[0] = (string.size() >> 8) & 0xFF;
            stream[1] = string.size() & 0xFF;
            std::memcpy(&(stream.data()[2]), string.data(), string.size());
            return stream;
        }
        operator std::string() const {
            return string;
        }
        uint16_t GetSize() const {
            return static_cast<uint16_t>(string.size() + 2);
        }
    private:
        std::string string;
    };

    class Connections {
    public:
        struct Connection {
            uint64_t id;
            AddressIP address;
            bool connected;
            std::chrono::time_point<std::chrono::system_clock> timestamp;
            std::vector<uint8_t> input, output;
            uint16_t keepAlive;
        };
        Connection Add(uint64_t connectionId, const AddressIP &address, bool &connected) {
            connected = false;
            std::lock_guard<std::mutex> lock(access);
            for (auto connection = connections.begin(); connection != connections.end(); connection++) {
                if (connection->id == connectionId) {
                    connected = connection->connected;
                    connection = connections.erase(connection);
                    break;
                }
            }
            Connection connection = { connectionId, address, false, std::chrono::system_clock::now(), std::vector<uint8_t>(), std::vector<uint8_t>(), 0 };
            connections.push_back(connection);
            return connection;
        }
        Connection ClearBuffers(uint64_t connectionId) {
            std::lock_guard<std::mutex> lock(access);
            auto connection = connections.begin();
            while (connection != connections.end()) {
                if (connection->id == connectionId) {
                    break;
                }
                connection++;
            }
            if (connection == connections.end()) {
                return { 0, AddressIP(), false, std::chrono::system_clock::now(), std::vector<uint8_t>(), std::vector<uint8_t>(), 0 };
            }
            Connection previous = *connection;
            connection->input.clear();
            connection->output.clear();
            return previous;
        }
        void Update(const Connection &updated, bool connected, bool packetHandled, const std::chrono::time_point<std::chrono::system_clock> &timestamp) {
            std::lock_guard<std::mutex> lock(access);
            auto connection = connections.begin();
            while (connection != connections.end()) {
                if (connection->id == updated.id) {
                    break;
                }
                connection++;
            }
            if (connection == connections.end()) {
                throw std::runtime_error("Bad connection identifier");
            }
            if (packetHandled) {
                if (connected) {
                    connection->keepAlive = updated.keepAlive;
                }
                connection->connected = connected;
                connection->timestamp = timestamp;
            }
            connection->input = updated.input;
        }
        Connection Delete(uint64_t connectionId) {
            std::lock_guard<std::mutex> lock(access);
            for (auto connection = connections.begin(); connection != connections.end(); connection++) {
                if (connection->id == connectionId) {
                    Connection deleted = *connection;
                    connection = connections.erase(connection);
                    return deleted;
                }
            }
            throw std::runtime_error("Bad connection identifier");
        }
        void Send(uint64_t connectionId, const std::vector<uint8_t> &data) {
            std::lock_guard<std::mutex> lock(access);
            for (Connection &connection : connections) {
                if (connection.id == connectionId) {
                    connection.output.insert(connection.output.begin(), data.begin(), data.end());
                    return;
                }
            }
            throw std::runtime_error("Bad connection identifier");
        }
        AddressIP GetAddress(uint64_t connectionId) {
            std::lock_guard<std::mutex> lock(access);
            for (Connection &connection : connections) {
                if (connection.id == connectionId) {
                    return connection.address;
                }
            }
            throw std::runtime_error("Bad connection identifier");
        }
    private:
        std::mutex access;
        std::vector<Connection> connections;
    };

    uint8_t GetConnectReturnCode(ConnectResponse response) {
        switch (response) {
        case ConnectResponse::Accepted:
            return MQTT_CONNACK_RETURN_CODE_ACCEPTED;
        case ConnectResponse::RefusedProtocol:
            return MQTT_CONNACK_RETURN_CODE_REFUSED_PROTOCOL;
        case ConnectResponse::RefusedBadCredentials:
            return MQTT_CONNACK_RETURN_CODE_REFUSED_BAD_CREDENTIALS;
        case ConnectResponse::RefusedIdentifier:
            return MQTT_CONNACK_RETURN_CODE_REFUSED_CLIENT_ID;
        case ConnectResponse::RefusedUnauthorized:
            return MQTT_CONNACK_RETURN_CODE_REFUSED_UNAUTHORIZED;
        case ConnectResponse::RefusedUnavailable:
        default:
            return MQTT_CONNACK_RETURN_CODE_REFUSED_UNAVAILABLE;
        }
    }

    uint8_t GetSubscribeReturnCode(SubscribeResponse response) {
        switch (response) {
        case SubscribeResponse::QoS2:
            return MQTT_SUBACK_RETURN_CODE_SUCCESS_QOS_2;
        case SubscribeResponse::QoS1:
            return MQTT_SUBACK_RETURN_CODE_SUCCESS_QOS_1;
        case SubscribeResponse::QoS0:
            return MQTT_SUBACK_RETURN_CODE_SUCCESS_QOS_0;
        default:
            return MQTT_SUBACK_RETURN_CODE_FAILURE;
        }
    }

    Server::Server()
    {
        server = reinterpret_cast<void *>(new TCPServer());
        connections = reinterpret_cast<void *>(new Connections());
        reinterpret_cast<TCPServer *>(server)->SetHandler([&](const TCPServer::Event &event, const TCPServer::InputStream &input, TCPServer::OutputStream &output) {
            Connections *connections = reinterpret_cast<Connections *>(this->connections);
            bool connected = false, handled = false;
            auto connection = (event.type == TCPServer::Event::Type::Connected) ? connections->Add(event.connectionId, event.address, connected) : connections->ClearBuffers(event.connectionId);
            if (connected && (disconnect != nullptr)) {
                try {
                    disconnect(event.connectionId, false);
                } catch (...) { }
            }
            if (connection.input.size() + input.length > MQTT_BUFFER_MAX_LENGTH) {
                output.disconnect = true;
                return;
            }
            connected = connection.connected;
            std::vector<uint8_t> inputBuffer, outputBuffer;
            inputBuffer.resize(connection.input.size() + input.length);
            std::memcpy(inputBuffer.data(), connection.input.data(), connection.input.size());
            std::memcpy(&(inputBuffer.data()[connection.input.size()]), input.data, input.length);
            outputBuffer = connection.output;
            auto now = std::chrono::system_clock::now();
            if (!inputBuffer.empty()) {
                std::vector<Packet> packetStream = Packet::feedList(inputBuffer);
                for (Packet &packet : packetStream) {
                    handled = true;
                    try {
                        Packet response = HandlePacket(packet, event.connectionId, connected, connection.keepAlive);
                        std::vector<uint8_t> outputData = response;
                        if (outputBuffer.size() + outputData.size() > MQTT_BUFFER_MAX_LENGTH) {
                            throw std::runtime_error("Out of memory");
                        }
                        outputBuffer.insert(outputBuffer.end(), outputData.begin(), outputData.end());
                    } catch (NoPacketException &) {
                        continue;
                    } catch (...) {
                        output.disconnect = true;
                        break;
                    }
                }
            } else if (connection.keepAlive && (std::chrono::duration_cast<std::chrono::seconds>(now - connection.timestamp).count() > connection.keepAlive + (connection.keepAlive >> 1))) {
                output.disconnect = true;
            }
            if ((event.type != TCPServer::Event::Type::Disconnected) && !outputBuffer.empty()) {
                output.length = static_cast<unsigned>(outputBuffer.size());
                output.data = new uint8_t[outputBuffer.size()];
                std::memcpy(output.data, outputBuffer.data(), outputBuffer.size());
            }
            if (!inputBuffer.empty() || handled) {
                connections->Update(connection, connected, handled, now);
            }
            if (event.type == TCPServer::Event::Type::Disconnected) {
                auto deleted = connections->Delete(event.connectionId);
                if (deleted.connected && (disconnect != nullptr)) {
                    try {
                        disconnect(event.connectionId, false);
                    } catch (...) { }
                }
            }
        });
    }

    Server::~Server()
    {
        delete reinterpret_cast<TCPServer *>(server);
        delete reinterpret_cast<Connections *>(connections);
    }

    void Server::Enable(const std::string &address, uint16_t port, uint32_t maxConn)
    {
        std::lock_guard<std::mutex> lock(access);
        reinterpret_cast<TCPServer *>(server)->Enable(address, port, maxConn);
    }

    void Server::Disable()
    {
        reinterpret_cast<TCPServer *>(server)->Disable();
    }

    bool Server::IsEnabled() const
    {
        return reinterpret_cast<TCPServer *>(server)->IsEnabled();
    }

    void Server::SetConnectHandler(const ConnectHandler &handler)
    {
        std::lock_guard<std::mutex> lock(access);
        connect = handler;
    }

    void Server::SetDisconnectHandler(const DisconnectHandler &handler)
    {
        std::lock_guard<std::mutex> lock(access);
        disconnect = handler;
    }

    void Server::SetPublishHandler(const PublishHandler &handler)
    {
        std::lock_guard<std::mutex> lock(access);
        publish = handler;
    }

    void Server::SetPubackHandler(const PubackHandler &handler)
    {
        std::lock_guard<std::mutex> lock(access);
        puback = handler;
    }

    void Server::SetPubrecHandler(const PubackHandler &handler)
    {
        std::lock_guard<std::mutex> lock(access);
        pubrec = handler;
    }

    void Server::SetPubrelHandler(const PubackHandler &handler)
    {
        std::lock_guard<std::mutex> lock(access);
        pubrel = handler;
    }

    void Server::SetPubcompHandler(const PubackHandler &handler)
    {
        std::lock_guard<std::mutex> lock(access);
        pubcomp = handler;
    }

    void Server::SetSubscribeHandler(const SubscribeHandler &handler)
    {
        std::lock_guard<std::mutex> lock(access);
        subscribe = handler;
    }

    void Server::SetUnsubscribeHandler(const UnsubscribeHandler &handler)
    {
        std::lock_guard<std::mutex> lock(access);
        unsubscribe = handler;
    }

    void Server::Publish(uint64_t connectionId, uint16_t packetId, const std::string &topicName, const std::vector<uint8_t> &payload, const PublishFlags &flags) {
        unsigned offset = 0;
        bool appendId = flags.qos1 || flags.qos2;
        std::vector<uint8_t> data, topicData = String(topicName);
        data.resize(topicData.size() + payload.size() + (appendId ? 2 : 0));
        std::memcpy(data.data(), topicData.data(), topicData.size());
        offset += static_cast<unsigned>(topicData.size());
        if (appendId) {
            data[offset++] = packetId >> 8;
            data[offset++] = packetId & 0xFF;
        }
        std::memcpy(&(data.data()[offset]), payload.data(), payload.size());
        Packet publish(
            MQTT_CONTROL_PACKET_TYPE_PUBLISH,
            (flags.dup ? MQTT_PUBLISH_FLAG_DUP : 0x0) |
            (flags.qos1 ? MQTT_PUBLISH_FLAG_QOS1 : 0x0) |
            (flags.qos2 ? MQTT_PUBLISH_FLAG_QOS2 : 0x0) |
            (flags.retain ? MQTT_PUBLISH_FLAG_RETAIN : 0x0),
            data
        );
        Connections *connections = reinterpret_cast<Connections *>(this->connections);
        connections->Send(connectionId, publish);
    }

    Packet Server::HandlePacket(const Packet &packet, uint64_t connectionId, bool &connected, uint16_t &timeLimit)
    {
        switch (packet.GetPacketType()) {
        case MQTT_CONTROL_PACKET_TYPE_CONNECT:
            if (packet.GetFlags() != MQTT_REQUIRED_FLAGS_CONNECT) {
                throw DisconnectException("CONNECT: invalid packet flags");
            } else {
                unsigned offset = 0;
                String protocolName;
                try {
                    protocolName = String(&packet.GetData()[offset], static_cast<uint32_t>(packet.GetData().size()));
                } catch (...) {
                    throw DisconnectException("CONNECT: malformed protocol name");
                }
                offset += protocolName.GetSize();
                if (packet.GetData().size() < offset + 4) {
                    throw DisconnectException("CONNECT: invalid packet length");
                }
                uint8_t protocolLevel = packet.GetData()[offset++];
                uint8_t connectFlags = packet.GetData()[offset++];
                uint16_t keepAlive = packet.GetData()[offset++] << 8;
                keepAlive |= packet.GetData()[offset++];
                String clientId;
                try {
                    clientId = String(&packet.GetData()[offset], static_cast<uint32_t>(packet.GetData().size() - offset));
                } catch (...) {
                    throw DisconnectException("CONNECT: malformed client identifier");
                }
                offset += clientId.GetSize();
                String willTopic, willMessage;
                if (connectFlags & MQTT_CONNECT_FLAG_WILL_FLAG) {
                    try {
                        willTopic = String(&packet.GetData()[offset], static_cast<uint32_t>(packet.GetData().size() - offset));
                    } catch (...) {
                        throw DisconnectException("CONNECT: malformed will topic");
                    }
                    offset += willTopic.GetSize();
                    try {
                        willMessage = String(&packet.GetData()[offset], static_cast<uint32_t>(packet.GetData().size() - offset));
                    } catch (...) {
                        throw DisconnectException("CONNECT: malformed will message");
                    }
                    offset += willMessage.GetSize();
                }
                String userName;
                if (connectFlags & MQTT_CONNECT_FLAG_USER_NAME) {
                    try {
                        userName = String(&packet.GetData()[offset], static_cast<uint32_t>(packet.GetData().size() - offset));
                    } catch (...) {
                        throw DisconnectException("CONNECT: malformed user name");
                    }
                    offset += userName.GetSize();
                }
                String password;
                if (connectFlags & MQTT_CONNECT_FLAG_USER_NAME) {
                    try {
                        password = String(&packet.GetData()[offset], static_cast<uint32_t>(packet.GetData().size() - offset));
                    } catch (...) {
                        throw DisconnectException("CONNECT: malformed password");
                    }
                    offset += password.GetSize();
                }
                bool sessionPresent = false;
                uint8_t returnCode = MQTT_CONNACK_RETURN_CODE_ACCEPTED;
                if ((static_cast<std::string>(protocolName) != MQTT_CONNECT_PROTOCOL_NAME) || (protocolLevel != MQTT_CONNECT_PROTOCOL_LEVEL) || connected || (offset < packet.GetData().size())) {
                    return Packet(MQTT_CONTROL_PACKET_TYPE_CONNACK, MQTT_REQUIRED_FLAGS_CONNACK, std::vector<uint8_t>({ 0x0, MQTT_CONNACK_RETURN_CODE_REFUSED_PROTOCOL }));
                } else if (connect != nullptr) {
                    try {
                        ConnectFlags flags = {
                            static_cast<bool>(connectFlags & MQTT_CONNECT_FLAG_USER_NAME),
                            static_cast<bool>(connectFlags & MQTT_CONNECT_FLAG_PASSWORD),
                            static_cast<bool>(connectFlags & MQTT_CONNECT_FLAG_WILL_RETAIN),
                            static_cast<bool>(connectFlags & MQTT_CONNECT_FLAG_WILL_QOS1),
                            static_cast<bool>(connectFlags & MQTT_CONNECT_FLAG_WILL_QOS2),
                            static_cast<bool>(connectFlags & MQTT_CONNECT_FLAG_WILL_FLAG),
                            static_cast<bool>(connectFlags & MQTT_CONNECT_FLAG_CLEAN_SESSION)
                        };
                        ConnectParams params = { clientId, willTopic, willMessage, userName, password, keepAlive };
                        returnCode = GetConnectReturnCode(connect(connectionId, flags, params, sessionPresent));
                    } catch (...) {
                        return Packet(MQTT_CONTROL_PACKET_TYPE_CONNACK, MQTT_REQUIRED_FLAGS_CONNACK, std::vector<uint8_t>({ 0x0, MQTT_CONNACK_RETURN_CODE_REFUSED_UNAVAILABLE }));
                    }
                }
                timeLimit = keepAlive;
                connected = (returnCode == MQTT_CONNACK_RETURN_CODE_ACCEPTED) || connected;
                return Packet(MQTT_CONTROL_PACKET_TYPE_CONNACK, MQTT_REQUIRED_FLAGS_CONNACK, std::vector<uint8_t>({ static_cast<uint8_t>(sessionPresent ? MQTT_CONNACK_FLAG_SESSION_PRESENT : 0x0), returnCode }));
            }
        case MQTT_CONTROL_PACKET_TYPE_PUBLISH:
            {
                unsigned offset = 0;
                String topicName;
                try {
                    topicName = String(&packet.GetData()[offset], static_cast<uint32_t>(packet.GetData().size()));
                } catch (...) {
                    throw DisconnectException("PUBLISH: malformed topic name");
                }
                offset += topicName.GetSize();
                if (packet.GetData().size() < offset + 2) {
                    throw DisconnectException("PUBLISH: invalid packet length");
                }
                PublishFlags flags = {
                    static_cast<bool>(packet.GetFlags() & MQTT_PUBLISH_FLAG_DUP),
                    static_cast<bool>(packet.GetFlags() & MQTT_PUBLISH_FLAG_QOS1),
                    static_cast<bool>(packet.GetFlags() & MQTT_PUBLISH_FLAG_QOS2),
                    static_cast<bool>(packet.GetFlags() & MQTT_PUBLISH_FLAG_RETAIN)
                };
                uint16_t packetIdentifier = 0;
                if (flags.qos1 || flags.qos2) {
                    packetIdentifier = packet.GetData()[offset++] << 8;
                    packetIdentifier |= packet.GetData()[offset++];
                }
                std::vector<uint8_t> payload;
                payload.resize(packet.GetData().size() - offset);
                std::memcpy(payload.data(), &packet.GetData()[offset], packet.GetData().size() - offset);
                if (flags.qos1 && flags.qos2) {
                    throw DisconnectException("PUBLISH: invalid QoS value");
                }
                std::size_t found = static_cast<std::string>(topicName).find("*");
                if (found != std::string::npos) {
                    throw DisconnectException("PUBLISH: invalid topic name");
                }
                if ((publish != nullptr) && connected) {
                    PublishResponse response = publish(connectionId, packetIdentifier, topicName, payload, flags);
                    switch (response) {
                    case PublishResponse::QoS1:
                        return Packet(MQTT_CONTROL_PACKET_TYPE_PUBACK, MQTT_REQUIRED_FLAGS_PUBACK, { static_cast<uint8_t>(packetIdentifier >> 8), static_cast<uint8_t>(packetIdentifier & 0xFF) });
                    case PublishResponse::QoS2:
                        return Packet(MQTT_CONTROL_PACKET_TYPE_PUBREC, MQTT_REQUIRED_FLAGS_PUBREC, { static_cast<uint8_t>(packetIdentifier >> 8), static_cast<uint8_t>(packetIdentifier & 0xFF) });
                    default:
                        break;
                    }
                }
                throw NoPacketException();
            }
        case MQTT_CONTROL_PACKET_TYPE_PUBACK:
            if (packet.GetFlags() != MQTT_REQUIRED_FLAGS_PUBACK) {
                throw DisconnectException("PUBACK: invalid packet flags");
            } else {
                unsigned offset = 0;
                if (packet.GetData().size() < 2) {
                    throw DisconnectException("PUBACK: invalid packet length");
                }
                uint16_t packetIdentifier = packet.GetData()[offset++] << 8;
                packetIdentifier |= packet.GetData()[offset++];
                if ((puback != nullptr) && connected) {
                    puback(connectionId, packetIdentifier);
                }
                throw NoPacketException();
            }
        case MQTT_CONTROL_PACKET_TYPE_PUBREL:
            if (packet.GetFlags() != MQTT_REQUIRED_FLAGS_PUBREL) {
                throw DisconnectException("PUBREL: invalid packet flags");
            } else {
                unsigned offset = 0;
                if (packet.GetData().size() != 2) {
                    throw DisconnectException("PUBREL: invalid packet length");
                }
                uint16_t packetIdentifier = packet.GetData()[offset++] << 8;
                packetIdentifier |= packet.GetData()[offset++];
                if ((pubrel != nullptr) && connected) {
                    pubrel(connectionId, packetIdentifier);
                }
                return Packet(MQTT_CONTROL_PACKET_TYPE_PUBCOMP, MQTT_REQUIRED_FLAGS_PUBCOMP, { static_cast<uint8_t>(packetIdentifier >> 8), static_cast<uint8_t>(packetIdentifier & 0xFF) });
            }
        case MQTT_CONTROL_PACKET_TYPE_PUBREC:
            if (packet.GetFlags() != MQTT_REQUIRED_FLAGS_PUBREC) {
                throw DisconnectException("PUBREC: invalid packet flags");
            } else {
                unsigned offset = 0;
                if (packet.GetData().size() != 2) {
                    throw DisconnectException("PUBREC: invalid packet length");
                }
                uint16_t packetIdentifier = packet.GetData()[offset++] << 8;
                packetIdentifier |= packet.GetData()[offset++];
                if ((pubrec != nullptr) && connected) {
                    pubrec(connectionId, packetIdentifier);
                }
                return Packet(MQTT_CONTROL_PACKET_TYPE_PUBREL, MQTT_REQUIRED_FLAGS_PUBREL, { static_cast<uint8_t>(packetIdentifier >> 8), static_cast<uint8_t>(packetIdentifier & 0xFF) });
            }
        case MQTT_CONTROL_PACKET_TYPE_PUBCOMP:
            if (packet.GetFlags() != MQTT_REQUIRED_FLAGS_PUBCOMP) {
                throw DisconnectException("PUBCOMP: invalid packet flags");
            } else {
                unsigned offset = 0;
                if (packet.GetData().size() != 2) {
                    throw DisconnectException("PUBCOMP: invalid packet length");
                }
                uint16_t packetIdentifier = packet.GetData()[offset++] << 8;
                packetIdentifier |= packet.GetData()[offset++];
                if ((pubcomp != nullptr) && connected) {
                    pubcomp(connectionId, packetIdentifier);
                }
                throw NoPacketException();
            }
        case MQTT_CONTROL_PACKET_TYPE_SUBSCRIBE:
            if (packet.GetFlags() != MQTT_REQUIRED_FLAGS_SUBSCRIBE) {
                throw DisconnectException("SUBSCRIBE: invalid packet flags");
            } else {
                unsigned offset = 0;
                if (packet.GetData().size() < 2) {
                    throw DisconnectException("SUBSCRIBE: invalid packet length");
                }
                uint16_t packetIdentifier = packet.GetData()[offset++] << 8;
                packetIdentifier |= packet.GetData()[offset++];
                std::vector<uint8_t> result = { static_cast<uint8_t>(packetIdentifier >> 8), static_cast<uint8_t>(packetIdentifier & 0xFF) };
                struct SubscribeRequest {
                    std::string topicFilter;
                    uint8_t requestedQoS;
                };
                std::vector<SubscribeRequest> requests;
                while (offset < packet.GetData().size()) {
                    String topicFilter;
                    try {
                        topicFilter = String(&packet.GetData()[offset], static_cast<uint32_t>(packet.GetData().size() - offset));
                    } catch (...) {
                        throw DisconnectException("SUBSCRIBE: malformed topic filter");
                    }
                    offset += topicFilter.GetSize();
                    if (packet.GetData().size() < offset + 1) {
                        throw DisconnectException("SUBSCRIBE: invalid packet length");
                    }
                    uint8_t requestedQoS = packet.GetData()[offset++];
                    if (requestedQoS > 2) {
                        throw DisconnectException("SUBSCRIBE: invalid QoS value");
                    }
                    requests.push_back({ static_cast<std::string>(topicFilter), requestedQoS });
                }
                if (requests.empty()) {
                    throw DisconnectException("SUBSCRIBE: missing at least one topic filter");
                }
                if (!connected) {
                    throw NoPacketException();
                }
                for (SubscribeRequest &request : requests) {
                    if (subscribe != nullptr) {
                        result.push_back(GetSubscribeReturnCode(subscribe(connectionId, request.topicFilter, request.requestedQoS)));
                        continue;
                    }
                    result.push_back(MQTT_SUBACK_RETURN_CODE_FAILURE);
                }
                return Packet(MQTT_CONTROL_PACKET_TYPE_SUBACK, MQTT_REQUIRED_FLAGS_SUBACK, result);
            }
        case MQTT_CONTROL_PACKET_TYPE_UNSUBSCRIBE:
            if (packet.GetFlags() != MQTT_REQUIRED_FLAGS_UNSUBSCRIBE) {
                throw DisconnectException("UNSUBSCRIBE: invalid packet flags");
            } else {
                unsigned offset = 0;
                if (packet.GetData().size() < 2) {
                    throw DisconnectException("UNSUBSCRIBE: invalid packet length");
                }
                uint16_t packetIdentifier = packet.GetData()[offset++] << 8;
                packetIdentifier |= packet.GetData()[offset++];
                struct UnsubscribeRequest {
                    std::string topicFilter;
                };
                std::vector<UnsubscribeRequest> requests;
                while (offset < packet.GetData().size()) {
                    String topicFilter;
                    try {
                        topicFilter = String(&packet.GetData()[offset], static_cast<uint32_t>(packet.GetData().size() - offset));
                    } catch (...) {
                        throw DisconnectException("UNSUBSCRIBE: malformed topic filter");
                    }
                    offset += topicFilter.GetSize();
                    requests.push_back({ static_cast<std::string>(topicFilter) });
                }
                if (requests.empty()) {
                    throw DisconnectException("UNSUBSCRIBE: missing at least one topic filter");
                }
                if (!connected) {
                    throw NoPacketException();
                }
                for (UnsubscribeRequest &request : requests) {
                    if (unsubscribe != nullptr) {
                        unsubscribe(connectionId, request.topicFilter);
                    }
                }
                return Packet(MQTT_CONTROL_PACKET_TYPE_UNSUBACK, MQTT_REQUIRED_FLAGS_UNSUBACK, { static_cast<uint8_t>(packetIdentifier >> 8), static_cast<uint8_t>(packetIdentifier & 0xFF) });
            }
        case MQTT_CONTROL_PACKET_TYPE_PINGREQ:
            if (packet.GetFlags() != MQTT_REQUIRED_FLAGS_PINGREQ) {
                throw DisconnectException("PINGREQ: invalid packet flags");
            }
            if (!packet.GetData().empty()) {
                throw DisconnectException("PINGREQ: invalid packet length");
            }
            if (!connected) {
                throw NoPacketException();
            }
            return Packet(MQTT_CONTROL_PACKET_TYPE_PINGRESP, MQTT_REQUIRED_FLAGS_PINGRESP, std::vector<uint8_t>());
        case MQTT_CONTROL_PACKET_TYPE_DISCONNECT:
            if (packet.GetFlags() != MQTT_REQUIRED_FLAGS_DISCONNECT) {
                throw DisconnectException("DISCONNECT: invalid packet flags");
            }
            if (!packet.GetData().empty()) {
                throw DisconnectException("DISCONNECT: invalid packet length");
            }
            if (!connected) {
                throw NoPacketException();
            }
            if (disconnect != nullptr) {
                disconnect(connectionId, true);
            }
            connected = false;
            throw DisconnectException();
        default:
            throw DisconnectException("Unsupported packet type");
        }
    }

    std::string Server::GetAddress(uint64_t connectionId) {
        Connections *connections = reinterpret_cast<Connections *>(this->connections);
        AddressIP address = connections->GetAddress(connectionId);
        if ((address.GetType() == AddressIP::Type::IPv4) && (reinterpret_cast<sockaddr_in *>(address.GetSockAddr())->sin_addr.s_addr == htonl(INADDR_ANY))) {
            throw std::invalid_argument("Cannot obtain connection address");
        }
        return address;
    }
}
