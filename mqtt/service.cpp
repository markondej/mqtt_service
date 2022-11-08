#include "service.hpp"
#include <fstream>
#include <cassert>
#include <chrono>
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
#include <climits>
#endif

#ifndef _MSC_VER
using std::min;
#endif

#ifndef SERVICE_TOPICS_LIMIT
#define SERVICE_TOPICS_LIMIT USHRT_MAX
#endif
#ifndef SERVICE_PAYLOAD_SIZE_LIMIT
#define SERVICE_PAYLOAD_SIZE_LIMIT 32 * 1024 * 1024
#endif
#ifndef SERVICE_REGISTERED_QOS2_PACKETS_LIMIT
#define SERVICE_REGISTERED_QOS2_PACKETS_LIMIT USHRT_MAX
#endif
#ifndef SERVICE_RECEIVED_PAYLOADS_LIMIT
#define SERVICE_RECEIVED_PAYLOADS_LIMIT USHRT_MAX
#endif
#ifndef SERVICE_PUBLISHED_PAYLOADS_LIMIT
#define SERVICE_PUBLISHED_PAYLOADS_LIMIT USHRT_MAX
#endif
#ifndef SERVICE_DEFAULT_KEEP_ALIVE_TIME
#define SERVICE_DEFAULT_KEEP_ALIVE_TIME 60
#endif

#define SERVICE_FILE_BUFFER_LENGTH 1024
#define SERVICE_STATUS_INTERVAL 30
#define SERVICE_NOP_DELAY 1000

#ifndef MQTT_SERVER_CONNECTIONS_LIMIT
#define MQTT_SERVER_CONNECTIONS_LIMIT USHRT_MAX
#endif

#ifndef MQTT_SERVER_RECV_BUFFER_LENGTH
#define MQTT_SERVER_RECV_BUFFER_LENGTH 1024
#endif

#define MQTT_SERVER_SERVER_NOP_DELAY 1000
#define MQTT_SERVER_CLIENT_NOP_DELAY 1000

#ifdef _WIN32
#define MQTT_SERVER_SOCKET SOCKET
#define MQTT_SERVER_SOCKLEN int
#define MQTT_SERVER_SOCKET_ERROR SOCKET_ERROR
#define MQTT_SERVER_CLOSESOCKET closesocket
#else
#define MQTT_SERVER_SOCKET int
#define MQTT_SERVER_SOCKLEN socklen_t
#define MQTT_SERVER_SOCKET_ERROR -1
#define MQTT_SERVER_CLOSESOCKET close
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
                throw std::runtime_error("Cannot initialize WinSock");
            }
            if ((LOBYTE(wsaData.wVersion) != 2) || (HIBYTE(wsaData.wVersion) != 2)) {
                WSACleanup();
                throw std::runtime_error("Cannot initialize WinSock");
            }
        }
    };

#endif
    class IPAddress {
    public:
        enum class Type {
            IPv4,
            IPv6,
            Unknown
        };
        IPAddress() {
            address = reinterpret_cast<sockaddr *>(new sockaddr_in);
            std::memset(address, 0, sizeof(sockaddr_in));
            (reinterpret_cast<sockaddr_in *>(address))->sin_family = AF_INET;
        }
        IPAddress(const std::string &address, Type type = Type::Unknown) {
            auto init = [&](Type type) {
                switch (type) {
                case Type::IPv6:
                    this->address = reinterpret_cast<sockaddr *>(new sockaddr_in6);
                    std::memset(this->address, 0, sizeof(sockaddr_in6));
                    (reinterpret_cast<sockaddr_in6 *>(this->address))->sin6_family = AF_INET6;
                    if (inet_pton(AF_INET6, address.c_str(), &(reinterpret_cast<sockaddr_in6 *>(this->address))->sin6_addr) <= 0) {
                        delete this->address;
                        throw std::runtime_error("Incorrect IPv6 address provided");
                    }
                    break;
                case Type::IPv4:
                default:
                    this->address = reinterpret_cast<sockaddr *>(new sockaddr_in);
                    std::memset(this->address, 0, sizeof(sockaddr_in));
                    (reinterpret_cast<sockaddr_in *>(this->address))->sin_family = AF_INET;
                    if (inet_pton(AF_INET, address.c_str(), &(reinterpret_cast<sockaddr_in *>(this->address))->sin_addr) <= 0) {
                        delete this->address;
                        throw std::runtime_error("Incorrect IPv4 address provided");
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
        IPAddress(const std::string &address, uint16_t port, Type type = Type::Unknown) : IPAddress(address, type) {
            SetPort(port);
        }
        IPAddress(unsigned long address) : IPAddress() {
            (reinterpret_cast<sockaddr_in *>(this->address))->sin_addr.s_addr = htonl(address);
        }
        IPAddress(unsigned long address, uint16_t port) : IPAddress(address) {
            SetPort(port);
        }
        IPAddress(const IPAddress &source) {
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
        IPAddress(IPAddress &&source) {
            address = source.address;
            source.address = reinterpret_cast<sockaddr *>(new sockaddr_in);
            std::memset(source.address, 0, sizeof(sockaddr_in));
            (reinterpret_cast<sockaddr_in *>(source.address))->sin_family = AF_INET;
        }
        virtual ~IPAddress() {
            delete address;
        }
        IPAddress &operator=(const IPAddress &source) {
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
        IPAddress &operator=(IPAddress &&source) {
            delete address;
            address = source.address;
            source.address = reinterpret_cast<sockaddr *>(new sockaddr_in);
            std::memset(source.address, 0, sizeof(sockaddr_in));
            (reinterpret_cast<sockaddr_in *>(source.address))->sin_family = AF_INET;
            return *this;
        }
        IPAddress &Resolve(const std::string &address, Type type = Type::IPv4) {
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
                return ntohs((reinterpret_cast<sockaddr_in6 *>(address))->sin6_port);
                break;
            case Type::IPv4:
            default:
                return ntohs((reinterpret_cast<sockaddr_in *>(address))->sin_port);
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
        MQTT_SERVER_SOCKLEN GetSockAddrLength() const {
            switch (GetType()) {
            case Type::IPv6:
                return sizeof(sockaddr_in6);
            case Type::IPv4:
            default:
                return sizeof(sockaddr_in);
            }
        }
        static bool IsCorrect(const std::string &address, Type type = Type::IPv4) {
            switch (type) {
            case Type::IPv4:
                return std::regex_match(address, std::regex("^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$"));
            case Type::IPv6:
                return std::regex_match(address, std::regex("^(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))$"));
            default:
                return IsCorrect(address, Type::IPv4) || IsCorrect(address, Type::IPv6);
            }
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
            const IPAddress *address;
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
        struct OutputStream : InputStream {
            bool disconnect;
        };
        using EventHandler = std::function<void(const Event &connection, const InputStream &input, OutputStream &output)>;
        TCPServer() : enabled(false), disable(false), eventHandler(nullptr) { }
        virtual ~TCPServer() {
            Disable();
            while (enabled.load()) {
                std::this_thread::sleep_for(std::chrono::microseconds(MQTT_SERVER_SERVER_NOP_DELAY));
            }
            FreeHandler(eventHandler);
        }
        TCPServer(const TCPServer &) = delete;
        TCPServer(TCPServer &&) = delete;
        TCPServer &operator=(const TCPServer &) = delete;
        void SetEventHandler(const EventHandler &handler) {
            SetHandler(eventHandler, handler);
        }
        void Enable(const std::string &address, uint16_t port, uint32_t connections = MQTT_SERVER_CONNECTIONS_LIMIT) {
            bool required = false;
            if (!enabled.compare_exchange_strong(required, true)) {
                throw std::runtime_error("Cannot enable service (already enabled)");
            }

            std::vector<Client *> clients;

#ifdef _WIN32
            MQTT_SERVER_SOCKET sock = INVALID_SOCKET;
#else
            MQTT_SERVER_SOCKET sock = MQTT_SERVER_SOCKET_ERROR;
#endif

            try {
#ifdef _WIN32
                WinSock::Initialize();
#endif
                IPAddress server(address, port);

#ifdef _WIN32
                if ((sock = socket(IPAddress::GetFamily(server.GetType()), SOCK_STREAM, IPPROTO_TCP)) == INVALID_SOCKET) {
#else
                if ((sock = socket(IPAddress::GetFamily(server.GetType()), SOCK_STREAM, IPPROTO_TCP)) == MQTT_SERVER_SOCKET_ERROR) {
#endif
                    throw std::runtime_error("Cannot enable service (socket error)");
                }

                auto setNonBlock = [](MQTT_SERVER_SOCKET sock) -> bool {
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
                    throw std::runtime_error("Cannot enable service (ioctlsocket error)");
                }

                int enable = 1;
                if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, reinterpret_cast<char *>(&enable), sizeof(enable)) == MQTT_SERVER_SOCKET_ERROR) {
                    throw std::runtime_error("Cannot enable service (setsockopt error)");
                }

                if (bind(sock, server.GetSockAddr(), server.GetSockAddrLength()) == MQTT_SERVER_SOCKET_ERROR) {
                    throw std::runtime_error("Cannot enable service (bind error)");
                }

                if (listen(sock, connections) == MQTT_SERVER_SOCKET_ERROR) {
                    throw std::runtime_error("Cannot enable service (listen error)");
                }

                disable.store(false);

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
                auto updateClients = [&]() {
                    unsigned enabled = 0;
                    for (auto client = clients.begin(); client != clients.end();) {
                        if (!(*client)->IsEnabled()) {
                            delete *client;
                            client = clients.erase(client);
                        }
                        else {
                            enabled++;
                            client++;
                        }
                    }
                    return enabled;
                };

                while (!disable.load()) {
                    IPAddress client(server);

                    MQTT_SERVER_SOCKET conn;
                    MQTT_SERVER_SOCKLEN length = client.GetSockAddrLength();
                    if ((updateClients() >= connections) ||
#ifdef _WIN32
                        ((conn = accept(sock, client.GetSockAddr(), &length)) == INVALID_SOCKET)
#else
                        ((conn = accept(sock, client.GetSockAddr(), &length)) == MQTT_SERVER_SOCKET_ERROR)
#endif
                        ) {
                        std::this_thread::sleep_for(std::chrono::microseconds(MQTT_SERVER_SERVER_NOP_DELAY));
                        continue;
                    }
                    if (!setNonBlock(conn)) {
                        MQTT_SERVER_CLOSESOCKET(conn);
                        continue;
                    }
                    try {
                        clients.push_back(new Client(conn, client, getNextId(), eventHandler));
                    } catch (...) {
#ifdef _WIN32
                        shutdown(conn, SD_BOTH);
#else
                        shutdown(conn, SHUT_RDWR);
#endif
                        MQTT_SERVER_CLOSESOCKET(conn);
                    }
                }

                for (Client *client : clients) {
                    client->Disable();
                }

                while (updateClients()) {
                    std::this_thread::sleep_for(std::chrono::microseconds(MQTT_SERVER_SERVER_NOP_DELAY));
                }

                MQTT_SERVER_CLOSESOCKET(sock);
            } catch (...) {
                for (auto &client : clients) {
                    delete client;
                }
#ifdef _WIN32
                if (sock != INVALID_SOCKET) {
#else
                if (sock != MQTT_SERVER_SOCKET_ERROR) {
#endif
                    MQTT_SERVER_CLOSESOCKET(sock);
                }
                enabled.store(false);
                throw;
            }

            enabled.store(false);
        }
        void Disable() {
            disable.store(true);
        }
        bool IsEnabled() const {
            return enabled.load();
        }
    protected:
        template <typename T>
        void SetHandler(std::atomic<T *> &inner, const T &handler) {
            if (handler == nullptr) {
                return;
            }
            T *required = nullptr, *desired = new T(handler);
            if (!inner.compare_exchange_strong(required, desired)) {
                delete desired;
            }
        }
        template <typename T>
        void FreeHandler(std::atomic<T *> &inner) {
            T *handler = inner.exchange(nullptr);
            if (handler != nullptr) {
                delete handler;
            }
        }
    private:
        class Client {
        public:
            Client(MQTT_SERVER_SOCKET sock, const IPAddress &address, uint64_t connectionId, const std::atomic<EventHandler *> &eventHandler) : enabled(true), disable(false), connectionId(connectionId) {
                thread = std::thread(ClientThread, this, sock, address, &eventHandler);
            }
            Client(const Client &) = delete;
            Client(Client &&) = delete;
            Client &operator=(const Client &) = delete;
            virtual ~Client() {
                Disable();
            }
            void Disable() {
                if (!disable.exchange(true) && thread.joinable()) {
                    thread.join();
                }
            }
            bool IsEnabled() const {
                return enabled.load();
            }
            uint64_t GetConnectionId() const {
                return connectionId;
            }
        private:
            static void ClientThread(Client *instance, MQTT_SERVER_SOCKET sock, const IPAddress &address, const std::atomic<EventHandler *> *eventHandler) noexcept {
                Event event = { instance->connectionId, &address, Event::Type::Connected };
                InputStream input = { nullptr, 0 };
                OutputStream output; output.data = nullptr; output.disconnect = false;
                try {
                    bool delay = false;
                    input.data = new uint8_t[MQTT_SERVER_RECV_BUFFER_LENGTH];
                    while (!instance->disable.load()) {
                        if (output.data != nullptr) {
                            int bytes = send(sock, reinterpret_cast<char *>(output.data), output.length, 0);
                            delete[] output.data; output.data = nullptr; output.length = 0;
                            if (bytes == MQTT_SERVER_SOCKET_ERROR) {
                                break;
                            }
                        } else if (delay && !output.disconnect) {
                            std::this_thread::sleep_for(std::chrono::microseconds(MQTT_SERVER_CLIENT_NOP_DELAY));
                        }
                        if (output.disconnect) {
                            break;
                        }
                        int bytes = recv(sock, reinterpret_cast<char *>(input.data), MQTT_SERVER_RECV_BUFFER_LENGTH, 0);
#ifdef _WIN32
                        if ((bytes == 0) || ((bytes == MQTT_SERVER_SOCKET_ERROR) && (WSAGetLastError() != WSAEWOULDBLOCK))) {
#else
                        if ((bytes == 0) || ((bytes == MQTT_SERVER_SOCKET_ERROR) && ((errno != EWOULDBLOCK) && (errno != EAGAIN)))) {
#endif
                            break;
                        }
                        input.length = (bytes != MQTT_SERVER_SOCKET_ERROR) ? bytes : 0;
                        delay = !input.length;
                        try {
                            output.disconnect = false;
                            EventHandler *handle = eventHandler->load(std::memory_order_consume);
                            if (handle != nullptr) {
                                (*handle)(event, input, output);
                            }
                            input.length = 0;
                        } catch (...) {
                            break;
                        }
                        event.type = Event::Type::None;
                    }
#ifdef _WIN32
                    shutdown(sock, SD_BOTH);
#else
                    shutdown(sock, SHUT_RDWR);
#endif
                    MQTT_SERVER_CLOSESOCKET(sock);
#ifdef _WIN32
                    sock = INVALID_SOCKET;
#else
                    sock = MQTT_SERVER_SOCKET_ERROR;
#endif

                    if (output.data != nullptr) {
                        delete[] output.data; output.data = nullptr; output.length = 0;
                    }
                    if (event.type != Event::Type::Connected) {
                        event.type = Event::Type::Disconnected;
                        try {
                            output.disconnect = true;
                            EventHandler *handle = eventHandler->load(std::memory_order_consume);
                            if (handle != nullptr) {
                                (*handle)(event, input, output);
                            }
                        } catch (...) { }
                    }
                } catch (...) {
#ifdef _WIN32
                    if (sock != INVALID_SOCKET) {
#else
                    if (sock != MQTT_SERVER_SOCKET_ERROR) {
#endif
                        MQTT_SERVER_CLOSESOCKET(sock);
                    }
                }
                if (input.data != nullptr) {
                    delete[] input.data;
                }
                if (output.data != nullptr) {
                    delete[] output.data;
                }
                instance->enabled.store(false);
            }
            std::thread thread;
            std::atomic_bool enabled, disable;
            std::atomic_uint64_t connectionId;
        };
        std::atomic_bool enabled, disable;
        std::atomic<EventHandler *> eventHandler;
    };

    class DisconnectException : public std::exception {
    public:
        DisconnectException() : reason("Client disconnected") { }
        DisconnectException(const std::string &reason) : reason(reason) { }
        virtual const char *what() const noexcept {
            return reason.c_str();
        }
    protected:
        std::string reason;
    };

    class NoPacketException : public std::exception {
    public:
        virtual const char *what() const noexcept {
            return "No MQTT packet";
        }
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
        Packet(const uint8_t *stream, std::size_t length) {
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
        static std::vector<Packet> FeedList(std::vector<uint8_t> &stream) {
            std::size_t consumed = 0;
            std::vector<Packet> packets;
            while (true) {
                try {
                    if (!(stream.size() - consumed)) {
                        stream.clear();
                        return packets;
                    }
                    packets.push_back(Packet(&stream[consumed], static_cast<unsigned>(stream.size() - consumed)));
                    consumed += std::prev(packets.end())->GetSize();
                } catch (NoPacketException &) {
                    std::memcpy(stream.data(), &stream[consumed], stream.size() - consumed);
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
        String() { }
        String(const std::string &string) {
            data.resize(string.size());
            std::memcpy(data.data(), string.data(), string.size());
        }
        String(const uint8_t *stream, uint32_t length) {
            if (length < 2) {
                throw std::invalid_argument("Cannot create MQTT string from stream, data stream to short");
            }
            uint16_t size = (stream[0] << 8) | stream[1];
            if (length < static_cast<unsigned>(size + 2)) {
                throw std::invalid_argument("Cannot create MQTT string from stream, data stream to short");
            }
            data.resize(size);
            std::memcpy(data.data(), &(stream[2]), size);
        }
        operator std::vector<uint8_t>() const {
            std::vector<uint8_t> stream;
            stream.resize(GetSize());
            stream[0] = (data.size() >> 8) & 0xFF;
            stream[1] = data.size() & 0xFF;
            std::memcpy(&stream[2], data.data(), data.size());
            return stream;
        }
        operator std::string() const {
            std::string string;
            for (uint8_t byte : data) {
                string += static_cast<char>(byte);
            }
            return string;
        }
        const std::vector<uint8_t> &GetData() const {
            return data;
        }
        uint16_t GetSize() const {
            return static_cast<uint16_t>(data.size() + 2);
        }
    private:
        std::vector<uint8_t> data;
    };

    class Connections {
    public:
        struct Connection {
            uint64_t id;
            IPAddress address;
            bool connected;
            std::chrono::time_point<std::chrono::system_clock> timestamp;
            std::vector<uint8_t> input, output;
            uint16_t keepAlive;
        };
        Connections() { };
        Connections(const Connections &) = delete;
        Connections(Connections &&) = delete;
        Connections &operator=(const Connections &) = delete;
        Connection Add(uint64_t connectionId, const IPAddress &address, bool &connected) {
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
                return { 0, IPAddress(), false, std::chrono::system_clock::now(), std::vector<uint8_t>(), std::vector<uint8_t>(), 0 };
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
                throw std::runtime_error("Incorrect connection identifier");
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
            throw std::runtime_error("Incorrect connection identifier");
        }
        void Send(uint64_t connectionId, const std::vector<uint8_t> &data) {
            std::lock_guard<std::mutex> lock(access);
            for (Connection &connection : connections) {
                if (connection.id == connectionId) {
                    connection.output.insert(connection.output.end(), data.begin(), data.end());
                    return;
                }
            }
            throw std::runtime_error("Incorrect connection identifier");
        }
        IPAddress GetAddress(uint64_t connectionId) const {
            std::lock_guard<std::mutex> lock(access);
            for (const Connection &connection : connections) {
                if (connection.id == connectionId) {
                    return connection.address;
                }
            }
            throw std::runtime_error("Incorrect connection identifier");
        }
    private:
        mutable std::mutex access;
        std::vector<Connection> connections;
    };

    class Server : private TCPServer {
    public:
        struct PublishFlags {
            bool dup, qos1, qos2, retain;
        };
        struct ConnectFlags {
            bool userName, password, willRetain, willQoS1, willQoS2, willFlag, cleanSession;
        };
        struct ConnectParams {
            std::string clientId, userName, password, willTopic;
            std::vector<uint8_t> willMessage;
            uint16_t keepAlive;
        };
        enum class ConnectResponse {
            Accepted,
            RefusedProtocol,
            RefusedIdentifier,
            RefusedUnavailable,
            RefusedBadCredentials,
            RefusedUnauthorized
        };
        enum class PublishResponse {
            QoS0,
            QoS1,
            QoS2
        };
        enum class SubscribeResponse {
            QoS0,
            QoS1,
            QoS2,
            Failure
        };
        using ConnectHandler = std::function<ConnectResponse(uint64_t connectionId, const ConnectFlags &flags, const ConnectParams &params, bool &sessionPresent)>;
        using DisconnectHandler = std::function<void(uint64_t connectionId, bool graceful)>;
        using PublishHandler = std::function<PublishResponse(uint64_t connectionId, unsigned packetId, const std::string &topicName, const std::vector<uint8_t> &payload, PublishFlags &flags)>;
        using PubackHandler = std::function<void(uint64_t connectionId, uint16_t packetId)>;
        using SubscribeHandler = std::function<SubscribeResponse(uint64_t connectionId, const std::string &topicFilter, uint8_t requestedQoS)>;
        using UnsubscribeHandler = std::function<void(uint64_t connectionId, const std::string &topicFilter)>;
        Server() : publish(nullptr), connect(nullptr), disconnect(nullptr), subscribe(nullptr), unsubscribe(nullptr), puback(nullptr), pubrec(nullptr), pubrel(nullptr), pubcomp(nullptr) {
            SetEventHandler([&](const TCPServer::Event &event, const TCPServer::InputStream &input, TCPServer::OutputStream &output) {
                bool connected = false, handled = false;
                auto connection = (event.type == TCPServer::Event::Type::Connected) ? connections.Add(event.connectionId, *event.address, connected) : connections.ClearBuffers(event.connectionId);
                if (connected) {
                    try {
                        DisconnectHandler *handle = disconnect.load(std::memory_order_consume);
                        if (handle != nullptr) {
                            (*handle)(event.connectionId, false);
                        }
                    } catch (...) { }
                }
                if (connection.input.size() + input.length > MQTT_BUFFER_MAX_LENGTH) {
                    output.disconnect = true;
                    return;
                }
                connected = connection.connected;
                auto size = connection.input.size();
                if (input.length) {
                    connection.input.resize(size + input.length);
                    std::memcpy(&connection.input[size], input.data, input.length);
                }
                auto now = std::chrono::system_clock::now();
                if (!connection.input.empty()) {
                    for (Packet &packet : Packet::FeedList(connection.input)) {
                        handled = true;
                        try {
                            std::vector<uint8_t> response = static_cast<std::vector<uint8_t>>(HandlePacket(packet, event.connectionId, connected, connection.keepAlive));
                            if (connection.output.size() + response.size() > MQTT_BUFFER_MAX_LENGTH) {
                                throw std::runtime_error("Out of memory");
                            }
                            connection.output.insert(connection.output.end(), response.begin(), response.end());
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
                if ((event.type != TCPServer::Event::Type::Disconnected) && !connection.output.empty()) {
                    output.length = static_cast<unsigned>(connection.output.size());
                    output.data = new uint8_t[connection.output.size()];
                    std::memcpy(output.data, connection.output.data(), connection.output.size());
                    connection.output.clear();
                }
                if (!connection.input.empty() || handled) {
                    connections.Update(connection, connected, handled, now);
                }
                if (event.type == TCPServer::Event::Type::Disconnected) {
                    auto deleted = connections.Delete(event.connectionId);
                    if (deleted.connected) {
                        try {
                            DisconnectHandler *handle = disconnect.load(std::memory_order_consume);
                            if (handle != nullptr) {
                                (*handle)(event.connectionId, false);
                            }
                        } catch (...) { }
                    }
                }
            });
        }
        virtual ~Server() {
            Disable();
            while (IsEnabled()) {
                std::this_thread::sleep_for(std::chrono::microseconds(MQTT_SERVER_SERVER_NOP_DELAY));
            }
            FreeHandler(publish);
            FreeHandler(connect);
            FreeHandler(disconnect);
            FreeHandler(subscribe);
            FreeHandler(puback);
            FreeHandler(pubrec);
            FreeHandler(pubrel);
            FreeHandler(pubcomp);
        }
        void Enable(const std::string &address, uint16_t port, uint32_t connections = MQTT_SERVER_CONNECTIONS_LIMIT) {
            TCPServer::Enable(address, port, connections);
        }
        void Disable() {
            TCPServer::Disable();
        }
        bool IsEnabled() const {
            return TCPServer::IsEnabled();
        }
        void SetConnectHandler(const ConnectHandler &handler) {
            SetHandler(connect, handler);
        }
        void SetDisconnectHandler(const DisconnectHandler &handler) {
            SetHandler(disconnect, handler);
        }
        void SetPublishHandler(const PublishHandler &handler) {
            SetHandler(publish, handler);
        }
        void SetPubackHandler(const PubackHandler &handler) {
            SetHandler(puback, handler);
        }
        void SetPubrecHandler(const PubackHandler &handler) {
            SetHandler(pubrec, handler);
        }
        void SetPubrelHandler(const PubackHandler &handler) {
            SetHandler(pubrel, handler);
        }
        void SetPubcompHandler(const PubackHandler &handler) {
            SetHandler(pubcomp, handler);
        }
        void SetSubscribeHandler(const SubscribeHandler &handler) {
            SetHandler(subscribe, handler);
        }
        void SetUnsubscribeHandler(const UnsubscribeHandler &handler) {
            SetHandler(unsubscribe, handler);
        }
        void Publish(uint64_t connectionId, uint16_t packetId, const std::string &topicName, const std::vector<uint8_t> &payload, const PublishFlags &flags) {
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
            std::memcpy(&data[offset], payload.data(), payload.size());
            Packet publish(
                MQTT_CONTROL_PACKET_TYPE_PUBLISH,
                (flags.dup ? MQTT_PUBLISH_FLAG_DUP : 0x0) |
                (flags.qos1 ? MQTT_PUBLISH_FLAG_QOS1 : 0x0) |
                (flags.qos2 ? MQTT_PUBLISH_FLAG_QOS2 : 0x0) |
                (flags.retain ? MQTT_PUBLISH_FLAG_RETAIN : 0x0),
                data
            );
            connections.Send(connectionId, publish);
        }
        std::string GetAddress(uint64_t connectionId) {
            IPAddress address = connections.GetAddress(connectionId);
            if ((address.GetType() == IPAddress::Type::IPv4) && (reinterpret_cast<sockaddr_in *>(address.GetSockAddr())->sin_addr.s_addr == htonl(INADDR_ANY))) {
                throw std::invalid_argument("Cannot obtain connection address");
            }
            return address;
        }
    private:
        uint8_t GetConnectReturnCode(ConnectResponse response) const {
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
        uint8_t GetSubscribeReturnCode(SubscribeResponse response) const {
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
        Packet HandlePacket(const Packet &packet, uint64_t connectionId, bool &connected, uint16_t &keepAlive) const {
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
                    keepAlive = packet.GetData()[offset++] << 8;
                    keepAlive |= packet.GetData()[offset++];
                    String clientId;
                    try {
                        clientId = String(&packet.GetData()[offset], static_cast<uint32_t>(packet.GetData().size() - offset));
                    } catch (...) {
                        throw DisconnectException("CONNECT: malformed client identifier");
                    }
                    if (clientId.GetData().empty()) {
                        throw DisconnectException("CONNECT: client identifier cannot be empty");
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
                    } else {
                        try {
                            ConnectHandler *handle = connect.load(std::memory_order_consume);
                            if (handle != nullptr) {
                                ConnectFlags flags = {
                                    static_cast<bool>(connectFlags & MQTT_CONNECT_FLAG_USER_NAME),
                                    static_cast<bool>(connectFlags & MQTT_CONNECT_FLAG_PASSWORD),
                                    static_cast<bool>(connectFlags & MQTT_CONNECT_FLAG_WILL_RETAIN),
                                    static_cast<bool>(connectFlags & MQTT_CONNECT_FLAG_WILL_QOS1),
                                    static_cast<bool>(connectFlags & MQTT_CONNECT_FLAG_WILL_QOS2),
                                    static_cast<bool>(connectFlags & MQTT_CONNECT_FLAG_WILL_FLAG),
                                    static_cast<bool>(connectFlags & MQTT_CONNECT_FLAG_CLEAN_SESSION)
                                };
                                ConnectParams params = { clientId, userName, password, willTopic, willMessage.GetData(), keepAlive };
                                returnCode = GetConnectReturnCode((*handle)(connectionId, flags, params, sessionPresent));
                            }
                        } catch (...) {
                            return Packet(MQTT_CONTROL_PACKET_TYPE_CONNACK, MQTT_REQUIRED_FLAGS_CONNACK, std::vector<uint8_t>({ 0x0, MQTT_CONNACK_RETURN_CODE_REFUSED_UNAVAILABLE }));
                        }
                    }
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
                    PublishFlags flags = {
                        static_cast<bool>(packet.GetFlags() & MQTT_PUBLISH_FLAG_DUP),
                        static_cast<bool>(packet.GetFlags() & MQTT_PUBLISH_FLAG_QOS1),
                        static_cast<bool>(packet.GetFlags() & MQTT_PUBLISH_FLAG_QOS2),
                        static_cast<bool>(packet.GetFlags() & MQTT_PUBLISH_FLAG_RETAIN)
                    };
                    if (packet.GetData().size() < offset + ((flags.qos1 || flags.qos2) ? 2 : 0)) {
                        throw DisconnectException("PUBLISH: invalid packet length");
                    }
                    uint16_t packetIdentifier = 0;
                    if (flags.qos1 || flags.qos2) {
                        packetIdentifier = packet.GetData()[offset++] << 8;
                        packetIdentifier |= packet.GetData()[offset++];
                    }
                    std::vector<uint8_t> payload;
                    payload.resize(packet.GetData().size() - offset);
                    if (payload.size()) {
                        std::memcpy(payload.data(), &packet.GetData()[offset], payload.size());
                    }
                    if (flags.qos1 && flags.qos2) {
                        throw DisconnectException("PUBLISH: invalid QoS value");
                    }
                    if (connected) {
                        try {
                            PublishResponse response = PublishResponse::QoS0;
                            PublishHandler *handle = publish.load(std::memory_order_consume);
                            if (handle != nullptr) {
                                response = (*handle)(connectionId, packetIdentifier, topicName, payload, flags);
                            }
                            switch (response) {
                            case PublishResponse::QoS1:
                                return Packet(MQTT_CONTROL_PACKET_TYPE_PUBACK, MQTT_REQUIRED_FLAGS_PUBACK, { static_cast<uint8_t>(packetIdentifier >> 8), static_cast<uint8_t>(packetIdentifier & 0xFF) });
                            case PublishResponse::QoS2:
                                return Packet(MQTT_CONTROL_PACKET_TYPE_PUBREC, MQTT_REQUIRED_FLAGS_PUBREC, { static_cast<uint8_t>(packetIdentifier >> 8), static_cast<uint8_t>(packetIdentifier & 0xFF) });
                            default:
                                break;
                            }
                        } catch (...) {
                            throw DisconnectException("PUBLISH: internal server error");
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
                    if (connected) {
                        try {
                            PubackHandler *handle = puback.load(std::memory_order_consume);
                            if (handle != nullptr) {
                                (*handle)(connectionId, packetIdentifier);
                            }
                        } catch (...) {
                            throw DisconnectException("PUBACK: internal server error");
                        }
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
                    if (connected) {
                        try {
                            PubackHandler *handle = pubrel.load(std::memory_order_consume);
                            if (handle != nullptr) {
                                (*handle)(connectionId, packetIdentifier);
                            }
                        } catch (...) {
                            throw DisconnectException("PUBREL: internal server error");
                        }
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
                    if (connected) {
                        try {
                            PubackHandler *handle = pubrec.load(std::memory_order_consume);
                            if (handle != nullptr) {
                                (*handle)(connectionId, packetIdentifier);
                            }
                        } catch (...) {
                            throw DisconnectException("PUBREC: internal server error");
                        }
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
                    if (connected) {
                        try {
                            PubackHandler *handle = pubcomp.load(std::memory_order_consume);
                            if (handle != nullptr) {
                                (*handle)(connectionId, packetIdentifier);
                            }
                        } catch (...) {
                            throw DisconnectException("PUBCOMP: internal server error");
                        }
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
                        try {
                            SubscribeHandler *handle = subscribe.load(std::memory_order_consume);
                            if (handle != nullptr) {
                                result.push_back(GetSubscribeReturnCode((*handle)(connectionId, request.topicFilter, request.requestedQoS)));
                                continue;
                            }
                            throw std::exception();
                        } catch (...) {
                            result.push_back(MQTT_SUBACK_RETURN_CODE_FAILURE);
                        }
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
                    try {
                        UnsubscribeHandler *handle = unsubscribe.load(std::memory_order_consume);
                        for (UnsubscribeRequest& request : requests) {
                            if (handle != nullptr) {
                                (*handle)(connectionId, request.topicFilter);
                            }
                        }
                    } catch (...) { }
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
                try {
                    DisconnectHandler *handle = disconnect.load(std::memory_order_consume);
                    if (handle != nullptr) {
                        (*handle)(connectionId, true);
                    }
                } catch (...) { }
                connected = false;
                throw DisconnectException();
            default:
                throw DisconnectException("Unsupported packet type");
            }
        }

        TCPServer tcp;
        Connections connections;
        std::atomic<PublishHandler *> publish;
        std::atomic <ConnectHandler *> connect;
        std::atomic <DisconnectHandler *> disconnect;
        std::atomic <SubscribeHandler *> subscribe;
        std::atomic <UnsubscribeHandler *> unsubscribe;
        std::atomic <PubackHandler *> puback, pubrec, pubrel, pubcomp;
    };

    struct Payload {
        struct Recipient {
            uint64_t connectionId;
            uint8_t requestedQoS;
        };
        std::string topicName;
        std::vector<uint8_t> data;
        uint8_t requestedQoS;
#ifndef SERVICE_OPERATION_MODE_QUEUE
        bool retain;
#endif
        std::vector<Recipient> recipients;
        bool assigned;
    };

    struct PublishedPayload {
        std::string topicName;
        std::vector<uint8_t> data;
        uint64_t connectionId;
        uint16_t packetId, timeout;
        uint8_t requestedQoS, selectedQoS;
#ifndef SERVICE_OPERATION_MODE_QUEUE
        bool retain;
#endif
        enum class Status {
            Added,
            Sent,
            Acknowledged
        } status;
        std::chrono::time_point<std::chrono::system_clock> timestamp;
    };

    class Clients {
    public:
        struct Client {
            uint64_t connectionId;
            std::string clientId;
            uint16_t keepAlive, packetIdSeq;
            bool willFlag;
            std::string willTopic;
            std::vector<uint8_t> willPayload;
            uint8_t willQoS;
#ifndef SERVICE_OPERATION_MODE_QUEUE
            bool willRetain;
#endif
            std::vector<uint16_t> packetIds;
        };
        Clients() { }
        Clients(const Clients &) = delete;
        Clients(Clients &&) = delete;
        Clients &operator=(const Clients &) = delete;
        Client Get(uint64_t connectionId) const {
            std::lock_guard<std::mutex> lock(access);
            for (const Client &client : clients) {
                if (client.connectionId == connectionId) {
                    return client;
                }
            }
            throw std::runtime_error("Client does not exist");
        }
        Client Add(
            uint64_t connectionId,
            const std::string &clientId,
            uint16_t keepAlive,
            bool willFlag = false,
            const std::string &willTopic = std::string(),
            const std::vector<uint8_t> &willPayload = { },
#ifndef SERVICE_OPERATION_MODE_QUEUE
            uint8_t willRequestedQoS = 0,
            bool willRetain = false
#else
            uint8_t willRequestedQoS = 0
#endif
        ) {
            std::lock_guard<std::mutex> lock(access);
            for (Client &client : clients) {
                if (client.connectionId == connectionId) {
                    throw std::runtime_error("Duplicated connection identifier");
                }
            }
            clients.push_back({
                connectionId,
                clientId,
                keepAlive ? keepAlive : static_cast<uint16_t>(SERVICE_DEFAULT_KEEP_ALIVE_TIME),
                0,
                willFlag,
                willTopic,
                willPayload,
#ifndef SERVICE_OPERATION_MODE_QUEUE
                willRequestedQoS,
                willRetain
#else
                willRequestedQoS
#endif
            });
            return *std::prev(clients.end());
        }
        void Delete(uint64_t connectionId) {
            std::lock_guard<std::mutex> lock(access);
            for (auto client = clients.begin(); client != clients.end();) {
                if (client->connectionId == connectionId) {
                    client = clients.erase(client);
                    return;
                }
                client++;
            }
            throw std::runtime_error("Client does not exist");
        }
        std::vector<std::pair<uint64_t, unsigned long long>> GetAvailablePacketsCount() const {
            std::vector<std::pair<uint64_t, unsigned long long>> available;
            std::lock_guard<std::mutex> lock(access);
            available.reserve(clients.size());
            for (const Client &client : clients) {
                available.push_back({ client.connectionId, SERVICE_PUBLISHED_PAYLOADS_LIMIT - client.packetIds.size() });
            }
            return available;
        }
        std::pair<uint16_t, uint16_t> AddPacket(uint64_t connectionId) {
            std::lock_guard<std::mutex> lock(access);
            auto getNextPacketId = [&](Client &client) -> uint16_t {
                for (uint16_t packetId = client.packetIdSeq + 1; packetId != client.packetIdSeq; packetId++) {
                    if (!packetId) {
                        packetId++;
                    }
                    auto id = client.packetIds.begin();
                    while (id != client.packetIds.end()) {
                        if (*id == packetId) {
                            break;
                        }
                        id++;
                    }
                    if (id == client.packetIds.end()) {
                        client.packetIdSeq = packetId;
                        return client.packetIdSeq;
                    }
                }
                throw std::runtime_error("Cannot generate packet identifier");
            };
            for (Client &client : clients) {
                if (client.connectionId == connectionId) {
                    uint16_t packetId = getNextPacketId(client);
                    client.packetIds.push_back(packetId);
                    return { packetId, client.keepAlive };
                }
            }
            throw std::runtime_error("Client does not exist");
        }
        void RemovePacket(uint64_t connectionId, uint16_t packetId) {
            std::lock_guard<std::mutex> lock(access);
            for (Client &client : clients) {
                if (client.connectionId == connectionId) {
                    for (auto id = client.packetIds.begin(); id != client.packetIds.end();) {
                        if (*id == packetId) {
                            id = client.packetIds.erase(id);
                            return;
                        }
                        id++;
                    }
                    return;
                }
            }
        }
        std::size_t Count() const {
            std::lock_guard<std::mutex> lock(access);
            return clients.size();
        }
    private:
        std::vector<Client> clients;
        mutable std::mutex access;
    };

    class Topics {
    public:
#ifndef SERVICE_OPERATION_MODE_QUEUE
        struct Retained {
            std::vector<uint8_t> payload;
            uint8_t requestedQoS;
        };
#endif
#ifndef SERVICE_OPERATION_MODE_QUEUE
        Topics(const std::string &filename) : filename(filename) {
            try {
                LoadRetained();
            } catch (...) { }
        }
        Topics() : filename() { }
#else
        Topics() { }
#endif
        Topics(const Topics &) = delete;
        Topics(Topics &&) = delete;
        Topics &operator=(const Topics &) = delete;
#ifndef SERVICE_OPERATION_MODE_QUEUE
        virtual ~Topics() {
            std::lock_guard<std::mutex> lock(access);
            if (!filename.empty()) {
                try {
                    SaveRetained();
                } catch (...) { }
            }
        }
        void Retain(const std::string &topicName, const std::vector<uint8_t> &payload, uint8_t requestedQoS) {
            std::lock_guard<std::mutex> lock(access);
            auto saveRetained = [&]() {
                if (!filename.empty()) {
                    try {
                        SaveRetained();
                    } catch (...) { }
                }
            };
            for (Topic &topic : topics) {
                if (topic.name == topicName) {
                    if (!payload.empty()) {
                        topic.retained = { { payload, requestedQoS } };
                    } else {
                        topic.retained = { };
                    }
                    saveRetained();
                    return;
                }
            }
            if (topics.size() >= SERVICE_TOPICS_LIMIT) {
                std::runtime_error("Topics limit exceeded");
            }
            if (!payload.empty()) {
                topics.push_back({ topicName, { }, { { payload, requestedQoS } } });
                saveRetained();
            }
        }
        std::vector<Retained> Subscribe(uint64_t connectionId, const std::string &topicName, uint8_t requestedQoS) {
#else
        void Subscribe(uint64_t connectionId, const std::string &topicName, uint8_t requestedQoS) {
#endif
            std::lock_guard<std::mutex> lock(access);
            for (Topic &topic : topics) {
                if (topic.name == topicName) {
                    for (auto &subscription : topic.subscriptions) {
                        if (subscription.connectionId == connectionId) {
                            subscription.requestedQoS = requestedQoS;
#ifndef SERVICE_OPERATION_MODE_QUEUE
                            return std::vector<Retained>();
#else
                            return;
#endif
                        }
                    }
                    topic.subscriptions.push_back({ connectionId, requestedQoS });
#ifndef SERVICE_OPERATION_MODE_QUEUE
                    return topic.retained;
#else
                    return;
#endif
                }
            }
            if (topics.size() >= SERVICE_TOPICS_LIMIT) {
                std::runtime_error("Topics limit exceeded");
            }
            topics.push_back({ topicName, { { connectionId, requestedQoS } } });
#ifndef SERVICE_OPERATION_MODE_QUEUE
            return std::vector<Retained>();
#endif
        }
        void Unsubscribe(uint64_t connectionId, const std::string &topicName) {
            std::lock_guard<std::mutex> lock(access);
            for (Topic &topic : topics) {
                if (topic.name == topicName) {
                    for (auto subscription = topic.subscriptions.begin(); subscription != topic.subscriptions.end();) {
                        if (subscription->connectionId == connectionId) {
                            subscription = topic.subscriptions.erase(subscription);
                            return;
                        }
                        subscription++;
                    }
                    std::runtime_error("Topic not subscribed by client");
                }
            }
            std::runtime_error("Topics does not exist");
        }
        std::vector<std::string> UnsubscribeAll(uint64_t connectionId) {
            std::vector<std::string> unsubscribed;
            std::lock_guard<std::mutex> lock(access);
            for (Topic &topic : topics) {
                for (auto subscription = topic.subscriptions.begin(); subscription != topic.subscriptions.end();) {
                    if (subscription->connectionId == connectionId) {
                        subscription = topic.subscriptions.erase(subscription);
                        unsubscribed.push_back(topic.name);
                        break;
                    }
                    subscription++;
                }
            }
            return unsubscribed;
        }
        std::size_t Count() const {
            std::lock_guard<std::mutex> lock(access);
            return topics.size();
        }
        std::vector<std::pair<std::string, std::vector<Payload::Recipient>>> GetSubscriptions() const {
            std::vector<std::pair<std::string, std::vector<Payload::Recipient>>> subscriptions;
            std::lock_guard<std::mutex> lock(access);
            subscriptions.reserve(topics.size());
            for (const Topic &topic : topics) {
                subscriptions.push_back({ topic.name, topic.subscriptions });
            }
            return subscriptions;
        }
        bool IsSubscribed(uint64_t connectionId, const std::string &topicName) const {
            std::lock_guard<std::mutex> lock(access);
            for (const Topic &topic : topics) {
                if (topic.name == topicName) {
                    for (auto &subscription : topic.subscriptions) {
                        if (subscription.connectionId == connectionId) {
                            return true;
                        }
                    }
                }
            }
            return false;
        }
    private:
        struct Topic {
            std::string name;
            std::vector<Payload::Recipient> subscriptions;
#ifndef SERVICE_OPERATION_MODE_QUEUE
            std::vector<Retained> retained;
#endif
        };
#ifndef SERVICE_OPERATION_MODE_QUEUE
        void LoadRetained() {
            enum class DataType {
                TopicNameSize,
                PayloadSize,
                TopicName,
                Payload,
                RequestedQoS
            };
            std::ifstream file;
            std::string topicName;
            std::vector<uint8_t> payload, read;
            uint32_t topicNameSize, payloadSize;
            uint8_t requestedQoS;
            uint8_t buffer[SERVICE_FILE_BUFFER_LENGTH];
            bool eof = false;
            DataType current = DataType::TopicNameSize;
            file.open(filename, std::ifstream::binary);
            if (!file.is_open()) {
                throw std::runtime_error("Cannot load retained payloads");
            }
            while (!eof) {
                std::memset(buffer, 0x00, SERVICE_FILE_BUFFER_LENGTH);
                file.read(reinterpret_cast<char *>(buffer), SERVICE_FILE_BUFFER_LENGTH);
                eof = file.rdstate() & std::ios::eofbit;
                for (unsigned i = 0; i < file.gcount(); i++) {
                    read.push_back(static_cast<uint8_t>(buffer[i]));
                    switch (current) {
                    case DataType::RequestedQoS:
                        current = DataType::TopicNameSize;
                        requestedQoS = read[0];
                        Retain(topicName, payload, requestedQoS);
                        read.clear();
                        break;
                    case DataType::Payload:
                        if (read.size() >= payloadSize) {
                            current = DataType::RequestedQoS;
                            payload = read;
                            read.clear();
                        }
                        break;
                    case DataType::PayloadSize:
                        if (read.size() >= sizeof(uint32_t)) {
                            current = DataType::Payload;
                            payloadSize = *reinterpret_cast<uint32_t *>(read.data());
                            read.clear();
                        }
                        break;
                    case DataType::TopicName:
                        if (read.size() >= topicNameSize) {
                            current = DataType::PayloadSize;
                            topicName.clear();
                            for (std::size_t j = 0; j < read.size(); j++) {
                                topicName += read[j];
                            }
                            read.clear();
                        }
                        break;
                    case DataType::TopicNameSize:
                        if (read.size() >= sizeof(uint32_t)) {
                            current = DataType::TopicName;
                            topicNameSize = *reinterpret_cast<uint32_t *>(read.data());
                            read.clear();
                        }
                        break;
                    }
                }
            }
            file.close();
        }
        void SaveRetained() const {
            std::ofstream file;
            file.open(filename);
            if (!file.is_open()) {
                throw std::runtime_error("Cannot save retained payloads");
            }
            for (const Topic &topic : topics) {
                for (const Retained &retained : topic.retained) {
                    uint32_t size = static_cast<uint32_t>(topic.name.size());
                    file.write(reinterpret_cast<const char *>(&size), sizeof(uint32_t));
                    file.write(topic.name.data(), topic.name.size());
                    size = static_cast<uint32_t>(retained.payload.size());
                    file.write(reinterpret_cast<const char *>(&size), sizeof(uint32_t));
                    file.write(reinterpret_cast<const char *>(retained.payload.data()), retained.payload.size());
                    file.write(reinterpret_cast<const char *>(&retained.requestedQoS), 1);
                }
            }
            file.close();
        }
        std::string filename;
#endif
        std::vector<Topic> topics;
        mutable std::mutex access;
    };

    class PublishedPayloads {
    public:
#ifdef SERVICE_OPERATION_MODE_QUEUE
        using RepublishHandler = std::function<void(const std::string &topicName, const std::vector<uint8_t> &payload, uint8_t requestedQoS) noexcept>;
#endif
        PublishedPayloads() { }
        PublishedPayloads(const PublishedPayloads &) = delete;
        PublishedPayloads(PublishedPayloads &&) = delete;
        PublishedPayloads &operator=(const PublishedPayloads &) = delete;
        void Remove(uint64_t connectionId, uint16_t packetId, uint8_t requiredQoS, PublishedPayload::Status requiredStatus) {
            std::lock_guard<std::mutex> lock(access);
            for (auto payload = payloads.begin(); payload != payloads.end();) {
                if ((payload->connectionId == connectionId) && (payload->packetId == packetId)) {
                    if ((payload->selectedQoS != requiredQoS) || (payload->status != requiredStatus)) {
                        throw std::runtime_error("Incorrect QoS or payload status");
                    }
                    payload = payloads.erase(payload);
                    return;
                }
                payload++;
            }
            throw std::runtime_error("Incorrect packet identifier");
        }
#ifndef SERVICE_OPERATION_MODE_QUEUE
        std::vector<uint16_t> RemoveAll(uint64_t connectionId) {
#else
        std::vector<uint16_t> RemoveAll(uint64_t connectionId, const RepublishHandler &republish) {
#endif
            std::vector<uint16_t> removed;
            std::lock_guard<std::mutex> lock(access);
            for (auto payload = payloads.begin(); payload != payloads.end();) {
                if (payload->connectionId == connectionId) {
#ifdef SERVICE_OPERATION_MODE_QUEUE
                    try {
                        republish(payload->topicName, payload->data, payload->requestedQoS);
                    } catch (...) { }
#endif
                    removed.push_back(payload->packetId);
                    payload = payloads.erase(payload);
                    continue;
                }
                payload++;
            }
            return removed;
        }
        void UpdateStatus(uint64_t connectionId, uint16_t packetId, uint8_t requiredQoS, PublishedPayload::Status requiredStatus, PublishedPayload::Status status) {
            std::lock_guard<std::mutex> lock(access);
            for (auto &payload : payloads) {
                if ((payload.packetId == packetId) && (payload.connectionId == connectionId)) {
                    if ((payload.selectedQoS != requiredQoS) || (payload.status != requiredStatus)) {
                        throw std::runtime_error("Incorrect QoS or payload status");
                    }
                    payload.timestamp = std::chrono::system_clock::now();
                    payload.status = status;
                    return;
                }
            }
            throw std::runtime_error("Incorrect packet identifier");
        }
        std::size_t Count() const {
            std::lock_guard<std::mutex> lock(access);
            return payloads.size();
        }
        void Append(const std::vector<PublishedPayload> &payloads) {
            if (payloads.empty()) {
                return;
            }
            std::lock_guard<std::mutex> lock(access);
            this->payloads.insert(this->payloads.end(), payloads.begin(), payloads.end());
        }
#ifndef SERVICE_OPERATION_MODE_QUEUE
        std::vector<std::pair<uint64_t, uint16_t>> Handle(Topics &topics, Server &server) {
#else
        std::vector<std::pair<uint64_t, uint16_t>> Handle(Topics &topics, Server &server, const RepublishHandler &republish) {
#endif
        std::vector<std::pair<uint64_t, uint16_t>> handled;
            std::lock_guard<std::mutex> lock(access);
            for (auto payload = payloads.begin(); payload != payloads.end();) {
                bool success = false;
                auto now = std::chrono::system_clock::now();
                try {
                    bool resend = false;
                    if ((payload->status != PublishedPayload::Status::Added) && (std::chrono::duration_cast<std::chrono::seconds>(now - payload->timestamp).count() > payload->timeout)) {
                        if (payload->status != PublishedPayload::Status::Sent) {
                            throw NoPacketException();
                        }
#ifndef SERVICE_OPERATION_MODE_QUEUE
                        if (!topics.IsSubscribed(payload->connectionId, payload->topicName)) {
                            throw std::runtime_error("Unsubscribed");
                        }
                        resend = true;
#else
                        throw std::runtime_error("Timeout");
#endif
                    }
                    if ((payload->status == PublishedPayload::Status::Added) || resend) {
                        server.Publish(payload->connectionId, payload->packetId, payload->topicName, payload->data, {
                            resend,
                            static_cast<bool>(payload->selectedQoS & 0x1), static_cast<bool>(payload->selectedQoS & 0x2),
#ifndef SERVICE_OPERATION_MODE_QUEUE
                            payload->retain
#else
                            false
#endif
                        });
                        payload->status = PublishedPayload::Status::Sent;
                        payload->timestamp = now;
                        if (!payload->selectedQoS) {
                            success = true;
                        }
                    }
#ifndef SERVICE_OPERATION_MODE_QUEUE
                } catch (...) {
#else
                } catch (NoPacketException &) {
                    success = true;
                } catch (...) {
                    republish(payload->topicName, payload->data, payload->requestedQoS);
#endif
                    success = true;
                }
                if (success) {
                    handled.push_back({ payload->connectionId, payload->packetId });
                    payload = payloads.erase(payload);
                    continue;
                }
                payload++;
            }
            return handled;
        }
    private:
        std::vector<PublishedPayload> payloads;
        mutable std::mutex access;
    };

    class Packets {
    public:
        Packets() { }
        Packets(const Packets &) = delete;
        Packets(Packets &&) = delete;
        Packets &operator=(const Packets &) = delete;
        void Register(uint64_t connectionId, uint16_t packetId, bool duplicate, uint16_t timeout) {
            std::lock_guard<std::mutex> lock(access);
            for (Connection &connection : connections) {
                if (connection.connectionId == connectionId) {
                    for (auto packet = connection.packets.begin(); packet != connection.packets.end();) {
                        if (packet->id == packetId) {
                            if (!duplicate) {
                                throw std::runtime_error("Duplicated packet identifier");
                            }
                            packet = connection.packets.erase(packet);
                            break;
                        }
                        packet++;
                    }
                    if (connection.packets.size() >= SERVICE_REGISTERED_QOS2_PACKETS_LIMIT) {
                        connection.packets.erase(connection.packets.begin());
                    }
                    connection.packets.push_back({ packetId, timeout, std::chrono::system_clock::now() });
                    return;
                }
            }
            connections.push_back({ connectionId, { { packetId, timeout, std::chrono::system_clock::now() } } });
        };
        void Unregister(uint64_t connectionId) {
            std::lock_guard<std::mutex> lock(access);
            for (auto connection = connections.begin(); connection != connections.end();) {
                if (connection->connectionId == connectionId) {
                    connection = connections.erase(connection);
                    return;
                }
                connection++;
            }
        };
        void Unregister(uint64_t connectionId, uint16_t packetId) {
            std::lock_guard<std::mutex> lock(access);
            for (auto connection = connections.begin(); connection != connections.end();) {
                if (connection->connectionId == connectionId) {
                    for (auto packet = connection->packets.begin(); packet != connection->packets.end();) {
                        if (packet->id == packetId) {
                            packet = connection->packets.erase(packet);
                            if (connection->packets.empty()) {
                                connection = connections.erase(connection);
                            }
                            return;
                        }
                        packet++;
                    }
                }
                connection++;
            }
            throw std::runtime_error("Incorrect packet identifier");
        };
        void HandleExpired() {
            std::lock_guard<std::mutex> lock(access);
            for (auto connection = connections.begin(); connection != connections.end();) {
                auto now = std::chrono::system_clock::now();
                for (auto packet = connection->packets.begin(); packet != connection->packets.end();) {
                    if (std::chrono::duration_cast<std::chrono::seconds>(now - packet->timestamp).count() > packet->timeout) {
                        packet = connection->packets.erase(packet);
                        continue;
                    }
                    packet++;
                }
                if (connection->packets.empty()) {
                    connection = connections.erase(connection);
                    continue;
                }
                connection++;
            }
        };
    private:
        struct Connection {
            struct Packet {
                uint16_t id, timeout;
                std::chrono::time_point<std::chrono::system_clock> timestamp;
            };
            uint64_t connectionId;
            std::vector<Packet> packets;
        };
        std::vector<Connection> connections;
        mutable std::mutex access;
    };

    Service::Service(
        const std::string &address,
        uint16_t port,
#ifndef SERVICE_OPERATION_MODE_QUEUE
        const std::string &filename,
#endif
        const ConnectHandler &connectHandler,
        const DisconnectHandler &disconnectHandler,
        const PublishHandler &publishHandler,
        const ExceptionHandler &exceptionHandler,
        const MessageHandler &messageHandler
    )
        : publishHandler(publishHandler), enabled(true), disable(false), topics(nullptr)
    {
#ifndef SERVICE_OPERATION_MODE_QUEUE
        if (!filename.empty()) {
            try {
                if (messageHandler != nullptr) {
                    messageHandler("Loading saved topics from " + filename);
                }
                topics = reinterpret_cast<void *>(new Topics(filename));
            } catch (...) {
                if (messageHandler != nullptr) {
                    messageHandler("Failed to load topics");
                }
            }
        }
        if (topics == nullptr) {
#else
        {
#endif
            topics = reinterpret_cast<void *>(new Topics());
        }
        thread = std::thread(ServiceThread, this, address, port, connectHandler, disconnectHandler, exceptionHandler, messageHandler);
    }

    Service::~Service()
    {
        Disable();
        delete reinterpret_cast<Topics *>(topics);
    }

    void Service::Publish(
        const std::string &clientId,
        const std::string &topicName,
        const std::vector<uint8_t> &payload,
        uint8_t requestedQoS,
#ifndef SERVICE_OPERATION_MODE_QUEUE
        bool retain,
#endif
        bool handle
    ) {
        if (payload.size() > SERVICE_PAYLOAD_SIZE_LIMIT) {
            throw std::runtime_error("Payload size limit violated");
        }
        {
            std::lock_guard<std::mutex> lock(access);
            if ((payloads.size() < SERVICE_RECEIVED_PAYLOADS_LIMIT) && (!handle || (publishHandler == nullptr) || publishHandler(clientId, topicName, payload))) {
                payloads.push_back({
                    topicName,
                    payload,
#ifndef SERVICE_OPERATION_MODE_QUEUE
                    requestedQoS,
                    retain
#else
                    requestedQoS
#endif
                });
            } else {
                throw std::runtime_error("Payload cannot be published");
            }
        }
#ifndef SERVICE_OPERATION_MODE_QUEUE
        if (retain) {
            try {
                reinterpret_cast<Topics *>(topics)->Retain(topicName, payload, requestedQoS);
            } catch (...) { }
        }
#endif
    }

    bool Service::IsEnabled() const
    {
        return enabled.load();
    }

    void Service::Disable()
    {
        if (!disable.exchange(true) && thread.joinable()) {
            thread.join();
        }
    }

    void Service::ServiceThread(
        Service *instance,
        const std::string &address,
        uint16_t port,
        const ConnectHandler &connectHandler,
        const DisconnectHandler &disconnectHandler,
        const ExceptionHandler &exceptionHandler,
        const MessageHandler &messageHandler
    ) noexcept {
        PublishedPayloads published;
        Packets receivedQoS2;
        Clients clients;
        Server server;

        Topics *topics = reinterpret_cast<Topics *>(instance->topics);

        auto handleException = [&](const std::exception &exception) {
            if (exceptionHandler != nullptr) {
                exceptionHandler(exception);
            }
        };
        auto printMessage = [&](const std::string &message) {
            if (messageHandler != nullptr) {
                messageHandler(message);
            }
        };
#ifndef SERVICE_OPERATION_MODE_QUEUE
        auto publishRetained = [&](uint64_t connectionId, const std::string &topicName, uint8_t requestedQoS, const std::vector<Topics::Retained> &retained) noexcept {
            for (auto &publish : retained) {
                std::lock_guard<std::mutex> lock(instance->access);
                if (instance->payloads.size() < SERVICE_RECEIVED_PAYLOADS_LIMIT) {
                    instance->payloads.push_back({ topicName, publish.payload, publish.requestedQoS, false, { { connectionId, requestedQoS } }, true });
                }
            }
        };
#endif
        auto removeRecipients = [&](uint64_t connectionId) {
            std::lock_guard<std::mutex> lock(instance->access);
            for (auto payload = instance->payloads.begin(); payload != instance->payloads.begin();) {
#ifndef SERVICE_OPERATION_MODE_QUEUE
                if (!payload->assigned) {
#else
                if (!payload->assigned || payload->recipients.empty()) {
#endif
                    continue;
                }
                for (auto recipient = payload->recipients.begin(); recipient != payload->recipients.end();) {
                    if (recipient->connectionId == connectionId) {
                        recipient = payload->recipients.erase(recipient);
                        continue;
                    }
                    recipient++;
                }
#ifndef SERVICE_OPERATION_MODE_QUEUE
                if (payload->recipients.empty()) {
                    payload = instance->payloads.erase(payload);
                }
#else
                if (payload->recipients.empty()) {
                    payload->assigned = false;
                }
#endif
                payload++;
            }
        };

        std::atomic_bool error(false);
        std::thread serverThread([&]() {
            printMessage("Starting service on: " + address + ":" + std::to_string(port));

            server.SetConnectHandler([&](uint64_t connectionId, const Server::ConnectFlags &flags, const Server::ConnectParams &params, bool &sessionPresent) -> Server::ConnectResponse {
                if (flags.userName || flags.password) {
                    printMessage("Connection refused [\"" + params.clientId + "\":" + std::to_string(connectionId) + "], authorization not supported");
                    return Server::ConnectResponse::RefusedBadCredentials;
                }
                {
                    std::lock_guard<std::mutex> lock(instance->access);
                    if ((connectHandler != nullptr) && !connectHandler(params.clientId)) {
                        return Server::ConnectResponse::RefusedIdentifier;
                    }
                }
                try {
                    Clients::Client client = clients.Add(
                        connectionId,
                        params.clientId,
                        params.keepAlive,
                        flags.willFlag,
                        params.willTopic,
                        params.willMessage,
#ifndef SERVICE_OPERATION_MODE_QUEUE
                        (static_cast<uint8_t>(flags.willQoS2) << 1) | static_cast<uint8_t>(flags.willQoS1),
                        flags.willRetain
#else
                        (static_cast<uint8_t>(flags.willQoS2) << 1) | static_cast<uint8_t>(flags.willQoS1)
#endif
                    );
                    printMessage("Client [\"" + client.clientId + "\":" + std::to_string(client.connectionId) + "] connected");
                } catch (...) {
                    if (disconnectHandler != nullptr) {
                        disconnectHandler(params.clientId);
                    }
                    throw;
                }
                return Server::ConnectResponse::Accepted;
            });
            server.SetDisconnectHandler([&](uint64_t connectionId, bool graceful) {
                Clients::Client client = clients.Get(connectionId);
                if (!graceful && client.willFlag) {
                    try {
#ifndef SERVICE_OPERATION_MODE_QUEUE
                        instance->Publish(client.clientId, client.willTopic, client.willPayload, client.willQoS, client.willRetain);
#else
                        instance->Publish(client.clientId, client.willTopic, client.willPayload, client.willQoS);
#endif
                        printMessage("Client [\"" + client.clientId + "\":" + std::to_string(client.connectionId) + "] published to \"" + client.willTopic + "\"");
                    } catch (...) { }
                }
                for (std::string &topicName : topics->UnsubscribeAll(connectionId)) {
                    printMessage("Client [\"" + client.clientId + "\":" + std::to_string(client.connectionId) + "] unsubscribed from \"" + topicName + "\"");
                }
                removeRecipients(connectionId);
#ifndef SERVICE_OPERATION_MODE_QUEUE
                for (uint16_t packetId : published.RemoveAll(connectionId)) {
#else
                for (uint16_t packetId : published.RemoveAll(connectionId, [&](const std::string &topicName, const std::vector<uint8_t> &payload, uint8_t requestedQoS) noexcept {
                    try {
                        instance->Publish(std::string(), topicName, payload, requestedQoS, false);
                    } catch (...) { }
                })) {
#endif
                    clients.RemovePacket(connectionId, packetId);
                }
                receivedQoS2.Unregister(connectionId);
                clients.Delete(connectionId);
                {
                    if (disconnectHandler != nullptr) {
                        disconnectHandler(client.clientId);
                    }
                }
                printMessage("Client [\"" + client.clientId + "\":" + std::to_string(client.connectionId) + "] disconnected");
            });
            server.SetSubscribeHandler([&](uint64_t connectionId, const std::string &topicFilter, uint8_t requestedQoS) -> Server::SubscribeResponse {
                Clients::Client client = clients.Get(connectionId);
                std::size_t found = topicFilter.find("*");
                if (found != std::string::npos) {
                    printMessage("Client [\"" + client.clientId + "\":" + std::to_string(client.connectionId) + "] failed to subscribe to \"" + topicFilter + "\", wildcards not supported");
                    return Server::SubscribeResponse::Failure;
                }
#ifndef SERVICE_OPERATION_MODE_QUEUE
                std::vector<Topics::Retained> retained;
                try {
                    retained = topics->Subscribe(connectionId, topicFilter, requestedQoS);
#else
                try {
                    topics->Subscribe(connectionId, topicFilter, requestedQoS);
#endif
                    printMessage("Client [\"" + client.clientId + "\":" + std::to_string(client.connectionId) + "] subscribed to \"" + topicFilter + "\"");
                } catch (...) {
                    printMessage("Client [\"" + client.clientId + "\":" + std::to_string(client.connectionId) + "] failed to subscribe to \"" + topicFilter + "\", topics limit exceeded");
                    return Server::SubscribeResponse::Failure;
                }
#ifndef SERVICE_OPERATION_MODE_QUEUE
                publishRetained(connectionId, topicFilter, requestedQoS, retained);
#endif
                switch (requestedQoS) {
                case 2:
                    return Server::SubscribeResponse::QoS2;
                case 1:
                    return Server::SubscribeResponse::QoS2;
                default:
                    return Server::SubscribeResponse::QoS0;
                }
            });
            server.SetUnsubscribeHandler([&](uint64_t connectionId, const std::string &topicFilter) {
                Clients::Client client = clients.Get(connectionId);
                try {
                    topics->Unsubscribe(connectionId, topicFilter);
                    printMessage("Client [\"" + client.clientId + "\":" + std::to_string(client.connectionId) + "] unsubscribed from \"" + topicFilter + "\"");
                } catch (...) { }
            });
            server.SetPublishHandler([&](uint64_t connectionId, uint16_t packetId, const std::string &topicName, const std::vector<uint8_t> &payload, Server::PublishFlags &flags) -> Server::PublishResponse {
                Clients::Client client = clients.Get(connectionId);
                uint8_t requestedQoS = (static_cast<uint8_t>(flags.qos2) << 1) | static_cast<uint8_t>(flags.qos1);
                if (requestedQoS > 1) {
                    try {
                        receivedQoS2.Register(connectionId, packetId, flags.dup, client.keepAlive);
                    } catch (...) {
                        throw NoPacketException();
                    }
                }
                try {
#ifndef SERVICE_OPERATION_MODE_QUEUE
                    instance->Publish(client.clientId, topicName, payload, requestedQoS, flags.retain);
#else
                    instance->Publish(client.clientId, topicName, payload, requestedQoS);
#endif
                    printMessage("Client [\"" + client.clientId + "\":" + std::to_string(client.connectionId) + "] published to \"" + topicName + "\"");
                } catch (...) {
                    printMessage("Client [\"" + client.clientId + "\":" + std::to_string(client.connectionId) + "] failed to publish to \"" + topicName + "\"");
                    throw NoPacketException();
                }
                switch (requestedQoS) {
                case 2:
                    return Server::PublishResponse::QoS2;
                case 1:
                    return Server::PublishResponse::QoS1;
                default:
                    return Server::PublishResponse::QoS0;
                }
            });
            server.SetPubackHandler([&](uint64_t connectionId, uint16_t packetId) {
                try {
                    published.Remove(connectionId, packetId, 1, PublishedPayload::Status::Sent);
                    clients.RemovePacket(connectionId, packetId);
                } catch (...) {
                    throw NoPacketException();
                }
            });
            server.SetPubrecHandler([&](uint64_t connectionId, uint16_t packetId) {
                try {
                    published.UpdateStatus(connectionId, packetId, 2, PublishedPayload::Status::Sent, PublishedPayload::Status::Acknowledged);
                } catch (...) {
                    throw NoPacketException();
                }
            });
            server.SetPubcompHandler([&](uint64_t connectionId, uint16_t packetId) {
                try {
                    published.Remove(connectionId, packetId, 2, PublishedPayload::Status::Acknowledged);
                    clients.RemovePacket(connectionId, packetId);
                } catch (...) {
                    throw NoPacketException();
                }
            });
            server.SetPubrelHandler([&](uint64_t connectionId, uint16_t packetId) {
                try {
                    receivedQoS2.Unregister(connectionId, packetId);
                } catch (...) {
                    throw NoPacketException();
                }
            });

            try {
                server.Enable(address, port);
            } catch (std::exception &exception) {
                handleException(exception);
                error.store(true);
            }
        });

        while (!instance->disable.load() && !server.IsEnabled()) {
            std::this_thread::sleep_for(std::chrono::microseconds(SERVICE_NOP_DELAY));
        }

        auto getPublished = [&]() -> std::vector<PublishedPayload> {
            std::vector<PublishedPayload> payloads;
            auto available = clients.GetAvailablePacketsCount();
            auto subscriptions = topics->GetSubscriptions();
            auto getSubscribers = [&](const std::string &topicName) -> std::vector<Payload::Recipient> {
                for (auto &subscription : subscriptions) {
                    if (subscription.first == topicName) {
                        return subscription.second;
                    }
                }
                return std::vector<Payload::Recipient>();
            };
            std::lock_guard<std::mutex> lock(instance->access);
            for (auto payload = instance->payloads.begin(); payload != instance->payloads.end();) {
#ifndef SERVICE_OPERATION_MODE_QUEUE
                if (!payload->assigned) {
                    payload->recipients = getSubscribers(payload->topicName);
#else
                auto subscriptions = getSubscribers(payload->topicName);
                if (!payload->assigned && !subscriptions.empty()) {
                    payload->recipients.push_back(subscriptions[rand() % subscriptions.size()]);
#endif
                    payload->assigned = true;
                }
                if (!payload->assigned) {
                    payload++;
                    continue;
                }
                for (auto recipient = payload->recipients.begin(); recipient != payload->recipients.end();) {
                    auto verify = available.begin();
                    while (verify != available.end()) {
                        if (verify->first == recipient->connectionId) {
                            if (!verify->second) {
                                recipient++;
                                break;
                            }
                            try {
                                auto added = clients.AddPacket(recipient->connectionId);
                                payloads.push_back({
                                    payload->topicName,
                                    payload->data,
                                    recipient->connectionId,
                                    added.first,
                                    added.second,
                                    payload->requestedQoS,
                                    min(payload->requestedQoS, recipient->requestedQoS),
#ifndef SERVICE_OPERATION_MODE_QUEUE
                                    payload->retain,
#endif
                                    PublishedPayload::Status::Added
                                });
                                recipient = payload->recipients.erase(recipient);
                                verify->second--;
                            } catch (...) {
                                recipient++;
                            }
                            break;
                        }
                        verify++;
                    }
                    if (verify == available.end()) {
                        recipient++;
                    }
                }
                if (payload->recipients.empty()) {
                    payload = instance->payloads.erase(payload);
                    continue;
                }
                payload++;
            }
            return payloads;
        };

        try {
            auto statusTimestamp = std::chrono::system_clock::now();
            std::size_t publishedCount = 0;
            while (!instance->disable.load() && !error.load()) {
                bool processing = false;
                auto payloads = getPublished();
                publishedCount += payloads.size();
                published.Append(payloads);
#ifndef SERVICE_OPERATION_MODE_QUEUE
                for (auto handled : published.Handle(*topics, server)) {
#else
                for (auto handled : published.Handle(*topics, server, [&](const std::string &topicName, const std::vector<uint8_t> &payload, uint8_t requestedQoS) noexcept {
                    try {
                        instance->Publish(std::string(), topicName, payload, requestedQoS, false);
                    } catch (...) { }
                })) {
#endif
                    clients.RemovePacket(handled.first, handled.second);
                    processing = true;
                }
                auto now = std::chrono::system_clock::now();
                if (std::chrono::duration_cast<std::chrono::seconds>(now - statusTimestamp).count() >= SERVICE_STATUS_INTERVAL) {
                    printMessage("Status: [topics:" + std::to_string(topics->Count()) + ", clients:" + std::to_string(clients.Count()) + ", processed:" + std::to_string(publishedCount) + "]");
                    statusTimestamp = now;
                    publishedCount = 0;
                }
                receivedQoS2.HandleExpired();
                if (payloads.empty() && !processing) {
                    std::this_thread::sleep_for(std::chrono::microseconds(SERVICE_NOP_DELAY));
                }
            }
        } catch (std::exception &exception) {
            handleException(exception);
        }
        server.Disable();
        if (serverThread.joinable()) {
            serverThread.join();
        }
        instance->enabled.store(false);
    }
}
