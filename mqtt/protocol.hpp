#pragma once

#include <functional>
#include <string>
#include <vector>
#include <mutex>

namespace mqtt {
    class Packet;

    struct PublishFlags {
        bool dup, qos1, qos2, retain;
    };

    struct ConnectFlags {
        bool userName, password, willRetain, willQoS1, willQoS2, willFlag, cleanSession;
    };

    struct ConnectParams {
        std::string clientId, willTopic, willMessage, userName, password;
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

    class DisconnectException : public std::exception {
    public:
        explicit DisconnectException();
        explicit DisconnectException(const std::string &reason);
        virtual const char *what() const noexcept;
    protected:
        std::string reason;
    };

    class NoPacketException : public std::exception {
    public:
        virtual const char *what() const noexcept;
    };

    class Server {
    public:
        Server();
        Server(const Server &) = delete;
        Server(Server &&) = delete;
        virtual ~Server();
        Server &operator=(const Server &) = delete;
        void Enable(const std::string &address, uint16_t port, uint32_t maxConn = 64);
        void Disable() noexcept;
        bool IsEnabled() const;
        void SetConnectHandler(const ConnectHandler &handler);
        void SetDisconnectHandler(const DisconnectHandler &handler);
        void SetPublishHandler(const PublishHandler &handler);
        void SetPubackHandler(const PubackHandler &handler);
        void SetPubrecHandler(const PubackHandler &handler);
        void SetPubrelHandler(const PubackHandler &handler);
        void SetPubcompHandler(const PubackHandler &handler);
        void SetSubscribeHandler(const SubscribeHandler &handler);
        void SetUnsubscribeHandler(const UnsubscribeHandler &handler);
        void Publish(uint64_t connectionId, uint16_t packetId, const std::string &topicName, const std::vector<uint8_t> &payload, const PublishFlags &flags);
        std::string GetAddress(uint64_t connectionId);
    private:
        Packet HandlePacket(const Packet &packet, uint64_t connectionId, bool &connected, uint16_t &keepAlive);

        void *server, *connections;
        std::mutex access;
        PublishHandler publish;
        ConnectHandler connect;
        DisconnectHandler disconnect;
        SubscribeHandler subscribe;
        UnsubscribeHandler unsubscribe;
        PubackHandler puback, pubrec, pubrel, pubcomp;
    };
}
