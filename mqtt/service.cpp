#include "service.hpp"
#include "protocol.hpp"
#include <algorithm>
#include <climits>

#ifndef SERVICE_TOPICS_LIMIT
#define SERVICE_TOPICS_LIMIT USHRT_MAX
#endif
#ifndef SERVICE_PAYLOAD_SIZE_LIMIT
#define SERVICE_PAYLOAD_SIZE_LIMIT 32 * 1024 * 1024
#endif
#ifndef SERVICE_PAYLOADS_LIMIT
#define SERVICE_PAYLOADS_LIMIT USHRT_MAX
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

#define SERVICE_STATUS_INTERVAL 30
#define SERVICE_NOP_DELAY 1000

namespace mqtt {
    struct Payload {
        struct Recipient {
            uint64_t connectionId;
            uint8_t requestedQoS;
        };
        std::string topicName;
        std::vector<uint8_t> data;
        uint8_t requestedQoS;
        std::vector<Recipient> recipients;
        bool assigned;
    };

    struct PublishedPayload {
        std::string topicName;
        std::vector<uint8_t> data;
        uint64_t connectionId;
        uint16_t packetId, timeout;
        uint8_t requestedQoS, selectedQoS;
        enum class Status {
            Added,
            Sent,
            Acknowledged
        } status;
        std::chrono::time_point<std::chrono::system_clock> timestamp;
    };

    using RepublishHandler = std::function<void(const std::string &topicName, const std::vector<uint8_t> &payload, uint8_t requestedQoS) noexcept>;

    class Clients {
    public:
        struct Client {
            uint64_t connectionId;
            uint16_t keepAlive, packetIdSeq;
            std::string clientId;
            std::vector<uint16_t> packetIds;
        };
        Clients() { }
        Clients(const Clients &) = delete;
        Clients(Clients &&) = delete;
        Clients &operator=(const Clients &) = delete;
        Client Get(uint64_t connectionId) {
            std::lock_guard<std::mutex> lock(access);
            for (Client &client : clients) {
                if (client.connectionId == connectionId) {
                    return client;
                }
            }
            throw std::runtime_error("Client does not exist");
        }
        Client Add(uint64_t connectionId, const std::string &clientId, uint16_t keepAlive) {
            std::lock_guard<std::mutex> lock(access);
            for (Client &client : clients) {
                if (client.connectionId == connectionId) {
                    throw std::runtime_error("Duplicated connection identifier");
                }
            }
            clients.push_back({ connectionId, keepAlive ? keepAlive : static_cast<uint16_t>(SERVICE_DEFAULT_KEEP_ALIVE_TIME), 0, clientId });
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
        std::vector<std::pair<uint64_t, unsigned long long>> GetAvailablePacketsCount() {
            std::vector<std::pair<uint64_t, unsigned long long>> available;
            std::lock_guard<std::mutex> lock(access);
            for (Client &client : clients) {
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
        unsigned long long Count() {
            std::lock_guard<std::mutex> lock(access);
            return clients.size();
        }
    private:
        std::vector<Client> clients;
        std::mutex access;
    };

    class Topics {
    public:
        Topics() { }
        Topics(const Topics &) = delete;
        Topics(Topics &&) = delete;
        Topics &operator=(const Topics &) = delete;
        void Subscribe(uint64_t connectionId, const std::string &topicName, uint8_t requestedQoS) {
            std::lock_guard<std::mutex> lock(access);
            for (Topic &topic : topics) {
                if (topic.name == topicName) {
                    for (auto &subscription : topic.subscriptions) {
                        if (subscription.connectionId == connectionId) {
                            subscription.requestedQoS = requestedQoS;
                            return;
                        }
                    }
                    topic.subscriptions.push_back({ connectionId, requestedQoS });
                    return;
                }
            }
            if (topics.size() >= SERVICE_TOPICS_LIMIT) {
                std::runtime_error("Topics limit exceeded");
            }
            topics.push_back({ topicName, { { connectionId, requestedQoS } } });
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
        unsigned long long Count() {
            std::lock_guard<std::mutex> lock(access);
            return topics.size();
        }
        std::vector<std::pair<std::string, std::vector<Payload::Recipient>>> GetSubscriptions() {
            std::vector<std::pair<std::string, std::vector<Payload::Recipient>>> subscriptions;
            std::lock_guard<std::mutex> lock(access);
            for (Topic &topic : topics) {
                subscriptions.push_back({ topic.name, topic.subscriptions });
            }
            return subscriptions;
        }
        bool IsSubscribed(uint64_t connectionId, const std::string &topicName) {
            std::lock_guard<std::mutex> lock(access);
            for (Topic &topic : topics) {
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
        };
        std::vector<Topic> topics;
        std::mutex access;
    };

    class PublishedPayloads {
    public:
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
        unsigned long long Count() {
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
#ifndef SERVICE_OPERATION_MODE_QUEUE
                        if (!topics.IsSubscribed(payload->connectionId, payload->topicName)) {
                            throw NoPacketException();
                        }
                        resend = true;
#else
                        throw std::runtime_error("Timeout");
#endif
                    }
                    if ((payload->status == PublishedPayload::Status::Added) || resend) {
                        server.Publish(payload->connectionId, payload->packetId, payload->topicName, payload->data, { resend, static_cast<bool>(payload->selectedQoS & 0x1), static_cast<bool>(payload->selectedQoS & 0x2), false });
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
        std::mutex access;
    };

    class QoS2Requests {
    public:
        QoS2Requests() { }
        QoS2Requests(const QoS2Requests &) = delete;
        QoS2Requests(QoS2Requests &&) = delete;
        QoS2Requests &operator=(const QoS2Requests &) = delete;
        void Register(uint64_t connectionId, uint16_t packetId, bool duplicate, uint16_t timeout) {
            std::lock_guard<std::mutex> lock(access);
            for (Connection &connection : connections) {
                if (connection.connectionId == connectionId) {
                    for (auto request = connection.requests.begin(); request != connection.requests.end();) {
                        if (request->packetId == packetId) {
                            if (!duplicate) {
                                throw std::runtime_error("Duplicated packet identifier");
                            }
                            request = connection.requests.erase(request);
                            break;
                        }
                        request++;
                    }
                    if (connection.requests.size() >= SERVICE_RECEIVED_PAYLOADS_LIMIT) {
                        connection.requests.erase(connection.requests.begin());
                    }
                    connection.requests.push_back({ packetId, timeout, std::chrono::system_clock::now() });
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
                    for (auto request = connection->requests.begin(); request != connection->requests.end();) {
                        if (request->packetId == packetId) {
                            request = connection->requests.erase(request);
                            if (connection->requests.empty()) {
                                connection = connections.erase(connection);
                            }
                            return;
                        }
                        request++;
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
                for (auto request = connection->requests.begin(); request != connection->requests.end();) {
                    if (std::chrono::duration_cast<std::chrono::seconds>(now - request->timestamp).count() > request->timeout) {
                        request = connection->requests.erase(request);
                        if (connection->requests.empty()) {
                            connection = connections.erase(connection);
                        }
                        continue;
                    }
                    request++;
                }
                connection++;
            }
        };
    private:
        struct Connection {
            struct Request {
                uint16_t packetId, timeout;
                std::chrono::time_point<std::chrono::system_clock> timestamp;
            };
            uint64_t connectionId;
            std::vector<Request> requests;
        };
        std::vector<Connection> connections;
        std::mutex access;
    };

    Service::Service(const std::string &address, uint16_t port, const ExceptionHandler &exceptionHandler, const MessageHandler &messageHandler)
    {
        printMessage = messageHandler;
        handleException = exceptionHandler;
        thread = std::thread(ServiceThread, this, address, port);
    }

    Service::~Service()
    {
        Close();
    }

    void Service::Publish(const std::string &topicName, const std::vector<uint8_t> &payload, uint8_t requestedQoS) {
        if (payload.size() > SERVICE_PAYLOAD_SIZE_LIMIT) {
            throw std::runtime_error("Payload size limit violated");
        }
        std::lock_guard<std::mutex> lock(access);
        if (payloads.size() < SERVICE_PAYLOADS_LIMIT) {
            payloads.push_back({ topicName, payload, requestedQoS });
        } else {
            throw std::runtime_error("Payloads limit exceeded");
        }
    }

    void Service::ServiceThread(Service *instance, const std::string &address, uint16_t port) noexcept {
        Server server;
        Clients clients;
        PublishedPayloads published;
        QoS2Requests requests;
        Topics topics;

        auto print = [&](const std::string &text) {
            if (instance->printMessage != nullptr) {
                instance->printMessage(text);
            }
        };

        auto removeRecipients = [&](uint64_t connectionId) {
            std::lock_guard<std::mutex> lock(instance->access);
            for (Payload &payload : instance->payloads) {
                if (!payload.assigned || payload.recipients.empty()) {
                    continue;
                }
                for (auto recipient = payload.recipients.begin(); recipient != payload.recipients.end();) {
                    if (recipient->connectionId == connectionId) {
                        recipient = payload.recipients.erase(recipient);
                        continue;
                    }
                    recipient++;
                }
#ifdef SERVICE_OPERATION_MODE_QUEUE
                if (payload.recipients.empty()) {
                    payload.assigned = false;
                }
#endif
            }
        };

        std::thread serverThread([&]() {
            print("Starting service at " + address + ":" + std::to_string(port));

            server.SetConnectHandler([&](uint64_t connectionId, const ConnectFlags &flags, const ConnectParams &params, bool &sessionPresent) -> ConnectResponse {
                if (flags.userName || flags.password) {
                    print("Connection refused [\"" + params.clientId + "\":" + std::to_string(connectionId) + "], authorization not supported");
                    return ConnectResponse::RefusedBadCredentials;
                }
                if (flags.willFlag) {
                    print("Connection refused [\"" + params.clientId + "\":" + std::to_string(connectionId) + "], Will not supported");
                    return ConnectResponse::RefusedUnavailable;
                }
                Clients::Client client = clients.Add(connectionId, params.clientId, params.keepAlive);
                print("Client [\"" + client.clientId + "\":" + std::to_string(client.connectionId) + "] connected");
                return ConnectResponse::Accepted;
            });
            server.SetDisconnectHandler([&](uint64_t connectionId, bool graceful) {
                Clients::Client client = clients.Get(connectionId);
                for (std::string &topicName : topics.UnsubscribeAll(connectionId)) {
                    print("Client [\"" + client.clientId + "\":" + std::to_string(client.connectionId) + "] unsubscribed from \"" + topicName + "\"");
                }
                removeRecipients(connectionId);
#ifndef SERVICE_OPERATION_MODE_QUEUE
                for (uint16_t packetId : published.RemoveAll(connectionId)) {
#else
                for (uint16_t packetId : published.RemoveAll(connectionId, [&](const std::string &topicName, const std::vector<uint8_t> &payload, uint8_t requestedQoS) noexcept {
                    try {
                        instance->Publish(topicName, payload, requestedQoS);
                    } catch (...) { }
                })) {
#endif
                    clients.RemovePacket(connectionId, packetId);
                }
                requests.Unregister(connectionId);
                clients.Delete(connectionId);
                print("Client [\"" + client.clientId + "\":" + std::to_string(client.connectionId) + "] disconnected");
            });
            server.SetSubscribeHandler([&](uint64_t connectionId, const std::string &topicFilter, uint8_t requestedQoS) -> SubscribeResponse {
                Clients::Client client = clients.Get(connectionId);
                std::size_t found = topicFilter.find("*");
                if (found != std::string::npos) {
                    print("Client [\"" + client.clientId + "\":" + std::to_string(client.connectionId) + "] failed to subscribe to \"" + topicFilter + "\", wildcards not supported");
                    return SubscribeResponse::Failure;
                }
                try {
                    topics.Subscribe(connectionId, topicFilter, requestedQoS);
                    print("Client [\"" + client.clientId + "\":" + std::to_string(client.connectionId) + "] subscribed to \"" + topicFilter + "\"");
                } catch (...) {
                    print("Client [\"" + client.clientId + "\":" + std::to_string(client.connectionId) + "] failed to subscribe to \"" + topicFilter + "\", topics limit exceeded");
                    return SubscribeResponse::Failure;
                }
                switch (requestedQoS) {
                case 2:
                    return SubscribeResponse::QoS2;
                case 1:
                    return SubscribeResponse::QoS2;
                default:
                    return SubscribeResponse::QoS0;
                }
            });
            server.SetUnsubscribeHandler([&](uint64_t connectionId, const std::string &topicFilter) {
                Clients::Client client = clients.Get(connectionId);
                try {
                    topics.Unsubscribe(connectionId, topicFilter);
                    print("Client [\"" + client.clientId + "\":" + std::to_string(client.connectionId) + "] unsubscribed from \"" + topicFilter + "\"");
                } catch (...) { }
            });
            server.SetPublishHandler([&](uint64_t connectionId, uint16_t packetId, const std::string &topicName, const std::vector<uint8_t> &payload, PublishFlags &flags) -> PublishResponse {
                Clients::Client client = clients.Get(connectionId);
                uint8_t requestedQoS = (static_cast<uint8_t>(flags.qos2) << 1) | static_cast<uint8_t>(flags.qos1);
                try {
                    if (requestedQoS > 1) {
                        requests.Register(connectionId, packetId, flags.dup, client.keepAlive);
                    }
                } catch (...) {
                    throw NoPacketException();
                }
                try {
                    instance->Publish(topicName, payload, requestedQoS);
                    print("Client [\"" + client.clientId + "\":" + std::to_string(client.connectionId) + "] published to \"" + topicName + "\"");
                } catch (...) {
                    print("Client [\"" + client.clientId + "\":" + std::to_string(client.connectionId) + "] failed to publish to \"" + topicName + "\", payloads limit exceeded");
                    throw NoPacketException();
                }
                switch (requestedQoS) {
                case 2:
                    return PublishResponse::QoS2;
                case 1:
                    return PublishResponse::QoS1;
                default:
                    return PublishResponse::QoS0;
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
                    requests.Unregister(connectionId, packetId);
                } catch (...) {
                    throw NoPacketException();
                }
            });

            try {
                server.Enable(address, port, SERVICE_DEFAULT_MAX_CONNECTIONS);
            } catch (std::exception &exception) {
                instance->handleException(exception);
                instance->closed = true;;
            }
        });

        auto getPublished = [&]() -> std::vector<PublishedPayload> {
            std::vector<PublishedPayload> payloads;
            auto available = clients.GetAvailablePacketsCount();
            auto subscriptions = topics.GetSubscriptions();
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
                                payloads.push_back({ payload->topicName, payload->data, recipient->connectionId, added.first, added.second, payload->requestedQoS, std::min(payload->requestedQoS, recipient->requestedQoS), PublishedPayload::Status::Added });
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
            unsigned long long publishedCount = 0;
            while (!instance->closed) {
                bool processing = false;
                auto payloads = getPublished();
                publishedCount += payloads.size();
                published.Append(payloads);
#ifndef SERVICE_OPERATION_MODE_QUEUE
                for (auto handled : published.Handle(topics, server)) {
#else
                for (auto handled : published.Handle(topics, server, [&](const std::string &topicName, const std::vector<uint8_t> &payload, uint8_t requestedQoS) noexcept {
                    try {
                        instance->Publish(topicName, payload, requestedQoS);
                    } catch (...) { }
                })) {
#endif
                    clients.RemovePacket(handled.first, handled.second);
                    processing = true;
                }
                auto now = std::chrono::system_clock::now();
                if (std::chrono::duration_cast<std::chrono::seconds>(now - statusTimestamp).count() >= SERVICE_STATUS_INTERVAL) {
                    print("Status: [topics:" + std::to_string(topics.Count()) + ", clients:" + std::to_string(clients.Count()) + ", processed:" + std::to_string(publishedCount) + "]");
                    statusTimestamp = now;
                    publishedCount = 0;
                }
                requests.HandleExpired();
                if (payloads.empty() && !processing) {
                    std::this_thread::sleep_for(std::chrono::microseconds(SERVICE_NOP_DELAY));
                }
            }
        } catch (std::exception &exception) {
            instance->handleException(exception);
            instance->closed = true;;
        }
        server.Disable();
        serverThread.join();
    }
}
