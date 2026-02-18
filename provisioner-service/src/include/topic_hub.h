#pragma once

#include <drogon/WebSocketController.h>
#include <json/json.h>
#include <string>
#include <vector>
#include <set>
#include <unordered_map>
#include <mutex>

namespace provisioner {

// Thread-safe topic-based pub/sub hub for WebSocket connections.
//
// Publishers (worker threads, handlers) call publish() with a topic and a
// JSON payload.  Subscribers (WebSocket connections) are registered via
// subscribe().  The hub forwards published messages to every connection
// subscribed to the matching topic.
//
// A reverse index (connection -> topics) allows O(1)-ish cleanup when a
// connection disconnects, without scanning every topic.
class TopicHub {
public:
    static TopicHub& instance() {
        static TopicHub hub;
        return hub;
    }

    void subscribe(const std::string& topic, const drogon::WebSocketConnectionPtr& conn) {
        std::lock_guard<std::mutex> lock(mutex_);
        topics_[topic].push_back(conn);
        connTopics_[conn.get()].insert(topic);
    }

    void unsubscribe(const std::string& topic, const drogon::WebSocketConnectionPtr& conn) {
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = topics_.find(topic);
        if (it != topics_.end()) {
            auto& vec = it->second;
            vec.erase(std::remove_if(vec.begin(), vec.end(),
                [&](const drogon::WebSocketConnectionPtr& c) { return c.get() == conn.get(); }),
                vec.end());
            if (vec.empty()) topics_.erase(it);
        }
        auto cit = connTopics_.find(conn.get());
        if (cit != connTopics_.end()) {
            cit->second.erase(topic);
            if (cit->second.empty()) connTopics_.erase(cit);
        }
    }

    // Remove a connection from all topics (call on WebSocket disconnect).
    void removeConnection(const drogon::WebSocketConnectionPtr& conn) {
        std::lock_guard<std::mutex> lock(mutex_);
        auto cit = connTopics_.find(conn.get());
        if (cit == connTopics_.end()) return;
        for (const auto& topic : cit->second) {
            auto tit = topics_.find(topic);
            if (tit != topics_.end()) {
                auto& vec = tit->second;
                vec.erase(std::remove_if(vec.begin(), vec.end(),
                    [&](const drogon::WebSocketConnectionPtr& c) { return c.get() == conn.get(); }),
                    vec.end());
                if (vec.empty()) topics_.erase(tit);
            }
        }
        connTopics_.erase(cit);
    }

    // Publish a JSON message to all subscribers of a topic.
    // Serialises the JSON once and sends the same string to every connection.
    // Prunes disconnected connections encountered during iteration.
    void publish(const std::string& topic, const Json::Value& msg) {
        Json::StreamWriterBuilder builder;
        builder["indentation"] = "";
        std::string payload = Json::writeString(builder, msg);

        std::lock_guard<std::mutex> lock(mutex_);
        auto it = topics_.find(topic);
        if (it == topics_.end()) return;

        auto& vec = it->second;
        vec.erase(std::remove_if(vec.begin(), vec.end(),
            [&](const drogon::WebSocketConnectionPtr& c) {
                if (!c->connected()) return true;
                c->send(payload);
                return false;
            }),
            vec.end());

        if (vec.empty()) topics_.erase(it);
    }

    // Remove a topic entirely (e.g. when an upload completes).
    void removeTopic(const std::string& topic) {
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = topics_.find(topic);
        if (it == topics_.end()) return;
        for (const auto& conn : it->second) {
            auto cit = connTopics_.find(conn.get());
            if (cit != connTopics_.end()) {
                cit->second.erase(topic);
                if (cit->second.empty()) connTopics_.erase(cit);
            }
        }
        topics_.erase(it);
    }

private:
    TopicHub() = default;
    TopicHub(const TopicHub&) = delete;
    TopicHub& operator=(const TopicHub&) = delete;

    std::mutex mutex_;
    // topic -> list of subscribed connections
    std::unordered_map<std::string, std::vector<drogon::WebSocketConnectionPtr>> topics_;
    // raw connection pointer -> set of topics (reverse index for fast disconnect cleanup)
    std::unordered_map<void*, std::set<std::string>> connTopics_;
};

} // namespace provisioner
