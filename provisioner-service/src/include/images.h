#pragma once

#include <drogon/drogon.h>
#include <drogon/HttpAppFramework.h>
#include <drogon/HttpResponse.h>
#include <string>
#include <vector>
#include <unordered_map>
#include <mutex>
#include <memory>
#include <queue>
#include <thread>
#include <condition_variable>
#include <atomic>
#include <chrono>
#include <optional>

namespace provisioner {

    // SHA256 calculation status
    enum class SHA256Status {
        PENDING,   // Calculation in progress
        COMPLETE,  // Calculation completed
        ERROR      // Error occurred during calculation
    };

    // Cancellation token for SHA256 calculations
    class SHA256CancellationToken {
    public:
        SHA256CancellationToken() : cancelled(false) {}
        
        void cancel() {
            cancelled.store(true);
        }
        
        bool is_cancelled() const {
            return cancelled.load();
        }
        
    private:
        std::atomic<bool> cancelled;
    };

    // SHA256 result structure
    struct SHA256Result {
        std::string value;       // SHA256 hash value or error message
        SHA256Status status;     // Status of the calculation
        std::optional<std::chrono::steady_clock::time_point> timestamp; // When calculation was started
        double progress;         // Progress from 0.0 to 1.0 (0% to 100%)
        std::shared_ptr<SHA256CancellationToken> cancellation_token; // Cancellation token for this job
        
        SHA256Result(const std::string& val, SHA256Status st) 
            : value(val), status(st), timestamp(std::nullopt), progress(-1.0), cancellation_token(nullptr) {}
            
        SHA256Result(const std::string& val, SHA256Status st, bool withTimestamp) 
            : value(val), status(st), progress(-1.0), cancellation_token(nullptr) {
            if (withTimestamp) {
                timestamp = std::chrono::steady_clock::now();
            } else {
                timestamp = std::nullopt;
            }
        }
        
        // Constructor with progress information
        SHA256Result(const std::string& val, SHA256Status st, double prog)
            : value(val), status(st), timestamp(std::nullopt), progress(prog), cancellation_token(nullptr) {}
            
        // Constructor with cancellation token
        SHA256Result(const std::string& val, SHA256Status st, bool withTimestamp, std::shared_ptr<SHA256CancellationToken> token) 
            : value(val), status(st), progress(-1.0), cancellation_token(token) {
            if (withTimestamp) {
                timestamp = std::chrono::steady_clock::now();
            } else {
                timestamp = std::nullopt;
            }
        }
    };

    // Export cache for WebSocket controller
    extern std::unordered_map<std::string, SHA256Result> sha256Cache;
    extern std::mutex sha256Cache_mutex;
    
    // Initialize the SHA256 calculation worker thread
    void initSHA256Worker();
    
    // Shutdown the SHA256 calculation worker thread
    void shutdownSHA256Worker();
    
    // Request a SHA256 calculation (queues the request)
    void requestSHA256Calculation(const std::string& imageName);
    
    // Cancel an ongoing SHA256 calculation by cancelling its token
    void cancelSHA256Calculation(const std::string& imageName);

    struct ImageInfo {
        std::string name;
        std::string sha256;
    };

    class Images {
    public:
        Images();
        ~Images();

        void registerHandlers(drogon::HttpAppFramework &app);
    };

} // namespace provisioner
