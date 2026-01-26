#include <drogon/drogon.h>
#include <drogon/HttpAppFramework.h>
#include <drogon/HttpResponse.h>
#include <drogon/HttpTypes.h>
#include <drogon/HttpController.h>
#include <drogon/HttpSimpleController.h>
#include <drogon/HttpTypes.h>
#include <drogon/WebSocketController.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/inotify.h>
#include <sys/select.h>
#include <errno.h>
#include <systemd/sd-bus.h>
#include "utils.h"

#include <filesystem>
#include <string>
#include <vector>
#include <fstream>
#include <sstream>
#include <iomanip>
#include <openssl/evp.h>
#include <mutex>
#include <unordered_map>
#include <queue>
#include <thread>
#include <condition_variable>
#include <atomic>
#include <chrono>
#include <cmath>
#include <random>

#include <images.h>
#include "utils.h"
#include "include/audit.h"

// WebSocket controller for SHA256 calculations
// Defined outside the provisioner namespace to avoid registration issues
class SHA256WebSocketController : public drogon::WebSocketController<SHA256WebSocketController> {
public:
    // Store active WebSocket connections
    static std::unordered_map<std::string, std::vector<drogon::WebSocketConnectionPtr>> activeConnections;
    static std::mutex connectionsMutex;
    
    // Send update to all clients interested in this image
    static void broadcastUpdate(const std::string& imageName, const provisioner::SHA256Result& result) {
        std::lock_guard<std::mutex> lock(connectionsMutex);
        
        auto it = activeConnections.find(imageName);
        if (it != activeConnections.end() && !it->second.empty()) {
            Json::Value response;
            response["image_name"] = imageName;
            
            switch (result.status) {
                case provisioner::SHA256Status::COMPLETE:
                    response["sha256"] = result.value;
                    response["status"] = "complete";
                    LOG_INFO << "WebSocket: Broadcasting COMPLETE status for " << imageName << ": " << result.value;
                    break;
                    
                case provisioner::SHA256Status::PENDING:
                    response["status"] = "pending";
                    // Include progress information if available
                    if (result.progress >= 0) {
                        response["progress"] = result.progress;
                        response["progress_percent"] = static_cast<int>(result.progress * 100);
                        LOG_INFO << "WebSocket: Broadcasting PENDING status for " << imageName 
                                 << " - " << static_cast<int>(result.progress * 100) << "% complete";
                    } else {
                        LOG_INFO << "WebSocket: Broadcasting PENDING status for " << imageName << " with no progress info";
                    }
                    break;
                    
                case provisioner::SHA256Status::ERROR:
                    response["error"] = result.value;
                    response["status"] = "error";
                    LOG_INFO << "WebSocket: Broadcasting ERROR status for " << imageName << ": " << result.value;
                    break;
            }
            
            std::string message = response.toStyledString();
            
            // Iterate over all clients and send the update
            auto& connections = it->second;
            auto connIt = connections.begin();
            while (connIt != connections.end()) {
                if ((*connIt)->connected()) {
                    (*connIt)->send(message);
                    ++connIt;
                } else {
                    // Remove disconnected clients
                    connIt = connections.erase(connIt);
                }
            }
        }
    }

    void handleNewMessage(const drogon::WebSocketConnectionPtr& wsConnPtr, std::string&& message, const drogon::WebSocketMessageType& type) override {
        if (type == drogon::WebSocketMessageType::Text) {
            Json::Value request;
            Json::CharReaderBuilder builder;
            std::string errors;
            std::istringstream iss(message);
            if (!Json::parseFromStream(builder, iss, &request, &errors)) {
                Json::Value response;
                response["error"] = "Invalid JSON";
                wsConnPtr->send(response.toStyledString());
                return;
            }
            
            if (request.isMember("action") && request["action"].asString() == "get_sha256" && 
                request.isMember("image_name")) {
                std::string imageName = request["image_name"].asString();
                // Refuse sidecar requests up-front
                try {
                    if (std::filesystem::path(imageName).extension() == ".sha256") {
                        Json::Value response;
                        response["image_name"] = imageName;
                        response["status"] = "error";
                        response["error"] = "Refused: .sha256 sidecar files are not hashable";
                        wsConnPtr->send(response.toStyledString());
                        return;
                    }
                } catch (...) {}
                
                // Register this connection as interested in this image
                {
                    std::lock_guard<std::mutex> lock(connectionsMutex);
                    activeConnections[imageName].push_back(wsConnPtr);
                }
                
                // Check cache for result
                {
                    std::lock_guard<std::mutex> lock(provisioner::sha256Cache_mutex);
                    auto it = provisioner::sha256Cache.find(imageName);
                    
                    if (it != provisioner::sha256Cache.end()) {
                        Json::Value response;
                        response["image_name"] = imageName;
                        
                        switch (it->second.status) {
                            case provisioner::SHA256Status::COMPLETE:
                                response["sha256"] = it->second.value;
                                response["status"] = "complete";
                                LOG_INFO << "WebSocket: Sending COMPLETE status for " << imageName << ": " << it->second.value;
                                break;
                                
                            case provisioner::SHA256Status::PENDING:
                                response["status"] = "pending";
                                // Include progress information if available
                                if (it->second.progress >= 0) {
                                    response["progress"] = it->second.progress;
                                    response["progress_percent"] = static_cast<int>(it->second.progress * 100);
                                    LOG_INFO << "WebSocket: Sending PENDING status for " << imageName 
                                             << " with progress " << static_cast<int>(it->second.progress * 100) << "%";
                                } else {
                                    LOG_INFO << "WebSocket: Sending PENDING status for " << imageName << " with no progress info";
                                }
                                break;
                                
                            case provisioner::SHA256Status::ERROR:
                                response["error"] = it->second.value;
                                response["status"] = "error";
                                LOG_INFO << "WebSocket: Sending ERROR status for " << imageName << ": " << it->second.value;
                                break;
                        }
                        
                        wsConnPtr->send(response.toStyledString());
                    } else {
                        // Start calculation if not found
                        provisioner::requestSHA256Calculation(imageName);
                        
                        // Send pending response
                        Json::Value response;
                        response["image_name"] = imageName;
                        response["status"] = "pending";
                        wsConnPtr->send(response.toStyledString());
                    }
                }
            }
        }
    }
    
    void handleNewConnection(const drogon::HttpRequestPtr& req, const drogon::WebSocketConnectionPtr& wsConnPtr) override {
        LOG_INFO << "New WebSocket connection for SHA256 calculation";
    }
    
    void handleConnectionClosed(const drogon::WebSocketConnectionPtr& wsConnPtr) override {
        LOG_INFO << "WebSocket connection closed";
        
        // Track which images need to be checked for cancellation
        std::vector<std::string> imagesToCheck;
        
        // Remove this connection from all image subscriptions
        {
            std::lock_guard<std::mutex> lock(connectionsMutex);
            for (auto& pair : activeConnections) {
                auto& connections = pair.second;
                size_t before = connections.size();
                connections.erase(
                    std::remove_if(connections.begin(), connections.end(),
                        [&wsConnPtr](const drogon::WebSocketConnectionPtr& conn) {
                            return conn == wsConnPtr;
                        }
                    ),
                    connections.end()
                );
                
                // If this connection was removed and no connections remain for this image
                if (before > connections.size() && connections.empty()) {
                    imagesToCheck.push_back(pair.first);
                    LOG_INFO << "WebSocket: No more connections interested in " << pair.first;
                }
            }
        }
        
        // Cancel SHA256 calculations for images with no interested connections
        for (const auto& imageName : imagesToCheck) {
            // Check if the calculation is still pending before cancelling
            {
                std::lock_guard<std::mutex> lock(provisioner::sha256Cache_mutex);
                auto it = provisioner::sha256Cache.find(imageName);
                if (it != provisioner::sha256Cache.end() && it->second.status == provisioner::SHA256Status::PENDING) {
                    LOG_INFO << "WebSocket: Cancelling SHA256 calculation for " << imageName << " (no interested connections)";
                    provisioner::cancelSHA256Calculation(imageName);
                }
            }
        }
    }
    
    WS_PATH_LIST_BEGIN
    WS_PATH_ADD("/ws/sha256");
    WS_PATH_LIST_END
};

// Define static members
std::unordered_map<std::string, std::vector<drogon::WebSocketConnectionPtr>> SHA256WebSocketController::activeConnections;
std::mutex SHA256WebSocketController::connectionsMutex;

// WebSocket controller for boot package status
class BootPackageWebSocketController : public drogon::WebSocketController<BootPackageWebSocketController> {
public:
    // Store active WebSocket connections
    static std::unordered_map<std::string, std::vector<drogon::WebSocketConnectionPtr>> activeConnections;
    static std::mutex connectionsMutex;
    
    // Send update to all clients interested in this image
    static void broadcastUpdate(const std::string& imageName, bool exists, const std::string& packageName, const std::string& status = "") {
        std::lock_guard<std::mutex> lock(connectionsMutex);
        
        auto it = activeConnections.find(imageName);
        if (it != activeConnections.end() && !it->second.empty()) {
            Json::Value response;
            response["image_name"] = imageName;
            response["exists"] = exists;
            
            if (!status.empty()) {
                response["status"] = status;
            } else if (exists) {
                response["package_name"] = packageName;
                response["status"] = "available";
                LOG_INFO << "WebSocket: Broadcasting boot package available for " << imageName << ": " << packageName;
            } else {
                response["status"] = "not_found";
                LOG_INFO << "WebSocket: Broadcasting boot package not found for " << imageName;
            }
            
            std::string message = response.toStyledString();
            
            // Iterate over all clients and send the update
            auto& connections = it->second;
            auto connIt = connections.begin();
            while (connIt != connections.end()) {
                if ((*connIt)->connected()) {
                    (*connIt)->send(message);
                    ++connIt;
                } else {
                    // Remove disconnected clients
                    connIt = connections.erase(connIt);
                }
            }
        }
    }

    void handleNewMessage(const drogon::WebSocketConnectionPtr& wsConnPtr, std::string&& message, const drogon::WebSocketMessageType& type) override {
        if (type == drogon::WebSocketMessageType::Text) {
            Json::Value request;
            Json::CharReaderBuilder builder;
            std::string errors;
            std::istringstream iss(message);
            if (!Json::parseFromStream(builder, iss, &request, &errors)) {
                Json::Value response;
                response["error"] = "Invalid JSON";
                wsConnPtr->send(response.toStyledString());
                return;
            }
            
            if (request.isMember("action") && request["action"].asString() == "check_boot_package" && 
                request.isMember("image_name")) {
                std::string imageName = request["image_name"].asString();
                
                // Register this connection as interested in this image
                {
                    std::lock_guard<std::mutex> lock(connectionsMutex);
                    activeConnections[imageName].push_back(wsConnPtr);
                }
                
                // Check for boot package
                provisioner::requestBootPackageCheck(imageName);
            }
        }
    }
    
    void handleNewConnection(const drogon::HttpRequestPtr& req, const drogon::WebSocketConnectionPtr& wsConnPtr) override {
        LOG_INFO << "New WebSocket connection for boot package status";
    }
    
    void handleConnectionClosed(const drogon::WebSocketConnectionPtr& wsConnPtr) override {
        LOG_INFO << "WebSocket connection closed for boot package";
        
        // Remove this connection from all image subscriptions
        {
            std::lock_guard<std::mutex> lock(connectionsMutex);
            for (auto& pair : activeConnections) {
                auto& connections = pair.second;
                connections.erase(
                    std::remove_if(connections.begin(), connections.end(),
                        [&wsConnPtr](const drogon::WebSocketConnectionPtr& conn) {
                            return conn == wsConnPtr;
                        }
                    ),
                    connections.end()
                );
            }
        }
    }
    
    WS_PATH_LIST_BEGIN
    WS_PATH_ADD("/ws/boot-package");
    WS_PATH_LIST_END
};

// Define static members
std::unordered_map<std::string, std::vector<drogon::WebSocketConnectionPtr>> BootPackageWebSocketController::activeConnections;
std::mutex BootPackageWebSocketController::connectionsMutex;

namespace provisioner {

    namespace {
        const std::string IMAGES_PATH = "/srv/rpi-sb-provisioner/images";
        
        // Message queue for SHA256 calculation requests
        std::queue<std::string> sha256RequestQueue;
        std::mutex queueMutex;
        std::condition_variable queueCV;
        std::atomic<bool> workerRunning{false};
        std::thread workerThread;
    } // namespace anonymous
    
    // In-memory cache for SHA256 results
    std::unordered_map<std::string, SHA256Result> sha256Cache;
    std::mutex sha256Cache_mutex;
    
    // Function to cancel SHA256 calculation for a specific image
    void cancelSHA256Calculation(const std::string& imageName) {
        std::lock_guard<std::mutex> lock(sha256Cache_mutex);
        auto it = sha256Cache.find(imageName);
        if (it != sha256Cache.end()) {
            if (it->second.cancellation_token) {
                it->second.cancellation_token->cancel();
                LOG_INFO << "Cancelled SHA256 calculation for: " << imageName;
            } else {
                LOG_WARN << "No cancellation token found for " << imageName << " in cache";
            }
        } else {
            LOG_WARN << "No cache entry found for " << imageName << " during cancellation";
        }
    }

    // Calculate SHA256 of a file
    std::string calculateSHA256(const std::filesystem::path& imagePath, const std::string& imageName, std::shared_ptr<SHA256CancellationToken> cancellationToken) {
        // Use smaller chunks (1MB) for more responsive cancellation
        constexpr size_t CHUNK_SIZE = 1 * 1024 * 1024; 
        // For very large files, process in even smaller sub-chunks within each chunk
        constexpr size_t SUB_CHUNK_SIZE = 256 * 1024; // 256KB sub-chunks
        std::vector<unsigned char> buffer(CHUNK_SIZE);
        unsigned char hash[EVP_MAX_MD_SIZE];
        unsigned int hash_len;
        
        EVP_MD_CTX* mdctx = EVP_MD_CTX_new();
        EVP_DigestInit_ex(mdctx, EVP_sha256(), nullptr);
        
        std::ifstream file(imagePath, std::ios::binary);
        if (!file) {
            EVP_MD_CTX_free(mdctx);
            return "file-read-error";
        }
        
        // Get file size for progress reporting
        file.seekg(0, std::ios::end);
        std::streamsize fileSize = file.tellg();
        file.seekg(0, std::ios::beg);
        
        // Log start of calculation
        LOG_INFO << "Starting SHA256 calculation for " << imagePath.filename().string() 
                 << " (" << (fileSize / (1024 * 1024)) << " MB)";
        
        std::streamsize totalBytesRead = 0;
        int lastProgressPercent = 0;
        
        while (file) {
            // Check for cancellation before each chunk
            if (cancellationToken) {
                if (cancellationToken->is_cancelled()) {
                    LOG_INFO << "SHA256 calculation cancelled for " << imageName;
                    EVP_MD_CTX_free(mdctx);
                    file.close();
                    return "calculation-cancelled";
                }
            } else {
                LOG_WARN << "No cancellation token available for " << imageName << " during chunk processing";
            }
            
            file.read(reinterpret_cast<char*>(buffer.data()), CHUNK_SIZE);
            std::streamsize bytes_read = file.gcount();
            if (bytes_read > 0) {
                // Process in smaller sub-chunks for more frequent cancellation checks
                std::streamsize processed = 0;
                while (processed < bytes_read) {
                    // Check for cancellation every sub-chunk
                    if (cancellationToken && cancellationToken->is_cancelled()) {
                        LOG_INFO << "SHA256 calculation cancelled during sub-chunk processing for " << imageName;
                        EVP_MD_CTX_free(mdctx);
                        file.close();
                        return "calculation-cancelled";
                    }
                    
                    std::streamsize sub_chunk_size = std::min(static_cast<std::streamsize>(SUB_CHUNK_SIZE), bytes_read - processed);
                    EVP_DigestUpdate(mdctx, buffer.data() + processed, sub_chunk_size);
                    processed += sub_chunk_size;
                }
                
                totalBytesRead += bytes_read;
                
                // Log progress every 10%
                if (fileSize > 0) {
                    int progressPercent = static_cast<int>((totalBytesRead * 100) / fileSize);
                    double progressFraction = static_cast<double>(totalBytesRead) / fileSize;
                    
                    if (progressPercent >= lastProgressPercent + 5) {
                        lastProgressPercent = (progressPercent / 5) * 5; // Round to nearest 5%
                        LOG_INFO << "SHA256 calculation: " << lastProgressPercent << "% complete for "
                                 << imagePath.filename().string();
                        
                        // Update the progress in the cache
                        if (!imageName.empty()) {
                            std::lock_guard<std::mutex> lock(sha256Cache_mutex);
                            auto it = sha256Cache.find(imageName);
                            if (it != sha256Cache.end() && it->second.status == SHA256Status::PENDING) {
                                // Update progress while keeping other fields the same
                                SHA256Result updatedResult("", SHA256Status::PENDING, progressFraction);
                                
                                // Preserve the timestamp if it exists
                                if (it->second.timestamp.has_value()) {
                                    updatedResult.timestamp = it->second.timestamp;
                                }
                                
                                // CRITICAL: Preserve the cancellation token!
                                updatedResult.cancellation_token = it->second.cancellation_token;
                                
                                sha256Cache.insert_or_assign(imageName, updatedResult);
                                
                                // Broadcast progress update to connected WebSocket clients
                                SHA256WebSocketController::broadcastUpdate(imageName, updatedResult);
                            }
                        }
                    }
                }
            }
        }
        
        // Final check for cancellation before completing
        if (cancellationToken && cancellationToken->is_cancelled()) {
            LOG_INFO << "SHA256 calculation cancelled at completion for " << imageName;
            EVP_MD_CTX_free(mdctx);
            file.close();
            return "calculation-cancelled";
        }
        
        EVP_DigestFinal_ex(mdctx, hash, &hash_len);
        EVP_MD_CTX_free(mdctx);
        file.close();
        
        std::stringstream ss;
        for(unsigned int i = 0; i < hash_len; i++) {
            ss << std::hex << std::setw(2) << std::setfill('0') << (int)hash[i];
        }
        std::string sha256 = ss.str();
        std::memset(hash, 0, EVP_MAX_MD_SIZE);
        
        LOG_INFO << "Completed SHA256 calculation for " << imagePath.filename().string();
        
        return sha256;
    }
    
    // The worker thread function that processes SHA256 calculation requests
    void sha256WorkerFunction() {
        LOG_INFO << "SHA256 worker thread started";
        
        while (workerRunning) {
            std::string imageName;
            
            // Wait for a request or shutdown signal
            {
                std::unique_lock<std::mutex> lock(queueMutex);
                queueCV.wait(lock, [&]() { 
                    return !sha256RequestQueue.empty() || !workerRunning; 
                });
                
                if (!workerRunning) {
                    break;
                }
                
                if (!sha256RequestQueue.empty()) {
                    imageName = sha256RequestQueue.front();
                    sha256RequestQueue.pop();
                }
            }
            
            if (!imageName.empty()) {
                LOG_INFO << "Processing SHA256 calculation for: " << imageName;
                
                std::filesystem::path imagePath(IMAGES_PATH);
                imagePath /= imageName;
                
                try {
                    if (!std::filesystem::exists(imagePath)) {
                        // File not found, update cache with error
                        std::lock_guard<std::mutex> lock(sha256Cache_mutex);
                        sha256Cache.insert_or_assign(imageName, SHA256Result(
                            "file-not-found",
                            SHA256Status::ERROR,
                            false
                        ));
                    } else {
                        // Get cancellation token from cache
                        std::shared_ptr<SHA256CancellationToken> cancellationToken;
                        {
                            std::lock_guard<std::mutex> lock(sha256Cache_mutex);
                            auto it = sha256Cache.find(imageName);
                            if (it != sha256Cache.end()) {
                                cancellationToken = it->second.cancellation_token;
                                LOG_INFO << "Retrieved cancellation token for " << imageName 
                                         << " (token valid: " << (cancellationToken ? "yes" : "no") << ")";
                            } else {
                                LOG_WARN << "No cache entry found for " << imageName << " during calculation";
                            }
                        }
                        
                        // Calculate SHA256
                        std::string sha256 = calculateSHA256(imagePath, imageName, cancellationToken);
                        
                        // Check if calculation was cancelled
                        if (sha256 == "calculation-cancelled") {
                            LOG_INFO << "SHA256 calculation was cancelled for " << imageName;
                            
                            // Log cancelled SHA256 calculation
                            AuditLog::logFileSystemAccess("SHA256_CANCELLED", imagePath.string(), true, "", 
                                "SHA256 calculation cancelled for: " + imageName);
                            
                            // Remove from cache since the file was deleted
                            std::lock_guard<std::mutex> lock(sha256Cache_mutex);
                            sha256Cache.erase(imageName);
                            continue; // Skip broadcasting
                        }
                        
                        // Update cache with result
                        std::lock_guard<std::mutex> lock(sha256Cache_mutex);
                        SHA256Result result(sha256, SHA256Status::COMPLETE, false);
                        // Preserve cancellation token from existing entry if it exists
                        auto it = sha256Cache.find(imageName);
                        if (it != sha256Cache.end()) {
                            result.cancellation_token = it->second.cancellation_token;
                        }
                        sha256Cache.insert_or_assign(imageName, result);
                        
                        // Write/refresh sidecar file with SHA256 to optimize future reads
                        try {
                            std::filesystem::path sidecarPath(IMAGES_PATH);
                            sidecarPath /= imageName;
                            sidecarPath += ".sha256";
                            std::ofstream sidecarFile(sidecarPath, std::ios::out | std::ios::trunc);
                            if (sidecarFile.is_open()) {
                                sidecarFile << sha256 << "\n";
                                sidecarFile.close();
                                AuditLog::logFileSystemAccess("WRITE", sidecarPath.string(), true, "", 
                                    std::string("Wrote SHA256 sidecar for: ") + imageName);
                            } else {
                                AuditLog::logFileSystemAccess("WRITE", sidecarPath.string(), false, "", 
                                    std::string("Failed to open SHA256 sidecar for writing: ") + imageName);
                            }
                        } catch (const std::filesystem::filesystem_error& e) {
                            LOG_ERROR << "Failed to write SHA256 sidecar (filesystem) for " << imageName << ": " << e.what();
                        } catch (const std::ios_base::failure& e) {
                            LOG_ERROR << "Failed to write SHA256 sidecar (io) for " << imageName << ": " << e.what();
                        } catch (const std::exception& e) {
                            LOG_ERROR << "Failed to write SHA256 sidecar for " << imageName << ": " << e.what();
                        }
                        
                        // Log successful SHA256 calculation
                        AuditLog::logFileSystemAccess("SHA256_COMPLETE", imagePath.string(), true, "", 
                            "SHA256 calculated for: " + imageName + " = " + sha256);
                        
                        // Broadcast completion to WebSocket clients
                        SHA256WebSocketController::broadcastUpdate(imageName, result);
                    }
                } catch (const std::filesystem::filesystem_error& e) {
                    // Update cache with more specific filesystem error
                    std::lock_guard<std::mutex> lock(sha256Cache_mutex);
                    SHA256Result result(std::string("Filesystem error: ") + e.what(), SHA256Status::ERROR, false);
                    auto it = sha256Cache.find(imageName);
                    if (it != sha256Cache.end()) {
                        result.cancellation_token = it->second.cancellation_token;
                    }
                    sha256Cache.insert_or_assign(imageName, result);
                    std::filesystem::path imagePath(IMAGES_PATH);
                    imagePath /= imageName;
                    AuditLog::logFileSystemAccess("SHA256_ERROR", imagePath.string(), false, "", 
                        "SHA256 calculation filesystem error for: " + imageName + " - " + e.what());
                    SHA256WebSocketController::broadcastUpdate(imageName, result);
                } catch (const std::bad_alloc& e) {
                    // Update cache with memory error
                    std::lock_guard<std::mutex> lock(sha256Cache_mutex);
                    SHA256Result result(std::string("Memory error: ") + e.what(), SHA256Status::ERROR, false);
                    auto it = sha256Cache.find(imageName);
                    if (it != sha256Cache.end()) {
                        result.cancellation_token = it->second.cancellation_token;
                    }
                    sha256Cache.insert_or_assign(imageName, result);
                    std::filesystem::path imagePath(IMAGES_PATH);
                    imagePath /= imageName;
                    AuditLog::logFileSystemAccess("SHA256_ERROR", imagePath.string(), false, "", 
                        "SHA256 calculation memory error for: " + imageName + " - " + e.what());
                    SHA256WebSocketController::broadcastUpdate(imageName, result);
                } catch (const std::exception& e) {
                    // General error fallback
                    std::lock_guard<std::mutex> lock(sha256Cache_mutex);
                    SHA256Result result(std::string("Error: ") + e.what(), SHA256Status::ERROR, false);
                    auto it = sha256Cache.find(imageName);
                    if (it != sha256Cache.end()) {
                        result.cancellation_token = it->second.cancellation_token;
                    }
                    sha256Cache.insert_or_assign(imageName, result);
                    std::filesystem::path imagePath(IMAGES_PATH);
                    imagePath /= imageName;
                    AuditLog::logFileSystemAccess("SHA256_ERROR", imagePath.string(), false, "", 
                        "SHA256 calculation error for: " + imageName + " - " + e.what());
                    SHA256WebSocketController::broadcastUpdate(imageName, result);
                }
            }
        }
        
        LOG_INFO << "SHA256 worker thread stopped";
    }
    
    // Initialize the SHA256 worker thread
    void initSHA256Worker() {
        if (!workerRunning) {
            workerRunning = true;
            workerThread = std::thread(sha256WorkerFunction);
            LOG_INFO << "SHA256 worker thread initialized";
        }
    }
    
    // Shutdown the SHA256 worker thread
    void shutdownSHA256Worker() {
        if (workerRunning) {
            workerRunning = false;
            queueCV.notify_one();
            if (workerThread.joinable()) {
                workerThread.join();
            }
            LOG_INFO << "SHA256 worker thread shutdown complete";
        }
    }
    
    // Request a SHA256 calculation
    void requestSHA256Calculation(const std::string& imageName) {
        // Reject hashing for sidecar checksum files and notify listeners if any
        try {
            if (std::filesystem::path(imageName).extension() == ".sha256") {
                std::lock_guard<std::mutex> lock(SHA256WebSocketController::connectionsMutex);
                auto it = SHA256WebSocketController::activeConnections.find(imageName);
                if (it != SHA256WebSocketController::activeConnections.end()) {
                    Json::Value response;
                    response["image_name"] = imageName;
                    response["status"] = "error";
                    response["error"] = "Refused: .sha256 sidecar files are not hashable";
                    const std::string msg = response.toStyledString();
                    for (auto &conn : it->second) { if (conn && conn->connected()) conn->send(msg); }
                }
                return;
            }
        } catch (...) { /* ignore */ }
        bool needsCalculation = false;
        
        // Get file size to calculate appropriate timeout
        auto calculateTimeout = [](const std::string& filename) -> unsigned int {
            std::filesystem::path imagePath(IMAGES_PATH);
            imagePath /= filename;
            
            try {
                if (std::filesystem::exists(imagePath)) {
                    // Get file size in MB
                    std::uintmax_t fileSizeMB = std::filesystem::file_size(imagePath) / (1024 * 1024);
                    
                    if (fileSizeMB == 0) {
                        // For very small files, use a 1-minute minimum
                        return 1;
                    }
                    
                    // Assume processing speed of approximately 40MB/second on slowest devices
                    // This is conservative for most devices but reasonable for mobile chipsets
                    // with slow storage
                    unsigned int estimatedMinutes = static_cast<unsigned int>(fileSizeMB / 40) + 1;
                    
                    // Add 50% buffer time for safety margin
                    estimatedMinutes = static_cast<unsigned int>(estimatedMinutes * 1.5);
                    
                    // Cap at reasonable maximum (120 minutes) for very large files
                    return std::min(estimatedMinutes, 120U);
                }
            } catch (const std::filesystem::filesystem_error& e) {
                LOG_ERROR << "Filesystem error calculating timeout for file " << filename << ": " << e.what();
            } catch (const std::exception& e) {
                LOG_ERROR << "Error calculating timeout for file " << filename << ": " << e.what();
            }
            
            // Default timeout (30 minutes) if we can't determine file size
            return 30;
        };
        
        // Check if a calculation is already in progress or complete
        {
            std::lock_guard<std::mutex> cacheLock(sha256Cache_mutex);
            auto it = sha256Cache.find(imageName);
            
            if (it == sha256Cache.end()) {
                // Not in cache at all - needs calculation
                needsCalculation = true;
                // Create cancellation token and mark as pending in the cache with a timestamp
                auto cancellationToken = std::make_shared<SHA256CancellationToken>();
                sha256Cache.insert_or_assign(imageName, SHA256Result("", SHA256Status::PENDING, true, cancellationToken));
                LOG_INFO << "Queuing new SHA256 calculation for " << imageName;
                
                // Log SHA256 calculation request
                std::filesystem::path imagePath(IMAGES_PATH);
                imagePath /= imageName;
                AuditLog::logFileSystemAccess("SHA256_START", imagePath.string(), true, "", 
                    "SHA256 calculation requested for: " + imageName);
            } else if (it->second.status != SHA256Status::PENDING) {
                // Only recalculate if not already in PENDING state
                // (if it's COMPLETE or ERROR, client should use those values)
                return;
            } else {
                // Already in PENDING state - check the timestamp
                auto now = std::chrono::steady_clock::now();
                
                // Calculate timeout dynamically based on file size
                unsigned int timeoutMinutes = calculateTimeout(imageName);
                
                if (it->second.timestamp && 
                    std::chrono::duration_cast<std::chrono::minutes>(now - *(it->second.timestamp)).count() > timeoutMinutes) {
                    // If it's been pending for longer than the calculated timeout, try again
                    needsCalculation = true;
                    // Update timestamp
                    it->second.timestamp = now;
                    LOG_INFO << "Re-queuing stale SHA256 calculation for " << imageName 
                             << " (exceeded " << timeoutMinutes << " minute timeout)";
                } else {
                    // Already pending and not stale - no need to queue again
                    LOG_INFO << "SHA256 calculation already in progress for " << imageName;
                }
            }
        }
        
        if (needsCalculation) {
            // Queue the calculation request
            {
                std::lock_guard<std::mutex> queueLock(queueMutex);
                sha256RequestQueue.push(imageName);
            }
            
            // Signal the worker thread
            queueCV.notify_one();
        }
    }

    Images::Images() : inotifyFd(-1), watchDescriptor(-1) {
        std::filesystem::path image_dir(IMAGES_PATH);
        
        // Create directory if it doesn't exist
        if (!std::filesystem::exists(image_dir)) {
            try {
                std::filesystem::create_directories(image_dir);
            } catch (const std::filesystem::filesystem_error& e) {
                throw std::runtime_error("Failed to create images directory: " + std::string(e.what()));
            }
        }

        // Check write permissions
        if (access(image_dir.c_str(), W_OK) != 0) {
            // Try to set write permissions
            if (chmod(image_dir.c_str(), S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH) != 0) {
                throw std::runtime_error("Failed to set write permissions on images directory");
            }
        }
        
        // Initialize the SHA256 worker thread
        initSHA256Worker();
        
        // Calculate SHA256 for all existing images at startup
        provisioner::calculateAllExistingSHA256();
        
        // Initialize file watching for new images
        initFileWatcher();
    }

    Images::~Images() {
        // Shutdown file watching
        shutdownFileWatcher();
        
        // Shutdown the SHA256 worker thread
        shutdownSHA256Worker();
    }

    // Calculate SHA256 for all existing images at startup
    void calculateAllExistingSHA256() {
        LOG_INFO << "Starting automatic SHA256 calculation for all existing images";
        
        try {
            for (const auto& entry : std::filesystem::directory_iterator(IMAGES_PATH)) {
                if (entry.is_regular_file()) {
                    // Skip .sha256 sidecar files
                    if (entry.path().extension() == ".sha256") {
                        continue;
                    }
                    std::string imageName = entry.path().filename().string();
                    LOG_INFO << "Queuing SHA256 calculation for existing image: " << imageName;
                    requestSHA256Calculation(imageName);
                }
            }
        } catch (const std::filesystem::filesystem_error& e) {
            LOG_ERROR << "Filesystem error scanning images directory for automatic SHA256 calculation: " << e.what();
        } catch (const std::exception& e) {
            LOG_ERROR << "Error scanning images directory for automatic SHA256 calculation: " << e.what();
        }
        
        LOG_INFO << "Automatic SHA256 calculation initiated for all existing images";
    }
    
    // Trigger boot.img generation for a newly uploaded image
    void triggerBootImgGeneration(const std::string& imageName) {
        LOG_INFO << "Triggering boot.img generation for: " << imageName;
        
        sd_bus_error error = SD_BUS_ERROR_NULL;
        sd_bus_message *reply = nullptr;
        sd_bus *bus = nullptr;
        int ret;
        
        // Connect to the system bus
        ret = sd_bus_open_system(&bus);
        if (ret < 0) {
            LOG_ERROR << "Failed to connect to system bus: " << strerror(-ret);
            return;
        }
        
        // Build the service unit name
        std::string serviceName = "rpi-sb-image-bootimg-generator@" + imageName + ".service";
        
        // Call StartUnit method on systemd's Manager interface
        // Method signature: StartUnit(in s name, in s mode, out o job)
        // mode "replace" means: start the unit and cancel any conflicting jobs
        ret = sd_bus_call_method(
            bus,
            "org.freedesktop.systemd1",           // service to contact
            "/org/freedesktop/systemd1",          // object path
            "org.freedesktop.systemd1.Manager",   // interface name
            "StartUnit",                          // method name
            &error,                               // error return
            &reply,                               // reply message
            "ss",                                 // input signature (two strings)
            serviceName.c_str(),                  // unit name
            "replace"                             // mode
        );
        
        if (ret < 0) {
            LOG_ERROR << "Failed to start boot.img generation service '" << serviceName 
                      << "': " << error.message;
            sd_bus_error_free(&error);
        } else {
            // Extract the job path from the reply (we don't need it, but should read it)
            const char *job_path;
            ret = sd_bus_message_read(reply, "o", &job_path);
            if (ret >= 0) {
                LOG_INFO << "Started boot.img generation service: " << serviceName 
                         << " (job: " << job_path << ")";
            } else {
                LOG_INFO << "Started boot.img generation service: " << serviceName;
            }
            
            // Broadcast "generating" status to WebSocket clients
            BootPackageWebSocketController::broadcastUpdate(imageName, false, "", "generating");
        }
        
        // Cleanup
        sd_bus_message_unref(reply);
        sd_bus_error_free(&error);
        sd_bus_unref(bus);
    }
    
    // Request boot package status check
    void requestBootPackageCheck(const std::string& imageName) {
        LOG_INFO << "Checking boot package for: " << imageName;
        
        // Check if provisioning style supports boot packages (secure-boot or fde-only)
        auto provisioningStyle = provisioner::utils::getConfigValue("PROVISIONING_STYLE");
        if (!provisioningStyle || (*provisioningStyle != "secure-boot" && *provisioningStyle != "fde-only")) {
            std::string style = provisioningStyle ? *provisioningStyle : "unknown";
            LOG_INFO << "Boot package not supported for provisioning style: " << style;
            BootPackageWebSocketController::broadcastUpdate(imageName, false, "", "unsupported");
            return;
        }
        
        // Remove file extension from image name to get base name
        std::string imageBaseName = imageName;
        size_t dotPos = imageBaseName.find_last_of('.');
        if (dotPos != std::string::npos) {
            imageBaseName = imageBaseName.substr(0, dotPos);
        }
        
        // Look for the debian package in the bootimg-output directory
        std::filesystem::path outputDir("/srv/rpi-sb-provisioner/images/bootimg-output");
        
        bool exists = false;
        std::string packageName;
        
        try {
            if (std::filesystem::exists(outputDir) && std::filesystem::is_directory(outputDir)) {
                // Look for .deb files matching the pattern
                for (const auto& entry : std::filesystem::directory_iterator(outputDir)) {
                    if (entry.is_regular_file() && entry.path().extension() == ".deb") {
                        // Check if this package was generated from the same source image
                        std::string infoFile = imageBaseName + ".package-info.txt";
                        std::filesystem::path infoPath = outputDir / infoFile;
                        
                        if (std::filesystem::exists(infoPath)) {
                            exists = true;
                            packageName = entry.path().filename().string();
                            break;
                        }
                    }
                }
            }
            
            // Broadcast result to all interested WebSocket clients
            BootPackageWebSocketController::broadcastUpdate(imageName, exists, packageName);
            
        } catch (const std::exception& e) {
            LOG_ERROR << "Error checking boot package: " << e.what();
            // Broadcast "not exists" on error
            BootPackageWebSocketController::broadcastUpdate(imageName, false, "");
        }
    }

    
    // File watcher function implementation
    void Images::fileWatcherFunction() {
        LOG_INFO << "File watcher thread started";
        
        const size_t EVENT_SIZE = sizeof(struct inotify_event);
        const size_t EVENT_BUF_LEN = 1024 * (EVENT_SIZE + 16);
        char buffer[EVENT_BUF_LEN];
        
        while (fileWatcherRunning) {
            fd_set fds;
            FD_ZERO(&fds);
            FD_SET(inotifyFd, &fds);
            
            struct timeval timeout;
            timeout.tv_sec = 1;  // 1 second timeout
            timeout.tv_usec = 0;
            
            int ret = select(inotifyFd + 1, &fds, nullptr, nullptr, &timeout);
            
            if (ret < 0) {
                if (errno == EINTR) continue;
                LOG_ERROR << "select() failed in file watcher: " << strerror(errno);
                break;
            }
            
            if (ret == 0) {
                // Timeout - check if we should continue running
                continue;
            }
            
            if (FD_ISSET(inotifyFd, &fds)) {
                int length = read(inotifyFd, buffer, EVENT_BUF_LEN);
                if (length < 0) {
                    if (errno == EINTR) continue;
                    LOG_ERROR << "read() failed in file watcher: " << strerror(errno);
                    break;
                }
                
                int i = 0;
                while (i < length) {
                    struct inotify_event* event = (struct inotify_event*)&buffer[i];
                    
                    if (event->len > 0) {
                        std::string filename(event->name);
                        
                        // Only process regular files (not directories)
                        if (!(event->mask & IN_ISDIR)) {
                            if (event->mask & IN_CREATE || event->mask & IN_MOVED_TO) {
                                LOG_INFO << "New image file detected: " << filename;
                                
                                // Wait a moment for the file to be fully written
                                std::this_thread::sleep_for(std::chrono::milliseconds(500));
                                
                                // Verify the file exists and is a regular file
                                std::filesystem::path filePath(IMAGES_PATH);
                                filePath /= filename;
                                
                                if (std::filesystem::exists(filePath) && std::filesystem::is_regular_file(filePath)) {
                                    // Skip sidecar checksum files
                                    if (filePath.extension() == ".sha256") {
                                        i += EVENT_SIZE + event->len;
                                        continue;
                                    }
                                    LOG_INFO << "Queuing SHA256 calculation for new image: " << filename;
                                    requestSHA256Calculation(filename);
                                }
                            }
                        }
                    }
                    
                    i += EVENT_SIZE + event->len;
                }
            }
        }
        
        LOG_INFO << "File watcher thread stopped";
    }
    
    void Images::initFileWatcher() {
        LOG_INFO << "Setting up file watcher for images directory";
        
        inotifyFd = inotify_init();
        if (inotifyFd < 0) {
            LOG_ERROR << "Failed to initialize inotify: " << strerror(errno);
            return;
        }
        
        watchDescriptor = inotify_add_watch(inotifyFd, IMAGES_PATH.c_str(), 
                                           IN_CREATE | IN_MOVED_TO | IN_CLOSE_WRITE);
        if (watchDescriptor < 0) {
            LOG_ERROR << "Failed to add watch for images directory: " << strerror(errno);
            close(inotifyFd);
            inotifyFd = -1;
            return;
        }
        
        fileWatcherRunning = true;
        fileWatcherThread = std::thread(&Images::fileWatcherFunction, this);
        
        LOG_INFO << "File watcher initialized successfully";
    }
    
    void Images::shutdownFileWatcher() {
        if (fileWatcherRunning) {
            fileWatcherRunning = false;
            
            if (fileWatcherThread.joinable()) {
                fileWatcherThread.join();
            }
            
            if (watchDescriptor >= 0) {
                inotify_rm_watch(inotifyFd, watchDescriptor);
                watchDescriptor = -1;
            }
            
            if (inotifyFd >= 0) {
                close(inotifyFd);
                inotifyFd = -1;
            }
            
            LOG_INFO << "File watcher shutdown complete";
        }
    }

    void Images::registerHandlers(drogon::HttpAppFramework &app)
    {
        // Register WebSocket controller - no need to call registerController explicitly
        // WebSocket controllers are automatically registered via WS_PATH macros
        
        app.registerHandler("/get-image-metadata", [](const drogon::HttpRequestPtr &req, std::function<void(const drogon::HttpResponsePtr &)> &&callback) {
            LOG_INFO << "Images::get-image-metadata";
            
            // Add audit log entry for handler access
            AuditLog::logHandlerAccess(req, "/get-image-metadata");
            
            // Get the image name from the request
            std::string imageName = req->getParameter("name");
            if (imageName.empty()) {
                auto resp = provisioner::utils::createErrorResponse(
                    req,
                    "Image name is required",
                    drogon::k400BadRequest,
                    "Missing Parameter",
                    "MISSING_IMAGE_NAME"
                );
                callback(resp);
                return;
            }
            
            std::filesystem::path imagePath(IMAGES_PATH);
            imagePath /= imageName;
            
            if (!std::filesystem::exists(imagePath)) {
                auto resp = provisioner::utils::createErrorResponse(
                    req,
                    "The requested image file was not found",
                    drogon::k400BadRequest,
                    "Image Not Found",
                    "IMAGE_NOT_FOUND",
                    "Requested image: " + imageName
                );
                callback(resp);
                return;
            }
            
            auto resp = drogon::HttpResponse::newHttpResponse();
            resp->setStatusCode(drogon::k200OK);
            resp->setContentTypeCode(drogon::CT_APPLICATION_JSON);
            Json::Value result;
            
            try {
                // Get file size
                std::uintmax_t fileSize = std::filesystem::file_size(imagePath);
                double fileSizeMB = static_cast<double>(fileSize) / (1024 * 1024);
                
                result["name"] = imageName;
                result["size_bytes"] = static_cast<Json::UInt64>(fileSize);
                result["size_mb"] = fileSizeMB;
                
                // Format human-readable size
                std::stringstream sizeStr;
                if (fileSize < 1024) {
                    sizeStr << fileSize << " B";
                } else if (fileSize < 1024 * 1024) {
                    sizeStr << std::fixed << std::setprecision(2) << (fileSize / 1024.0) << " KB";
                } else if (fileSize < 1024 * 1024 * 1024) {
                    sizeStr << std::fixed << std::setprecision(2) << (fileSize / (1024.0 * 1024.0)) << " MB";
                } else {
                    sizeStr << std::fixed << std::setprecision(2) << (fileSize / (1024.0 * 1024.0 * 1024.0)) << " GB";
                }
                result["size_formatted"] = sizeStr.str();
                
                // Get file modification time
                auto fileTime = std::filesystem::last_write_time(imagePath);
                auto systemTime = std::chrono::file_clock::to_sys(fileTime);
                auto time_t_time = std::chrono::system_clock::to_time_t(systemTime);
                
                std::stringstream timeStr;
                timeStr << std::put_time(std::localtime(&time_t_time), "%Y-%m-%d %H:%M:%S");
                result["last_modified"] = timeStr.str();
                
                // Calculate estimated processing time based on size
                // Assume processing speed of approximately 40MB/second on slowest devices
                double estimatedSeconds = fileSizeMB / 40.0;
                unsigned int estimatedMinutes = static_cast<unsigned int>(std::ceil(estimatedSeconds / 60.0));
                result["estimated_process_minutes"] = static_cast<Json::UInt>(estimatedMinutes);
                
            } catch (const std::filesystem::filesystem_error& e) {
                LOG_ERROR << "Error getting metadata for " << imageName << ": " << e.what();
                auto resp = provisioner::utils::createErrorResponse(
                    req,
                    "Error retrieving image metadata",
                    drogon::k500InternalServerError,
                    "Metadata Error",
                    "METADATA_ERROR",
                    e.what()
                );
                callback(resp);
                return;
            } catch (const std::exception& e) {
                LOG_ERROR << "Error getting metadata for " << imageName << ": " << e.what();
                auto resp = provisioner::utils::createErrorResponse(
                    req,
                    "Error retrieving image metadata",
                    drogon::k500InternalServerError,
                    "Metadata Error",
                    "METADATA_ERROR",
                    e.what()
                );
                callback(resp);
                return;
            }
            
            resp->setBody(result.toStyledString());
            callback(resp);
        });
        
        app.registerHandler("/get-images", [](const drogon::HttpRequestPtr &req, std::function<void(const drogon::HttpResponsePtr &)> &&callback) {
            LOG_INFO << "Images::get-images";

            // Add audit log entry for handler access
            AuditLog::logHandlerAccess(req, "/get-images");

            std::vector<ImageInfo> imageInfos;
            
            LOG_INFO << "Scanning directory: " << IMAGES_PATH;
            for (const auto &entry : std::filesystem::directory_iterator(IMAGES_PATH)) {
                LOG_INFO << "Found entry: " << entry.path().string();
                if (entry.is_regular_file()) {
                    std::filesystem::path imagePath = entry.path();
                    // Skip SHA256 sidecar files from the listing
                    if (imagePath.extension() == ".sha256") {
                        continue;
                    }
                    ImageInfo info;
                    info.name = imagePath.filename().string();
                    
                    // Prefer sidecar file if present; fall back to cache status
                    try {
                        std::filesystem::path sidecarPath = imagePath;
                        sidecarPath += ".sha256";
                        if (std::filesystem::exists(sidecarPath)) {
                            std::ifstream in(sidecarPath);
                            std::string line;
                            if (in && std::getline(in, line)) {
                                // Trim trailing whitespace
                                while (!line.empty() && (line.back()==' ' || line.back()=='\t' || line.back()=='\n' || line.back()=='\r')) {
                                    line.pop_back();
                                }
                                info.sha256 = line;
                            }
                        }
                    } catch (const std::filesystem::filesystem_error& e) {
                        // Ignore filesystem errors while reading sidecar, but log at debug level
                        LOG_DEBUG << "Ignoring sidecar filesystem read error for " << imagePath.filename().string() << ": " << e.what();
                    } catch (const std::ios_base::failure& e) {
                        LOG_DEBUG << "Ignoring sidecar IO error for " << imagePath.filename().string() << ": " << e.what();
                    } catch (const std::exception& e) {
                        LOG_DEBUG << "Ignoring sidecar generic read error for " << imagePath.filename().string() << ": " << e.what();
                    }
                    
                    if (info.sha256.empty()) {
                        // Get SHA256 from cache if available
                        {
                            std::lock_guard<std::mutex> lock(sha256Cache_mutex);
                            auto it = sha256Cache.find(info.name);
                            if (it != sha256Cache.end()) {
                                if (it->second.status == SHA256Status::COMPLETE) {
                                    info.sha256 = it->second.value;
                                } else if (it->second.status == SHA256Status::PENDING) {
                                    info.sha256 = "Calculating...";
                                } else {
                                    info.sha256 = "Error";
                                }
                            } else {
                                // Not in cache yet, calculation may still be pending
                                info.sha256 = "Calculating...";
                            }
                        }
                    }
                    
                    imageInfos.push_back(info);
                    LOG_INFO << "Added image: " << info.name;
                }
            }
            
            LOG_INFO << "Total images found: " << imageInfos.size();
            
            auto resp = drogon::HttpResponse::newHttpResponse();
            
            // Check if the client accepts HTML
            auto acceptHeader = req->getHeader("Accept");
            if (!acceptHeader.empty() && (acceptHeader.find("text/html") != std::string::npos)) {
                LOG_INFO << "HTML response requested";

                // Get current gold master image
                std::string currentGoldMaster;
                auto goldMasterPath = provisioner::utils::getConfigValue("GOLD_MASTER_OS_FILE");
                if (goldMasterPath) {
                    currentGoldMaster = *goldMasterPath;
                    // Extract just the filename from the full path
                    std::filesystem::path path(currentGoldMaster);
                    currentGoldMaster = path.filename().string();
                } else {
                    LOG_ERROR << "Failed to read GOLD_MASTER_OS_FILE from config";
                }

                drogon::HttpViewData viewData;
                std::vector<std::map<std::string, std::string>> imageMaps;
                for (const auto& info : imageInfos) {
                    std::map<std::string, std::string> imageMap;
                    imageMap["name"] = info.name;
                    imageMap["sha256"] = info.sha256;
                    imageMap["is_gold_master"] = (info.name == currentGoldMaster) ? "true" : "false";
                    imageMaps.push_back(imageMap);
                }
                viewData.insert("images", imageMaps);
                viewData.insert("currentPage", std::string("images"));
                viewData.insert("useWebSocket", true); // Tell the template to use WebSocket
                LOG_INFO << "View data populated with " << imageMaps.size() << " images";
                resp = drogon::HttpResponse::newHttpViewResponse("images.csp", viewData);
            } else {
                LOG_INFO << "JSON response requested";
                Json::Value imageArray(Json::arrayValue);
                for (const auto& info : imageInfos) {
                    Json::Value imageObj;
                    imageObj["name"] = info.name;
                    imageObj["sha256"] = info.sha256;
                    imageArray.append(imageObj);
                }
                resp->setStatusCode(drogon::k200OK);
                resp->setContentTypeCode(drogon::CT_APPLICATION_JSON);
                resp->setBody(imageArray.toStyledString());
            }
            
            callback(resp);
        });

        // JSON-only endpoint for listing images (used by Options page)
        app.registerHandler("/images/list", [](const drogon::HttpRequestPtr &req, std::function<void(const drogon::HttpResponsePtr &)> &&callback) {
            LOG_INFO << "Images::list (JSON)";
            AuditLog::logHandlerAccess(req, "/images/list");

            std::vector<ImageInfo> imageInfos;
            
            try {
                for (const auto &entry : std::filesystem::directory_iterator(IMAGES_PATH)) {
                    if (entry.is_regular_file()) {
                        std::filesystem::path imagePath = entry.path();
                        // Skip SHA256 sidecar files from the listing
                        if (imagePath.extension() == ".sha256") {
                            continue;
                        }
                        ImageInfo info;
                        info.name = imagePath.filename().string();
                        
                        // Get file size
                        try {
                            info.size = std::filesystem::file_size(imagePath);
                        } catch (...) {
                            info.size = 0;
                        }
                        
                        // Get SHA256 - prefer sidecar file, then cache
                        try {
                            std::filesystem::path sidecarPath = imagePath;
                            sidecarPath += ".sha256";
                            if (std::filesystem::exists(sidecarPath)) {
                                std::ifstream in(sidecarPath);
                                std::string line;
                                if (in && std::getline(in, line)) {
                                    while (!line.empty() && (line.back()==' ' || line.back()=='\t' || line.back()=='\n' || line.back()=='\r')) {
                                        line.pop_back();
                                    }
                                    info.sha256 = line;
                                }
                            }
                        } catch (...) {}
                        
                        if (info.sha256.empty()) {
                            std::lock_guard<std::mutex> lock(sha256Cache_mutex);
                            auto it = sha256Cache.find(info.name);
                            if (it != sha256Cache.end()) {
                                if (it->second.status == SHA256Status::COMPLETE) {
                                    info.sha256 = it->second.value;
                                } else if (it->second.status == SHA256Status::PENDING) {
                                    info.sha256 = "Calculating...";
                                } else {
                                    info.sha256 = "Error";
                                }
                            } else {
                                info.sha256 = "Calculating...";
                            }
                        }
                        
                        imageInfos.push_back(info);
                    }
                }
            } catch (const std::filesystem::filesystem_error& e) {
                LOG_ERROR << "Error scanning images directory: " << e.what();
            }
            
            // Get current gold master for comparison
            std::string currentGoldMaster;
            auto goldMasterPath = provisioner::utils::getConfigValue("GOLD_MASTER_OS_FILE");
            if (goldMasterPath) {
                currentGoldMaster = *goldMasterPath;
            }
            
            // Build JSON response
            Json::Value response;
            Json::Value imageArray(Json::arrayValue);
            
            for (const auto& info : imageInfos) {
                Json::Value imageObj;
                imageObj["name"] = info.name;
                imageObj["path"] = std::string(IMAGES_PATH) + "/" + info.name;
                imageObj["sha256"] = info.sha256;
                imageObj["size_mb"] = info.size / (1024.0 * 1024.0);
                imageObj["is_gold_master"] = (currentGoldMaster.find(info.name) != std::string::npos);
                imageArray.append(imageObj);
            }
            
            response["images"] = imageArray;
            
            auto resp = drogon::HttpResponse::newHttpResponse();
            resp->setStatusCode(drogon::k200OK);
            resp->setContentTypeCode(drogon::CT_APPLICATION_JSON);
            resp->setBody(response.toStyledString());
            callback(resp);
        });

        app.registerHandler("/get-image-sha256", [](const drogon::HttpRequestPtr &req, std::function<void(const drogon::HttpResponsePtr &)> &&callback) {
            LOG_INFO << "Images::get-image-sha256";

            // Add audit log entry for handler access
            AuditLog::logHandlerAccess(req, "/get-image-sha256");

            // Get the image name from the request
            std::string imageName = req->getParameter("name");
            if (imageName.empty()) {
                auto resp = provisioner::utils::createErrorResponse(
                    req,
                    "Image name is required",
                    drogon::k400BadRequest,
                    "Missing Parameter",
                    "MISSING_IMAGE_NAME"
                );
                callback(resp);
                return;
            }

            std::filesystem::path imagePath(IMAGES_PATH);
            imagePath /= imageName;

            if (!std::filesystem::exists(imagePath)) {
                auto resp = provisioner::utils::createErrorResponse(
                    req,
                    "The requested image file was not found",
                    drogon::k400BadRequest,
                    "Image Not Found",
                    "IMAGE_NOT_FOUND",
                    "Requested image: " + imageName
                );
                callback(resp);
                return;
            }

            // Check cache for SHA256 result
            bool resultReady = false;
            std::string sha256;
            SHA256Status status = SHA256Status::PENDING;
            double progress = 0.0;
            
            {
                std::lock_guard<std::mutex> lock(sha256Cache_mutex);
                auto it = sha256Cache.find(imageName);
                if (it != sha256Cache.end()) {
                    status = it->second.status;
                    if (status == SHA256Status::COMPLETE) {
                        sha256 = it->second.value;
                        resultReady = true;
                        LOG_INFO << "Found complete SHA256 in cache for " << imageName << ": " << sha256;
                    } else if (status == SHA256Status::ERROR) {
                        sha256 = it->second.value;
                        resultReady = true;
                        LOG_INFO << "Found error SHA256 in cache for " << imageName << ": " << sha256;
                    } else if (status == SHA256Status::PENDING) {
                        // It's pending, check if we have progress info
                        if (it->second.progress >= 0) {
                            progress = it->second.progress;
                            LOG_INFO << "SHA256 calculation in progress for " << imageName 
                                     << " - " << (progress * 100) << "% complete";
                        }
                    }
                }
            }
            
            auto resp = drogon::HttpResponse::newHttpResponse();
            resp->setStatusCode(drogon::k200OK);
            resp->setContentTypeCode(drogon::CT_APPLICATION_JSON);
            Json::Value result;
            
            if (!resultReady) {
                // Return immediate status for pending calculations
                if (status == SHA256Status::PENDING) {
                    result["sha256"] = "Calculating...";
                    result["status"] = "pending";
                    result["message"] = "SHA256 calculation is in progress.";
                    // Include progress if available
                    if (progress > 0) {
                        result["progress"] = progress;
                        result["progress_percent"] = static_cast<int>(progress * 100);
                    }
                } else {
                    // Not in cache yet, start calculation and return pending status
                    result["sha256"] = "Calculating...";
                    result["status"] = "pending";
                    result["message"] = "SHA256 calculation started.";
                    
                    // Start calculation in background
                    requestSHA256Calculation(imageName);
                }
            } else {
                result["sha256"] = sha256;
                result["status"] = (status == SHA256Status::COMPLETE) ? "complete" : "error";
            }
            
            resp->setBody(result.toStyledString());
            callback(resp);
        });

        app.registerHandler("/upload-image", [](const drogon::HttpRequestPtr &req, std::function<void(const drogon::HttpResponsePtr &)> &&callback) {
            LOG_INFO << "Images::uploadImage";
            
            // Add audit log entry for handler access
            AuditLog::logHandlerAccess(req, "/upload-image");
            
            auto resp = drogon::HttpResponse::newHttpResponse();

            // Get the file from the request
            drogon::MultiPartParser parser;
            if (parser.parse(req) != 0 || parser.getFiles().size() != 1) {
                auto resp = provisioner::utils::createErrorResponse(
                    req,
                    "Invalid request: Expected exactly one file in multipart form data",
                    drogon::k400BadRequest,
                    "Invalid Request",
                    "INVALID_UPLOAD_REQUEST"
                );
                callback(resp);
                return;
            }
            auto files = parser.getFiles();

            const auto& file = files[0];
            std::string originalFilename = file.getFileName();
            
            // Function to generate a unique filename (race-condition safe with timestamp fallback)
            auto generateUniqueFilename = [](const std::string& originalName, const std::string& basePath) -> std::string {
                std::filesystem::path targetDir(basePath);
                std::filesystem::path originalPath = targetDir / originalName;
                
                // If file doesn't exist, use original name
                if (!std::filesystem::exists(originalPath)) {
                    return originalName;
                }
                
                // Extract filename parts for numbered variants
                std::filesystem::path nameOnly = originalPath.stem();
                std::filesystem::path extension = originalPath.extension();
                
                // Try numbered variants
                for (int i = 1; i <= 9999; ++i) {
                    std::string newName = nameOnly.string() + "_" + std::to_string(i) + extension.string();
                    std::filesystem::path newPath = targetDir / newName;
                    
                    if (!std::filesystem::exists(newPath)) {
                        return newName;
                    }
                }
                
                // If we can't find a unique name after 9999 attempts, use timestamp + random
                auto now = std::chrono::system_clock::now();
                auto timestamp = std::chrono::duration_cast<std::chrono::milliseconds>(now.time_since_epoch()).count();
                std::random_device rd;
                std::mt19937 gen(rd());
                std::uniform_int_distribution<> dis(1000, 9999);
                int random = dis(gen);
                
                return nameOnly.string() + "_" + std::to_string(timestamp) + "_" + std::to_string(random) + extension.string();
            };
            
            // Generate unique filename to avoid conflicts
            std::string finalFilename = generateUniqueFilename(originalFilename, IMAGES_PATH);
            
            // Create target path with unique filename
            std::filesystem::path targetPath(IMAGES_PATH);
            targetPath /= finalFilename;

            try {
                // Move uploaded file to target location with unique name
                file.saveAs(targetPath);
                
                // Log successful file upload
                AuditLog::logFileSystemAccess("UPLOAD", targetPath.string(), true, "", 
                    "Original filename: " + originalFilename + (originalFilename != finalFilename ? ", renamed to: " + finalFilename : ""));
                
                // Clear any stale cache entry for this filename
                {
                    std::lock_guard<std::mutex> lock(sha256Cache_mutex);
                    sha256Cache.erase(finalFilename);
                }
                
                // Start SHA256 calculation in the background
                requestSHA256Calculation(finalFilename);
                
                // Trigger boot.img generation for secure-boot configurations
                triggerBootImgGeneration(finalFilename);
                
                // Set success response with JSON payload
                resp->setStatusCode(drogon::k200OK);
                resp->setContentTypeCode(drogon::CT_APPLICATION_JSON);
                Json::Value result;
                result["success"] = true;
                
                // Include both original and final filenames in response
                if (originalFilename != finalFilename) {
                    result["message"] = "File uploaded successfully (renamed to avoid conflict)";
                    result["original_filename"] = originalFilename;
                    result["filename"] = finalFilename;
                    result["renamed"] = true;
                } else {
                    result["message"] = "File uploaded successfully";
                    result["filename"] = finalFilename;
                    result["renamed"] = false;
                }
                
                result["sha256"] = "Calculating..."; // SHA256 calculation in progress
                resp->setBody(result.toStyledString());
            } catch (const std::filesystem::filesystem_error& e) {
                LOG_ERROR << "Failed to save uploaded file (filesystem): " << e.what();
            } catch (const std::exception& e) {
                LOG_ERROR << "Failed to save uploaded file: " << e.what();
                
                // Log failed file upload
                AuditLog::logFileSystemAccess("UPLOAD", targetPath.string(), false, "", 
                    "Upload failed: " + std::string(e.what()) + ", Original filename: " + originalFilename);
                
                auto resp = provisioner::utils::createErrorResponse(
                    req,
                    "Failed to save uploaded file",
                    drogon::k500InternalServerError,
                    "Upload Error",
                    "UPLOAD_SAVE_ERROR",
                    e.what()
                );
                callback(resp);
                return;
            }

            callback(resp);
        });

        app.registerHandler("/get-boot-package-info", [](const drogon::HttpRequestPtr &req, std::function<void(const drogon::HttpResponsePtr &)> &&callback) {
            LOG_INFO << "Images::getBootPackageInfo";
            
            // Add audit log entry for handler access
            AuditLog::logHandlerAccess(req, "/get-boot-package-info");
            
            std::string imageName = req->getParameter("name");
            if (imageName.empty()) {
                auto resp = provisioner::utils::createErrorResponse(
                    req,
                    "Missing required parameter: name",
                    drogon::k400BadRequest,
                    "Bad Request",
                    "MISSING_PARAMETER"
                );
                callback(resp);
                return;
            }
            
            // Check if provisioning style supports boot packages (secure-boot or fde-only)
            auto provisioningStyle = provisioner::utils::getConfigValue("PROVISIONING_STYLE");
            if (!provisioningStyle || (*provisioningStyle != "secure-boot" && *provisioningStyle != "fde-only")) {
                Json::Value result;
                result["exists"] = false;
                result["image_name"] = imageName;
                result["status"] = "unsupported";
                auto resp = drogon::HttpResponse::newHttpJsonResponse(result);
                callback(resp);
                return;
            }
            
            // Remove file extension from image name to get base name
            std::string imageBaseName = imageName;
            size_t dotPos = imageBaseName.find_last_of('.');
            if (dotPos != std::string::npos) {
                imageBaseName = imageBaseName.substr(0, dotPos);
            }
            
            // Look for the debian package in the bootimg-output directory
            std::filesystem::path outputDir("/srv/rpi-sb-provisioner/images/bootimg-output");
            
            Json::Value result;
            result["exists"] = false;
            result["image_name"] = imageName;
            result["status"] = "not_found";
            
            try {
                if (std::filesystem::exists(outputDir) && std::filesystem::is_directory(outputDir)) {
                    // Look for .deb files matching the pattern: rpi-sb-boot-update_*_all.deb
                    for (const auto& entry : std::filesystem::directory_iterator(outputDir)) {
                        if (entry.is_regular_file() && entry.path().extension() == ".deb") {
                            std::string filename = entry.path().filename().string();
                            // Check if this package was generated from the same source image
                            // by checking for the package-info file
                            std::string infoFile = imageBaseName + ".package-info.txt";
                            std::filesystem::path infoPath = outputDir / infoFile;
                            
                            if (std::filesystem::exists(infoPath)) {
                                result["exists"] = true;
                                result["package_name"] = filename;
                                result["package_path"] = entry.path().string();
                                result["status"] = "available";
                                break;
                            }
                        }
                    }
                }
                
                auto resp = drogon::HttpResponse::newHttpJsonResponse(result);
                callback(resp);
            } catch (const std::exception& e) {
                LOG_ERROR << "Error checking boot package: " << e.what();
                auto resp = provisioner::utils::createErrorResponse(
                    req,
                    "Failed to check boot package",
                    drogon::k500InternalServerError,
                    "Internal Error",
                    "BOOT_PACKAGE_CHECK_ERROR",
                    e.what()
                );
                callback(resp);
            }
        });

        app.registerHandler("/generate-boot-package", [](const drogon::HttpRequestPtr &req, std::function<void(const drogon::HttpResponsePtr &)> &&callback) {
            LOG_INFO << "Images::generateBootPackage";
            
            // Add audit log entry for handler access
            AuditLog::logHandlerAccess(req, "/generate-boot-package");
            
            // Check if provisioning style supports boot packages (secure-boot or fde-only)
            auto provisioningStyle = provisioner::utils::getConfigValue("PROVISIONING_STYLE");
            if (!provisioningStyle || (*provisioningStyle != "secure-boot" && *provisioningStyle != "fde-only")) {
                std::string style = provisioningStyle ? *provisioningStyle : "unknown";
                auto resp = provisioner::utils::createErrorResponse(
                    req,
                    "Boot package generation only supported in secure-boot or fde-only mode (current: " + style + ")",
                    drogon::k400BadRequest,
                    "Bad Request",
                    "UNSUPPORTED_PROVISIONING_STYLE"
                );
                callback(resp);
                return;
            }
            
            std::string imageName = req->getParameter("name");
            if (imageName.empty()) {
                auto resp = provisioner::utils::createErrorResponse(
                    req,
                    "Missing required parameter: name",
                    drogon::k400BadRequest,
                    "Bad Request",
                    "MISSING_PARAMETER"
                );
                callback(resp);
                return;
            }
            
            // Verify the image file exists
            std::filesystem::path imagePath(IMAGES_PATH);
            imagePath /= imageName;
            
            if (!std::filesystem::exists(imagePath)) {
                auto resp = provisioner::utils::createErrorResponse(
                    req,
                    "Image file not found: " + imageName,
                    drogon::k404NotFound,
                    "Not Found",
                    "IMAGE_NOT_FOUND"
                );
                callback(resp);
                return;
            }
            
            // Trigger boot.img generation
            triggerBootImgGeneration(imageName);
            
            // Log the action
            AuditLog::logFileSystemAccess("GENERATE_BOOT_PACKAGE", imagePath.string(), true, "", 
                "Manual boot package generation requested");
            
            // Return success response
            Json::Value result;
            result["success"] = true;
            result["message"] = "Boot package generation started for " + imageName;
            result["image_name"] = imageName;
            
            auto resp = drogon::HttpResponse::newHttpJsonResponse(result);
            resp->setStatusCode(drogon::k200OK);
            callback(resp);
        });

        app.registerHandler("/download-boot-package", [](const drogon::HttpRequestPtr &req, std::function<void(const drogon::HttpResponsePtr &)> &&callback) {
            LOG_INFO << "Images::downloadBootPackage";
            
            // Add audit log entry for handler access
            AuditLog::logHandlerAccess(req, "/download-boot-package");
            
            std::string imageName = req->getParameter("name");
            if (imageName.empty()) {
                auto resp = provisioner::utils::createErrorResponse(
                    req,
                    "Missing required parameter: name",
                    drogon::k400BadRequest,
                    "Bad Request",
                    "MISSING_PARAMETER"
                );
                callback(resp);
                return;
            }
            
            // Remove file extension from image name to get base name
            std::string imageBaseName = imageName;
            size_t dotPos = imageBaseName.find_last_of('.');
            if (dotPos != std::string::npos) {
                imageBaseName = imageBaseName.substr(0, dotPos);
            }
            
            // Look for the debian package in the bootimg-output directory
            std::filesystem::path outputDir("/srv/rpi-sb-provisioner/images/bootimg-output");
            std::filesystem::path packagePath;
            std::string packageName;
            
            try {
                if (std::filesystem::exists(outputDir) && std::filesystem::is_directory(outputDir)) {
                    // Look for .deb files with corresponding package-info file
                    for (const auto& entry : std::filesystem::directory_iterator(outputDir)) {
                        if (entry.is_regular_file() && entry.path().extension() == ".deb") {
                            std::string infoFile = imageBaseName + ".package-info.txt";
                            std::filesystem::path infoPath = outputDir / infoFile;
                            
                            if (std::filesystem::exists(infoPath)) {
                                packagePath = entry.path();
                                packageName = entry.path().filename().string();
                                break;
                            }
                        }
                    }
                }
                
                if (packagePath.empty() || !std::filesystem::exists(packagePath)) {
                    auto resp = provisioner::utils::createErrorResponse(
                        req,
                        "Boot package not found for this image",
                        drogon::k404NotFound,
                        "Not Found",
                        "BOOT_PACKAGE_NOT_FOUND"
                    );
                    callback(resp);
                    return;
                }
                
                // Log the download
                AuditLog::logFileSystemAccess("DOWNLOAD", packagePath.string(), true, "",
                    "Boot package downloaded for image: " + imageName);
                
                // Send the file
                auto resp = drogon::HttpResponse::newFileResponse(packagePath.string());
                resp->setContentTypeCode(drogon::CT_APPLICATION_OCTET_STREAM);
                resp->addHeader("Content-Disposition", "attachment; filename=\"" + packageName + "\"");
                callback(resp);
                
            } catch (const std::exception& e) {
                LOG_ERROR << "Error downloading boot package: " << e.what();
                auto resp = provisioner::utils::createErrorResponse(
                    req,
                    "Failed to download boot package",
                    drogon::k500InternalServerError,
                    "Internal Error",
                    "BOOT_PACKAGE_DOWNLOAD_ERROR",
                    e.what()
                );
                callback(resp);
            }
        });

        app.registerHandler("/delete-image", [](const drogon::HttpRequestPtr &req, std::function<void(const drogon::HttpResponsePtr &)> &&callback) {
            LOG_INFO << "Images::deleteImage";
            
            // Add audit log entry for handler access
            AuditLog::logHandlerAccess(req, "/delete-image");
            
            auto resp = drogon::HttpResponse::newHttpResponse();

            // Get the image name from the request
            std::string imageName = req->getParameter("name");
            if (imageName.empty()) {
                auto resp = provisioner::utils::createErrorResponse(
                    req,
                    "Image name is required",
                    drogon::k400BadRequest,
                    "Missing Parameter",
                    "MISSING_IMAGE_NAME"
                );
                callback(resp);
                return;
            }
            
            std::filesystem::path imagePath(IMAGES_PATH);
            imagePath /= imageName;

            if (std::filesystem::exists(imagePath)) {
                try {
                    // Cancel any ongoing SHA256 calculation for this image
                    cancelSHA256Calculation(imageName);
                    
                    // Remove from SHA256 cache
                    {
                        std::lock_guard<std::mutex> lock(sha256Cache_mutex);
                        sha256Cache.erase(imageName);
                    }
                    
                    std::filesystem::remove(imagePath);
                    
                    // Log successful file deletion
                    AuditLog::logFileSystemAccess("DELETE", imagePath.string(), true, "", 
                        "Image file deleted: " + imageName);
                    
                    resp->setStatusCode(drogon::k200OK);
                    callback(resp);
                    return;
                } catch (const std::filesystem::filesystem_error& e) {
                    LOG_ERROR << "Failed to delete image: " << e.what();
                    
                    // Log failed file deletion
                    AuditLog::logFileSystemAccess("DELETE", imagePath.string(), false, "", 
                        "Failed to delete image: " + std::string(e.what()));
                    
                    auto resp = provisioner::utils::createErrorResponse(
                        req,
                        "Failed to delete image file",
                        drogon::k500InternalServerError,
                        "Deletion Error",
                        "IMAGE_DELETE_ERROR",
                        e.what()
                    );
                    callback(resp);
                    return;
                }
            } else {
                LOG_ERROR << "Image not found: " << imagePath;
                auto resp = provisioner::utils::createErrorResponse(
                    req,
                    "The requested image file was not found",
                    drogon::k400BadRequest,
                    "Image Not Found",
                    "IMAGE_NOT_FOUND",
                    "Requested image: " + imageName
                );
                callback(resp);
                return;
            }
        });
    }
} // namespace provisioner