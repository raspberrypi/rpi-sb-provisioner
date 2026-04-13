#include <drogon/drogon.h>
#include <drogon/HttpAppFramework.h>
#include <drogon/HttpResponse.h>
#include <drogon/HttpTypes.h>
#include <drogon/HttpController.h>
#include <drogon/HttpSimpleController.h>
#include <drogon/HttpTypes.h>
#include <drogon/WebSocketController.h>
#include <drogon/RequestStream.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/inotify.h>
#include <sys/select.h>
#include <errno.h>
#include <systemd/sd-bus.h>
#include "utils.h"
#include "include/schema_validator.h"

#include <archive.h>
#include <archive_entry.h>

#include <filesystem>
#include <set>
#include <string>
#include <vector>
#include <fstream>
#include <sstream>
#include <iomanip>
#include <openssl/evp.h>
#include <mutex>
#include <unordered_map>
#include <queue>
#include <deque>
#include <thread>
#include <condition_variable>
#include <atomic>
#include <chrono>
#include <cmath>
#include <random>
#include <cstdlib>
#include <array>

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

#include "include/topic_hub.h"

// Generic progress WebSocket controller — delegates everything to TopicHub.
// Clients send {"subscribe":"upload:<id>"} / {"unsubscribe":"upload:<id>"}.
class ProgressWebSocketController : public drogon::WebSocketController<ProgressWebSocketController> {
public:
    void handleNewMessage(const drogon::WebSocketConnectionPtr& wsConnPtr,
                          std::string&& message,
                          const drogon::WebSocketMessageType& type) override
    {
        if (type != drogon::WebSocketMessageType::Text) return;

        Json::CharReaderBuilder rbuilder;
        Json::Value root;
        std::string errs;
        std::istringstream s(message);
        if (!Json::parseFromStream(rbuilder, s, &root, &errs)) return;

        auto& hub = provisioner::TopicHub::instance();

        if (root.isMember("subscribe") && root["subscribe"].isString()) {
            hub.subscribe(root["subscribe"].asString(), wsConnPtr);
        } else if (root.isMember("unsubscribe") && root["unsubscribe"].isString()) {
            hub.unsubscribe(root["unsubscribe"].asString(), wsConnPtr);
        }
    }

    void handleNewConnection(const drogon::HttpRequestPtr&,
                             const drogon::WebSocketConnectionPtr&) override {}

    void handleConnectionClosed(const drogon::WebSocketConnectionPtr& wsConnPtr) override {
        provisioner::TopicHub::instance().removeConnection(wsConnPtr);
    }

    WS_PATH_LIST_BEGIN
    WS_PATH_ADD("/ws/progress");
    WS_PATH_LIST_END
};

namespace provisioner {

    namespace {
        const std::string IMAGES_PATH = "/srv/rpi-sb-provisioner/images";
        
        // Message queue for SHA256 calculation requests
        std::queue<std::string> sha256RequestQueue;
        std::mutex queueMutex;
        std::condition_variable queueCV;
        std::atomic<bool> workerRunning{false};
        std::thread workerThread;

        // ---- IDP artefact helpers ----

        // Check if a directory is an IDP artefact (contains exactly one .json file)
        bool isIdpArtefactDirectory(const std::filesystem::path& dirPath) {
            if (!std::filesystem::is_directory(dirPath)) return false;
            int jsonCount = 0;
            try {
                for (const auto& entry : std::filesystem::directory_iterator(dirPath)) {
                    if (entry.is_regular_file() && entry.path().extension() == ".json") {
                        jsonCount++;
                    }
                }
            } catch (...) {
                return false;
            }
            return jsonCount == 1;
        }

        // Find the single .json file in an IDP artefact directory
        std::filesystem::path findIdpJsonFile(const std::filesystem::path& dirPath) {
            for (const auto& entry : std::filesystem::directory_iterator(dirPath)) {
                if (entry.is_regular_file() && entry.path().extension() == ".json") {
                    return entry.path();
                }
            }
            return {};
        }

        // Translate IDP device class (e.g., "pi5", "cm4") to provisioner RPI_DEVICE_FAMILY convention
        std::string mapIdpDeviceClassToFamily(const std::string& idpClass) {
            if (idpClass == "pi5" || idpClass == "cm5") return "5";
            if (idpClass == "pi4" || idpClass == "cm4") return "4";
            if (idpClass == "pi2w") return "2W";
            return idpClass; // pass through unknown values
        }

        // Translate IDP storage type to provisioner RPI_DEVICE_STORAGE_TYPE convention
        std::string mapIdpStorageType(const std::string& idpStorage) {
            // IDP uses the same values as the provisioner: "sd", "emmc", "nvme"
            return idpStorage;
        }

        // Parse an IDP JSON file and return analysis metadata
        Json::Value analyzeIdpArtefact(const std::filesystem::path& dirPath) {
            Json::Value result;
            result["type"] = "idp";

            auto jsonPath = findIdpJsonFile(dirPath);
            if (jsonPath.empty()) {
                result["error"] = "No JSON description file found";
                return result;
            }

            std::ifstream jsonFile(jsonPath);
            if (!jsonFile.is_open()) {
                result["error"] = "Cannot open JSON description file";
                return result;
            }

            Json::Value json;
            Json::CharReaderBuilder builder;
            std::string errors;
            if (!Json::parseFromStream(builder, jsonFile, &json, &errors)) {
                result["error"] = "JSON parse error: " + errors;
                return result;
            }

            // Schema-validate the image description
            auto schemaResult = provisioner::schema::validateImageJsonFull(json);
            result["schema_valid"] = schemaResult.valid;
            if (!schemaResult.valid) {
                result["schema_errors"] = schemaResult.errorsToJson();
            }

            // Extract IGmeta fields
            if (json.isMember("IGmeta")) {
                const auto& meta = json["IGmeta"];
                if (meta.isMember("IGconf_device_class")) {
                    std::string rawClass = meta["IGconf_device_class"].asString();
                    result["device_class_raw"] = rawClass;
                    result["device_class"] = mapIdpDeviceClassToFamily(rawClass);
                }
                if (meta.isMember("IGconf_device_storage_type")) {
                    std::string rawStorage = meta["IGconf_device_storage_type"].asString();
                    result["storage_type_raw"] = rawStorage;
                    result["storage_type"] = mapIdpStorageType(rawStorage);
                }
                if (meta.isMember("IGconf_image_version")) {
                    result["image_version"] = meta["IGconf_image_version"].asString();
                }
            }

            // Extract attributes
            if (json.isMember("attributes")) {
                const auto& attrs = json["attributes"];
                if (attrs.isMember("image-name")) {
                    result["image_name"] = attrs["image-name"].asString();
                }
            }

            // Check encryption -- look for encrypted partitions in the provisionmap
            bool hasEncryption = false;
            std::string cipher;
            if (json.isMember("layout")) {
                const auto& layout = json["layout"];
                if (layout.isMember("provisionmap")) {
                    const auto& pmap = layout["provisionmap"];
                    for (const auto& entry : pmap) {
                        if (entry.isMember("encrypted") && entry["encrypted"].isObject()) {
                            hasEncryption = true;
                            const auto& enc = entry["encrypted"];
                            if (enc.isMember("luks2") && enc["luks2"].isMember("cipher")) {
                                cipher = enc["luks2"]["cipher"].asString();
                            }
                        }
                    }
                }

                // Count partitions
                if (layout.isMember("partitionimages")) {
                    result["partition_count"] = static_cast<Json::UInt>(layout["partitionimages"].size());
                }
            }
            result["encryption"] = hasEncryption;
            if (!cipher.empty()) {
                result["cipher"] = cipher;
            }

            // Count sparse image files referenced by the IDP descriptor
            int simgCount = 0;
            if (json.isMember("layout") && json["layout"].isMember("partitionimages")) {
                std::set<std::string> seen;
                const auto& pimages = json["layout"]["partitionimages"];
                for (const auto& key : pimages.getMemberNames()) {
                    if (pimages[key].isMember("simage")) {
                        std::string name = pimages[key]["simage"].asString();
                        if (!name.empty() && seen.insert(name).second) {
                            std::filesystem::path p = dirPath / name;
                            if (std::filesystem::exists(p) && std::filesystem::is_regular_file(p)) {
                                simgCount++;
                            }
                        }
                    }
                }
            }
            result["simg_file_count"] = simgCount;

            return result;
        }

        // Validate archive entry path for security (no path traversal)
        bool isArchivePathSafe(const std::string& entryPath) {
            // Reject absolute paths
            if (!entryPath.empty() && entryPath[0] == '/') return false;
            // Reject path traversal
            if (entryPath.find("..") != std::string::npos) return false;
            return true;
        }

        // Check available disk space at a path (returns bytes available)
        std::uintmax_t getAvailableDiskSpace(const std::string& path) {
            struct statvfs stat;
            if (statvfs(path.c_str(), &stat) != 0) {
                return 0;
            }
            return static_cast<std::uintmax_t>(stat.f_bavail) * stat.f_frsize;
        }

        // Run an external command and return exit code
        int runCommand(const std::string& cmd) {
            return std::system(cmd.c_str());
        }

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
        constexpr size_t CHUNK_SIZE = 1 * 1024 * 1024;
        constexpr size_t SUB_CHUNK_SIZE = 256 * 1024;
        std::vector<unsigned char> buffer(CHUNK_SIZE);

        provisioner::utils::SHA256Hasher hasher;
        
        std::ifstream file(imagePath, std::ios::binary);
        if (!file) {
            return "file-read-error";
        }
        
        // Get file size for progress reporting
        file.seekg(0, std::ios::end);
        std::streamsize fileSize = file.tellg();
        file.seekg(0, std::ios::beg);
        
        LOG_INFO << "Starting SHA256 calculation for " << imagePath.filename().string() 
                 << " (" << (fileSize / (1024 * 1024)) << " MB)";
        
        std::streamsize totalBytesRead = 0;
        int lastProgressPercent = 0;
        
        while (file) {
            if (cancellationToken) {
                if (cancellationToken->is_cancelled()) {
                    LOG_INFO << "SHA256 calculation cancelled for " << imageName;
                    return "calculation-cancelled";
                }
            } else {
                LOG_WARN << "No cancellation token available for " << imageName << " during chunk processing";
            }
            
            file.read(reinterpret_cast<char*>(buffer.data()), CHUNK_SIZE);
            std::streamsize bytes_read = file.gcount();
            if (bytes_read > 0) {
                std::streamsize processed = 0;
                while (processed < bytes_read) {
                    if (cancellationToken && cancellationToken->is_cancelled()) {
                        LOG_INFO << "SHA256 calculation cancelled during sub-chunk processing for " << imageName;
                        return "calculation-cancelled";
                    }
                    
                    std::streamsize sub_chunk_size = std::min(static_cast<std::streamsize>(SUB_CHUNK_SIZE), bytes_read - processed);
                    hasher.update(buffer.data() + processed, sub_chunk_size);
                    processed += sub_chunk_size;
                }
                
                totalBytesRead += bytes_read;
                
                if (fileSize > 0) {
                    int progressPercent = static_cast<int>((totalBytesRead * 100) / fileSize);
                    double progressFraction = static_cast<double>(totalBytesRead) / fileSize;
                    
                    if (progressPercent >= lastProgressPercent + 5) {
                        lastProgressPercent = (progressPercent / 5) * 5;
                        LOG_INFO << "SHA256 calculation: " << lastProgressPercent << "% complete for "
                                 << imagePath.filename().string();
                        
                        if (!imageName.empty()) {
                            std::lock_guard<std::mutex> lock(sha256Cache_mutex);
                            auto it = sha256Cache.find(imageName);
                            if (it != sha256Cache.end() && it->second.status == SHA256Status::PENDING) {
                                SHA256Result updatedResult("", SHA256Status::PENDING, progressFraction);
                                
                                if (it->second.timestamp.has_value()) {
                                    updatedResult.timestamp = it->second.timestamp;
                                }
                                
                                updatedResult.cancellation_token = it->second.cancellation_token;
                                
                                sha256Cache.insert_or_assign(imageName, updatedResult);
                                
                                SHA256WebSocketController::broadcastUpdate(imageName, updatedResult);
                            }
                        }
                    }
                }
            }
        }
        
        if (cancellationToken && cancellationToken->is_cancelled()) {
            LOG_INFO << "SHA256 calculation cancelled at completion for " << imageName;
            return "calculation-cancelled";
        }
        
        std::string sha256 = hasher.finalize();
        
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
        
        // JSON endpoint for listing images (used by Options page image browser)
        app.registerHandler("/images/list", [](const drogon::HttpRequestPtr &req, std::function<void(const drogon::HttpResponsePtr &)> &&callback) {
            LOG_INFO << "Images::list (JSON)";
            AuditLog::logHandlerAccess(req, "/images/list");

            std::vector<ImageInfo> imageInfos;
            
            try {
                for (const auto &entry : std::filesystem::directory_iterator(IMAGES_PATH)) {
                    // Include IDP artefact directories
                    if (entry.is_directory()) {
                        if (entry.path().filename().string()[0] == '.') continue;
                        if (isIdpArtefactDirectory(entry.path())) {
                            ImageInfo info;
                            info.name = entry.path().filename().string();
                            info.is_idp = true;
                            // Read SHA256 from sidecar file (hash of the original archive)
                            info.sha256 = "IDP Artefact";
                            try {
                                std::filesystem::path sidecarPath = entry.path();
                                sidecarPath += ".sha256";
                                if (std::filesystem::exists(sidecarPath)) {
                                    std::ifstream in(sidecarPath);
                                    std::string line;
                                    if (in && std::getline(in, line)) {
                                        while (!line.empty() && (line.back()==' ' || line.back()=='\t' || line.back()=='\n' || line.back()=='\r')) {
                                            line.pop_back();
                                        }
                                        if (!line.empty()) info.sha256 = line;
                                    }
                                }
                            } catch (...) {}
                            // Sum up directory size
                            try {
                                std::uintmax_t totalSize = 0;
                                for (const auto& f : std::filesystem::recursive_directory_iterator(entry.path())) {
                                    if (f.is_regular_file()) totalSize += std::filesystem::file_size(f);
                                }
                                info.size = totalSize;
                            } catch (...) {
                                info.size = 0;
                            }
                            imageInfos.push_back(info);
                        }
                        continue;
                    }

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
                imageObj["is_idp"] = info.is_idp;
                imageObj["type"] = info.is_idp ? "idp" : "traditional";
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

            // For IDP artefact directories, return the sidecar hash immediately
            if (std::filesystem::is_directory(imagePath)) {
                auto resp = drogon::HttpResponse::newHttpResponse();
                resp->setStatusCode(drogon::k200OK);
                resp->setContentTypeCode(drogon::CT_APPLICATION_JSON);
                Json::Value result;
                result["name"] = imageName;

                std::filesystem::path sidecarPath = imagePath;
                sidecarPath += ".sha256";
                if (std::filesystem::exists(sidecarPath)) {
                    try {
                        std::ifstream in(sidecarPath);
                        std::string line;
                        if (in && std::getline(in, line)) {
                            while (!line.empty() && (line.back()==' ' || line.back()=='\t' || line.back()=='\n' || line.back()=='\r')) {
                                line.pop_back();
                            }
                            result["sha256"] = line;
                            result["status"] = "complete";
                        } else {
                            result["sha256"] = "IDP Artefact";
                            result["status"] = "complete";
                        }
                    } catch (...) {
                        result["sha256"] = "IDP Artefact";
                        result["status"] = "error";
                    }
                } else {
                    result["sha256"] = "IDP Artefact";
                    result["status"] = "complete";
                    result["message"] = "No archive hash available (sidecar file missing).";
                }

                resp->setBody(result.toStyledString());
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

        app.registerHandler("/upload-image", [](const drogon::HttpRequestPtr &req, drogon::RequestStreamPtr &&stream, std::function<void(const drogon::HttpResponsePtr &)> &&callback) {
            LOG_INFO << "Images::uploadImage";

            AuditLog::logHandlerAccess(req, "/upload-image");

            // Helper: case-insensitive suffix check
            auto endsWith = [](const std::string& s, const std::string& suffix) -> bool {
                return s.size() >= suffix.size() &&
                       s.compare(s.size() - suffix.size(), suffix.size(), suffix) == 0;
            };

            // Helper: generate a unique filename (race-condition safe with timestamp fallback)
            auto generateUniqueFilename = [](const std::string& originalName, const std::string& basePath) -> std::string {
                std::filesystem::path targetDir(basePath);
                std::filesystem::path originalPath = targetDir / originalName;

                if (!std::filesystem::exists(originalPath)) {
                    return originalName;
                }

                std::filesystem::path nameOnly = originalPath.stem();
                std::filesystem::path extension = originalPath.extension();

                for (int i = 1; i <= 9999; ++i) {
                    std::string newName = nameOnly.string() + "_" + std::to_string(i) + extension.string();
                    if (!std::filesystem::exists(targetDir / newName)) {
                        return newName;
                    }
                }

                auto now = std::chrono::system_clock::now();
                auto timestamp = std::chrono::duration_cast<std::chrono::milliseconds>(now.time_since_epoch()).count();
                std::random_device rd;
                std::mt19937 gen(rd());
                std::uniform_int_distribution<> dis(1000, 9999);
                return nameOnly.string() + "_" + std::to_string(timestamp) + "_" + std::to_string(dis(gen)) + extension.string();
            };

            // Helper: strip archive extension to get the artefact name
            auto stripArchiveExtension = [&endsWith](const std::string& filename, const std::string& lowerFilename) -> std::string {
                if (endsWith(lowerFilename, ".tar.xz"))  return filename.substr(0, filename.size() - 7);
                if (endsWith(lowerFilename, ".tar.zst")) return filename.substr(0, filename.size() - 8);
                return filename;
            };

            // Helper: strip compression extension from .img.{xz,zst} -> .img
            auto stripImgCompressionExtension = [&endsWith](const std::string& filename, const std::string& lowerFilename) -> std::string {
                if (endsWith(lowerFilename, ".img.xz"))  return filename.substr(0, filename.size() - 3);
                if (endsWith(lowerFilename, ".img.zst")) return filename.substr(0, filename.size() - 4);
                return filename;
            };

            auto isSupportedUpload = [&endsWith](const std::string& lowerFilename) -> bool {
                return endsWith(lowerFilename, ".img") ||
                       endsWith(lowerFilename, ".img.xz") ||
                       endsWith(lowerFilename, ".img.zst") ||
                       endsWith(lowerFilename, ".tar.xz") ||
                       endsWith(lowerFilename, ".tar.zst");
            };

            // ---- Non-stream fallback (if streaming is disabled) ----
            if (!stream) {
                LOG_WARN << "Request stream not available, falling back to buffered upload";
                auto resp = drogon::HttpResponse::newHttpResponse();

                drogon::MultiPartParser parser;
                if (parser.parse(req) != 0 || parser.getFiles().size() != 1) {
                    auto resp = provisioner::utils::createErrorResponse(
                        req, "Invalid request: Expected exactly one file in multipart form data",
                        drogon::k400BadRequest, "Invalid Request", "INVALID_UPLOAD_REQUEST");
                    callback(resp);
                    return;
                }
                const auto& file = parser.getFiles()[0];
                std::string originalFilename = file.getFileName();
                std::string finalFilename = generateUniqueFilename(originalFilename, IMAGES_PATH);
                std::filesystem::path targetPath = std::filesystem::path(IMAGES_PATH) / finalFilename;

                try {
                    file.saveAs(targetPath);
                    AuditLog::logFileSystemAccess("UPLOAD", targetPath.string(), true, "",
                        "Original filename: " + originalFilename + (originalFilename != finalFilename ? ", renamed to: " + finalFilename : ""));
                    {
                        std::lock_guard<std::mutex> lock(sha256Cache_mutex);
                        sha256Cache.erase(finalFilename);
                    }
                    requestSHA256Calculation(finalFilename);
                    triggerBootImgGeneration(finalFilename);

                    resp->setStatusCode(drogon::k200OK);
                    resp->setContentTypeCode(drogon::CT_APPLICATION_JSON);
                    Json::Value result;
                    result["success"] = true;
                    result["is_idp"] = false;
                    result["filename"] = finalFilename;
                    result["renamed"] = (originalFilename != finalFilename);
                    if (originalFilename != finalFilename) result["original_filename"] = originalFilename;
                    result["message"] = result["renamed"].asBool() ? "File uploaded successfully (renamed to avoid conflict)" : "File uploaded successfully";
                    result["sha256"] = "Calculating...";
                    resp->setBody(result.toStyledString());
                } catch (const std::exception& e) {
                    LOG_ERROR << "Failed to save uploaded file: " << e.what();
                    AuditLog::logFileSystemAccess("UPLOAD", targetPath.string(), false, "",
                        "Upload failed: " + std::string(e.what()));
                    auto resp = provisioner::utils::createErrorResponse(
                        req, "Failed to save uploaded file", drogon::k500InternalServerError,
                        "Upload Error", "UPLOAD_SAVE_ERROR", e.what());
                    callback(resp);
                    return;
                }
                callback(resp);
                return;
            }

            // ---- Streaming upload path ----

            // Early disk space check using Content-Length header.
            // This is a baseline check -- for compressed images, the worker thread
            // performs exact pre-allocation via posix_fallocate after reading the
            // container metadata (xz/zstd embed the uncompressed size).
            size_t contentLength = req->realContentLength();
            if (contentLength > 0) {
                auto availableSpace = getAvailableDiskSpace(IMAGES_PATH);
                // Use 5x multiplier to account for possible compression.
                // At this point we don't know if the upload is compressed or not
                // (the filename arrives later in the multipart headers), so we
                // apply the multiplier conservatively. For uncompressed .img
                // uploads this means we require 5x headroom, which is acceptable.
                size_t spaceNeeded = contentLength * 5;
                if (availableSpace < spaceNeeded) {
                    LOG_ERROR << "Insufficient disk space for upload: need ~" << spaceNeeded
                              << " bytes (5x Content-Length), have " << availableSpace;
                    stream->setStreamReader(drogon::RequestStreamReader::newNullReader());
                    auto resp = provisioner::utils::createErrorResponse(
                        req, "Insufficient disk space for upload",
                        drogon::k507InsufficientStorage, "Disk Space Error", "INSUFFICIENT_DISK_SPACE");
                    callback(resp);
                    return;
                }
            }

            // Shared context for streaming callbacks
            struct UploadContext {
                // Common
                std::string originalFilename;
                std::string finalFilename;
                bool isArchive = false;
                bool isCompressedImg = false;
                bool hadError = false;
                std::string errorMessage;
                drogon::HttpStatusCode errorCode = drogon::k500InternalServerError;

                // .img direct-write state
                int fd = -1;
                size_t totalBytesWritten = 0;
                std::string targetPath;

                // Archive / compressed-img shared state (libarchive producer-consumer)
                std::string artefactName;
                std::filesystem::path tempDir;
                std::filesystem::path finalDir;
                std::mutex bufferMutex;
                std::condition_variable bufferCv;
                std::deque<std::vector<char>> chunks;
                std::vector<char> currentReadChunk;
                bool streamFinished = false;
                std::thread extractionThread;
                bool extractionOk = false;
                std::string extractionError;

                // SHA256 computed inline on the raw upload data (archives)
                // For .img and compressed .img, SHA256 is on the decompressed data
                std::unique_ptr<provisioner::utils::SHA256Hasher> sha256Hasher;

                // SHA256 computed in worker thread on decompressed data (compressed .img only)
                std::unique_ptr<provisioner::utils::SHA256Hasher> workerSha256Hasher;
                std::string workerSha256Result;

                // WebSocket progress push (set from X-Upload-Id header; empty = no push)
                std::string uploadId;
                std::atomic<int64_t> progressBytesWritten{0};
                int64_t progressTotalBytes = 0;

                // Response plumbing
                std::function<void(const drogon::HttpResponsePtr &)> callback;
                drogon::HttpRequestPtr req;
                size_t contentLength = 0;

                ~UploadContext() {
                    if (fd >= 0) ::close(fd);
                    if (extractionThread.joinable()) extractionThread.join();
                }
            };

            auto ctx = std::make_shared<UploadContext>();
            ctx->callback = std::move(callback);
            ctx->req = req;
            ctx->contentLength = contentLength;
            ctx->uploadId = req->getHeader("X-Upload-Id");

            // libarchive custom read callback: blocks on the producer-consumer buffer
            auto archiveReadCb = [](struct archive*, void* clientData, const void** buffer) -> la_ssize_t {
                auto* c = static_cast<UploadContext*>(clientData);
                std::unique_lock<std::mutex> lock(c->bufferMutex);
                c->bufferCv.wait(lock, [&] { return !c->chunks.empty() || c->streamFinished; });
                if (c->chunks.empty()) return 0; // EOF
                c->currentReadChunk = std::move(c->chunks.front());
                c->chunks.pop_front();
                *buffer = c->currentReadChunk.data();
                return static_cast<la_ssize_t>(c->currentReadChunk.size());
            };

            auto reader = drogon::RequestStreamReader::newMultipartReader(
                req,
                // ---- headerCb: called when a new multipart part header is parsed ----
                [ctx, endsWith, generateUniqueFilename, stripArchiveExtension, stripImgCompressionExtension, isSupportedUpload, archiveReadCb](drogon::MultipartHeader &&header) {
                    if (ctx->hadError) return;

                    ctx->originalFilename = header.filename;
                    if (ctx->originalFilename.empty()) return;

                    std::string lowerFilename = ctx->originalFilename;
                    std::transform(lowerFilename.begin(), lowerFilename.end(), lowerFilename.begin(), ::tolower);

                    if (!isSupportedUpload(lowerFilename)) {
                        ctx->hadError = true;
                        ctx->errorMessage = "Unsupported file type. Accepted formats: .img, .img.xz, .img.zst, .tar.xz, .tar.zst";
                        return;
                    }

                    ctx->isArchive = endsWith(lowerFilename, ".tar.xz") ||
                                     endsWith(lowerFilename, ".tar.zst");

                    ctx->isCompressedImg = endsWith(lowerFilename, ".img.xz") ||
                                           endsWith(lowerFilename, ".img.zst");

                    // Initialize inline SHA256 for archives (hashes the compressed stream)
                    // For plain .img and compressed .img, SHA256 is on decompressed data
                    if (ctx->isArchive) {
                        ctx->sha256Hasher = std::make_unique<provisioner::utils::SHA256Hasher>();
                    }

                    if (ctx->isArchive) {
                        // --- Archive streaming path ---
                        ctx->artefactName = stripArchiveExtension(ctx->originalFilename, lowerFilename);
                        ctx->finalDir = std::filesystem::path(IMAGES_PATH) / ctx->artefactName;
                        ctx->tempDir = std::filesystem::path(IMAGES_PATH) / ("." + ctx->artefactName + ".extracting");

                        LOG_INFO << "Streaming archive upload (IDP artefact): " << ctx->originalFilename;

                        try {
                            std::filesystem::create_directories(ctx->tempDir);
                        } catch (const std::exception& e) {
                            ctx->hadError = true;
                            ctx->errorMessage = "Failed to create extraction directory: " + std::string(e.what());
                            return;
                        }

                        // Spawn worker thread for libarchive extraction
                        std::string tempDirStr = ctx->tempDir.string();
                        ctx->extractionThread = std::thread([ctx, archiveReadCb, tempDirStr]() {
                            struct archive *a = archive_read_new();
                            archive_read_support_filter_xz(a);
                            archive_read_support_filter_zstd(a);
                            archive_read_support_format_tar(a);

                            if (archive_read_open(a, ctx.get(), nullptr, archiveReadCb, nullptr) != ARCHIVE_OK) {
                                ctx->extractionError = "Failed to open archive stream: " + std::string(archive_error_string(a));
                                archive_read_free(a);
                                return;
                            }

                            struct archive *ext = archive_write_disk_new();
                            archive_write_disk_set_options(ext,
                                ARCHIVE_EXTRACT_TIME | ARCHIVE_EXTRACT_PERM | ARCHIVE_EXTRACT_NO_OVERWRITE);
                            archive_write_disk_set_standard_lookup(ext);

                            struct archive_entry *entry;
                            int r;
                            size_t archiveBytesWritten = 0;
                            auto lastPublish = std::chrono::steady_clock::now() - std::chrono::seconds(1);
                            while ((r = archive_read_next_header(a, &entry)) == ARCHIVE_OK) {
                                std::string entryPath = archive_entry_pathname(entry);
                                if (!isArchivePathSafe(entryPath)) {
                                    ctx->extractionError = "Archive contains unsafe path: " + entryPath;
                                    break;
                                }

                                std::string fullPath = tempDirStr + "/" + entryPath;
                                archive_entry_set_pathname(entry, fullPath.c_str());

                                r = archive_write_header(ext, entry);
                                if (r != ARCHIVE_OK) {
                                    ctx->extractionError = "Failed to write header: " + std::string(archive_error_string(ext));
                                    break;
                                }

                                if (archive_entry_size(entry) > 0) {
                                    const void *buff;
                                    size_t size;
                                    la_int64_t offset;
                                    while ((r = archive_read_data_block(a, &buff, &size, &offset)) == ARCHIVE_OK) {
                                        if (archive_write_data_block(ext, buff, size, offset) != ARCHIVE_OK) {
                                            ctx->extractionError = "Failed to write data: " + std::string(archive_error_string(ext));
                                            break;
                                        }
                                        archiveBytesWritten += size;
                                        if (!ctx->uploadId.empty()) {
                                            auto now = std::chrono::steady_clock::now();
                                            if (now - lastPublish >= std::chrono::milliseconds(250)) {
                                                lastPublish = now;
                                                Json::Value p;
                                                p["phase"] = "extracting";
                                                p["bytes_written"] = static_cast<Json::Int64>(archiveBytesWritten);
                                                p["current_entry"] = entryPath;
                                                provisioner::TopicHub::instance().publish("upload:" + ctx->uploadId, p);
                                            }
                                        }
                                    }
                                    if (!ctx->extractionError.empty()) break;
                                    if (r != ARCHIVE_EOF) {
                                        ctx->extractionError = "Error reading data: " + std::string(archive_error_string(a));
                                        break;
                                    }
                                }
                                archive_write_finish_entry(ext);
                            }

                            if (ctx->extractionError.empty() && r != ARCHIVE_EOF && r != ARCHIVE_OK) {
                                ctx->extractionError = "Archive read error: " + std::string(archive_error_string(a));
                            }

                            ctx->extractionOk = ctx->extractionError.empty();
                            archive_write_free(ext);
                            archive_read_free(a);
                        });
                    } else if (ctx->isCompressedImg) {
                        // --- Compressed .img streaming path ---
                        // Decompress on-the-fly via libarchive format_raw, write plain .img
                        std::string imgFilename = stripImgCompressionExtension(ctx->originalFilename, lowerFilename);
                        ctx->finalFilename = generateUniqueFilename(imgFilename, IMAGES_PATH);
                        ctx->targetPath = (std::filesystem::path(IMAGES_PATH) / ctx->finalFilename).string();

                        LOG_INFO << "Streaming compressed .img upload: " << ctx->originalFilename
                                 << " -> " << ctx->finalFilename;

                        ctx->fd = ::open(ctx->targetPath.c_str(), O_WRONLY | O_CREAT | O_TRUNC, 0644);
                        if (ctx->fd < 0) {
                            ctx->hadError = true;
                            ctx->errorMessage = "Failed to open target file: " + std::string(strerror(errno));
                            return;
                        }

                        // Spawn decompression worker thread
                        ctx->extractionThread = std::thread([ctx, archiveReadCb]() {
                            struct archive *a = archive_read_new();
                            archive_read_support_filter_xz(a);
                            archive_read_support_filter_zstd(a);
                            archive_read_support_format_raw(a);

                            if (archive_read_open(a, ctx.get(), nullptr, archiveReadCb, nullptr) != ARCHIVE_OK) {
                                ctx->extractionError = "Failed to open compressed stream: " + std::string(archive_error_string(a));
                                archive_read_free(a);
                                return;
                            }

                            struct archive_entry *entry;
                            if (archive_read_next_header(a, &entry) != ARCHIVE_OK) {
                                ctx->extractionError = "Failed to read compressed stream header: " + std::string(archive_error_string(a));
                                archive_read_free(a);
                                return;
                            }

                            // Pre-allocate using the decompressed size from container metadata.
                            // xz and zstd both embed the uncompressed size reliably.
                            la_int64_t entrySize = archive_entry_size(entry);
                            if (entrySize > 0) {
                                int fa_ret = posix_fallocate(ctx->fd, 0, static_cast<off_t>(entrySize));
                                if (fa_ret != 0) {
                                    ctx->extractionError = "Failed to pre-allocate disk space for decompressed image: " + std::string(strerror(fa_ret));
                                    ctx->errorCode = drogon::k507InsufficientStorage;
                                    ctx->hadError = true;
                                    archive_read_free(a);
                                    return;
                                }
                                LOG_INFO << "Pre-allocated " << entrySize << " bytes for decompressed image";
                                ctx->progressTotalBytes = static_cast<int64_t>(entrySize);
                            }

                            // Initialize SHA256 for the decompressed data
                            ctx->workerSha256Hasher = std::make_unique<provisioner::utils::SHA256Hasher>();

                            // Read decompressed data blocks and write to disk
                            const void *buff;
                            size_t size;
                            la_int64_t offset;
                            int r;
                            auto lastPublish = std::chrono::steady_clock::now() - std::chrono::seconds(1);
                            while ((r = archive_read_data_block(a, &buff, &size, &offset)) == ARCHIVE_OK) {
                                ctx->workerSha256Hasher->update(buff, size);

                                const char *ptr = static_cast<const char*>(buff);
                                size_t remaining = size;
                                while (remaining > 0) {
                                    ssize_t written = ::write(ctx->fd, ptr, remaining);
                                    if (written < 0) {
                                        if (errno == EINTR) continue;
                                        ctx->extractionError = "Write failed: " + std::string(strerror(errno));
                                        if (errno == ENOSPC) ctx->errorCode = drogon::k507InsufficientStorage;
                                        ctx->hadError = true;
                                        archive_read_free(a);
                                        return;
                                    }
                                    ptr += written;
                                    remaining -= static_cast<size_t>(written);
                                }
                                ctx->totalBytesWritten += size;

                                if (!ctx->uploadId.empty()) {
                                    auto now = std::chrono::steady_clock::now();
                                    if (now - lastPublish >= std::chrono::milliseconds(250)) {
                                        lastPublish = now;
                                        Json::Value p;
                                        p["phase"] = "decompressing";
                                        p["bytes_written"] = static_cast<Json::Int64>(ctx->totalBytesWritten);
                                        if (ctx->progressTotalBytes > 0)
                                            p["total_bytes"] = static_cast<Json::Int64>(ctx->progressTotalBytes);
                                        provisioner::TopicHub::instance().publish("upload:" + ctx->uploadId, p);
                                    }
                                }
                            }

                            if (r != ARCHIVE_EOF) {
                                ctx->extractionError = "Decompression error: " + std::string(archive_error_string(a));
                                archive_read_free(a);
                                return;
                            }

                            // Finalize SHA256 in the worker
                            ctx->workerSha256Result = ctx->workerSha256Hasher->finalize();

                            ctx->extractionOk = true;
                            archive_read_free(a);
                        });
                    } else {
                        // --- .img direct-write path ---
                        ctx->finalFilename = generateUniqueFilename(ctx->originalFilename, IMAGES_PATH);
                        ctx->targetPath = (std::filesystem::path(IMAGES_PATH) / ctx->finalFilename).string();

                        LOG_INFO << "Streaming .img upload: " << ctx->originalFilename << " -> " << ctx->finalFilename;

                        // Initialize inline SHA256 for plain .img
                        ctx->sha256Hasher = std::make_unique<provisioner::utils::SHA256Hasher>();

                        ctx->fd = ::open(ctx->targetPath.c_str(), O_WRONLY | O_CREAT | O_TRUNC, 0644);
                        if (ctx->fd < 0) {
                            ctx->hadError = true;
                            ctx->errorMessage = "Failed to open target file: " + std::string(strerror(errno));
                            return;
                        }

                        // Pre-allocate disk space using Content-Length as an upper bound
                        if (ctx->contentLength > 0) {
                            int fa_ret = posix_fallocate(ctx->fd, 0, static_cast<off_t>(ctx->contentLength));
                            if (fa_ret != 0) {
                                ctx->hadError = true;
                                ctx->errorCode = drogon::k507InsufficientStorage;
                                ctx->errorMessage = "Failed to pre-allocate disk space: " + std::string(strerror(fa_ret));
                                ::close(ctx->fd);
                                ctx->fd = -1;
                                ::unlink(ctx->targetPath.c_str());
                                return;
                            }
                        }
                    }
                },
                // ---- dataCb: called for each chunk of data ----
                [ctx](const char *data, size_t length) {
                    if (ctx->hadError) return;

                    if (length == 0) {
                        // Part complete
                        if (ctx->isArchive || ctx->isCompressedImg) {
                            // Signal EOF to the extraction/decompression thread
                            {
                                std::lock_guard<std::mutex> lock(ctx->bufferMutex);
                                ctx->streamFinished = true;
                            }
                            ctx->bufferCv.notify_one();
                        } else if (ctx->fd >= 0) {
                            // Trim the pre-allocated file to actual size and close
                            if (::ftruncate(ctx->fd, static_cast<off_t>(ctx->totalBytesWritten)) != 0) {
                                LOG_WARN << "ftruncate failed: " << strerror(errno);
                            }
                            ::close(ctx->fd);
                            ctx->fd = -1;
                        }
                        return;
                    }

                    // Update inline SHA256 for archives (hashes compressed stream)
                    // and plain .img (hashes raw data). Compressed .img computes
                    // SHA256 on decompressed data inside the worker thread instead.
                    if (ctx->sha256Hasher) {
                        ctx->sha256Hasher->update(data, length);
                    }

                    if (ctx->isArchive || ctx->isCompressedImg) {
                        // Push chunk to the producer-consumer buffer for libarchive
                        {
                            std::lock_guard<std::mutex> lock(ctx->bufferMutex);
                            ctx->chunks.emplace_back(data, data + length);
                        }
                        ctx->bufferCv.notify_one();
                    } else if (ctx->fd >= 0) {
                        // Write directly to the pre-allocated file
                        const char *ptr = data;
                        size_t remaining = length;
                        while (remaining > 0) {
                            ssize_t written = ::write(ctx->fd, ptr, remaining);
                            if (written < 0) {
                                if (errno == EINTR) continue;
                                ctx->hadError = true;
                                ctx->errorMessage = "Write failed: " + std::string(strerror(errno));
                                if (errno == ENOSPC) ctx->errorCode = drogon::k507InsufficientStorage;
                                return;
                            }
                            ptr += written;
                            remaining -= static_cast<size_t>(written);
                        }
                        ctx->totalBytesWritten += length;
                    }
                },
                // ---- finishCb: called when the stream completes or errors ----
                [ctx, endsWith](std::exception_ptr ex) {
                    // Finalize inline SHA256
                    std::string sha256Hex;
                    if (ctx->sha256Hasher) {
                        sha256Hex = ctx->sha256Hasher->finalize();
                    }

                    // Helper: signal the worker thread and clean up on error
                    auto signalWorkerAndCleanup = [&ctx]() {
                        if (ctx->isArchive || ctx->isCompressedImg) {
                            { std::lock_guard<std::mutex> lock(ctx->bufferMutex); ctx->streamFinished = true; }
                            ctx->bufferCv.notify_one();
                            if (ctx->extractionThread.joinable()) ctx->extractionThread.join();
                            if (ctx->isArchive && std::filesystem::exists(ctx->tempDir))
                                std::filesystem::remove_all(ctx->tempDir);
                        }
                        if (!ctx->targetPath.empty()) ::unlink(ctx->targetPath.c_str());
                    };

                    // Helper: publish an error/completion message and tear down the topic
                    auto publishProgress = [&ctx](const std::string& phase, const std::string& errMsg = "") {
                        if (ctx->uploadId.empty()) return;
                        Json::Value p;
                        p["phase"] = phase;
                        if (!errMsg.empty()) p["message"] = errMsg;
                        auto& hub = provisioner::TopicHub::instance();
                        hub.publish("upload:" + ctx->uploadId, p);
                        hub.removeTopic("upload:" + ctx->uploadId);
                    };

                    // Handle stream-level errors
                    if (ex) {
                        try { std::rethrow_exception(ex); }
                        catch (const drogon::StreamError& e) { LOG_ERROR << "Stream error: " << e.what(); }
                        catch (const std::exception& e) { LOG_ERROR << "Upload stream error: " << e.what(); }

                        signalWorkerAndCleanup();
                        publishProgress("error", "Upload stream failed");

                        auto resp = provisioner::utils::createErrorResponse(
                            ctx->req, "Upload stream failed", drogon::k400BadRequest,
                            "Upload Error", "STREAM_ERROR");
                        ctx->callback(resp);
                        return;
                    }

                    // Handle write errors detected during streaming
                    if (ctx->hadError) {
                        signalWorkerAndCleanup();
                        publishProgress("error", ctx->errorMessage);
                        auto resp = provisioner::utils::createErrorResponse(
                            ctx->req, ctx->errorMessage, ctx->errorCode,
                            "Upload Error", "UPLOAD_WRITE_ERROR");
                        ctx->callback(resp);
                        return;
                    }

                    if (ctx->isArchive) {
                        // ---- Archive post-processing ----
                        // Wait for extraction thread to finish
                        if (ctx->extractionThread.joinable()) ctx->extractionThread.join();

                        if (!ctx->extractionOk) {
                            LOG_ERROR << "Archive extraction failed: " << ctx->extractionError;
                            if (std::filesystem::exists(ctx->tempDir)) std::filesystem::remove_all(ctx->tempDir);
                            AuditLog::logFileSystemAccess("UPLOAD_ARCHIVE", ctx->finalDir.string(), false, "",
                                "Archive extraction failed: " + ctx->extractionError);
                            publishProgress("error", "Archive extraction failed: " + ctx->extractionError);
                            auto resp = provisioner::utils::createErrorResponse(
                                ctx->req, "Failed to extract archive: " + ctx->extractionError,
                                drogon::k500InternalServerError, "Extraction Error", "ARCHIVE_EXTRACT_ERROR");
                            ctx->callback(resp);
                            return;
                        }

                        // Security: validate all extracted paths
                        try {
                            for (const auto& entry : std::filesystem::recursive_directory_iterator(ctx->tempDir)) {
                                auto relativePath = std::filesystem::relative(entry.path(), ctx->tempDir).string();
                                if (!isArchivePathSafe(relativePath)) {
                                    LOG_ERROR << "Archive contains unsafe path: " << relativePath;
                                    std::filesystem::remove_all(ctx->tempDir);
                                    auto resp = provisioner::utils::createErrorResponse(
                                        ctx->req, "Archive contains unsafe paths (path traversal detected)",
                                        drogon::k400BadRequest, "Security Error", "ARCHIVE_PATH_TRAVERSAL");
                                    ctx->callback(resp);
                                    return;
                                }
                            }
                        } catch (const std::exception& e) {
                            std::filesystem::remove_all(ctx->tempDir);
                            auto resp = provisioner::utils::createErrorResponse(
                                ctx->req, "Failed to validate extracted paths",
                                drogon::k500InternalServerError, "Extraction Error", "ARCHIVE_VALIDATE_ERROR", e.what());
                            ctx->callback(resp);
                            return;
                        }

                        // If single top-level directory, promote its contents
                        int topLevelEntries = 0;
                        std::filesystem::path singleSubdir;
                        for (const auto& entry : std::filesystem::directory_iterator(ctx->tempDir)) {
                            topLevelEntries++;
                            if (entry.is_directory()) singleSubdir = entry.path();
                        }
                        if (topLevelEntries == 1 && !singleSubdir.empty()) {
                            auto promotedTemp = std::filesystem::path(IMAGES_PATH) / ("." + ctx->artefactName + ".promoted");
                            std::filesystem::rename(singleSubdir, promotedTemp);
                            std::filesystem::remove_all(ctx->tempDir);
                            ctx->tempDir = promotedTemp;
                        }

                        // Replace any existing artefact directory with minimal downtime.
                        // Move the old directory aside first (atomic rename), then rename
                        // the new one into place (atomic rename), then delete the old one.
                        // This avoids a window where finalDir doesn't exist at all, which
                        // would cause /analyze-image to return 404 during a concurrent request.
                        if (std::filesystem::exists(ctx->finalDir)) {
                            auto oldDir = std::filesystem::path(IMAGES_PATH) / ("." + ctx->artefactName + ".old");
                            if (std::filesystem::exists(oldDir)) std::filesystem::remove_all(oldDir);
                            std::filesystem::rename(ctx->finalDir, oldDir);
                            std::filesystem::rename(ctx->tempDir, ctx->finalDir);
                            std::filesystem::remove_all(oldDir);
                        } else {
                            std::filesystem::rename(ctx->tempDir, ctx->finalDir);
                        }

                        AuditLog::logFileSystemAccess("UPLOAD_ARCHIVE", ctx->finalDir.string(), true, "",
                            "IDP artefact archive streamed and extracted: " + ctx->originalFilename + " -> " + ctx->artefactName);

                        // Write SHA256 sidecar
                        if (!sha256Hex.empty()) {
                            std::filesystem::path sidecarPath = ctx->finalDir;
                            sidecarPath += ".sha256";
                            try {
                                std::ofstream sidecarFile(sidecarPath, std::ios::out | std::ios::trunc);
                                if (sidecarFile.is_open()) {
                                    sidecarFile << sha256Hex << "\n";
                                    sidecarFile.close();
                                    LOG_INFO << "Wrote IDP archive SHA256 sidecar: " << sidecarPath.string();
                                }
                            } catch (const std::exception& e) {
                                LOG_ERROR << "Failed to write IDP SHA256 sidecar: " << e.what();
                            }
                        }

                        // Build success response
                        auto resp = drogon::HttpResponse::newHttpResponse();
                        resp->setStatusCode(drogon::k200OK);
                        resp->setContentTypeCode(drogon::CT_APPLICATION_JSON);
                        Json::Value result;
                        result["success"] = true;
                        result["message"] = "IDP artefact uploaded and extracted successfully";
                        result["filename"] = ctx->artefactName;
                        result["is_idp"] = true;
                        result["renamed"] = false;
                        result["sha256"] = sha256Hex;

                        if (isIdpArtefactDirectory(ctx->finalDir)) {
                            result["analysis"] = analyzeIdpArtefact(ctx->finalDir);
                        }

                        publishProgress("complete");
                        resp->setBody(result.toStyledString());
                        ctx->callback(resp);
                    } else if (ctx->isCompressedImg) {
                        // ---- Compressed .img post-processing ----
                        if (ctx->extractionThread.joinable()) ctx->extractionThread.join();

                        if (!ctx->extractionOk) {
                            LOG_ERROR << "Decompression failed: " << ctx->extractionError;
                            if (!ctx->targetPath.empty()) ::unlink(ctx->targetPath.c_str());
                            publishProgress("error", "Decompression failed: " + ctx->extractionError);
                            auto resp = provisioner::utils::createErrorResponse(
                                ctx->req, "Failed to decompress image: " + ctx->extractionError,
                                ctx->errorCode, "Decompression Error", "DECOMPRESS_ERROR");
                            ctx->callback(resp);
                            return;
                        }

                        // Trim the file to actual decompressed size
                        if (ctx->fd >= 0) {
                            if (::ftruncate(ctx->fd, static_cast<off_t>(ctx->totalBytesWritten)) != 0) {
                                LOG_WARN << "ftruncate failed: " << strerror(errno);
                            }
                            ::close(ctx->fd);
                            ctx->fd = -1;
                        }

                        AuditLog::logFileSystemAccess("UPLOAD", ctx->targetPath, true, "",
                            "Compressed image decompressed: " + ctx->originalFilename + " -> " + ctx->finalFilename);

                        {
                            std::lock_guard<std::mutex> lock(sha256Cache_mutex);
                            sha256Cache.erase(ctx->finalFilename);
                        }

                        // Store the worker-computed SHA256 in the cache directly
                        if (!ctx->workerSha256Result.empty()) {
                            std::lock_guard<std::mutex> lock(sha256Cache_mutex);
                            sha256Cache.insert_or_assign(ctx->finalFilename,
                                SHA256Result(ctx->workerSha256Result, SHA256Status::COMPLETE));
                        }

                        triggerBootImgGeneration(ctx->finalFilename);

                        auto resp = drogon::HttpResponse::newHttpResponse();
                        resp->setStatusCode(drogon::k200OK);
                        resp->setContentTypeCode(drogon::CT_APPLICATION_JSON);
                        Json::Value result;
                        result["success"] = true;
                        result["is_idp"] = false;
                        result["filename"] = ctx->finalFilename;
                        result["renamed"] = (ctx->originalFilename != (ctx->finalFilename));
                        if (ctx->originalFilename != ctx->finalFilename) result["original_filename"] = ctx->originalFilename;
                        result["message"] = "Compressed image uploaded and decompressed successfully";
                        result["sha256"] = ctx->workerSha256Result.empty() ? "Calculating..." : ctx->workerSha256Result;
                        publishProgress("complete");
                        resp->setBody(result.toStyledString());
                        ctx->callback(resp);
                    } else {
                        // ---- .img post-processing ----
                        AuditLog::logFileSystemAccess("UPLOAD", ctx->targetPath, true, "",
                            "Original filename: " + ctx->originalFilename +
                            (ctx->originalFilename != ctx->finalFilename ? ", renamed to: " + ctx->finalFilename : ""));

                        {
                            std::lock_guard<std::mutex> lock(sha256Cache_mutex);
                            sha256Cache.erase(ctx->finalFilename);
                        }

                        requestSHA256Calculation(ctx->finalFilename);
                        triggerBootImgGeneration(ctx->finalFilename);

                        auto resp = drogon::HttpResponse::newHttpResponse();
                        resp->setStatusCode(drogon::k200OK);
                        resp->setContentTypeCode(drogon::CT_APPLICATION_JSON);
                        Json::Value result;
                        result["success"] = true;
                        result["is_idp"] = false;
                        result["filename"] = ctx->finalFilename;
                        result["renamed"] = (ctx->originalFilename != ctx->finalFilename);
                        if (ctx->originalFilename != ctx->finalFilename) result["original_filename"] = ctx->originalFilename;
                        result["message"] = result["renamed"].asBool()
                            ? "File uploaded successfully (renamed to avoid conflict)"
                            : "File uploaded successfully";
                        result["sha256"] = sha256Hex.empty() ? "Calculating..." : sha256Hex;
                        resp->setBody(result.toStyledString());
                        ctx->callback(resp);
                    }
                }
            );

            stream->setStreamReader(std::move(reader));
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

        // Analyze an image: returns type (traditional or IDP) and metadata for IDP artefacts
        app.registerHandler("/analyze-image", [](const drogon::HttpRequestPtr &req, std::function<void(const drogon::HttpResponsePtr &)> &&callback) {
            LOG_INFO << "Images::analyzeImage";
            AuditLog::logHandlerAccess(req, "/analyze-image");

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
                    "The requested image was not found",
                    drogon::k404NotFound,
                    "Image Not Found",
                    "IMAGE_NOT_FOUND",
                    "Requested image: " + imageName
                );
                callback(resp);
                return;
            }

            Json::Value result;
            result["name"] = imageName;

            if (std::filesystem::is_directory(imagePath) && isIdpArtefactDirectory(imagePath)) {
                // IDP artefact directory
                result = analyzeIdpArtefact(imagePath);
                result["name"] = imageName;
                result["path"] = imagePath.string();
            } else if (std::filesystem::is_regular_file(imagePath)) {
                // Traditional .img file
                result["type"] = "traditional";
                result["path"] = imagePath.string();
                try {
                    result["size_bytes"] = static_cast<Json::UInt64>(std::filesystem::file_size(imagePath));
                } catch (...) {}
            } else if (std::filesystem::is_directory(imagePath)) {
                // Directory but not a valid IDP artefact
                result["type"] = "unknown_directory";
                result["error"] = "Directory does not contain exactly one JSON file";
                result["path"] = imagePath.string();
            } else {
                result["type"] = "unknown";
                result["path"] = imagePath.string();
            }

            auto resp = drogon::HttpResponse::newHttpJsonResponse(result);
            callback(resp);
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
                    
                    if (std::filesystem::is_directory(imagePath)) {
                        // IDP artefact directory -- remove recursively
                        std::filesystem::remove_all(imagePath);
                        // Also remove the sidecar .sha256 file if it exists
                        std::filesystem::path sidecarPath = imagePath;
                        sidecarPath += ".sha256";
                        if (std::filesystem::exists(sidecarPath)) {
                            std::filesystem::remove(sidecarPath);
                        }
                        AuditLog::logFileSystemAccess("DELETE", imagePath.string(), true, "", 
                            "IDP artefact directory deleted: " + imageName);
                    } else {
                        std::filesystem::remove(imagePath);
                        // Also remove the sidecar .sha256 file if it exists
                        std::filesystem::path sidecarPath = imagePath;
                        sidecarPath += ".sha256";
                        if (std::filesystem::exists(sidecarPath)) {
                            std::filesystem::remove(sidecarPath);
                        }
                        AuditLog::logFileSystemAccess("DELETE", imagePath.string(), true, "", 
                            "Image file deleted: " + imageName);
                    }
                    
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