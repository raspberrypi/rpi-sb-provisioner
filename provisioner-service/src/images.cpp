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

#include <images.h>

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
        
        // Remove this connection from all image subscriptions
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
    
    WS_PATH_LIST_BEGIN
    WS_PATH_ADD("/ws/sha256");
    WS_PATH_LIST_END
};

// Define static members
std::unordered_map<std::string, std::vector<drogon::WebSocketConnectionPtr>> SHA256WebSocketController::activeConnections;
std::mutex SHA256WebSocketController::connectionsMutex;

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
    
    // Calculate SHA256 of a file
    std::string calculateSHA256(const std::filesystem::path& imagePath, const std::string& imageName) {
        // Use larger chunks (8MB) for better performance with large files
        constexpr size_t CHUNK_SIZE = 8 * 1024 * 1024; 
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
            file.read(reinterpret_cast<char*>(buffer.data()), CHUNK_SIZE);
            std::streamsize bytes_read = file.gcount();
            if (bytes_read > 0) {
                EVP_DigestUpdate(mdctx, buffer.data(), bytes_read);
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
                                
                                sha256Cache.insert_or_assign(imageName, updatedResult);
                                
                                // Broadcast progress update to connected WebSocket clients
                                SHA256WebSocketController::broadcastUpdate(imageName, updatedResult);
                            }
                        }
                    }
                }
            }
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
                        // Calculate SHA256
                        std::string sha256 = calculateSHA256(imagePath, imageName);
                        
                        // Update cache with result
                        std::lock_guard<std::mutex> lock(sha256Cache_mutex);
                        SHA256Result result(sha256, SHA256Status::COMPLETE, false);
                        sha256Cache.insert_or_assign(imageName, result);
                        
                        // Broadcast completion to WebSocket clients
                        SHA256WebSocketController::broadcastUpdate(imageName, result);
                    }
                } catch (const std::exception& e) {
                    // Update cache with error
                    std::lock_guard<std::mutex> lock(sha256Cache_mutex);
                    SHA256Result result(std::string("Error: ") + e.what(), SHA256Status::ERROR, false);
                    sha256Cache.insert_or_assign(imageName, result);
                    
                    // Broadcast error to WebSocket clients
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
                // Mark as pending in the cache with a timestamp
                sha256Cache.insert_or_assign(imageName, SHA256Result("", SHA256Status::PENDING, true));
                LOG_INFO << "Queuing new SHA256 calculation for " << imageName;
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

    Images::Images() {
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
    }

    Images::~Images() {
        // Shutdown the SHA256 worker thread
        shutdownSHA256Worker();
    }

    void Images::registerHandlers(drogon::HttpAppFramework &app)
    {
        // Register WebSocket controller - no need to call registerController explicitly
        // WebSocket controllers are automatically registered via WS_PATH macros
        
        app.registerHandler("/get-image-metadata", [](const drogon::HttpRequestPtr &req, std::function<void(const drogon::HttpResponsePtr &)> &&callback) {
            LOG_INFO << "Images::get-image-metadata";
            
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

            std::vector<ImageInfo> imageInfos;
            
            LOG_INFO << "Scanning directory: " << IMAGES_PATH;
            for (const auto &entry : std::filesystem::directory_iterator(IMAGES_PATH)) {
                LOG_INFO << "Found entry: " << entry.path().string();
                if (entry.is_regular_file()) {
                    std::filesystem::path imagePath = entry.path();
                    ImageInfo info;
                    info.name = imagePath.filename().string();
                    info.sha256 = "use-websocket"; // Indicate client should use WebSocket
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

        app.registerHandler("/get-image-sha256", [](const drogon::HttpRequestPtr &req, std::function<void(const drogon::HttpResponsePtr &)> &&callback) {
            LOG_INFO << "Images::get-image-sha256";

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
                // If not in cache or pending, tell client to use WebSocket
                result["sha256"] = "use-websocket";
                result["message"] = "SHA256 calculation is in progress. Please use WebSocket API for real-time updates.";
                // Include progress if available
                if (progress > 0) {
                    result["progress"] = progress;
                    result["progress_percent"] = static_cast<int>(progress * 100);
                }
                
                // Start calculation in background if it's not already in progress
                requestSHA256Calculation(imageName);
            } else {
                result["sha256"] = sha256;
                result["status"] = (status == SHA256Status::COMPLETE) ? "complete" : "error";
            }
            
            resp->setBody(result.toStyledString());
            callback(resp);
        });

        app.registerHandler("/upload-image", [](const drogon::HttpRequestPtr &req, std::function<void(const drogon::HttpResponsePtr &)> &&callback) {
            LOG_INFO << "Images::uploadImage";
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
            std::string filename = file.getFileName();
            
            // Create target path
            std::filesystem::path targetPath("/srv/rpi-sb-provisioner/images");
            targetPath /= filename;

            try {
                // Move uploaded file to target location
                file.saveAs(targetPath);
                
                // Start SHA256 calculation in the background
                requestSHA256Calculation(filename);
                
                // Set success response with JSON payload
                resp->setStatusCode(drogon::k200OK);
                resp->setContentTypeCode(drogon::CT_APPLICATION_JSON);
                Json::Value result;
                result["success"] = true;
                result["message"] = "File uploaded successfully";
                result["filename"] = filename;
                result["sha256"] = "use-websocket"; // Hint to use WebSocket for SHA256
                resp->setBody(result.toStyledString());
            } catch (const std::exception& e) {
                LOG_ERROR << "Failed to save uploaded file: " << e.what();
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

        app.registerHandler("/delete-image", [](const drogon::HttpRequestPtr &req, std::function<void(const drogon::HttpResponsePtr &)> &&callback) {
            LOG_INFO << "Images::deleteImage";
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
                    std::filesystem::remove(imagePath);
                    
                    // Remove from SHA256 cache
                    {
                        std::lock_guard<std::mutex> lock(sha256Cache_mutex);
                        sha256Cache.erase(imageName);
                    }
                    
                    resp->setStatusCode(drogon::k200OK);
                    callback(resp);
                    return;
                } catch (const std::filesystem::filesystem_error& e) {
                    LOG_ERROR << "Failed to delete image: " << e.what();
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