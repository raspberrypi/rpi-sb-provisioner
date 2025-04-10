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
#include <future>

#include "images.h"

// WebSocket controller for SHA256 calculations
// Defined outside the provisioner namespace to avoid registration issues
class SHA256WebSocketController : public drogon::WebSocketController<SHA256WebSocketController> {
public:
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
                
                // Check cache first
                {
                    std::lock_guard<std::mutex> lock(provisioner::sha256Cache_mutex);
                    auto it = provisioner::sha256Cache.find(imageName);
                    if (it != provisioner::sha256Cache.end()) {
                        Json::Value response;
                        response["image_name"] = imageName;
                        response["sha256"] = it->second;
                        response["status"] = "complete";
                        wsConnPtr->send(response.toStyledString());
                        return;
                    }
                }
                
                // Send pending response
                Json::Value pendingResponse;
                pendingResponse["image_name"] = imageName;
                pendingResponse["status"] = "pending";
                wsConnPtr->send(pendingResponse.toStyledString());
                
                // Start calculation
                auto future = provisioner::startSHA256Calculation(imageName);
                
                // Handle the result when ready
                drogon::app().getLoop()->runAfter(0.1, [imageName, wsConnPtr, future]() {
                    if (future->wait_for(std::chrono::seconds(0)) == std::future_status::ready) {
                        try {
                            std::string sha256 = future->get();
                            Json::Value response;
                            response["image_name"] = imageName;
                            response["sha256"] = sha256;
                            response["status"] = "complete";
                            wsConnPtr->send(response.toStyledString());
                        } catch (const std::exception& e) {
                            Json::Value response;
                            response["image_name"] = imageName;
                            response["error"] = e.what();
                            response["status"] = "error";
                            wsConnPtr->send(response.toStyledString());
                        }
                    } else {
                        // Check again later
                        drogon::app().getLoop()->runAfter(0.5, [imageName, wsConnPtr, future]() {
                            try {
                                std::string sha256 = future->get();
                                Json::Value response;
                                response["image_name"] = imageName;
                                response["sha256"] = sha256;
                                response["status"] = "complete";
                                wsConnPtr->send(response.toStyledString());
                            } catch (const std::exception& e) {
                                Json::Value response;
                                response["image_name"] = imageName;
                                response["error"] = e.what();
                                response["status"] = "error";
                                wsConnPtr->send(response.toStyledString());
                            }
                        });
                    }
                });
            }
        }
    }
    
    void handleNewConnection(const drogon::HttpRequestPtr& req, const drogon::WebSocketConnectionPtr& wsConnPtr) override {
        LOG_INFO << "New WebSocket connection for SHA256 calculation";
    }
    
    void handleConnectionClosed(const drogon::WebSocketConnectionPtr& wsConnPtr) override {
        LOG_INFO << "WebSocket connection closed";
    }
    
    WS_PATH_LIST_BEGIN
    WS_PATH_ADD("/ws/sha256");
    WS_PATH_LIST_END
};

namespace provisioner {

    namespace {
        const std::string IMAGES_PATH = "/srv/rpi-sb-provisioner/images";
    } // namespace anonymous
    
    // In-memory cache for SHA256 values
    std::unordered_map<std::string, std::string> sha256Cache;
    std::mutex sha256Cache_mutex;
    
    // Active calculations to prevent duplicate work
    std::unordered_map<std::string, std::shared_ptr<std::promise<std::string>>> activeCalculations;
    std::mutex calculationsMutex;
    
    // Calculate SHA256 of a file
    std::string calculateSHA256(const std::filesystem::path& imagePath) {
        constexpr size_t CHUNK_SIZE = 1024 * 1024; // 1MB chunks
        std::vector<unsigned char> buffer(CHUNK_SIZE);
        unsigned char hash[EVP_MAX_MD_SIZE];
        unsigned int hash_len;
        
        EVP_MD_CTX* mdctx = EVP_MD_CTX_new();
        EVP_DigestInit_ex(mdctx, EVP_sha256(), nullptr);
        
        std::ifstream file(imagePath, std::ios::binary);
        while (file) {
            file.read(reinterpret_cast<char*>(buffer.data()), CHUNK_SIZE);
            std::streamsize bytes_read = file.gcount();
            if (bytes_read > 0) {
                EVP_DigestUpdate(mdctx, buffer.data(), bytes_read);
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
        
        return sha256;
    }
    
    // Get SHA256 from cache or calculate it
    std::string getSHA256(const std::string& imageName, bool* calculated = nullptr) {
        std::filesystem::path imagePath(IMAGES_PATH);
        imagePath /= imageName;
        
        if (!std::filesystem::exists(imagePath)) {
            return "file-not-found";
        }
        
        // Check cache first
        {
            std::lock_guard<std::mutex> lock(sha256Cache_mutex);
            auto it = sha256Cache.find(imageName);
            if (it != sha256Cache.end()) {
                if (calculated) *calculated = false;
                return it->second;
            }
        }
        
        // Calculate SHA256
        std::string sha256 = calculateSHA256(imagePath);
        
        // Store in cache
        {
            std::lock_guard<std::mutex> lock(sha256Cache_mutex);
            sha256Cache[imageName] = sha256;
        }
        
        if (calculated) *calculated = true;
        return sha256;
    }
    
    // Start SHA256 calculation in background and return a future
    std::shared_ptr<std::future<std::string>> startSHA256Calculation(const std::string& imageName) {
        std::lock_guard<std::mutex> lock(calculationsMutex);
        
        // Check if calculation is already in progress
        auto it = activeCalculations.find(imageName);
        if (it != activeCalculations.end()) {
            return std::make_shared<std::future<std::string>>(it->second->get_future());
        }
        
        // Start new calculation
        auto promise = std::make_shared<std::promise<std::string>>();
        activeCalculations[imageName] = promise;
        auto future = std::make_shared<std::future<std::string>>(promise->get_future());
        
        // Run calculation in a thread from Drogon's thread pool
        drogon::app().getLoop()->queueInLoop([imageName, promise]() {
            try {
                std::string sha256 = getSHA256(imageName);
                promise->set_value(sha256);
            } catch (const std::exception& e) {
                promise->set_exception(std::current_exception());
            }
            
            // Remove from active calculations
            std::lock_guard<std::mutex> lock(calculationsMutex);
            activeCalculations.erase(imageName);
        });
        
        return future;
    }

    Images::Images()
    {
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
    }

    Images::~Images() = default;

    void Images::registerHandlers(drogon::HttpAppFramework &app)
    {
        // Register WebSocket controller - no need to call registerController explicitly
        // WebSocket controllers are automatically registered via WS_PATH macros
        
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
                try {
                    std::ifstream configFile("/etc/rpi-sb-provisioner/config");
                    std::string line;
                    if (configFile.is_open()) {
                        while (std::getline(configFile, line)) {
                            size_t delimiter_pos = line.find('=');
                            if (delimiter_pos != std::string::npos) {
                                std::string key = line.substr(0, delimiter_pos);
                                if (key == "GOLD_MASTER_OS_FILE") {
                                    currentGoldMaster = line.substr(delimiter_pos + 1);
                                    // Extract just the filename from the full path
                                    std::filesystem::path path(currentGoldMaster);
                                    currentGoldMaster = path.filename().string();
                                    break;
                                }
                            }
                        }
                        configFile.close();
                    }
                } catch (const std::exception& e) {
                    LOG_ERROR << "Failed to read config file: " << e.what();
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

            // Check cache first for immediate response
            bool calculated = false;
            std::string sha256;
            {
                std::lock_guard<std::mutex> lock(sha256Cache_mutex);
                auto it = sha256Cache.find(imageName);
                if (it != sha256Cache.end()) {
                    sha256 = it->second;
                }
            }
            
            auto resp = drogon::HttpResponse::newHttpResponse();
            resp->setStatusCode(drogon::k200OK);
            resp->setContentTypeCode(drogon::CT_APPLICATION_JSON);
            Json::Value result;
            
            if (sha256.empty()) {
                // If not in cache, tell client to use WebSocket
                result["sha256"] = "use-websocket";
                result["message"] = "SHA256 calculation is in progress. Please use WebSocket API for real-time updates.";
                // Start calculation in background
                startSHA256Calculation(imageName);
            } else {
                result["sha256"] = sha256;
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
                startSHA256Calculation(filename);
                
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