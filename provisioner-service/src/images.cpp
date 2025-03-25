#include <drogon/drogon.h>
#include <drogon/HttpAppFramework.h>
#include <drogon/HttpResponse.h>
#include <drogon/HttpTypes.h>
#include <drogon/HttpController.h>
#include <drogon/HttpSimpleController.h>
#include <drogon/HttpTypes.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>

#include <filesystem>
#include <string>
#include <vector>
#include <fstream>
#include <sstream>
#include <iomanip>
#include <openssl/evp.h>

#include "images.h"

namespace provisioner {

    namespace {
        const std::string IMAGES_PATH = "/srv/rpi-sb-provisioner/images";
    } // namespace anonymous

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
        app.registerHandler("/get-images", [](const HttpRequestPtr &req, std::function<void(const HttpResponsePtr &)> &&callback) {
            LOG_INFO << "Images::get-images";

            std::vector<ImageInfo> imageInfos;
            
            LOG_INFO << "Scanning directory: " << IMAGES_PATH;
            for (const auto &entry : std::filesystem::directory_iterator(IMAGES_PATH)) {
                LOG_INFO << "Found entry: " << entry.path().string();
                if (entry.is_regular_file()) {
                    std::filesystem::path imagePath = entry.path();
                    ImageInfo info;
                    info.name = imagePath.filename().string();
                    info.sha256 = "Calculating..."; // Placeholder for async calculation
                    imageInfos.push_back(info);
                    LOG_INFO << "Added image: " << info.name;
                }
            }
            
            LOG_INFO << "Total images found: " << imageInfos.size();
            
            auto resp = HttpResponse::newHttpResponse();
            
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

                HttpViewData viewData;
                std::vector<std::map<std::string, std::string>> imageMaps;
                for (const auto& info : imageInfos) {
                    std::map<std::string, std::string> imageMap;
                    imageMap["name"] = info.name;
                    imageMap["sha256"] = info.sha256;
                    imageMap["is_gold_master"] = (info.name == currentGoldMaster) ? "true" : "false";
                    imageMaps.push_back(imageMap);
                }
                viewData.insert("images", imageMaps);
                LOG_INFO << "View data populated with " << imageMaps.size() << " images";
                resp = HttpResponse::newHttpViewResponse("images.csp", viewData);
            } else {
                LOG_INFO << "JSON response requested";
                Json::Value imageArray(Json::arrayValue);
                for (const auto& info : imageInfos) {
                    Json::Value imageObj;
                    imageObj["name"] = info.name;
                    imageObj["sha256"] = info.sha256;
                    imageArray.append(imageObj);
                }
                resp->setStatusCode(k200OK);
                resp->setContentTypeCode(CT_APPLICATION_JSON);
                resp->setBody(imageArray.toStyledString());
            }
            
            callback(resp);
        });

        app.registerHandler("/get-image-sha256", [](const HttpRequestPtr &req, std::function<void(const HttpResponsePtr &)> &&callback) {
            LOG_INFO << "Images::get-image-sha256";
            auto resp = HttpResponse::newHttpResponse();

            // Get the image name from the request
            std::string imageName = req->getParameter("name");
            if (imageName.empty()) {
                resp->setStatusCode(k400BadRequest);
                resp->setBody("Image name is required");
                callback(resp);
                return;
            }

            std::filesystem::path imagePath(IMAGES_PATH);
            imagePath /= imageName;

            if (!std::filesystem::exists(imagePath)) {
                resp->setStatusCode(k404NotFound);
                resp->setBody("Image not found");
                callback(resp);
                return;
            }

            // Calculate SHA256 of file in chunks
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
            std::memset(hash, 0, EVP_MAX_MD_SIZE);
            
            resp->setStatusCode(k200OK);
            resp->setContentTypeCode(CT_APPLICATION_JSON);
            Json::Value result;
            result["sha256"] = ss.str();
            resp->setBody(result.toStyledString());
            
            callback(resp);
        });

        app.registerHandler("/upload-image", [](const HttpRequestPtr &req, std::function<void(const HttpResponsePtr &)> &&callback) {
            LOG_INFO << "Images::uploadImage";
            auto resp = HttpResponse::newHttpResponse();

            // Get the file from the request
            MultiPartParser parser;
            if (parser.parse(req) != 0 || parser.getFiles().size() != 1) {
                resp->setStatusCode(k400BadRequest);
                resp->setBody("Invalid request");
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
                resp->setStatusCode(k200OK);
            } catch (const std::exception& e) {
                LOG_ERROR << "Failed to save uploaded file: " << e.what();
                resp->setStatusCode(k500InternalServerError);
                resp->setBody("Failed to save file");
                callback(resp);
                return;
            }

            callback(resp);
        });

        app.registerHandler("/delete-image", [](const HttpRequestPtr &req, std::function<void(const HttpResponsePtr &)> &&callback) {
            LOG_INFO << "Images::deleteImage";
            auto resp = HttpResponse::newHttpResponse();

            // Get the image name from the request
            std::string imageName = req->getParameter("name");
            if (imageName.empty()) {
                resp->setStatusCode(k400BadRequest);
                resp->setBody("Image name is required");
                callback(resp);
                return;
            }
            
            std::filesystem::path imagePath(IMAGES_PATH);
            imagePath /= imageName;

            if (std::filesystem::exists(imagePath)) {
                try {
                    std::filesystem::remove(imagePath);
                    resp->setStatusCode(k200OK);
                } catch (const std::filesystem::filesystem_error& e) {
                    LOG_ERROR << "Failed to delete image: " << e.what();
                    resp->setStatusCode(k500InternalServerError);
                    resp->setBody("Failed to delete image");
                }
            } else {
                LOG_ERROR << "Image not found: " << imagePath;
                resp->setStatusCode(k404NotFound);
                resp->setBody("Image not found");
            }

            callback(resp);
        });
    }
} // namespace provisioner