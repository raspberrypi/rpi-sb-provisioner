#include <drogon/HttpResponse.h>
#include <drogon/HttpAppFramework.h>
#include <devices.h>
#include <sqlite3.h>
#include <json/json.h>
#include <fstream>
#include <sstream>
#include <systemd/sd-bus.h>

using namespace drogon;

namespace provisioner {

    struct Device {
        std::string serial;
        std::string port;
        std::string ip_address;
        std::string state;
        std::string image;
    };

    struct DeviceList {
        std::vector<Device> devices;
    };

    Devices::Devices() 
        :
        systemd_bus(nullptr, sd_bus_unref)
    {
        sd_bus* bus = nullptr;
        int ret = sd_bus_default_system(&bus);
        if (ret < 0) {
            throw std::runtime_error("Failed to connect to system bus: " + std::string(strerror(-ret)));
        }
        systemd_bus = std::unique_ptr<sd_bus, decltype(&sd_bus_unref)>(bus, sd_bus_unref);
    }

    Devices::~Devices() = default;

    void Devices::registerHandlers(drogon::HttpAppFramework &app)
    {
        app.registerHandler("/devices", [](const HttpRequestPtr &req, std::function<void(const HttpResponsePtr &)> &&callback) {
            auto devices = std::make_unique<DeviceList>();
            auto resp = HttpResponse::newHttpResponse();

            sqlite3* db;
            int rc = sqlite3_open("/srv/rpi-sb-provisioner/state.db", &db);
            if (rc) {
                auto errorMsg = "Failed to open database: " + std::string(sqlite3_errmsg(db));
                
                // Check if the client accepts HTML
                auto acceptHeader = req->getHeader("Accept");
                if (!acceptHeader.empty() && (acceptHeader.find("text/html") != std::string::npos)) {
                    HttpViewData viewData;
                    viewData.insert("currentPage", std::string("devices"));
                    viewData.insert("warning", errorMsg);
                    resp = HttpResponse::newHttpViewResponse("devices.csp", viewData);
                } else {
                    resp->setStatusCode(k500InternalServerError);
                    resp->setBody(errorMsg);
                }
                
                callback(resp);
                return;
            }

            std::vector<std::string> serials;
            sqlite3_stmt* stmt;
            const char* sql = "SELECT serial, endpoint, state, image, ip_address FROM devices ORDER BY ts DESC";
            LOG_INFO << "Executing SQL: " << sql;
            rc = sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr);

            if (rc != SQLITE_OK) {
                auto errorMsg = "Failed to prepare SQL statement: " + std::string(sqlite3_errmsg(db));
                LOG_ERROR << errorMsg;
                sqlite3_close(db);
                
                // Check if the client accepts HTML
                auto acceptHeader = req->getHeader("Accept");
                if (!acceptHeader.empty() && (acceptHeader.find("text/html") != std::string::npos)) {
                    HttpViewData viewData;
                    viewData.insert("currentPage", std::string("devices"));
                    viewData.insert("warning", errorMsg);
                    resp = HttpResponse::newHttpViewResponse("devices.csp", viewData);
                } else {
                    resp->setStatusCode(k500InternalServerError);
                    resp->setBody(errorMsg);
                }
                
                callback(resp);
                return;
            }

            while (sqlite3_step(stmt) == SQLITE_ROW) {
                const unsigned char* serial = sqlite3_column_text(stmt, 0);
                const unsigned char* endpoint = sqlite3_column_text(stmt, 1);
                const unsigned char* state = sqlite3_column_text(stmt, 2);
                const unsigned char* image = sqlite3_column_text(stmt, 3);
                const unsigned char* ip_address = sqlite3_column_text(stmt, 4);
                
                LOG_INFO << "Found device: " << (const char*)serial << ", " << (const char*)endpoint << ", " << (const char*)state;
                
                devices->devices.push_back({
                    (const char*)serial, 
                    (const char*)endpoint, 
                    (const char*)ip_address,
                    (const char*)state,
                    (const char*)image
                });
            }

            sqlite3_finalize(stmt);
            sqlite3_close(db);

            // Check if the client accepts HTML
            auto acceptHeader = req->getHeader("Accept");
            if (!acceptHeader.empty() && (acceptHeader.find("text/html") != std::string::npos)) {
                LOG_INFO << "HTML response requested";

                HttpViewData viewData;
                std::vector<std::map<std::string, std::string>> devicesList;
                for (const auto& device : devices->devices) {
                    std::map<std::string, std::string> deviceMap;
                    deviceMap["serial"] = device.serial;
                    deviceMap["port"] = device.port;
                    deviceMap["ip_address"] = device.ip_address;
                    deviceMap["state"] = device.state;
                    deviceMap["image"] = device.image;
                    devicesList.push_back(deviceMap);
                }
                viewData.insert("devices", devicesList);
                viewData.insert("currentPage", std::string("devices"));
                resp = HttpResponse::newHttpViewResponse("devices.csp", viewData);
            } else {
                // JSON response for API clients
                LOG_INFO << "JSON response requested";
                resp->setStatusCode(k200OK);
                resp->setContentTypeCode(CT_APPLICATION_JSON);

                Json::Value root;
                Json::Value deviceArray(Json::arrayValue);
                for (const auto& device : devices->devices) {
                    Json::Value deviceObj;
                    deviceObj["serial"] = device.serial;
                    deviceObj["port"] = device.port;
                    deviceObj["ip_address"] = device.ip_address;
                    deviceObj["state"] = device.state;
                    deviceObj["image"] = device.image;
                    deviceArray.append(deviceObj);
                }
                root["devices"] = deviceArray;

                Json::FastWriter writer;
                std::string jsonString = writer.write(root);
                resp->setBody(jsonString);
            }

            callback(resp);
        }); // devices handler

        app.registerHandler("/devices/:serialno", [](const HttpRequestPtr &req, std::function<void(const HttpResponsePtr &)> &&callback) {
            auto resp = HttpResponse::newHttpResponse();
            auto serialno = req->getParameter("serialno");
            if (serialno.empty()) {
                resp->setStatusCode(k400BadRequest);
                resp->setBody("Serial number is required");
                callback(resp);
                return;
            }

            sqlite3* db;
            int rc = sqlite3_open("/srv/rpi-sb-provisioner/state.db", &db);
            if (rc) {
                resp->setStatusCode(k500InternalServerError);
                resp->setBody("Failed to open database");
                callback(resp);
                return;
            }

            sqlite3_stmt* stmt;
            const char* sql = "SELECT serial, endpoint, state, image, ip_address FROM devices WHERE serial = ?";
            rc = sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr);

            if (rc != SQLITE_OK) {
                sqlite3_close(db);
                resp->setStatusCode(k500InternalServerError);
                resp->setBody("Failed to prepare SQL statement");
                callback(resp);
                return;
            }

            sqlite3_bind_text(stmt, 1, serialno.c_str(), -1, SQLITE_STATIC);

            if (sqlite3_step(stmt) != SQLITE_ROW) {
                sqlite3_finalize(stmt);
                sqlite3_close(db);
                resp->setStatusCode(k404NotFound);
                resp->setBody("Device not found");
                callback(resp);
                return;
            }

            const unsigned char* serial = sqlite3_column_text(stmt, 0);
            const unsigned char* endpoint = sqlite3_column_text(stmt, 1);
            const unsigned char* state = sqlite3_column_text(stmt, 2);
            const unsigned char* image = sqlite3_column_text(stmt, 3);
            const unsigned char* ip_address = sqlite3_column_text(stmt, 4);

            Device device;
            device.serial = (const char*)serial;
            device.port = (const char*)endpoint;
            device.ip_address = (const char*)ip_address;
            device.state = (const char*)state;
            device.image = (const char*)image;

            sqlite3_finalize(stmt);
            sqlite3_close(db);

            // Check if the client accepts HTML
            auto acceptHeader = req->getHeader("Accept");
            if (!acceptHeader.empty() && (acceptHeader.find("text/html") != std::string::npos)) {
                // Read log files
                std::string provisioner_log, bootstrap_log, triage_log;
                
                std::string logPath = "/var/log/rpi-sb-provisioner/" + device.serial + "/provisioner.log";
                std::ifstream provisionerFile(logPath);
                if (provisionerFile.is_open()) {
                    std::stringstream buffer;
                    buffer << provisionerFile.rdbuf();
                    provisioner_log = buffer.str();
                }

                logPath = "/var/log/rpi-sb-provisioner/" + device.serial + "/bootstrap.log";
                std::ifstream bootstrapFile(logPath);
                if (bootstrapFile.is_open()) {
                    std::stringstream buffer;
                    buffer << bootstrapFile.rdbuf();
                    bootstrap_log = buffer.str();
                }

                logPath = "/var/log/rpi-sb-provisioner/" + device.serial + "/triage.log";
                std::ifstream triageFile(logPath);
                if (triageFile.is_open()) {
                    std::stringstream buffer;
                    buffer << triageFile.rdbuf();
                    triage_log = buffer.str();
                }

                HttpViewData viewData;
                viewData.insert("device", device);
                viewData.insert("provisioner_log", provisioner_log);
                viewData.insert("bootstrap_log", bootstrap_log);
                viewData.insert("triage_log", triage_log);
                viewData.insert("currentPage", std::string("devices"));
                resp = HttpResponse::newHttpViewResponse("device_detail.csp", viewData);
            } else {
                Json::Value root;
                root["serial"] = device.serial;
                root["port"] = device.port;
                root["state"] = device.state;

                Json::FastWriter writer;
                std::string jsonString = writer.write(root);
                resp->setStatusCode(k200OK);
                resp->setContentTypeCode(CT_APPLICATION_JSON);
                resp->setBody(jsonString);
            }

            callback(resp);
        }); // serial-specific handler

        app.registerHandler("/devices/:serialno/log/provisioner", [](const HttpRequestPtr &req, std::function<void(const HttpResponsePtr &)> &&callback) {
            auto resp = HttpResponse::newHttpResponse();
            auto serialno = req->getParameter("serialno");
            if (serialno.empty()) {
                resp->setStatusCode(k400BadRequest);
                resp->setBody("Serial number is required");
                callback(resp);
                return;
            }

            std::string logPath = "/var/log/rpi-sb-provisioner/" + serialno + "/provisioner.log";
            std::ifstream logFile(logPath);
            if (!logFile.is_open()) {
                resp->setStatusCode(k404NotFound);
                resp->setBody("Log file not found");
                callback(resp);
                return;
            }

            std::stringstream buffer;
            buffer << logFile.rdbuf();
            resp->setStatusCode(k200OK);
            resp->setContentTypeCode(CT_TEXT_PLAIN);
            resp->setBody(buffer.str());
            callback(resp);
        }); // devices/:serialno/log/provisioner handler

        app.registerHandler("/devices/:serialno/log/bootstrap", [](const HttpRequestPtr &req, std::function<void(const HttpResponsePtr &)> &&callback) {
            auto resp = HttpResponse::newHttpResponse();
            auto serialno = req->getParameter("serialno");
            if (serialno.empty()) {
                resp->setStatusCode(k400BadRequest);
                resp->setBody("Serial number is required");
                callback(resp);
                return;
            }

            std::string logPath = "/var/log/rpi-sb-provisioner/" + serialno + "/bootstrap.log";
            std::ifstream logFile(logPath);
            if (!logFile.is_open()) {
                resp->setStatusCode(k404NotFound);
                resp->setBody("Log file not found");
                callback(resp);
                return;
            }

            std::stringstream buffer;
            buffer << logFile.rdbuf();
            resp->setStatusCode(k200OK);
            resp->setContentTypeCode(CT_TEXT_PLAIN);
            resp->setBody(buffer.str());
            callback(resp);
        }); // devices/:serialno/log/bootstrap handler

        app.registerHandler("/devices/:serialno/log/triage", [](const HttpRequestPtr &req, std::function<void(const HttpResponsePtr &)> &&callback) {
            auto resp = HttpResponse::newHttpResponse();
            auto serialno = req->getParameter("serialno");
            if (serialno.empty()) {
                resp->setStatusCode(k400BadRequest);
                resp->setBody("Serial number is required");
                callback(resp);
                return;
            }

            std::string logPath = "/var/log/rpi-sb-provisioner/" + serialno + "/triage.log";
            std::ifstream logFile(logPath);
            if (!logFile.is_open()) {
                resp->setStatusCode(k404NotFound);
                resp->setBody("Log file not found");
                callback(resp);
                return;
            }

            std::stringstream buffer;
            buffer << logFile.rdbuf();
            resp->setStatusCode(k200OK);
            resp->setContentTypeCode(CT_TEXT_PLAIN);
            resp->setBody(buffer.str());
            callback(resp);
        }); // devices/:serialno/log/triage handler

        app.registerHandler("/devices/:serialno/key/public", [](const HttpRequestPtr &req, std::function<void(const HttpResponsePtr &)> &&callback) {
            auto resp = HttpResponse::newHttpResponse();
            auto serialno = req->getParameter("serialno");
            if (serialno.empty()) {
                resp->setStatusCode(k400BadRequest);
                resp->setBody("Serial number is required");
                callback(resp);
                return;
            }

            std::string keyPath = "/var/log/rpi-sb-provisioner/" + serialno + "/keypair/" + serialno + ".pub";
            std::ifstream keyFile(keyPath);
            if (!keyFile.is_open()) {
                resp->setStatusCode(k404NotFound);
                resp->setBody("Key file not found");
                callback(resp);
                return;
            }

            std::stringstream buffer;
            buffer << keyFile.rdbuf();
            resp->setContentTypeCode(CT_APPLICATION_OCTET_STREAM);
            resp->setStatusCode(k200OK);
            resp->setBody(buffer.str());
            callback(resp);
        }); // devices/:serialno/key/public handler

        app.registerHandler("/devices/:serialno/key/private", [](const HttpRequestPtr &req, std::function<void(const HttpResponsePtr &)> &&callback) {
            auto resp = HttpResponse::newHttpResponse();
            auto serialno = req->getParameter("serialno");
            if (serialno.empty()) {
                resp->setStatusCode(k400BadRequest);
                resp->setBody("Serial number is required");
                callback(resp);
                return;
            }

            std::string keyPath = "/var/log/rpi-sb-provisioner/" + serialno + "/keypair/" + serialno + ".der";
            std::ifstream keyFile(keyPath);
            if (!keyFile.is_open()) {
                resp->setStatusCode(k404NotFound);
                resp->setBody("Key file not found");
                callback(resp);
                return;
            }

            std::stringstream buffer;
            buffer << keyFile.rdbuf();
            resp->setStatusCode(k200OK);
            resp->setContentTypeCode(CT_APPLICATION_OCTET_STREAM);
            resp->setBody(buffer.str());
            callback(resp);
        }); // devices/:serialno/key/private handler
    }

    
} // namespace provisioner

