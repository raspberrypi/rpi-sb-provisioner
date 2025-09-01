#include <drogon/HttpResponse.h>
#include <drogon/HttpAppFramework.h>
#include <drogon/WebSocketController.h>
#include <devices.h>
#include <sqlite3.h>
#include <json/json.h>
#include <fstream>
#include <sstream>
#include <systemd/sd-bus.h>
#include <filesystem>
#include <unordered_map>
#include <set>
#include <thread>
#include <mutex>
#include <atomic>
#include <chrono>
#include <algorithm>
#include <cctype>
#include "utils.h"
#include "include/audit.h"

using namespace drogon;

// Forward declare snapshot helper accessible to other scopes in this TU
namespace provisioner { std::string getTopologySnapshotString(); }

// WebSocket controller for device topology streaming
class DevicesWebSocketController : public drogon::WebSocketController<DevicesWebSocketController> {
public:
    static std::vector<drogon::WebSocketConnectionPtr> subscribers;
    static std::mutex subscribersMutex;

    static void broadcast(const std::string &message) {
        std::lock_guard<std::mutex> lock(subscribersMutex);
        auto it = subscribers.begin();
        while (it != subscribers.end()) {
            if ((*it)->connected()) {
                (*it)->send(message);
                ++it;
            } else {
                it = subscribers.erase(it);
            }
        }
    }

    void handleNewMessage(const drogon::WebSocketConnectionPtr& wsConnPtr, std::string&& message, const drogon::WebSocketMessageType& type) override {
        // No-op for now; could support subscription filters later
        (void)wsConnPtr; (void)message; (void)type;
    }

    void handleNewConnection(const drogon::HttpRequestPtr& req, const drogon::WebSocketConnectionPtr& wsConnPtr) override {
        (void)req;
        {
            std::lock_guard<std::mutex> lock(subscribersMutex);
            subscribers.push_back(wsConnPtr);
        }
        // Send initial snapshot
        wsConnPtr->send(provisioner::getTopologySnapshotString());
    }

    void handleConnectionClosed(const drogon::WebSocketConnectionPtr& wsConnPtr) override {
        std::lock_guard<std::mutex> lock(subscribersMutex);
        subscribers.erase(std::remove(subscribers.begin(), subscribers.end(), wsConnPtr), subscribers.end());
    }

    WS_PATH_LIST_BEGIN
    WS_PATH_ADD("/ws/devices");
    WS_PATH_LIST_END
};

std::vector<drogon::WebSocketConnectionPtr> DevicesWebSocketController::subscribers;
std::mutex DevicesWebSocketController::subscribersMutex;

// (removed incorrect forward declaration of anonymous-namespace function)

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

    // Representation of a USB node (hub or device)
    struct UsbNode {
        std::string id;          // unique path id (e.g. 1-1.4)
        std::string parentId;    // parent path id or empty for root
        std::string vendor;      // idVendor
        std::string product;     // idProduct
        std::string serial;      // serial (if available)
        bool isHub{false};
        // Optional provisioning info
        std::string state;
        std::string image;
        std::string ip;
        int portCount{0};        // number of ports if hub (from maxchild)
        bool isPlaceholder{false};
    };

    // Tracker state
    namespace {
        std::thread topologyThread;
        std::atomic<bool> topologyRunning{false};
        std::mutex topologyMutex;
        // Map id -> node
        std::unordered_map<std::string, UsbNode> currentTopology;
        // App start time in milliseconds since epoch; used to ignore stale DB rows
        std::atomic<long long> appStartMs{0};

        std::string readFileTrimmed(const std::filesystem::path &p) {
            try {
                std::ifstream f(p);
                if (!f.is_open()) return "";
                std::string s;
                std::getline(f, s);
                while (!s.empty() && (s.back()=='\n' || s.back()=='\r' || s.back()=='\t' || s.back()==' ')) s.pop_back();
                return s;
            } catch (...) { return ""; }
        }

        std::string baseDeviceDirName(const std::string &name) {
            // Strip interface suffix after ':' (e.g. 1-1.2:1.0 -> 1-1.2)
            auto pos = name.find(':');
            if (pos != std::string::npos) return name.substr(0, pos);
            return name;
        }

        std::string computeParentId(const std::string &id) {
            // Parent is prefix before last '.' if present, otherwise attach to server
            auto pos = id.rfind('.');
            if (pos != std::string::npos) {
                return id.substr(0, pos);
            }
            // If id contains '-' treat as directly connected to server
            return "server";
        }

        std::unordered_map<std::string, UsbNode> scanUsbSysfs() {
            std::unordered_map<std::string, UsbNode> nodes;
            // Always include the server root node
            UsbNode server;
            server.id = "server";
            server.parentId = "";
            server.isHub = true;
            server.vendor = "Provisioner";
            server.product = "Server";
            nodes.insert({server.id, server});

            const std::filesystem::path usbPath("/sys/bus/usb/devices");
            if (!std::filesystem::exists(usbPath)) {
                return nodes;
            }

            for (const auto &entry : std::filesystem::directory_iterator(usbPath)) {
                if (!entry.is_directory()) continue;
                const std::string name = entry.path().filename().string();
                if (name.find('-') == std::string::npos) continue; // skip non-device entries like usb1
                const bool isInterface = (name.find(':') != std::string::npos);
                const std::string id = baseDeviceDirName(name);

                // Create or get existing node by base id
                UsbNode &node = nodes[id];
                if (node.id.empty()) {
                    node.id = id;
                    node.parentId = computeParentId(id);
                }

                const std::filesystem::path baseDir = usbPath / id;

                // Populate from device directory when available
                if (!isInterface) {
                    const std::string v = readFileTrimmed(entry.path()/"idVendor");
                    const std::string p = readFileTrimmed(entry.path()/"idProduct");
                    if (!v.empty()) node.vendor = v;
                    if (!p.empty()) node.product = p;
                    const std::string s = readFileTrimmed(entry.path()/"serial");
                    if (!s.empty()) node.serial = s;
                }

                // Detect hubs via either device or interface class files
                const std::string bDeviceClass = std::filesystem::exists(entry.path()/"bDeviceClass")
                    ? readFileTrimmed(entry.path()/"bDeviceClass")
                    : (std::filesystem::exists(baseDir/"bDeviceClass") ? readFileTrimmed(baseDir/"bDeviceClass") : "");
                const std::string bInterfaceClass = std::filesystem::exists(entry.path()/"bInterfaceClass")
                    ? readFileTrimmed(entry.path()/"bInterfaceClass")
                    : (std::filesystem::exists(baseDir/"bInterfaceClass") ? readFileTrimmed(baseDir/"bInterfaceClass") : "");
                if (bDeviceClass == "09" || bDeviceClass == "9" || bDeviceClass == "0x09" ||
                    bInterfaceClass == "09" || bInterfaceClass == "9" || bInterfaceClass == "0x09") {
                    node.isHub = true;
                }

                // Read maxchild from whichever location provides it
                for (const auto &dir : {entry.path(), baseDir}) {
                    std::error_code ec;
                    const auto path = dir/"maxchild";
                    if (std::filesystem::exists(path, ec)) {
                        const std::string mc = readFileTrimmed(path);
                        if (!mc.empty()) {
                            try { node.portCount = std::max(node.portCount, std::stoi(mc)); } catch (...) {}
                        }
                    }
                }

                // On this platform, root hubs expose child ports as usbX-portN directories under the interface dir
                if (isInterface && id.size() >= 2 && id.rfind("-0") == id.size() - 2) {
                    for (const auto &child : std::filesystem::directory_iterator(entry.path())) {
                        const std::string childName = child.path().filename().string();
                        // Match pattern: usb<bus>-port<idx>
                        auto dashPos = childName.find("-port");
                        if (dashPos == std::string::npos) continue;
                        // Extract trailing number after "-port"
                        const std::string portStr = childName.substr(dashPos + 5);
                        try {
                            int portNum = std::stoi(portStr);
                            if (portNum > node.portCount) node.portCount = portNum;
                        } catch (...) {
                            // ignore non-numeric suffixes
                        }
                    }
                }
            }

            // Add placeholder entries for unconnected hub ports
            std::vector<UsbNode> placeholders;
            for (const auto &p : nodes) {
                const UsbNode &hub = p.second;
                if (!hub.isHub || hub.portCount <= 0) continue;
                const bool isRootHub = (hub.id.size() >= 2 && hub.id.rfind("-0") == hub.id.size() - 2);
                for (int i = 1; i <= hub.portCount; ++i) {
                    std::string childId;
                    std::string parentId;
                    if (isRootHub) {
                        // Root hub children use pattern "<bus>-<port>", and attach directly to server
                        const std::string busPrefix = hub.id.substr(0, hub.id.size() - 2);
                        childId = busPrefix + "-" + std::to_string(i);
                        parentId = "server";
                    } else {
                        childId = hub.id + "." + std::to_string(i);
                        parentId = hub.id;
                    }
                    if (nodes.find(childId) != nodes.end()) continue;
                    UsbNode ph;
                    ph.id = childId;
                    ph.parentId = parentId;
                    ph.isHub = false;
                    // Leave vendor/product empty; UI will render as placeholder by id
                    ph.serial = "";
                    ph.state = "";
                    ph.image = "";
                    ph.ip = "";
                    ph.isPlaceholder = true;
                    placeholders.push_back(std::move(ph));
                }
            }
            for (const auto &ph : placeholders) {
                nodes.insert_or_assign(ph.id, ph);
            }

            return nodes;
        }

        void enrichWithProvisioningState(std::unordered_map<std::string, UsbNode> &nodes) {
            // Build latest record per endpoint (descending ts ensures first seen is newest)
            struct DbRecord { std::string serial, state, image, ip; };
            std::unordered_map<std::string, DbRecord> latestByEndpoint;

            sqlite3* db;
            int rc = sqlite3_open("/srv/rpi-sb-provisioner/state.db", &db);
            if (rc) {
                return;
            }
            const char* sql = "SELECT serial, endpoint, state, image, ip_address FROM devices WHERE ts >= ? ORDER BY ts DESC";
            sqlite3_stmt* stmt;
            rc = sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr);
            if (rc != SQLITE_OK) {
                sqlite3_close(db);
                return;
            }
            // Bind application start time (milliseconds)
            sqlite3_bind_int64(stmt, 1, static_cast<sqlite3_int64>(appStartMs.load()));
            while (sqlite3_step(stmt) == SQLITE_ROW) {
                const unsigned char* serial = sqlite3_column_text(stmt, 0);
                const unsigned char* endpoint = sqlite3_column_text(stmt, 1);
                const unsigned char* state = sqlite3_column_text(stmt, 2);
                const unsigned char* image = sqlite3_column_text(stmt, 3);
                const unsigned char* ip = sqlite3_column_text(stmt, 4);
                if (!endpoint) continue;
                std::string endpointStr = reinterpret_cast<const char*>(endpoint);
                if (latestByEndpoint.find(endpointStr) == latestByEndpoint.end()) {
                    latestByEndpoint.emplace(endpointStr, DbRecord{
                        serial ? reinterpret_cast<const char*>(serial) : std::string{},
                        state ? reinterpret_cast<const char*>(state) : std::string{},
                        image ? reinterpret_cast<const char*>(image) : std::string{},
                        ip ? reinterpret_cast<const char*>(ip) : std::string{}
                    });
                }
            }
            sqlite3_finalize(stmt);
            sqlite3_close(db);

            // Apply only when: (1) port is connected (non-placeholder), (2) we have a latest record for this endpoint
            for (const auto &p : latestByEndpoint) {
                const std::string &endpoint = p.first;
                const DbRecord &rec = p.second;
                auto it = nodes.find(endpoint);
                if (it == nodes.end()) continue; // endpoint not present in current topology
                UsbNode &n = it->second;
                if (n.isPlaceholder) continue; // not connected
                if (n.isHub) continue; // never apply provisioning state to hubs
                n.state = rec.state;
                n.image = rec.image;
                n.ip = rec.ip;
            }
        }

        int inferModelGeneration(const UsbNode &n) {
            if (n.image.empty()) return 0;
            std::string img = n.image;
            std::transform(img.begin(), img.end(), img.begin(), [](unsigned char c){ return static_cast<char>(std::tolower(c)); });
            if (img.find("2712") != std::string::npos || img.find("rpi5") != std::string::npos || img.find("pi5") != std::string::npos) return 5;
            if (img.find("2711") != std::string::npos || img.find("rpi4") != std::string::npos || img.find("pi4") != std::string::npos) return 4;
            return 0;
        }

        Json::Value topologyToJson(const std::unordered_map<std::string, UsbNode> &nodes,
                                   const std::vector<std::string> &removed = {}) {
            Json::Value root;
            root["type"] = "topology";
            Json::Value arr(Json::arrayValue);
            for (const auto &p : nodes) {
                const UsbNode &n = p.second;
                // Hide root hub interface nodes (e.g., "1-0", "2-0"); we only show their ports as children of server
                if (n.isHub) {
                    const std::string &nid = n.id;
                    if (nid.size() >= 2 && nid.rfind("-0") == nid.size() - 2) {
                        continue;
                    }
                }
                Json::Value j;
                j["id"] = n.id;
                if (!n.parentId.empty()) j["parentId"] = n.parentId; else j["parentId"] = Json::nullValue;
                j["isHub"] = n.isHub;
                if (!n.vendor.empty()) j["vendor"] = n.vendor;
                if (!n.product.empty()) j["product"] = n.product;
                if (!n.serial.empty()) j["serial"] = n.serial;
                if (!n.state.empty()) j["state"] = n.state;
                if (!n.image.empty()) j["image"] = n.image;
                if (!n.ip.empty()) j["ip"] = n.ip;
                if (n.isPlaceholder) j["placeholder"] = true;
                int gen = inferModelGeneration(n);
                if (gen > 0) j["modelGen"] = gen;
                arr.append(j);
            }
            root["nodes"] = arr;
            if (!removed.empty()) {
                Json::Value r(Json::arrayValue);
                for (const auto &id : removed) r.append(id);
                root["removed"] = r;
            }
            root["timestamp"] = static_cast<Json::UInt64>(std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::system_clock::now().time_since_epoch()).count());
            return root;
        }

        std::string topologySnapshotString() {
            std::lock_guard<std::mutex> lock(topologyMutex);
            Json::FastWriter w; // compact ok
            return w.write(topologyToJson(currentTopology));
        }
        
        void topologyWorker() {
            LOG_INFO << "Topology worker started";
            Json::Value lastJson;
            while (topologyRunning) {
                auto newMap = scanUsbSysfs();
                enrichWithProvisioningState(newMap);

                bool changed = false;
                std::vector<std::string> removed;
                {
                    std::lock_guard<std::mutex> lock(topologyMutex);
                    // Simple change detection by size and a few key fields; fallback to full JSON compare
                    if (newMap.size() != currentTopology.size()) {
                        changed = true;
                    } else {
                        for (const auto &p : newMap) {
                            auto it = currentTopology.find(p.first);
                            if (it == currentTopology.end()) { changed = true; break; }
                            const UsbNode &a = p.second;
                            const UsbNode &b = it->second;
                            if (a.parentId != b.parentId || a.vendor != b.vendor || a.product != b.product ||
                                a.serial != b.serial || a.isHub != b.isHub || a.state != b.state ||
                                a.image != b.image || a.ip != b.ip) { changed = true; break; }
                        }
                    }
                    if (changed) {
                        // Compute removed BEFORE updating currentTopology
                        for (const auto &p : currentTopology) {
                            if (p.first == "server") continue;
                            if (newMap.find(p.first) == newMap.end()) removed.push_back(p.first);
                        }
                        // Update current topology after computing removed
                        currentTopology = newMap; // copy to keep newMap for message payload
                    }
                }

                if (changed) {
                    Json::FastWriter w;
                    // Use the updated currentTopology as the payload, along with removed ids
                    std::string msg = w.write(topologyToJson(currentTopology, removed));
                    DevicesWebSocketController::broadcast(msg);
                }

                for (int i=0; i<10 && topologyRunning; ++i) {
                    std::this_thread::sleep_for(std::chrono::milliseconds(300));
                }
            }
            LOG_INFO << "Topology worker stopped";
        }
    }
    
    // Provide a wrapper visible from outside the anonymous namespace
    std::string getTopologySnapshotString() {
        return topologySnapshotString();
    }

    Devices::Devices() 
        :
        systemd_bus(nullptr, sd_bus_unref)
    {
        // Record app start time for gating enrichment to contemporaneous records
        appStartMs = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::system_clock::now().time_since_epoch()).count();
        sd_bus* bus = nullptr;
        int ret = sd_bus_default_system(&bus);
        if (ret < 0) {
            throw std::runtime_error("Failed to connect to system bus: " + std::string(strerror(-ret)));
        }
        systemd_bus = std::unique_ptr<sd_bus, decltype(&sd_bus_unref)>(bus, sd_bus_unref);
        // Start topology watcher
        if (!topologyRunning) {
            topologyRunning = true;
            topologyThread = std::thread(topologyWorker);
        }
    }

    Devices::~Devices() {
        // Stop topology watcher
        if (topologyRunning) {
            topologyRunning = false;
            if (topologyThread.joinable()) topologyThread.join();
        }
    }

    void Devices::registerHandlers(drogon::HttpAppFramework &app)
    {
        app.registerHandler("/devices", [](const HttpRequestPtr &req, std::function<void(const HttpResponsePtr &)> &&callback) {
            // Add audit log entry for handler access
            AuditLog::logHandlerAccess(req, "/devices");
            
            auto devices = std::make_unique<DeviceList>();
            auto resp = HttpResponse::newHttpResponse();

            sqlite3* db;
            int rc = sqlite3_open("/srv/rpi-sb-provisioner/state.db", &db);
            if (rc) {
                auto errorMsg = "Failed to open database: " + std::string(sqlite3_errmsg(db));
                
                // Check if the client accepts HTML
                auto acceptHeader = req->getHeader("Accept");
                if (!acceptHeader.empty() && (acceptHeader.find("text/html") != std::string::npos)) {
                    auto resp = provisioner::utils::createErrorResponse(
                        req,
                        errorMsg,
                        drogon::k500InternalServerError,
                        "Database Error",
                        "DB_OPEN_ERROR"
                    );
                    callback(resp);
                    return;
                } else {
                    auto resp = provisioner::utils::createErrorResponse(
                        req,
                        errorMsg,
                        drogon::k500InternalServerError,
                        "Database Error",
                        "DB_OPEN_ERROR"
                    );
                    callback(resp);
                    return;
                }
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
                
                auto resp = provisioner::utils::createErrorResponse(
                    req,
                    errorMsg,
                    drogon::k500InternalServerError,
                    "Database Error",
                    "SQL_PREPARE_ERROR",
                    std::string(sqlite3_errmsg(db))
                );
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

        app.registerHandler("/devices/{serialno}", [](const HttpRequestPtr &req, std::function<void(const HttpResponsePtr &)> &&callback, const std::string &serialno) {
            auto resp = HttpResponse::newHttpResponse();
            LOG_INFO << "Device detail request for serial: '" << serialno << "'";
            
            // Add audit log entry for handler access
            AuditLog::logHandlerAccess(req, "/devices/" + serialno);
            
            if (serialno.empty()) {
                LOG_ERROR << "Empty serial number in request";
                auto resp = provisioner::utils::createErrorResponse(
                    req,
                    "Serial number is required",
                    drogon::k400BadRequest,
                    "Missing Parameter",
                    "MISSING_SERIAL"
                );
                callback(resp);
                return;
            }

            sqlite3* db;
            int rc = sqlite3_open("/srv/rpi-sb-provisioner/state.db", &db);
            if (rc) {
                auto resp = provisioner::utils::createErrorResponse(
                    req,
                    "Failed to open device database",
                    drogon::k500InternalServerError,
                    "Database Error",
                    "DB_OPEN_ERROR",
                    std::string(sqlite3_errmsg(db))
                );
                sqlite3_close(db);
                callback(resp);
                return;
            }

            sqlite3_stmt* stmt;
            const char* sql = "SELECT serial, endpoint, state, image, ip_address FROM devices WHERE serial = ?";
            rc = sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr);

            if (rc != SQLITE_OK) {
                sqlite3_close(db);
                auto resp = provisioner::utils::createErrorResponse(
                    req,
                    "Failed to prepare SQL statement",
                    drogon::k500InternalServerError,
                    "Database Error",
                    "SQL_PREPARE_ERROR",
                    std::string(sqlite3_errmsg(db))
                );
                callback(resp);
                return;
            }

            sqlite3_bind_text(stmt, 1, serialno.c_str(), -1, SQLITE_STATIC);

            if (sqlite3_step(stmt) != SQLITE_ROW) {
                sqlite3_finalize(stmt);
                sqlite3_close(db);
                auto resp = provisioner::utils::createErrorResponse(
                    req,
                    "Device not found in database",
                    drogon::k400BadRequest,
                    "Device Not Found",
                    "DEVICE_NOT_FOUND",
                    "Requested serial: " + serialno
                );
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
                
                std::string logPath = "/var/log/rpi-sb-provisioner/" + provisioner::utils::sanitize_path_component(device.serial) + "/provisioner.log";
                std::ifstream provisionerFile(logPath);
                if (provisionerFile.is_open()) {
                    // Log file access to audit log
                    AuditLog::logFileSystemAccess("READ", logPath, true);
                    
                    std::stringstream buffer;
                    buffer << provisionerFile.rdbuf();
                    provisioner_log = buffer.str();
                } else {
                    // Log failed file access to audit log
                    AuditLog::logFileSystemAccess("READ", logPath, false);
                }

                logPath = "/var/log/rpi-sb-provisioner/" + provisioner::utils::sanitize_path_component(device.serial) + "/bootstrap.log";
                std::ifstream bootstrapFile(logPath);
                if (bootstrapFile.is_open()) {
                    // Log file access to audit log
                    AuditLog::logFileSystemAccess("READ", logPath, true);
                    
                    std::stringstream buffer;
                    buffer << bootstrapFile.rdbuf();
                    bootstrap_log = buffer.str();
                } else {
                    // Log failed file access to audit log
                    AuditLog::logFileSystemAccess("READ", logPath, false);
                }

                logPath = "/var/log/rpi-sb-provisioner/" + provisioner::utils::sanitize_path_component(device.serial) + "/triage.log";
                std::ifstream triageFile(logPath);
                if (triageFile.is_open()) {
                    // Log file access to audit log
                    AuditLog::logFileSystemAccess("READ", logPath, true);
                    
                    std::stringstream buffer;
                    buffer << triageFile.rdbuf();
                    triage_log = buffer.str();
                } else {
                    // Log failed file access to audit log
                    AuditLog::logFileSystemAccess("READ", logPath, false);
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
        }); // devices/{serialno} handler

        app.registerHandler("/devices/{serialno}/log/provisioner", [](const HttpRequestPtr &req, std::function<void(const HttpResponsePtr &)> &&callback, const std::string &serialno) {
            auto resp = HttpResponse::newHttpResponse();
            LOG_INFO << "Provisioner log request for serial: '" << serialno << "'";
            
            // Add audit log entry for handler access
            AuditLog::logHandlerAccess(req, "/devices/" + serialno + "/log/provisioner");
            
            if (serialno.empty()) {
                LOG_ERROR << "Empty serial number in request";
                auto resp = provisioner::utils::createErrorResponse(
                    req,
                    "Serial number is required",
                    drogon::k400BadRequest,
                    "Missing Parameter",
                    "MISSING_SERIAL"
                );
                callback(resp);
                return;
            }

            std::string logPath = "/var/log/rpi-sb-provisioner/" + provisioner::utils::sanitize_path_component(serialno) + "/provisioner.log";
            LOG_INFO << "Attempting to open log file at: " << logPath;
            
            std::ifstream logFile(logPath);
            if (!logFile.is_open()) {
                LOG_ERROR << "Failed to open log file: " << logPath;
                // Log failed file access to audit log
                AuditLog::logFileSystemAccess("READ", logPath, false);
                
                auto resp = provisioner::utils::createErrorResponse(
                    req,
                    "Log file not found",
                    drogon::k400BadRequest,
                    "Log Not Found",
                    "LOG_NOT_FOUND",
                    "Attempted path: " + logPath
                );
                callback(resp);
                return;
            }

            // Log successful file access to audit log
            AuditLog::logFileSystemAccess("READ", logPath, true);
            
            LOG_INFO << "Successfully opened log file: " << logPath;
            std::stringstream buffer;
            buffer << logFile.rdbuf();
            resp->setStatusCode(k200OK);
            resp->setContentTypeCode(CT_TEXT_PLAIN);
            resp->setBody(buffer.str());
            callback(resp);
        }); // devices/{serialno}/log/provisioner handler

        app.registerHandler("/devices/{serialno}/log/bootstrap", [](const HttpRequestPtr &req, std::function<void(const HttpResponsePtr &)> &&callback, const std::string &serialno) {
            auto resp = HttpResponse::newHttpResponse();
            LOG_INFO << "Bootstrap log request for serial: '" << serialno << "'";
            
            if (serialno.empty()) {
                LOG_ERROR << "Empty serial number in request";
                auto resp = provisioner::utils::createErrorResponse(
                    req,
                    "Serial number is required",
                    drogon::k400BadRequest,
                    "Missing Parameter",
                    "MISSING_SERIAL"
                );
                callback(resp);
                return;
            }

            std::string logPath = "/var/log/rpi-sb-provisioner/" + provisioner::utils::sanitize_path_component(serialno) + "/bootstrap.log";
            LOG_INFO << "Attempting to open log file at: " << logPath;
            
            std::ifstream logFile(logPath);
            if (!logFile.is_open()) {
                LOG_ERROR << "Failed to open log file: " << logPath;
                auto resp = provisioner::utils::createErrorResponse(
                    req,
                    "Log file not found",
                    drogon::k400BadRequest,
                    "Log Not Found",
                    "LOG_NOT_FOUND",
                    "Attempted path: " + logPath
                );
                callback(resp);
                return;
            }

            LOG_INFO << "Successfully opened log file: " << logPath;
            std::stringstream buffer;
            buffer << logFile.rdbuf();
            resp->setStatusCode(k200OK);
            resp->setContentTypeCode(CT_TEXT_PLAIN);
            resp->setBody(buffer.str());
            callback(resp);
        }); // devices/{serialno}/log/bootstrap handler

        app.registerHandler("/devices/{serialno}/log/triage", [](const HttpRequestPtr &req, std::function<void(const HttpResponsePtr &)> &&callback, const std::string &serialno) {
            auto resp = HttpResponse::newHttpResponse();
            LOG_INFO << "Triage log request for serial: '" << serialno << "'";
            
            if (serialno.empty()) {
                LOG_ERROR << "Empty serial number in request";
                auto resp = provisioner::utils::createErrorResponse(
                    req,
                    "Serial number is required",
                    drogon::k400BadRequest,
                    "Missing Parameter",
                    "MISSING_SERIAL"
                );
                callback(resp);
                return;
            }

            std::string logPath = "/var/log/rpi-sb-provisioner/" + provisioner::utils::sanitize_path_component(serialno) + "/triage.log";
            LOG_INFO << "Attempting to open log file at: " << logPath;
            
            std::ifstream logFile(logPath);
            if (!logFile.is_open()) {
                LOG_ERROR << "Failed to open log file: " << logPath;
                auto resp = provisioner::utils::createErrorResponse(
                    req,
                    "Log file not found",
                    drogon::k400BadRequest,
                    "Log Not Found",
                    "LOG_NOT_FOUND",
                    "Attempted path: " + logPath
                );
                callback(resp);
                return;
            }

            LOG_INFO << "Successfully opened log file: " << logPath;
            std::stringstream buffer;
            buffer << logFile.rdbuf();
            resp->setStatusCode(k200OK);
            resp->setContentTypeCode(CT_TEXT_PLAIN);
            resp->setBody(buffer.str());
            callback(resp);
        }); // devices/:serialno/log/triage handler

        app.registerHandler("/devices/{serialno}/key/public", [](const HttpRequestPtr &req, std::function<void(const HttpResponsePtr &)> &&callback, const std::string &serialno) {
            auto resp = HttpResponse::newHttpResponse();
            LOG_INFO << "Public key request for serial: '" << serialno << "'";
            
            if (serialno.empty()) {
                LOG_ERROR << "Empty serial number in request";
                auto resp = provisioner::utils::createErrorResponse(
                    req,
                    "Serial number is required",
                    drogon::k400BadRequest,
                    "Missing Parameter",
                    "MISSING_SERIAL"
                );
                callback(resp);
                return;
            }

            std::string keyPath = "/var/log/rpi-sb-provisioner/" + provisioner::utils::sanitize_path_component(serialno) + "/keypair/" + provisioner::utils::sanitize_path_component(serialno) + ".pub";
            std::ifstream keyFile(keyPath);
            if (!keyFile.is_open()) {
                auto resp = provisioner::utils::createErrorResponse(
                    req,
                    "Public key file not found",
                    drogon::k400BadRequest,
                    "Key Not Found",
                    "KEY_NOT_FOUND",
                    "Attempted path: " + keyPath
                );
                callback(resp);
                return;
            }

            std::stringstream buffer;
            buffer << keyFile.rdbuf();
            resp->setContentTypeCode(CT_APPLICATION_OCTET_STREAM);
            resp->setStatusCode(k200OK);
            resp->setBody(buffer.str());
            callback(resp);
        }); // devices/{serialno}/key/public handler

        app.registerHandler("/devices/{serialno}/key/private", [](const HttpRequestPtr &req, std::function<void(const HttpResponsePtr &)> &&callback, const std::string &serialno) {
            auto resp = HttpResponse::newHttpResponse();
            LOG_INFO << "Private key request for serial: '" << serialno << "'";
            
            if (serialno.empty()) {
                LOG_ERROR << "Empty serial number in request";
                auto resp = provisioner::utils::createErrorResponse(
                    req,
                    "Serial number is required",
                    drogon::k400BadRequest,
                    "Missing Parameter",
                    "MISSING_SERIAL"
                );
                callback(resp);
                return;
            }

            std::string keyPath = "/var/log/rpi-sb-provisioner/" + provisioner::utils::sanitize_path_component(serialno) + "/keypair/" + provisioner::utils::sanitize_path_component(serialno) + ".der";
            std::ifstream keyFile(keyPath);
            if (!keyFile.is_open()) {
                auto resp = provisioner::utils::createErrorResponse(
                    req,
                    "Private key file not found",
                    drogon::k400BadRequest,
                    "Key Not Found",
                    "KEY_NOT_FOUND",
                    "Attempted path: " + keyPath
                );
                callback(resp);
                return;
            }

            std::stringstream buffer;
            buffer << keyFile.rdbuf();
            resp->setStatusCode(k200OK);
            resp->setContentTypeCode(CT_APPLICATION_OCTET_STREAM);
            resp->setBody(buffer.str());
            callback(resp);
        }); // devices/{serialno}/key/private handler
    }

    
} // namespace provisioner

