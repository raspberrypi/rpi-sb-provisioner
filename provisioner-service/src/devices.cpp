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
        std::string productName; // textual product name (e.g., BCM2712 Boot)
        std::string serial;      // serial (if available)
        bool isHub{false};
        // Optional provisioning info
        std::string state;
        std::string image;
        std::string ip;
        std::string model;       // device model/type (e.g., CM5, 4B, Zero 2 W)
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
        
        // Test mode state for fake device injection
        std::atomic<bool> testModeEnabled{false};
        std::unordered_map<std::string, UsbNode> testTopology;
        
        // USB spec constants
        constexpr int USB_MAX_DEVICES = 127;      // Maximum devices per host controller
        constexpr int USB_MAX_HUB_DEPTH = 5;      // Maximum external hubs in chain (7 tiers total)
        
        // Generate a fake serial number
        std::string generateFakeSerial(int index) {
            char buf[32];
            snprintf(buf, sizeof(buf), "TEST%08x", 0x10000000 + index);
            return buf;
        }
        
        // Generate a fake IP address
        std::string generateFakeIP(int index) {
            return "192.168.100." + std::to_string((index % 254) + 1);
        }
        
        // Test scenario generators
        std::unordered_map<std::string, UsbNode> generateDirectDevices(int count) {
            // Devices connected directly to root ports (no hubs)
            std::unordered_map<std::string, UsbNode> nodes;
            
            // Server root
            UsbNode server;
            server.id = "server";
            server.parentId = "";
            server.isHub = true;
            server.vendor = "Provisioner";
            server.product = "Server";
            nodes["server"] = server;
            
            // Add root hub placeholder for USB 3 (bus 3)
            UsbNode rootHub;
            rootHub.id = "3-0";
            rootHub.parentId = "server";
            rootHub.isHub = true;
            rootHub.portCount = std::min(count, 4);
            nodes["3-0"] = rootHub;
            
            // Direct devices on different root ports
            const char* states[] = {"bootstrap", "triage", "provisioning", "complete", "error"};
            const char* models[] = {"CM5", "CM4", "Pi 5", "Pi 4B", "Zero 2 W"};
            const int modelGens[] = {5, 4, 5, 4, 0};
            
            for (int i = 0; i < count && i < 4; ++i) {
                UsbNode dev;
                dev.id = "3-" + std::to_string(i + 1);
                dev.parentId = "server";
                dev.isHub = false;
                dev.vendor = "2e8a";
                dev.product = "000" + std::to_string(i);
                dev.productName = "BCM2712 Boot";
                dev.serial = generateFakeSerial(i);
                dev.state = states[i % 5];
                dev.ip = generateFakeIP(i);
                dev.model = models[i % 5];
                nodes[dev.id] = dev;
            }
            
            return nodes;
        }
        
        std::unordered_map<std::string, UsbNode> generateHubWithDevices(int hubPorts, int deviceCount) {
            // Single hub with multiple devices
            std::unordered_map<std::string, UsbNode> nodes;
            
            // Server root
            UsbNode server;
            server.id = "server";
            server.parentId = "";
            server.isHub = true;
            server.vendor = "Provisioner";
            server.product = "Server";
            nodes["server"] = server;
            
            // Root hub
            UsbNode rootHub;
            rootHub.id = "3-0";
            rootHub.parentId = "server";
            rootHub.isHub = true;
            rootHub.portCount = 2;
            nodes["3-0"] = rootHub;
            
            // USB Hub on port 1
            UsbNode hub;
            hub.id = "3-1";
            hub.parentId = "server";
            hub.isHub = true;
            hub.vendor = "0bda";
            hub.product = "5411";
            hub.productName = "USB3.0 Hub";
            hub.portCount = hubPorts;
            nodes["3-1"] = hub;
            
            // Devices under the hub
            const char* states[] = {"bootstrap", "triage", "provisioning", "complete", "error"};
            const char* models[] = {"CM5", "CM4", "Pi 5", "Pi 4B", "Zero 2 W"};
            
            for (int i = 0; i < deviceCount && i < hubPorts; ++i) {
                UsbNode dev;
                dev.id = "3-1." + std::to_string(i + 1);
                dev.parentId = "3-1";
                dev.isHub = false;
                dev.vendor = "2e8a";
                dev.product = "000" + std::to_string(i);
                dev.productName = "BCM2712 Boot";
                dev.serial = generateFakeSerial(100 + i);
                dev.state = states[i % 5];
                dev.ip = generateFakeIP(100 + i);
                dev.model = models[i % 5];
                nodes[dev.id] = dev;
            }
            
            // Add placeholders for empty ports
            for (int i = deviceCount; i < hubPorts; ++i) {
                UsbNode ph;
                ph.id = "3-1." + std::to_string(i + 1);
                ph.parentId = "3-1";
                ph.isHub = false;
                ph.isPlaceholder = true;
                nodes[ph.id] = ph;
            }
            
            return nodes;
        }
        
        std::unordered_map<std::string, UsbNode> generateNestedHubs(int depth, int devicesPerHub) {
            // Nested hubs up to specified depth (max 5)
            std::unordered_map<std::string, UsbNode> nodes;
            depth = std::min(depth, USB_MAX_HUB_DEPTH);
            
            // Server root
            UsbNode server;
            server.id = "server";
            server.parentId = "";
            server.isHub = true;
            server.vendor = "Provisioner";
            server.product = "Server";
            nodes["server"] = server;
            
            // Root hub
            UsbNode rootHub;
            rootHub.id = "3-0";
            rootHub.parentId = "server";
            rootHub.isHub = true;
            rootHub.portCount = 2;
            nodes["3-0"] = rootHub;
            
            // Build chain of hubs
            std::string parentId = "server";
            std::string currentId = "3-1";
            const char* states[] = {"bootstrap", "triage", "provisioning", "complete"};
            const char* models[] = {"CM5", "CM4", "Pi 5", "Pi 4B"};
            int deviceIndex = 0;
            
            for (int d = 0; d < depth; ++d) {
                // Add hub at this depth
                UsbNode hub;
                hub.id = currentId;
                hub.parentId = parentId;
                hub.isHub = true;
                hub.vendor = "0bda";
                hub.product = "5411";
                hub.productName = "USB3.0 Hub (Tier " + std::to_string(d + 1) + ")";
                hub.portCount = devicesPerHub + 1; // +1 for next hub
                nodes[hub.id] = hub;
                
                // Add devices at this level
                for (int i = 0; i < devicesPerHub; ++i) {
                    UsbNode dev;
                    dev.id = currentId + "." + std::to_string(i + 1);
                    dev.parentId = currentId;
                    dev.isHub = false;
                    dev.vendor = "2e8a";
                    dev.product = "0003";
                    dev.productName = "BCM2712 Boot";
                    dev.serial = generateFakeSerial(200 + deviceIndex);
                    dev.state = states[deviceIndex % 4];
                    dev.ip = generateFakeIP(200 + deviceIndex);
                    dev.model = models[deviceIndex % 4];
                    nodes[dev.id] = dev;
                    deviceIndex++;
                }
                
                // Prepare for next level
                parentId = currentId;
                currentId = currentId + "." + std::to_string(devicesPerHub + 1);
            }
            
            return nodes;
        }
        
        std::unordered_map<std::string, UsbNode> generateMaxTopology() {
            // Maximum USB topology: 127 devices with hub hierarchy
            std::unordered_map<std::string, UsbNode> nodes;
            
            // Server root
            UsbNode server;
            server.id = "server";
            server.parentId = "";
            server.isHub = true;
            server.vendor = "Provisioner";
            server.product = "Server";
            nodes["server"] = server;
            
            // Root hubs for USB2 (bus 1) and USB3 (bus 3)
            for (int bus : {1, 3}) {
                UsbNode rootHub;
                rootHub.id = std::to_string(bus) + "-0";
                rootHub.parentId = "server";
                rootHub.isHub = true;
                rootHub.portCount = 4;
                nodes[rootHub.id] = rootHub;
            }
            
            const char* states[] = {"bootstrap", "triage", "provisioning", "complete", "error"};
            const char* models[] = {"CM5", "CM4", "Pi 5", "Pi 4B", "Zero 2 W"};
            int deviceIndex = 0;
            int totalDevices = 0;
            
            // Create hierarchical structure to reach ~127 devices
            // 4 root ports × 7-port hubs × 4 devices per hub = 112 devices + hubs
            for (int bus : {1, 3}) {
                for (int rootPort = 1; rootPort <= 2 && totalDevices < USB_MAX_DEVICES - 10; ++rootPort) {
                    std::string hubId = std::to_string(bus) + "-" + std::to_string(rootPort);
                    
                    // Add 7-port hub
                    UsbNode hub;
                    hub.id = hubId;
                    hub.parentId = "server";
                    hub.isHub = true;
                    hub.vendor = "0bda";
                    hub.product = "5411";
                    hub.productName = "USB3.0 Hub";
                    hub.portCount = 7;
                    nodes[hub.id] = hub;
                    totalDevices++;
                    
                    // Add devices to hub
                    for (int port = 1; port <= 7 && totalDevices < USB_MAX_DEVICES; ++port) {
                        // Every 3rd port gets a sub-hub with more devices
                        if (port % 3 == 0 && totalDevices < USB_MAX_DEVICES - 5) {
                            std::string subHubId = hubId + "." + std::to_string(port);
                            UsbNode subHub;
                            subHub.id = subHubId;
                            subHub.parentId = hubId;
                            subHub.isHub = true;
                            subHub.vendor = "0bda";
                            subHub.product = "5411";
                            subHub.productName = "USB3.0 Sub-Hub";
                            subHub.portCount = 4;
                            nodes[subHub.id] = subHub;
                            totalDevices++;
                            
                            // Devices on sub-hub
                            for (int subPort = 1; subPort <= 4 && totalDevices < USB_MAX_DEVICES; ++subPort) {
                                UsbNode dev;
                                dev.id = subHubId + "." + std::to_string(subPort);
                                dev.parentId = subHubId;
                                dev.isHub = false;
                                dev.vendor = "2e8a";
                                dev.product = "0003";
                                dev.productName = "BCM2712 Boot";
                                dev.serial = generateFakeSerial(deviceIndex);
                                dev.state = states[deviceIndex % 5];
                                dev.ip = generateFakeIP(deviceIndex);
                                dev.model = models[deviceIndex % 5];
                                nodes[dev.id] = dev;
                                deviceIndex++;
                                totalDevices++;
                            }
                        } else {
                            // Regular device
                            UsbNode dev;
                            dev.id = hubId + "." + std::to_string(port);
                            dev.parentId = hubId;
                            dev.isHub = false;
                            dev.vendor = "2e8a";
                            dev.product = "0003";
                            dev.productName = "BCM2712 Boot";
                            dev.serial = generateFakeSerial(deviceIndex);
                            dev.state = states[deviceIndex % 5];
                            dev.ip = generateFakeIP(deviceIndex);
                            dev.model = models[deviceIndex % 5];
                            nodes[dev.id] = dev;
                            deviceIndex++;
                            totalDevices++;
                        }
                    }
                }
            }
            
            LOG_INFO << "Generated max topology with " << totalDevices << " devices";
            return nodes;
        }
        
        std::unordered_map<std::string, UsbNode> generateMixedTopology() {
            // Mixed topology: direct devices, hubs, and nested hubs
            std::unordered_map<std::string, UsbNode> nodes;
            
            // Server root
            UsbNode server;
            server.id = "server";
            server.parentId = "";
            server.isHub = true;
            server.vendor = "Provisioner";
            server.product = "Server";
            nodes["server"] = server;
            
            // Root hubs
            for (int bus : {1, 3}) {
                UsbNode rootHub;
                rootHub.id = std::to_string(bus) + "-0";
                rootHub.parentId = "server";
                rootHub.isHub = true;
                rootHub.portCount = 4;
                nodes[rootHub.id] = rootHub;
            }
            
            const char* states[] = {"bootstrap", "triage", "provisioning", "complete", "error"};
            const char* models[] = {"CM5", "CM4", "Pi 5", "Pi 4B", "Zero 2 W"};
            int deviceIndex = 0;
            
            // USB3 bus: Direct device on port 1
            {
                UsbNode dev;
                dev.id = "3-1";
                dev.parentId = "server";
                dev.isHub = false;
                dev.vendor = "2e8a";
                dev.product = "0003";
                dev.productName = "BCM2712 Boot";
                dev.serial = generateFakeSerial(deviceIndex++);
                dev.state = "complete";
                dev.ip = generateFakeIP(0);
                dev.model = "CM5";
                nodes[dev.id] = dev;
            }
            
            // USB3 bus: Hub on port 2 with devices
            {
                UsbNode hub;
                hub.id = "3-2";
                hub.parentId = "server";
                hub.isHub = true;
                hub.vendor = "0bda";
                hub.product = "5411";
                hub.productName = "USB3.0 Hub";
                hub.portCount = 4;
                nodes[hub.id] = hub;
                
                for (int i = 1; i <= 3; ++i) {
                    UsbNode dev;
                    dev.id = "3-2." + std::to_string(i);
                    dev.parentId = "3-2";
                    dev.isHub = false;
                    dev.vendor = "2e8a";
                    dev.product = "0003";
                    dev.productName = "BCM2712 Boot";
                    dev.serial = generateFakeSerial(deviceIndex);
                    dev.state = states[deviceIndex % 5];
                    dev.ip = generateFakeIP(deviceIndex);
                    dev.model = models[deviceIndex % 5];
                    nodes[dev.id] = dev;
                    deviceIndex++;
                }
                
                // Placeholder for empty port
                UsbNode ph;
                ph.id = "3-2.4";
                ph.parentId = "3-2";
                ph.isPlaceholder = true;
                nodes[ph.id] = ph;
            }
            
            // USB2 bus: Nested hubs
            {
                UsbNode hub1;
                hub1.id = "1-1";
                hub1.parentId = "server";
                hub1.isHub = true;
                hub1.vendor = "0bda";
                hub1.product = "5411";
                hub1.productName = "USB2.0 Hub";
                hub1.portCount = 4;
                nodes[hub1.id] = hub1;
                
                // Device on hub1 port 1
                UsbNode dev1;
                dev1.id = "1-1.1";
                dev1.parentId = "1-1";
                dev1.isHub = false;
                dev1.vendor = "2e8a";
                dev1.product = "0003";
                dev1.productName = "BCM2711 Boot";
                dev1.serial = generateFakeSerial(deviceIndex++);
                dev1.state = "provisioning";
                dev1.ip = generateFakeIP(50);
                dev1.model = "CM4";
                nodes[dev1.id] = dev1;
                
                // Nested hub on hub1 port 2
                UsbNode hub2;
                hub2.id = "1-1.2";
                hub2.parentId = "1-1";
                hub2.isHub = true;
                hub2.vendor = "0bda";
                hub2.product = "5411";
                hub2.productName = "USB2.0 Sub-Hub";
                hub2.portCount = 4;
                nodes[hub2.id] = hub2;
                
                // Devices on nested hub
                for (int i = 1; i <= 2; ++i) {
                    UsbNode dev;
                    dev.id = "1-1.2." + std::to_string(i);
                    dev.parentId = "1-1.2";
                    dev.isHub = false;
                    dev.vendor = "2e8a";
                    dev.product = "0003";
                    dev.productName = "BCM2711 Boot";
                    dev.serial = generateFakeSerial(deviceIndex);
                    dev.state = states[deviceIndex % 5];
                    dev.ip = generateFakeIP(60 + i);
                    dev.model = "Pi 4B";
                    nodes[dev.id] = dev;
                    deviceIndex++;
                }
            }
            
            return nodes;
        }

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
                    const std::string pn = readFileTrimmed(entry.path()/"product");
                    if (!pn.empty()) node.productName = pn;
                    // Default model hint from product name; refined later by manufacturing data
                    if (node.model.empty() && !pn.empty()) node.model = pn;
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
            // Also capture latest manufacturing info by serial (boardname/processor)
            struct MfgRecord { std::string boardname, processor; };
            std::unordered_map<std::string, MfgRecord> latestMfgBySerial;

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

            // Read manufacturing database if present for device-type inference
            {
                sqlite3* mdb = nullptr;
                int rc2 = sqlite3_open("/srv/rpi-sb-provisioner/manufacturing.db", &mdb);
                if (rc2 == SQLITE_OK) {
                    const char* msql = "SELECT serial, boardname, processor FROM devices ORDER BY provision_ts DESC";
                    sqlite3_stmt* mstmt = nullptr;
                    rc2 = sqlite3_prepare_v2(mdb, msql, -1, &mstmt, nullptr);
                    if (rc2 == SQLITE_OK) {
                        while (sqlite3_step(mstmt) == SQLITE_ROW) {
                            const unsigned char* serial = sqlite3_column_text(mstmt, 0);
                            const unsigned char* boardname = sqlite3_column_text(mstmt, 1);
                            const unsigned char* processor = sqlite3_column_text(mstmt, 2);
                            if (!serial) continue;
                            std::string s = reinterpret_cast<const char*>(serial);
                            if (latestMfgBySerial.find(s) == latestMfgBySerial.end()) {
                                latestMfgBySerial.emplace(s, MfgRecord{
                                    boardname ? reinterpret_cast<const char*>(boardname) : std::string{},
                                    processor ? reinterpret_cast<const char*>(processor) : std::string{}
                                });
                            }
                        }
                    }
                    if (mstmt) sqlite3_finalize(mstmt);
                    sqlite3_close(mdb);
                }
            }

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
                // Do not clobber existing non-empty image (used for model inference) with empty DB values
                if (!rec.image.empty()) {
                    n.image = rec.image;
                }
                n.ip = rec.ip;
                // If we also have a manufacturing record for this device by serial, use it to annotate image/model
                if (!n.serial.empty()) {
                    auto mit = latestMfgBySerial.find(n.serial);
                    if (mit != latestMfgBySerial.end()) {
                        const auto &mr = mit->second;
                        // Prefer model from manufacturing boardname (e.g., CM5, 4B)
                        if (!mr.boardname.empty()) n.model = mr.boardname;
                        else if (!mr.processor.empty() && n.model.empty()) n.model = mr.processor;
                        // Keep image for OS image name only; if image was being used as model before, do not overwrite unless set
                        if (n.image.empty() && !mr.boardname.empty()) n.image = n.image; // no-op placeholder to emphasize separation
                    }
                }
            }

            // Fallback: Match by serial number when endpoint lookup failed
            // This handles cases where the endpoint field in the database doesn't match the USB topology
            // (e.g., due to incorrect USB path extraction during bootstrap phase)
            std::unordered_map<std::string, DbRecord> latestBySerial;
            for (const auto &p : latestByEndpoint) {
                if (!p.second.serial.empty()) {
                    latestBySerial[p.second.serial] = p.second;
                }
            }

            for (auto &p : nodes) {
                UsbNode &n = p.second;
                // Skip if already has state (endpoint match succeeded), is placeholder, or is hub
                if (!n.state.empty() || n.isPlaceholder || n.isHub) continue;
                // Skip if no serial available
                if (n.serial.empty()) continue;
                
                auto sit = latestBySerial.find(n.serial);
                if (sit != latestBySerial.end()) {
                    const auto &rec = sit->second;
                    n.state = rec.state;
                    if (!rec.image.empty()) {
                        n.image = rec.image;
                    }
                    n.ip = rec.ip;
                    // Apply manufacturing data if available
                    auto mit = latestMfgBySerial.find(n.serial);
                    if (mit != latestMfgBySerial.end()) {
                        const auto &mr = mit->second;
                        if (!mr.boardname.empty()) n.model = mr.boardname;
                        else if (!mr.processor.empty() && n.model.empty()) n.model = mr.processor;
                    }
                }
            }
        }

        int inferModelGeneration(const UsbNode &n) {
            // Prefer explicit image tag if available
            if (!n.model.empty()) {
                std::string img = n.model;
                std::transform(img.begin(), img.end(), img.begin(), [](unsigned char c){ return static_cast<char>(std::tolower(c)); });
                if (img.find("2712") != std::string::npos ||
                    img.find("rpi5") != std::string::npos ||
                    img.find("pi5") != std::string::npos ||
                    img.find("cm5") != std::string::npos ||
                    img.find("compute module 5") != std::string::npos)
                {
                    return 5;
                }
                if (img.find("2711") != std::string::npos ||
                    img.find("rpi4") != std::string::npos ||
                    img.find("pi4") != std::string::npos ||
                    img.find("cm4") != std::string::npos ||
                    img.find("compute module 4") != std::string::npos ||
                    img.find("pi 400") != std::string::npos)
                {
                    return 4;
                }
            }
            if (!n.image.empty()) {
                std::string img = n.image;
                std::transform(img.begin(), img.end(), img.begin(), [](unsigned char c){ return static_cast<char>(std::tolower(c)); });
                if (img.find("2712") != std::string::npos || img.find("rpi5") != std::string::npos || img.find("pi5") != std::string::npos) return 5;
                if (img.find("2711") != std::string::npos || img.find("rpi4") != std::string::npos || img.find("pi4") != std::string::npos) return 4;
            }
            // Fall back to USB product name (e.g., "BCM2712 Boot") seen at connect time
            if (!n.productName.empty()) {
                std::string pn = n.productName;
                std::transform(pn.begin(), pn.end(), pn.begin(), [](unsigned char c){ return static_cast<char>(std::tolower(c)); });
                if (pn.find("2712") != std::string::npos) return 5;
                if (pn.find("2711") != std::string::npos) return 4;
            }
            // Fall back to endpoint-derived hints: if image was populated from manufacturing processor earlier
            if (n.image.empty() && !n.product.empty()) {
                // In some flows we set image to BCM2711/BCM2712 in enrichment; if not present at call time, skip.
            }
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
                if (!n.productName.empty()) j["productName"] = n.productName;
                if (!n.serial.empty()) j["serial"] = n.serial;
                if (!n.state.empty()) j["state"] = n.state;
                if (!n.image.empty()) j["image"] = n.image;
                if (!n.model.empty()) j["model"] = n.model;
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
        
        void injectTestTopology(const std::string& scenario) {
            std::unordered_map<std::string, UsbNode> newTopology;
            
            if (scenario == "direct") {
                newTopology = generateDirectDevices(4);
            } else if (scenario == "hub") {
                newTopology = generateHubWithDevices(7, 5);
            } else if (scenario == "nested") {
                newTopology = generateNestedHubs(3, 2);
            } else if (scenario == "deep") {
                newTopology = generateNestedHubs(USB_MAX_HUB_DEPTH, 1);
            } else if (scenario == "max") {
                newTopology = generateMaxTopology();
            } else if (scenario == "mixed") {
                newTopology = generateMixedTopology();
            } else if (scenario == "clear" || scenario == "off") {
                testModeEnabled = false;
                LOG_INFO << "Test mode disabled";
                return;
            } else {
                LOG_WARN << "Unknown test scenario: " << scenario;
                return;
            }
            
            {
                std::lock_guard<std::mutex> lock(topologyMutex);
                testTopology = newTopology;
                testModeEnabled = true;
            }
            
            // Broadcast the test topology
            Json::FastWriter w;
            std::string msg = w.write(topologyToJson(newTopology));
            DevicesWebSocketController::broadcast(msg);
            
            LOG_INFO << "Test mode enabled with scenario: " << scenario << " (" << newTopology.size() << " nodes)";
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
                // Skip real USB scanning when test mode is enabled
                if (testModeEnabled) {
                    for (int i=0; i<10 && topologyRunning; ++i) {
                        std::this_thread::sleep_for(std::chrono::milliseconds(300));
                    }
                    continue;
                }
                
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
            const char* sql = "SELECT serial, endpoint, state, image, ip_address FROM devices WHERE serial = ? ORDER BY ts DESC LIMIT 1";
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
            LOG_WARN << "SECURITY: Private key download request for serial: '" << serialno << "' from " << AuditLog::getClientIP(req);
            
            // SECURITY CHECK: This endpoint is disabled by default for security reasons
            // Private keys should NEVER be exposed via HTTP in production environments
            auto privateKeyAccessEnabled = provisioner::utils::getConfigValue("RPI_SB_PROVISIONER_ENABLE_PRIVATE_KEY_API");
            if (!privateKeyAccessEnabled || *privateKeyAccessEnabled != "true") {
                LOG_ERROR << "SECURITY: Private key API access denied - endpoint is disabled. "
                          << "Set RPI_SB_PROVISIONER_ENABLE_PRIVATE_KEY_API=true in /etc/rpi-sb-provisioner/config to enable this DANGEROUS endpoint.";
                
                // Add audit log entry for denied access attempt
                AuditLog::logHandlerAccess(req, "/devices/" + serialno + "/key/private");
                AuditLog::logFileSystemAccess("DENIED_PRIVATE_KEY_ACCESS", 
                    "/var/log/rpi-sb-provisioner/" + serialno + "/keypair/" + serialno + ".der", 
                    false, 
                    "", 
                    "Private key API is disabled for security. Client IP: " + AuditLog::getClientIP(req));
                
                auto resp = provisioner::utils::createErrorResponse(
                    req,
                    "Private key download API is disabled for security reasons. "
                    "This endpoint must be explicitly enabled in configuration: "
                    "Set RPI_SB_PROVISIONER_ENABLE_PRIVATE_KEY_API=true in /etc/rpi-sb-provisioner/config. "
                    "WARNING: Enabling this endpoint exposes device private keys via HTTP and should only be done in secure, isolated networks.",
                    drogon::k403Forbidden,
                    "Endpoint Disabled",
                    "PRIVATE_KEY_API_DISABLED",
                    "This is a security feature. Private keys are cryptographic secrets that should not be transmitted over HTTP."
                );
                callback(resp);
                return;
            }
            
            // Log that this dangerous endpoint is enabled and being used
            LOG_WARN << "SECURITY WARNING: Private key API is ENABLED and being accessed. "
                     << "This is a security risk. Private keys are being transmitted over HTTP.";
            
            // Add audit log entry for handler access
            AuditLog::logHandlerAccess(req, "/devices/" + serialno + "/key/private");
            
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
                // Log failed file access to audit log
                AuditLog::logFileSystemAccess("READ_PRIVATE_KEY", keyPath, false, "", 
                    "Private key file not found for serial: " + serialno + ", Client IP: " + AuditLog::getClientIP(req));
                
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

            // CRITICAL SECURITY LOG: Private key is being transmitted
            LOG_WARN << "SECURITY ALERT: Private key for device " << serialno 
                     << " is being transmitted to " << AuditLog::getClientIP(req);
            
            // Log successful private key access to audit log
            AuditLog::logFileSystemAccess("READ_PRIVATE_KEY", keyPath, true, "", 
                "CRITICAL: Private key transmitted for serial: " + serialno + 
                ", Client IP: " + AuditLog::getClientIP(req) + 
                ", User-Agent: " + req->getHeader("User-Agent"));

            std::stringstream buffer;
            buffer << keyFile.rdbuf();
            resp->setStatusCode(k200OK);
            resp->setContentTypeCode(CT_APPLICATION_OCTET_STREAM);
            resp->setBody(buffer.str());
            callback(resp);
        }); // devices/{serialno}/key/private handler

        // Secret test mode endpoint - only accessible with special header or localhost
        app.registerHandler("/devices/_test/{scenario}", [](const HttpRequestPtr &req, std::function<void(const HttpResponsePtr &)> &&callback, const std::string &scenario) {
            auto resp = HttpResponse::newHttpResponse();
            
            // Security: Only allow from localhost or with secret header
            std::string clientIP = AuditLog::getClientIP(req);
            std::string secretHeader = req->getHeader("X-Test-Secret");
            bool isLocalhost = (clientIP == "127.0.0.1" || clientIP == "::1" || clientIP.find("localhost") != std::string::npos);
            bool hasSecret = (secretHeader == "rpi-provisioner-test-2024");
            
            if (!isLocalhost && !hasSecret) {
                resp->setStatusCode(k404NotFound);
                resp->setBody("Not Found");
                callback(resp);
                return;
            }
            
            LOG_INFO << "Test mode request: scenario=" << scenario << " from " << clientIP;
            
            // Inject the test topology
            injectTestTopology(scenario);
            
            Json::Value result;
            result["status"] = "ok";
            result["scenario"] = scenario;
            result["testMode"] = testModeEnabled.load();
            result["availableScenarios"] = Json::arrayValue;
            result["availableScenarios"].append("direct");   // 4 devices directly on root ports
            result["availableScenarios"].append("hub");      // 7-port hub with 5 devices
            result["availableScenarios"].append("nested");   // 3-level nested hubs
            result["availableScenarios"].append("deep");     // Max depth (5 hubs) chain
            result["availableScenarios"].append("max");      // Near 127 device limit
            result["availableScenarios"].append("mixed");    // Mixed topology
            result["availableScenarios"].append("clear");    // Disable test mode
            result["availableScenarios"].append("off");      // Alias for clear
            
            Json::FastWriter writer;
            resp->setStatusCode(k200OK);
            resp->setContentTypeCode(CT_APPLICATION_JSON);
            resp->setBody(writer.write(result));
            callback(resp);
        }); // devices/_test/{scenario} handler

        // Test mode status endpoint
        app.registerHandler("/devices/_test", [](const HttpRequestPtr &req, std::function<void(const HttpResponsePtr &)> &&callback) {
            auto resp = HttpResponse::newHttpResponse();
            
            // Security: Only allow from localhost or with secret header
            std::string clientIP = AuditLog::getClientIP(req);
            std::string secretHeader = req->getHeader("X-Test-Secret");
            bool isLocalhost = (clientIP == "127.0.0.1" || clientIP == "::1" || clientIP.find("localhost") != std::string::npos);
            bool hasSecret = (secretHeader == "rpi-provisioner-test-2024");
            
            if (!isLocalhost && !hasSecret) {
                resp->setStatusCode(k404NotFound);
                resp->setBody("Not Found");
                callback(resp);
                return;
            }
            
            Json::Value result;
            result["testMode"] = testModeEnabled.load();
            result["availableScenarios"] = Json::arrayValue;
            result["availableScenarios"].append("direct");
            result["availableScenarios"].append("hub");
            result["availableScenarios"].append("nested");
            result["availableScenarios"].append("deep");
            result["availableScenarios"].append("max");
            result["availableScenarios"].append("mixed");
            result["availableScenarios"].append("clear");
            result["availableScenarios"].append("off");
            result["description"] = Json::objectValue;
            result["description"]["direct"] = "4 devices connected directly to root ports";
            result["description"]["hub"] = "Single 7-port hub with 5 devices";
            result["description"]["nested"] = "3-level nested hub hierarchy";
            result["description"]["deep"] = "Maximum depth (5 external hubs) chain";
            result["description"]["max"] = "Near USB maximum (127 devices)";
            result["description"]["mixed"] = "Mixed topology with direct, hub, and nested devices";
            result["description"]["clear"] = "Disable test mode, return to real USB scanning";
            
            Json::FastWriter writer;
            resp->setStatusCode(k200OK);
            resp->setContentTypeCode(CT_APPLICATION_JSON);
            resp->setBody(writer.write(result));
            callback(resp);
        }); // devices/_test handler
    }

    
} // namespace provisioner

