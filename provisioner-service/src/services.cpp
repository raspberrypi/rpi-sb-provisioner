#include <systemd/sd-bus.h>
#include <systemd/sd-journal.h>

// Suppress constants from systemd, in favour of trantor logging
#undef LOG_INFO
#undef LOG_ERROR
#undef LOG_WARN
#undef LOG_DEBUG
#undef LOG_TRACE
#undef LOG_FATAL
#undef LOG_SYSERR

#include <drogon/drogon.h>
// Bring in Drogon logging macros
#include <trantor/utils/Logger.h>
using namespace trantor;

#include <string>
#include <vector>
#include <regex>
#include <memory>
#include <unordered_set>
#include <sstream>
#include <algorithm>
#include <time.h>

#include <services.h>
#include "utils.h"
#include "include/audit.h"

namespace provisioner {

    Services::Services() = default;

    Services::~Services() = default;

    void Services::registerHandlers(drogon::HttpAppFramework &app)
    {
        // Add async services endpoint that does the heavy lifting
        app.registerHandler("/api/v2/services", [](const HttpRequestPtr &req, std::function<void(const HttpResponsePtr &)> &&callback) {
            using namespace trantor;
            LOG_INFO << "Services::api-services (async)";
            
            // Add audit log entry for handler access
            AuditLog::logHandlerAccess(req, "/api/v2/services");

            std::vector<ServiceInfo> serviceInfos;
            sd_bus *bus = nullptr;
            sd_bus_error error = SD_BUS_ERROR_NULL;
            
            // Connect to the system bus
            int r = sd_bus_open_system(&bus);
            if (r < 0) {
                LOG_ERROR << "Failed to connect to system bus: " << strerror(-r);
                auto resp = provisioner::utils::createErrorResponse(
                    req,
                    "Failed to connect to system bus",
                    drogon::k500InternalServerError,
                    "System Bus Error",
                    "BUS_CONNECT_ERROR",
                    std::string("Error: ") + strerror(-r)
                );
                callback(resp);
                return;
            }

            // =================================================================
            // STEP 1: Use journal to discover ALL services (active and historic)
            // =================================================================
            LOG_INFO << "Discovering services via systemd journal...";
            
            // Map of discovered service names to their timestamps
            std::unordered_map<std::string, uint64_t> discoveredServices;
            std::vector<std::string> matchingUnitNames;
            
            // Try direct journal command approach instead of pattern-based matching
            sd_journal *journal;
            int j_r = sd_journal_open(&journal, SD_JOURNAL_LOCAL_ONLY);
            if (j_r >= 0) {
                // Use journal to query for all unique _SYSTEMD_UNIT values
                LOG_INFO << "Searching journal for all systemd units...";
                
                // Process entries and look for matching patterns
                j_r = sd_journal_query_unique(journal, "_SYSTEMD_UNIT");
                if (j_r >= 0) {
                    const void *data;
                    size_t dataSize;
                    
                    // Get all unique unit values
                    j_r = sd_journal_enumerate_unique(journal, &data, &dataSize);
                    while (j_r > 0) {
                        std::string entry(static_cast<const char*>(data), dataSize);
                        if (entry.length() > 14) { // "_SYSTEMD_UNIT="
                            std::string unitName = entry.substr(14);

                            // Skip UI service
                            if (unitName.find("rpi-provisioner-ui") != std::string::npos) {
                                LOG_INFO << "Skipping UI service: " << unitName;
                                // Move to next unique value
                                j_r = sd_journal_enumerate_unique(journal, &data, &dataSize);
                                continue;
                            }
                            
                            // Check if the unit name is one we're interested in
                            if ((unitName.find("rpi-sb-") != std::string::npos && unitName.find(".service") != std::string::npos) ||
                                (unitName.find("rpi-") != std::string::npos && unitName.find("provisioner") != std::string::npos && 
                                 unitName.find(".service") != std::string::npos)) {

                                // This is a matching service - now find its most recent timestamp
                                sd_journal *unitJournal;
                                if (sd_journal_open(&unitJournal, SD_JOURNAL_LOCAL_ONLY) >= 0) {
                                    // Filter for this specific unit
                                    std::string match = "_SYSTEMD_UNIT=" + unitName;
                                    if (sd_journal_add_match(unitJournal, match.c_str(), match.length()) >= 0) {
                                        // Get the most recent entry
                                        if (sd_journal_seek_tail(unitJournal) >= 0 && 
                                            sd_journal_previous(unitJournal) > 0) {
                                            // Get the timestamp
                                            uint64_t timestamp;
                                            if (sd_journal_get_realtime_usec(unitJournal, &timestamp) >= 0) {
                                                // Successfully got timestamp
                                                discoveredServices[unitName] = timestamp;
                                                LOG_INFO << "Found service in journal: " << unitName;
                                            }
                                        }
                                    }
                                    sd_journal_close(unitJournal);
                                }
                            }
                        }
                        // Move to next unique value
                        j_r = sd_journal_enumerate_unique(journal, &data, &dataSize);
                    }
                } else {
                    LOG_WARN << "Failed to query unique journal entries: " << strerror(-j_r);
                }
                
                sd_journal_close(journal);
            } else {
                LOG_WARN << "Failed to open journal: " << strerror(-j_r);
            }
            
            LOG_INFO << "Journal discovery found " << discoveredServices.size() << " services";
            for (const auto& service : discoveredServices) {
                LOG_INFO << " - Discovered: " << service.first;
            }
            
            // =================================================================
            // STEP 2: Query systemd for current status of discovered services
            // =================================================================
            LOG_INFO << "Querying systemd for service states...";
            
            // Now we have all services from the journal, use systemd to get current status
            sd_bus_message *m = nullptr;
            
            // Use ListUnits to get status of all units
            r = sd_bus_call_method(bus,
                               "org.freedesktop.systemd1",
                               "/org/freedesktop/systemd1",
                               "org.freedesktop.systemd1.Manager",
                               "ListUnits",
                               &error,
                               &m,
                               "");
            
            if (r < 0) {
                LOG_ERROR << "Failed to call ListUnits: " << error.message;
                sd_bus_error_free(&error);
                sd_bus_unref(bus);
                auto resp = provisioner::utils::createErrorResponse(
                    req,
                    "Failed to list systemd units",
                    drogon::k500InternalServerError,
                    "Systemd Error",
                    "LIST_UNITS_ERROR",
                    std::string("Error: ") + error.message
                );
                callback(resp);
                return;
            }
            
            // Parse the response
            r = sd_bus_message_enter_container(m, SD_BUS_TYPE_ARRAY, "(ssssssouso)");
            if (r < 0) {
                LOG_ERROR << "Failed to enter array container: " << strerror(-r);
                sd_bus_message_unref(m);
                sd_bus_unref(bus);
                auto resp = provisioner::utils::createErrorResponse(
                    req,
                    "Failed to parse systemd response",
                    drogon::k500InternalServerError,
                    "Parsing Error",
                    "PARSE_RESPONSE_ERROR", 
                    std::string("Error: ") + strerror(-r)
                );
                callback(resp);
                return;
            }
            
            // Map of service name to its current status
            std::unordered_map<std::string, std::pair<std::string, std::string>> serviceStates;
            
            // Process all units returned by systemd
            while ((r = sd_bus_message_enter_container(m, SD_BUS_TYPE_STRUCT, "ssssssouso")) == 1) {
                const char *name, *description, *load_state, *active_state, *sub_state;
                
                // Read the first 5 string fields of the struct
                r = sd_bus_message_read(m, "sssss", &name, &description, &load_state, &active_state, &sub_state);
                if (r < 0) {
                    LOG_ERROR << "Failed to read unit data: " << strerror(-r);
                    // Skip remaining fields in the struct
                    sd_bus_message_skip(m, "souso");
                    sd_bus_message_exit_container(m);
                    continue;
                }
                
                // Skip remaining fields in the struct
                sd_bus_message_skip(m, "souso");
                
                // Store state information for this unit
                std::string serviceName(name);
                serviceStates[serviceName] = std::make_pair(std::string(active_state), std::string(sub_state));
                
                // Exit the struct container for this unit
                sd_bus_message_exit_container(m);
            }
            
            // Always exit the array container when done
            sd_bus_message_exit_container(m);
            sd_bus_message_unref(m);
            
            // =================================================================
            // STEP 3: Create service info objects for all discovered services
            // =================================================================
            for (const auto& service : discoveredServices) {
                std::string serviceName = service.first;
                uint64_t timestamp = service.second;
                
                ServiceInfo info;
                
                // Check if it's an instance unit (has @ symbol)
                size_t atPos = serviceName.find('@');
                if (atPos != std::string::npos && atPos + 1 < serviceName.length()) {
                    // It's an instance unit
                    std::string baseName = serviceName.substr(0, atPos+1);
                    std::string instanceParam = serviceName.substr(atPos+1);
                    
                    // Remove .service suffix if present
                    size_t servicePos = instanceParam.find(".service");
                    if (servicePos != std::string::npos) {
                        instanceParam = instanceParam.substr(0, servicePos);
                    }
                    
                    info.name = baseName;
                    info.instance = instanceParam;
                    
                    // Extract base name without @ for better grouping in UI
                    std::string baseServiceName = baseName;
                    if (!baseServiceName.empty() && baseServiceName.back() == '@') {
                        baseServiceName.pop_back();
                        info.base_name = baseServiceName;
                    }
                } else {
                    // Regular service without instance parameter
                    // Remove .service suffix if present
                    std::string baseName = serviceName;
                    size_t servicePos = baseName.find(".service");
                    if (servicePos != std::string::npos) {
                        baseName = baseName.substr(0, servicePos);
                    }
                    
                    info.name = baseName;
                    info.instance = "";
                    info.base_name = baseName;
                }
                
                // Set status from current state if available, otherwise mark as inactive
                if (serviceStates.find(serviceName) != serviceStates.end()) {
                    info.active = serviceStates[serviceName].first;
                    info.status = serviceStates[serviceName].second;
                    LOG_INFO << "Current state for " << serviceName << ": " 
                             << info.active << "/" << info.status;
                } else {
                    info.active = "inactive";
                    info.status = "completed";
                    LOG_INFO << "Service " << serviceName << " is no longer active, marking as completed";
                }
                
                // Use journal timestamp
                info.timestamp = timestamp;
                
                // Add to the service list
                serviceInfos.push_back(info);
                matchingUnitNames.push_back(serviceName);
            }
            
            LOG_INFO << "Found " << serviceInfos.size() << " matching services";
            
            // Log all units found for complete debugging
            LOG_INFO << "All units returned by systemd (" << matchingUnitNames.size() << "):";
            for (const auto& unit : matchingUnitNames) {
                LOG_INFO << " - " << unit;
            }
            
            // Sort services by timestamp (most recent first)
            std::sort(serviceInfos.begin(), serviceInfos.end(), 
                [](const ServiceInfo& a, const ServiceInfo& b) {
                    return a.timestamp > b.timestamp; // Descending order
                });
            
            // Removed detailed sorted services logging
            
            sd_bus_unref(bus);
            
            // Always return JSON response for this API endpoint
            Json::Value serviceArray(Json::arrayValue);
            
            for (const auto& info : serviceInfos) {
                Json::Value serviceObj;
                serviceObj["name"] = info.name;
                serviceObj["status"] = info.status;
                serviceObj["active"] = info.active;
                serviceObj["instance"] = info.instance;
                serviceObj["base_name"] = info.base_name;
                
                // Add timestamp in microseconds since epoch (will be converted to local time in frontend)
                serviceObj["timestamp"] = Json::Value::UInt64(info.timestamp);
                
                // Reconstruct the full service name for log links
                std::string fullName;
                if (!info.instance.empty()) {
                    fullName = info.name + info.instance + ".service";
                } else {
                    fullName = info.name + ".service";
                }
                serviceObj["full_name"] = fullName;
                
                serviceArray.append(serviceObj);
            }
            
            Json::Value rootObj;
            rootObj["services"] = serviceArray;
            
            auto resp = drogon::HttpResponse::newHttpJsonResponse(rootObj);
            LOG_INFO << "Async JSON response prepared with " << serviceArray.size() << " services";
            
            callback(resp);
        });

        // Add fast HTML-only services page that shows loading state
        app.registerHandler("/services", [](const HttpRequestPtr &req, std::function<void(const HttpResponsePtr &)> &&callback) {
            using namespace trantor;
            LOG_INFO << "Services::services (fast HTML)";
            
            // Add audit log entry for handler access
            AuditLog::logHandlerAccess(req, "/services");

            // Return HTML view immediately with empty services list
            drogon::HttpViewData viewData;
            std::vector<std::map<std::string, std::string>> serviceMaps; // Empty list
            
            viewData.insert("services", serviceMaps);
            viewData.insert("currentPage", std::string("services"));
            viewData.insert("loading", true); // Flag to show loading state
            
            auto resp = drogon::HttpResponse::newHttpViewResponse("services.csp", viewData);
            LOG_INFO << "Fast HTML view prepared with loading state";
            
            callback(resp);
        });

        app.registerHandler("/service-log/{name}", [](const drogon::HttpRequestPtr &req, std::function<void(const drogon::HttpResponsePtr &)> &&callback, const std::string &name) {
            using namespace trantor;
            LOG_INFO << "Services::service-log for " << name;
            
            // Add audit log entry for handler access
            AuditLog::logHandlerAccess(req, "/service-log/" + name);
            
            std::string serviceName = name;

            // Validate that the service name starts with one of the allowed prefixes
            if (serviceName.find("rpi-sb-") != 0 && 
                serviceName.find("rpi-naked-") != 0 && 
                serviceName.find("rpi-fde-") != 0) {
                LOG_INFO << "Rejected access to logs for unauthorized service: " << serviceName;
                auto resp = provisioner::utils::createErrorResponse(
                    req,
                    "Access denied: Only logs for rpi-sb, rpi-naked, and rpi-fde services are available",
                    drogon::k403Forbidden,
                    "Unauthorized Service",
                    "SERVICE_UNAUTHORIZED"
                );
                callback(resp);
                return;
            }

            // Log systemd log access to audit log
            AuditLog::logSystemdAccess(serviceName);

            // Parse pagination and ordering parameters
            int page = 1;
            int pageSize = 50;
            std::string order = "desc"; // Default to newest first
            
            auto pageParam = req->getParameter("page");
            if (!pageParam.empty()) {
                try {
                    page = std::stoi(pageParam);
                    if (page < 1) page = 1;
                } catch (...) {
                    page = 1;
                }
            }
            
            auto pageSizeParam = req->getParameter("page_size");
            if (!pageSizeParam.empty()) {
                try {
                    pageSize = std::stoi(pageSizeParam);
                    if (pageSize < 1) pageSize = 50;
                    if (pageSize > 500) pageSize = 500; // Cap at 500
                } catch (...) {
                    pageSize = 50;
                }
            }
            
            auto orderParam = req->getParameter("order");
            if (!orderParam.empty() && (orderParam == "asc" || orderParam == "desc")) {
                order = orderParam;
            }
            
            LOG_INFO << "Fetching logs: page=" << page << ", page_size=" << pageSize << ", order=" << order;

            // Open the journal
            sd_journal *j;
            int r = sd_journal_open(&j, SD_JOURNAL_LOCAL_ONLY);
            if (r < 0) {
                LOG_ERROR << "Failed to open journal: " << strerror(-r);
                auto resp = provisioner::utils::createErrorResponse(
                    req,
                    "Failed to open journal",
                    drogon::k500InternalServerError,
                    "Journal Error",
                    "JOURNAL_OPEN_ERROR", 
                    std::string("Error: ") + strerror(-r)
                );
                callback(resp);
                return;
            }
            
            // Add filter for the specific unit
            std::string match = "_SYSTEMD_UNIT=" + serviceName;
            r = sd_journal_add_match(j, match.c_str(), 0);
            if (r < 0) {
                LOG_ERROR << "Failed to add journal match: " << strerror(-r);
                sd_journal_close(j);
                auto resp = provisioner::utils::createErrorResponse(
                    req,
                    "Failed to filter journal",
                    drogon::k500InternalServerError,
                    "Journal Error",
                    "JOURNAL_FILTER_ERROR",
                    std::string("Error: ") + strerror(-r)
                );
                callback(resp);
                return;
            }
            
            // Count total entries for pagination metadata
            int totalEntries = 0;
            if (order == "desc") {
                sd_journal_seek_head(j);
            } else {
                sd_journal_seek_tail(j);
            }
            
            while ((order == "desc" ? sd_journal_next(j) : sd_journal_previous(j)) > 0) {
                totalEntries++;
            }
            
            int totalPages = (totalEntries + pageSize - 1) / pageSize;
            if (page > totalPages && totalPages > 0) page = totalPages;
            
            // Seek to appropriate position based on order and page
            if (order == "desc") {
                // Newest first: start from tail, go backwards
                sd_journal_seek_tail(j);
                int skipCount = (page - 1) * pageSize;
                if (skipCount > 0) {
                    sd_journal_previous_skip(j, skipCount);
                }
            } else {
                // Oldest first: start from head, go forwards
                sd_journal_seek_head(j);
                int skipCount = (page - 1) * pageSize;
                if (skipCount > 0) {
                    sd_journal_next_skip(j, skipCount);
                }
            }
            
            // Collect log entries for the current page
            std::vector<std::string> logEntries;
            int collected = 0;
            
            while (collected < pageSize && (order == "desc" ? sd_journal_previous(j) : sd_journal_next(j)) > 0) {
                const void *data;
                size_t length;
                
                // Get the log message
                r = sd_journal_get_data(j, "MESSAGE", &data, &length);
                if (r < 0) {
                    LOG_ERROR << "Failed to read log message: " << strerror(-r);
                    continue;
                }
                
                // Extract the actual message (skip "MESSAGE=" prefix)
                std::string message(static_cast<const char*>(data), length);
                if (message.substr(0, 8) == "MESSAGE=") {
                    message = message.substr(8);
                }
                
                // Get the timestamp
                uint64_t time;
                r = sd_journal_get_realtime_usec(j, &time);
                if (r < 0) {
                    LOG_ERROR << "Failed to get timestamp: " << strerror(-r);
                    continue;
                }
                
                // Convert timestamp to ISO 8601 format (UTC)
                time_t secs = time / 1000000;
                uint64_t usecs = time % 1000000;
                struct tm tm;
                gmtime_r(&secs, &tm);
                char timestr[64];
                strftime(timestr, sizeof(timestr), "%Y-%m-%dT%H:%M:%S", &tm);
                
                // Add milliseconds and Z suffix for ISO 8601 UTC format
                char isotimestr[80];
                snprintf(isotimestr, sizeof(isotimestr), "%s.%03ldZ", timestr, usecs / 1000);
                
                // Add the formatted log entry
                std::string entry = std::string(isotimestr) + " " + message;
                logEntries.push_back(entry);
                collected++;
            }
            
            // If order is desc, we collected backwards, so reverse to show newest first
            if (order == "desc") {
                std::reverse(logEntries.begin(), logEntries.end());
            }
            
            sd_journal_close(j);
            
            // Create the response
            auto resp = drogon::HttpResponse::newHttpResponse();
            
            // Check if JSON format is requested
            auto acceptHeader = req->getHeader("Accept");
            if (!acceptHeader.empty() && acceptHeader.find("application/json") != std::string::npos) {
                // Return JSON response for polling updates
                Json::Value root;
                Json::Value logArray(Json::arrayValue);
                
                for (const auto& entry : logEntries) {
                    logArray.append(entry);
                }
                
                root["logs"] = logArray;
                root["service_name"] = serviceName;
                root["page"] = page;
                root["page_size"] = pageSize;
                root["total_entries"] = totalEntries;
                root["total_pages"] = totalPages;
                root["order"] = order;
                
                resp->setStatusCode(drogon::k200OK);
                resp->setContentTypeCode(drogon::CT_APPLICATION_JSON);
                resp->setBody(root.toStyledString());
            } else {
                // Create view data and return HTML
                drogon::HttpViewData viewData;
                viewData.insert("service_name", serviceName);
                viewData.insert("log_entries", logEntries);
                viewData.insert("currentPage", std::string("services"));
                viewData.insert("auto_refresh", true); // Flag to enable auto-refresh in template
                viewData.insert("page", page);
                viewData.insert("page_size", pageSize);
                viewData.insert("total_entries", totalEntries);
                viewData.insert("total_pages", totalPages);
                viewData.insert("order", order);
                resp = drogon::HttpResponse::newHttpViewResponse("service_log.csp", viewData);
            }
            
            callback(resp);
        });

        // Add JSON-only endpoint for polling service logs
        app.registerHandler("/api/v2/service-log/{name}", [](const drogon::HttpRequestPtr &req, std::function<void(const drogon::HttpResponsePtr &)> &&callback, const std::string &name) {
            using namespace trantor;
            LOG_INFO << "Services::api-service-log for " << name;
            
            // Add audit log entry for handler access
            AuditLog::logHandlerAccess(req, "/api/v2/service-log/" + name);
            
            std::string serviceName = name;

            // Validate that the service name starts with one of the allowed prefixes
            if (serviceName.find("rpi-sb-") != 0 && 
                serviceName.find("rpi-naked-") != 0 && 
                serviceName.find("rpi-fde-") != 0) {
                LOG_INFO << "Rejected access to logs for unauthorized service: " << serviceName;
                auto resp = provisioner::utils::createErrorResponse(
                    req,
                    "Access denied: Only logs for rpi-sb, rpi-naked, and rpi-fde services are available",
                    drogon::k403Forbidden,
                    "Unauthorized Service",
                    "SERVICE_UNAUTHORIZED",
                    "Requested service: " + serviceName
                );
                callback(resp);
                return;
            }

            // Log systemd log access to audit log
            AuditLog::logSystemdAccess(serviceName);

            // Parse pagination and ordering parameters
            int page = 1;
            int pageSize = 50;
            std::string order = "desc"; // Default to newest first
            
            auto pageParam = req->getParameter("page");
            if (!pageParam.empty()) {
                try {
                    page = std::stoi(pageParam);
                    if (page < 1) page = 1;
                } catch (...) {
                    page = 1;
                }
            }
            
            auto pageSizeParam = req->getParameter("page_size");
            if (!pageSizeParam.empty()) {
                try {
                    pageSize = std::stoi(pageSizeParam);
                    if (pageSize < 1) pageSize = 50;
                    if (pageSize > 500) pageSize = 500; // Cap at 500
                } catch (...) {
                    pageSize = 50;
                }
            }
            
            auto orderParam = req->getParameter("order");
            if (!orderParam.empty() && (orderParam == "asc" || orderParam == "desc")) {
                order = orderParam;
            }
            
            LOG_INFO << "API fetching logs: page=" << page << ", page_size=" << pageSize << ", order=" << order;

            // Open the journal
            sd_journal *j;
            int r = sd_journal_open(&j, SD_JOURNAL_LOCAL_ONLY);
            if (r < 0) {
                LOG_ERROR << "Failed to open journal: " << strerror(-r);
                auto resp = provisioner::utils::createErrorResponse(
                    req,
                    "Failed to open journal",
                    drogon::k500InternalServerError,
                    "Journal Error",
                    "JOURNAL_OPEN_ERROR", 
                    std::string("Error: ") + strerror(-r)
                );
                callback(resp);
                return;
            }
            
            // Add filter for the specific unit
            std::string match = "_SYSTEMD_UNIT=" + serviceName;
            r = sd_journal_add_match(j, match.c_str(), 0);
            if (r < 0) {
                LOG_ERROR << "Failed to add journal match: " << strerror(-r);
                sd_journal_close(j);
                auto resp = provisioner::utils::createErrorResponse(
                    req,
                    "Failed to filter journal",
                    drogon::k500InternalServerError,
                    "Journal Error",
                    "JOURNAL_FILTER_ERROR",
                    std::string("Error: ") + strerror(-r)
                );
                callback(resp);
                return;
            }
            
            // Count total entries for pagination metadata
            int totalEntries = 0;
            if (order == "desc") {
                sd_journal_seek_head(j);
            } else {
                sd_journal_seek_tail(j);
            }
            
            while ((order == "desc" ? sd_journal_next(j) : sd_journal_previous(j)) > 0) {
                totalEntries++;
            }
            
            int totalPages = (totalEntries + pageSize - 1) / pageSize;
            if (page > totalPages && totalPages > 0) page = totalPages;
            
            // Seek to appropriate position based on order and page
            if (order == "desc") {
                // Newest first: start from tail, go backwards
                sd_journal_seek_tail(j);
                int skipCount = (page - 1) * pageSize;
                if (skipCount > 0) {
                    sd_journal_previous_skip(j, skipCount);
                }
            } else {
                // Oldest first: start from head, go forwards
                sd_journal_seek_head(j);
                int skipCount = (page - 1) * pageSize;
                if (skipCount > 0) {
                    sd_journal_next_skip(j, skipCount);
                }
            }
            
            // Collect log entries for the current page
            std::vector<std::string> logEntries;
            int collected = 0;
            
            while (collected < pageSize && (order == "desc" ? sd_journal_previous(j) : sd_journal_next(j)) > 0) {
                const void *data;
                size_t length;
                
                // Get the log message
                r = sd_journal_get_data(j, "MESSAGE", &data, &length);
                if (r < 0) {
                    continue;
                }
                
                // Extract the actual message
                std::string message(static_cast<const char*>(data), length);
                if (message.substr(0, 8) == "MESSAGE=") {
                    message = message.substr(8);
                }
                
                // Get the timestamp
                uint64_t time;
                r = sd_journal_get_realtime_usec(j, &time);
                if (r < 0) {
                    continue;
                }
                
                // Convert timestamp to ISO 8601 format (UTC)
                time_t secs = time / 1000000;
                uint64_t usecs = time % 1000000;
                struct tm tm;
                gmtime_r(&secs, &tm);
                char timestr[64];
                strftime(timestr, sizeof(timestr), "%Y-%m-%dT%H:%M:%S", &tm);
                
                // Add milliseconds and Z suffix for ISO 8601 UTC format
                char isotimestr[80];
                snprintf(isotimestr, sizeof(isotimestr), "%s.%03ldZ", timestr, usecs / 1000);
                
                // Add the formatted log entry
                std::string entry = std::string(isotimestr) + " " + message;
                logEntries.push_back(entry);
                collected++;
            }
            
            // If order is desc, we collected backwards, so reverse to show newest first
            if (order == "desc") {
                std::reverse(logEntries.begin(), logEntries.end());
            }
            
            sd_journal_close(j);
            
            // Return JSON response
            Json::Value root;
            Json::Value logArray(Json::arrayValue);
            
            for (const auto& entry : logEntries) {
                logArray.append(entry);
            }
            
            root["logs"] = logArray;
            root["service_name"] = serviceName;
            root["page"] = page;
            root["page_size"] = pageSize;
            root["total_entries"] = totalEntries;
            root["total_pages"] = totalPages;
            root["order"] = order;
            
            auto resp = drogon::HttpResponse::newHttpJsonResponse(root);
            callback(resp);
        });
    }
} // namespace provisioner 