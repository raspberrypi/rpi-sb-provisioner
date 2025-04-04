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

namespace provisioner {

    Services::Services() = default;

    Services::~Services() = default;

    void Services::registerHandlers(drogon::HttpAppFramework &app)
    {
        app.registerHandler("/services", [](const HttpRequestPtr &req, std::function<void(const HttpResponsePtr &)> &&callback) {
            LOG_INFO << "Services::services";

            std::vector<ServiceInfo> serviceInfos;
            sd_bus *bus = nullptr;
            sd_bus_error error = SD_BUS_ERROR_NULL;
            
            // Connect to the system bus
            int r = sd_bus_open_system(&bus);
            if (r < 0) {
                LOG_ERROR << "Failed to connect to system bus: " << strerror(-r);
                auto resp = HttpResponse::newHttpResponse();
                resp->setStatusCode(k500InternalServerError);
                resp->setBody("Failed to connect to system bus");
                callback(resp);
                return;
            }

            // Use D-Bus API as our method of service detection
            
            // Use a targeted approach with specific patterns instead of all units
            LOG_INFO << "Querying systemd for service patterns...";
            sd_bus_message *m = nullptr;
            
            // Use ListUnitsByPatterns to only get the units we're interested in
            r = sd_bus_call_method(bus,
                               "org.freedesktop.systemd1",
                               "/org/freedesktop/systemd1",
                               "org.freedesktop.systemd1.Manager",
                               "ListUnitsByPatterns",
                               &error,
                               &m,
                               "asas",
                               0, NULL,   // Match all states - empty array means all
                               3, "rpi-sb-*.service", "rpi-naked-*.service", "rpi-fde-*.service");
            
            if (r < 0) {
                LOG_ERROR << "Failed to call ListUnitsByPatterns: " << error.message;
                sd_bus_error_free(&error);
                sd_bus_unref(bus);
                auto resp = drogon::HttpResponse::newHttpResponse();
                resp->setStatusCode(drogon::k500InternalServerError);
                resp->setBody("Failed to list systemd units: " + std::string(error.message));
                callback(resp);
                return;
            }
            
            // Parse the response
            r = sd_bus_message_enter_container(m, SD_BUS_TYPE_ARRAY, "(ssssssouso)");
            if (r < 0) {
                LOG_ERROR << "Failed to enter array container: " << strerror(-r);
                sd_bus_message_unref(m);
                sd_bus_unref(bus);
                auto resp = drogon::HttpResponse::newHttpResponse();
                resp->setStatusCode(drogon::k500InternalServerError);
                resp->setBody("Failed to parse systemd response");
                callback(resp);
                return;
            }
            
            // Process all units returned
            int totalUnits = 0;
            std::vector<std::string> matchingUnitNames;
            
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
                
                totalUnits++;
                std::string serviceName(name);
                
                // Check for any rpi service
                if (serviceName.find("rpi-sb-") != std::string::npos ||
                    serviceName.find("rpi-naked-") != std::string::npos ||
                    serviceName.find("rpi-fde-") != std::string::npos) {
                    matchingUnitNames.push_back(serviceName);
                    
                    // Add matching unit to our service info list
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
                        info.status = sub_state;
                        info.active = active_state;
                        
                        // Get the last active timestamp for the service
                        info.timestamp = 0; // Default value
                        
                        // Try using journal to get timestamp (more reliable than D-Bus properties)
                        sd_journal *j;
                        int j_r = sd_journal_open(&j, SD_JOURNAL_LOCAL_ONLY);
                        if (j_r >= 0) {
                            // Add filter for the specific unit
                            std::string match = "_SYSTEMD_UNIT=" + serviceName;
                            j_r = sd_journal_add_match(j, match.c_str(), 0);
                            
                            if (j_r >= 0) {
                                // Seek to the latest entry
                                j_r = sd_journal_seek_tail(j);
                                if (j_r >= 0) {
                                    // Get the first (latest) entry
                                    j_r = sd_journal_previous(j);
                                    if (j_r > 0) {
                                        // Get the timestamp
                                        uint64_t usec;
                                        j_r = sd_journal_get_realtime_usec(j, &usec);
                                        if (j_r >= 0) {
                                            info.timestamp = usec;
                                            // Don't log success case to reduce noise
                                        } else {
                                            LOG_WARN << "Failed to get journal timestamp for " << serviceName << ": " << strerror(-j_r);
                                        }
                                    } else {
                                        // Don't log empty journal - normal for new services
                                    }
                                } else {
                                    LOG_WARN << "Failed to seek journal tail for " << serviceName << ": " << strerror(-j_r);
                                }
                            } else {
                                LOG_WARN << "Failed to add journal match for " << serviceName << ": " << strerror(-j_r);
                            }
                            sd_journal_close(j);
                        } else {
                            LOG_WARN << "Failed to open journal for " << serviceName << ": " << strerror(-j_r);
                        }
                        
                        // If we couldn't get a timestamp, use current time for active services and a lower value for failed
                        if (info.timestamp == 0) {
                            if (info.active == "active") {
                                // For active services, use current time (prioritize them)
                                struct timespec ts;
                                clock_gettime(CLOCK_REALTIME, &ts);
                                info.timestamp = (uint64_t)ts.tv_sec * 1000000 + (uint64_t)ts.tv_nsec / 1000;
                                // Reduced logging - no need to log fallback for active services
                            } else {
                                // For failed/inactive services, use a lower timestamp (older)
                                struct timespec ts;
                                clock_gettime(CLOCK_REALTIME, &ts);
                                // Subtract 1 hour to make them appear below active services
                                info.timestamp = ((uint64_t)ts.tv_sec - 3600) * 1000000 + (uint64_t)ts.tv_nsec / 1000;
                                // Reduced logging - no need to log fallback for inactive services
                            }
                        }
                        
                        serviceInfos.push_back(info);
                        // Removed detailed service addition logging
                    } else {
                        // Regular service - no need to log skipping
                        continue;
                    }
                }
                
                // Exit the struct container for this unit
                sd_bus_message_exit_container(m);
            }
            
            // Always exit the array container when done
            sd_bus_message_exit_container(m);
            sd_bus_message_unref(m);
            
            LOG_INFO << "Processed " << totalUnits << " units, found " << serviceInfos.size() << " matching services";
            
            // Sort services by timestamp (most recent first)
            std::sort(serviceInfos.begin(), serviceInfos.end(), 
                [](const ServiceInfo& a, const ServiceInfo& b) {
                    return a.timestamp > b.timestamp; // Descending order
                });
            
            // Removed detailed sorted services logging
            
            sd_bus_unref(bus);
            
            auto resp = drogon::HttpResponse::newHttpResponse();
            
            // Check the Accept header for JSON
            auto acceptHeader = req->getHeader("Accept");
            if (!acceptHeader.empty() && acceptHeader.find("application/json") != std::string::npos) {
                // Return JSON response
                Json::Value serviceArray(Json::arrayValue);
                
                for (const auto& info : serviceInfos) {
                    Json::Value serviceObj;
                    serviceObj["name"] = info.name;
                    serviceObj["status"] = info.status;
                    serviceObj["active"] = info.active;
                    serviceObj["instance"] = info.instance;
                    serviceObj["base_name"] = info.base_name;
                    
                    // Reconstruct the full service name for log links
                    std::string fullName;
                    if (!info.instance.empty()) {
                        fullName = info.name + info.instance + ".service";
                    } else {
                        fullName = info.name + ".service";
                    }
                    serviceObj["full_name"] = fullName;
                    
                    // Removed per-service JSON logging
                    
                    serviceArray.append(serviceObj);
                }
                
                // Minimal logging for JSON response
                
                Json::Value rootObj;
                rootObj["services"] = serviceArray;
                
                resp->setStatusCode(drogon::k200OK);
                resp->setContentTypeCode(drogon::CT_APPLICATION_JSON);
                std::string jsonOutput = rootObj.toStyledString();
                // Removed JSON output logging
                resp->setBody(jsonOutput);
                
                LOG_INFO << "JSON response prepared with " << serviceArray.size() << " services";
            } else {
                // Return HTML view
                drogon::HttpViewData viewData;
                std::vector<std::map<std::string, std::string>> serviceMaps;
                
                for (auto && info : serviceInfos) {
                    std::map<std::string, std::string> serviceMap;
                    
                    serviceMap["name"] = info.name;
                    serviceMap["status"] = info.status;
                    serviceMap["active"] = info.active;
                    serviceMap["instance"] = info.instance;
                    serviceMap["base_name"] = info.base_name;
                    
                    // Reconstruct the full service name for log links
                    std::string fullName;
                    if (!info.instance.empty()) {
                        fullName = info.name + info.instance + ".service";
                    } else {
                        fullName = info.name + ".service";
                    }
                    serviceMap["full_name"] = fullName;
                    
                    // Removed per-service UI logging
                    
                    serviceMaps.push_back(serviceMap);
                }
                viewData.insert("services", serviceMaps);
                viewData.insert("currentPage", std::string("services"));
                // Minimal view data logging
                resp = drogon::HttpResponse::newHttpViewResponse("services.csp", viewData);
                
                LOG_INFO << "HTML view prepared with " << serviceMaps.size() << " services";
            }
            
            callback(resp);
        });

        app.registerHandler("/service-log/{name}", [](const drogon::HttpRequestPtr &req, std::function<void(const drogon::HttpResponsePtr &)> &&callback, const std::string &name) {
            LOG_INFO << "Services::service-log for " << name;
            
            std::string serviceName = name;

            // Open the journal
            sd_journal *j;
            int r = sd_journal_open(&j, SD_JOURNAL_LOCAL_ONLY);
            if (r < 0) {
                LOG_ERROR << "Failed to open journal: " << strerror(-r);
                auto resp = drogon::HttpResponse::newHttpResponse();
                resp->setStatusCode(drogon::k500InternalServerError);
                resp->setBody("Failed to open journal");
                callback(resp);
                return;
            }
            
            // Add filter for the specific unit
            std::string match = "_SYSTEMD_UNIT=" + serviceName;
            r = sd_journal_add_match(j, match.c_str(), 0);
            if (r < 0) {
                LOG_ERROR << "Failed to add journal match: " << strerror(-r);
                sd_journal_close(j);
                auto resp = drogon::HttpResponse::newHttpResponse();
                resp->setStatusCode(drogon::k500InternalServerError);
                resp->setBody("Failed to filter journal");
                callback(resp);
                return;
            }
            
            // Seek to the end
            r = sd_journal_seek_tail(j);
            if (r < 0) {
                LOG_ERROR << "Failed to seek to end of journal: " << strerror(-r);
                sd_journal_close(j);
                auto resp = drogon::HttpResponse::newHttpResponse();
                resp->setStatusCode(drogon::k500InternalServerError);
                resp->setBody("Failed to seek in journal");
                callback(resp);
                return;
            }
            
            // Move back 200 log entries
            r = sd_journal_previous_skip(j, 200);
            if (r < 0) {
                LOG_ERROR << "Failed to skip backwards in journal: " << strerror(-r);
                sd_journal_close(j);
                auto resp = drogon::HttpResponse::newHttpResponse();
                resp->setStatusCode(drogon::k500InternalServerError);
                resp->setBody("Failed to navigate journal");
                callback(resp);
                return;
            }
            
            // Collect log entries
            std::vector<std::string> logEntries;
            while (sd_journal_next(j) > 0) {
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
                
                // Convert timestamp to readable format
                time_t secs = time / 1000000;
                struct tm tm;
                localtime_r(&secs, &tm);
                char timestr[64];
                strftime(timestr, sizeof(timestr), "%Y-%m-%d %H:%M:%S", &tm);
                
                // Add the formatted log entry
                std::string entry = std::string(timestr) + " " + message;
                logEntries.push_back(entry);
            }
            
            sd_journal_close(j);
            
            // Create the response
            auto resp = drogon::HttpResponse::newHttpResponse();
            
            // Create view data and return HTML
            drogon::HttpViewData viewData;
            viewData.insert("service_name", serviceName);
            viewData.insert("log_entries", logEntries);
            viewData.insert("currentPage", std::string("services"));
            resp = drogon::HttpResponse::newHttpViewResponse("service_log.csp", viewData);
            
            callback(resp);
        });
    }
} // namespace provisioner 