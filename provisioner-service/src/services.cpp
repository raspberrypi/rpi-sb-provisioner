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

#include "services.h"

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

            // Define the regex patterns for services to include
            std::regex servicePattern("^(rpi-sb|rpi-naked|rpi-fde)");
            
            // Get a list of all units from systemd
            sd_bus_message *m = nullptr;
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
                
                auto resp = drogon::HttpResponse::newHttpResponse();
                resp->setStatusCode(drogon::k500InternalServerError);
                resp->setBody("Failed to list systemd units");
                callback(resp);
                return;
            }

            // Parse the response
            r = sd_bus_message_enter_container(m, SD_BUS_TYPE_ARRAY, "(ssssssouso)");
            if (r < 0) {
                LOG_ERROR << "Failed to parse response: " << strerror(-r);
                sd_bus_message_unref(m);
                sd_bus_unref(bus);
                
                auto resp = drogon::HttpResponse::newHttpResponse();
                resp->setStatusCode(drogon::k500InternalServerError);
                resp->setBody("Failed to parse systemd response");
                callback(resp);
                return;
            }

            // Iterate through all units
            while ((r = sd_bus_message_enter_container(m, SD_BUS_TYPE_STRUCT, "ssssssouso")) > 0) {
                const char *name, *description, *load_state, *active_state, *sub_state;
                
                // Read the first 5 string fields of the struct
                r = sd_bus_message_read(m, "sssss", &name, &description, &load_state, &active_state, &sub_state);
                if (r < 0) {
                    LOG_ERROR << "Failed to parse unit data: " << strerror(-r);
                    continue;
                }
                
                // Skip remaining fields in the struct
                sd_bus_message_skip(m, "ouso");
                sd_bus_message_exit_container(m);
                
                // Check if the service matches our pattern
                std::string serviceName(name);
                if (std::regex_search(serviceName, servicePattern)) {
                    ServiceInfo info;
                    info.name = serviceName;
                    info.status = sub_state;
                    info.active = active_state;
                    serviceInfos.push_back(info);
                    LOG_INFO << "Found service: " << info.name << ", status: " << info.status << ", active: " << info.active;
                }
            }
            
            sd_bus_message_unref(m);
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
                    serviceArray.append(serviceObj);
                }
                
                Json::Value rootObj;
                rootObj["services"] = serviceArray;
                
                resp->setStatusCode(drogon::k200OK);
                resp->setContentTypeCode(drogon::CT_APPLICATION_JSON);
                resp->setBody(rootObj.toStyledString());
            } else {
                // Return HTML view
                drogon::HttpViewData viewData;
                std::vector<std::map<std::string, std::string>> serviceMaps;
                for (const auto& info : serviceInfos) {
                    std::map<std::string, std::string> serviceMap;
                    serviceMap["name"] = info.name;
                    serviceMap["status"] = info.status;
                    serviceMap["active"] = info.active;
                    serviceMaps.push_back(serviceMap);
                }
                viewData.insert("services", serviceMaps);
                viewData.insert("currentPage", std::string("services"));
                LOG_INFO << "View data populated with " << serviceMaps.size() << " services";
                resp = drogon::HttpResponse::newHttpViewResponse("services.csp", viewData);
            }
            
            callback(resp);
        });

        app.registerHandler("/service-log/{name}", [](const drogon::HttpRequestPtr &req, std::function<void(const drogon::HttpResponsePtr &)> &&callback, const std::string &name) {
            LOG_INFO << "Services::service-log for " << name;
            
            std::string serviceName = name;
            
            // Validate service name
            std::regex servicePattern("^(rpi-sb|rpi-naked|rpi-fde)[a-z0-9_.-]+$");
            if (!std::regex_match(serviceName, servicePattern)) {
                auto resp = drogon::HttpResponse::newHttpResponse();
                resp->setStatusCode(drogon::k400BadRequest);
                resp->setBody("Invalid service name");
                callback(resp);
                return;
            }
            
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