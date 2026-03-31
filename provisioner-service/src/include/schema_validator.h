#pragma once

#include <json/json.h>
#include <string>
#include <vector>

namespace provisioner {
namespace schema {

    struct ValidationError {
        std::string path;
        std::string description;
    };

    struct ValidationResult {
        bool valid = true;
        std::vector<ValidationError> errors;

        Json::Value errorsToJson() const;
    };

    // Validate a full image.json document against the top-level schema.
    ValidationResult validateImageJson(const Json::Value& document);

    // Validate the provisionmap portion of an image.json.
    // Wraps layout.provisionmap as {"layout":{"provisionmap":[...]}} before
    // validating, matching the approach used by rpi-image-gen's pmap tool.
    ValidationResult validateProvisionmap(const Json::Value& document);

    // Run both validations and merge results.
    ValidationResult validateImageJsonFull(const Json::Value& document);

} // namespace schema
} // namespace provisioner
