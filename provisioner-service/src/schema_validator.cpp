#include "include/schema_validator.h"
#include "include/schemas.h"

#include <valijson/adapters/jsoncpp_adapter.hpp>
#include <valijson/schema.hpp>
#include <valijson/schema_parser.hpp>
#include <valijson/validator.hpp>
#include <valijson/validation_results.hpp>

#include <sstream>

namespace provisioner {
namespace schema {

    namespace {
        // Parse a JSON string into a Json::Value, fatal on failure.
        Json::Value parseSchemaString(std::string_view src) {
            Json::Value root;
            Json::CharReaderBuilder builder;
            std::string errors;
            std::istringstream stream{std::string(src)};
            if (!Json::parseFromStream(builder, stream, &root, &errors)) {
                throw std::runtime_error("Failed to parse embedded schema: " + errors);
            }
            return root;
        }

        // Build a valijson::Schema from a parsed JSON schema document.
        valijson::Schema buildSchema(const Json::Value& schemaJson) {
            valijson::Schema schema;
            valijson::SchemaParser parser;
            valijson::adapters::JsonCppAdapter adapter(schemaJson);
            parser.populateSchema(adapter, schema);
            return schema;
        }

        // Thread-safe lazy singletons via Meyers' pattern.
        const valijson::Schema& getImageJsonSchema() {
            static const valijson::Schema schema = [] {
                auto json = parseSchemaString(kImageJsonSchema);
                return buildSchema(json);
            }();
            return schema;
        }

        const valijson::Schema& getProvisionmapSchema() {
            static const valijson::Schema schema = [] {
                auto json = parseSchemaString(kProvisionmapSchema);
                return buildSchema(json);
            }();
            return schema;
        }

        // Run a valijson schema against a document and collect errors.
        ValidationResult runValidation(const valijson::Schema& schema, const Json::Value& document) {
            ValidationResult result;
            valijson::Validator validator;
            valijson::ValidationResults valResults;
            valijson::adapters::JsonCppAdapter adapter(document);

            result.valid = validator.validate(schema, adapter, &valResults);

            if (!result.valid) {
                valijson::ValidationResults::Error error;
                while (valResults.popError(error)) {
                    std::string path;
                    for (const auto& segment : error.context) {
                        path += segment;
                    }
                    result.errors.push_back({path, error.description});
                }
            }
            return result;
        }
    } // anonymous namespace

    Json::Value ValidationResult::errorsToJson() const {
        Json::Value arr(Json::arrayValue);
        for (const auto& e : errors) {
            Json::Value obj;
            obj["path"] = e.path;
            obj["description"] = e.description;
            arr.append(obj);
        }
        return arr;
    }

    ValidationResult validateImageJson(const Json::Value& document) {
        return runValidation(getImageJsonSchema(), document);
    }

    ValidationResult validateProvisionmap(const Json::Value& document) {
        // Only validate if provisionmap is present; its absence is allowed
        // (not all images use a provisionmap).
        if (!document.isMember("layout") ||
            !document["layout"].isMember("provisionmap") ||
            !document["layout"]["provisionmap"].isArray() ||
            document["layout"]["provisionmap"].empty()) {
            return {true, {}};
        }

        // Wrap the provisionmap as the schema expects it, matching
        // the approach used by rpi-image-gen's pmap validation tool.
        Json::Value wrapped;
        wrapped["layout"]["provisionmap"] = document["layout"]["provisionmap"];
        return runValidation(getProvisionmapSchema(), wrapped);
    }

    ValidationResult validateImageJsonFull(const Json::Value& document) {
        auto topResult = validateImageJson(document);
        auto pmapResult = validateProvisionmap(document);

        if (!pmapResult.valid) {
            topResult.valid = false;
            topResult.errors.insert(topResult.errors.end(),
                                    pmapResult.errors.begin(),
                                    pmapResult.errors.end());
        }
        return topResult;
    }

} // namespace schema
} // namespace provisioner
