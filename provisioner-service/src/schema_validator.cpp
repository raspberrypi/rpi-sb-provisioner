#include "include/schema_validator.h"
#include "schemas_generated.h"

#include <valijson/adapters/jsoncpp_adapter.hpp>
#include <valijson/schema.hpp>
#include <valijson/schema_parser.hpp>
#include <valijson/validator.hpp>
#include <valijson/validation_results.hpp>

#include <cctype>
#include <cstdint>
#include <functional>
#include <sstream>
#include <string>

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
        // ===== Checks a JSON Schema cannot make =====
        //
        // The schema fixes the shape of a description. It cannot say whether a
        // value means anything, and the on-device parser in rpi-fastbootd
        // rejects several that a schema accepts. Anything checked here is
        // checked because rpiidp checks it: the point is to fail on this
        // machine, where the file is in hand and the operator is watching,
        // rather than on a bench part-way through provisioning a board.

        // Parse a genimage-style size: digits with an optional K/M/G/s suffix,
        // exactly as fromGIsz() in rpiidp/src/parser.cpp reads it. Returns
        // false on anything that function would throw over -- which, until it
        // was guarded, took the whole fastboot daemon down with it.
        bool parseGenimageSize(const std::string& text, uint64_t& out) {
            size_t digits = 0;
            while (digits < text.size() &&
                   std::isdigit(static_cast<unsigned char>(text[digits]))) {
                ++digits;
            }
            if (digits == 0) {
                return false;
            }

            uint64_t value = 0;
            try {
                value = std::stoull(text.substr(0, digits));
            } catch (const std::exception&) {
                return false; // longer than a uint64 can hold
            }

            const std::string suffix = text.substr(digits);
            uint64_t multiplier = 1;
            if (suffix.empty())                          multiplier = 1;
            else if (suffix == "K" || suffix == "k")     multiplier = 1024ULL;
            else if (suffix == "M" || suffix == "m")     multiplier = 1024ULL * 1024;
            else if (suffix == "G" || suffix == "g")     multiplier = 1024ULL * 1024 * 1024;
            else if (suffix == "s")                      multiplier = 512ULL;
            else return false;

            if (value != 0 && multiplier > UINT64_MAX / value) {
                return false;
            }
            out = value * multiplier;
            return true;
        }

        void checkSemantics(const Json::Value& document, ValidationResult& result) {
            auto reject = [&result](const char* path, std::string description) {
                result.valid = false;
                result.errors.push_back({path, std::move(description)});
            };

            // rpiidp only registers a parser for IG major version 2, so a
            // document announcing any other major is refused outright. The
            // schema checks the semver shape but not which major it names.
            const Json::Value& igversion = document["IGversion"];
            if (igversion.isString()) {
                const std::string text = igversion.asString();
                const size_t dot = text.find('.');
                if (dot != std::string::npos && text.substr(0, dot) != "2") {
                    reject("IGversion",
                           "unsupported image generator major version in '" + text +
                           "'; the device parses version 2 descriptions");
                }
            }

            // image-palign-bytes is a string, so the schema cannot tell 1M from
            // 1MB. The device reads it as a genimage size and requires a whole
            // number of mebibytes.
            const Json::Value& palign = document["attributes"]["image-palign-bytes"];
            if (palign.isString()) {
                const std::string text = palign.asString();
                uint64_t bytes = 0;
                if (!parseGenimageSize(text, bytes)) {
                    reject("attributes/image-palign-bytes",
                           "'" + text + "' is not a size the device can read; "
                           "expected digits with an optional K, M, G or s suffix");
                } else if (bytes == 0 || bytes % (1024ULL * 1024) != 0) {
                    reject("attributes/image-palign-bytes",
                           "'" + text + "' is not a multiple of 1MiB");
                }
            }

            // Every partition reference in the provisionmap names an entry in
            // partitionimages. A name with nothing behind it leaves the device
            // with a map it cannot resolve.
            //
            // Walked recursively rather than at fixed depths. A reference can
            // sit directly under a flat layout, inside an A or B slot, or below
            // an encrypted node, and the set of places grows with the format --
            // enumerating them here is how this check would quietly stop
            // matching anything. An object carrying a string "image" is a
            // partition reference wherever it appears; a crypt container has no
            // image because it is created on the device, and is skipped by the
            // same rule.
            const Json::Value& images = document["layout"]["partitionimages"];
            const Json::Value& pmap = document["layout"]["provisionmap"];
            if (images.isObject() && pmap.isArray()) {
                std::function<void(const Json::Value&)> walk = [&](const Json::Value& node) {
                    if (node.isArray()) {
                        for (const auto& child : node) walk(child);
                        return;
                    }
                    if (!node.isObject()) {
                        return;
                    }
                    const Json::Value& image = node["image"];
                    if (image.isString() && !images.isMember(image.asString())) {
                        reject("layout/provisionmap",
                               "names partition image '" + image.asString() +
                               "', which is not in layout.partitionimages");
                    }
                    for (const auto& child : node) walk(child);
                };
                walk(pmap);
            }
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

        // Only worth asking once the shape holds: these read named fields, and
        // on a document that failed the schema they would mostly restate what
        // the schema already said.
        if (topResult.valid) {
            checkSemantics(document, topResult);
        }
        return topResult;
    }

} // namespace schema
} // namespace provisioner
