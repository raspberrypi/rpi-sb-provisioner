# Embed the IDP JSON schemas published by rpi-image-gen into a generated header.
#
# These schemas describe the image descriptions this service accepts, and
# rpi-image-gen is what produces those descriptions. Keeping a hand-written copy
# here meant keeping two definitions of the same contract in step by hand, which
# did not happen: the copy drifted into a loose shape check that accepted
# descriptions the on-device parser then rejected, and its provenance comment
# still pointed at a path that had since moved.
#
# Taking the schemas from a pinned rpi-image-gen makes the drift visible. It
# turns up as a diff when the pin is bumped, in review, rather than as a failed
# provisioning run on someone's bench.

# rpi_embed_schema(<json-file> <constant-name> <output-variable>)
#
# Appends a `constexpr std::string_view <constant-name>` holding the file's
# contents to <output-variable>.
function(rpi_embed_schema json_path constant_name out_var)
    if(NOT EXISTS "${json_path}")
        message(FATAL_ERROR
            "Schema not found: ${json_path}\n"
            "The pinned rpi-image-gen does not carry this file. If the schemas "
            "have moved, update the paths alongside RPI_IMAGE_GEN_TAG.")
    endif()

    file(READ "${json_path}" contents)

    # Record where it came from, so the generated header says what it is a copy
    # of without anyone having to go and look.
    file(RELATIVE_PATH json_relative_path "${rpi_image_gen_SOURCE_DIR}" "${json_path}")

    # The contents go into a raw string literal, so they must not contain its
    # terminator. Nothing legitimate would, but a schema that did would produce
    # a C++ file that fails to compile somewhere far from the cause.
    string(FIND "${contents}" ")json\"" terminator_at)
    if(NOT terminator_at EQUAL -1)
        message(FATAL_ERROR
            "${json_path} contains a raw string terminator; cannot embed it.")
    endif()

    set(${out_var} "${${out_var}}
    // From rpi-image-gen ${RPI_IMAGE_GEN_TAG}: ${json_relative_path}
    constexpr std::string_view ${constant_name} = R\"json(
${contents})json\";
" PARENT_SCOPE)
endfunction()
