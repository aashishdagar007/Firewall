if(NOT DEFINED AEGIS_EXECUTABLE OR NOT EXISTS "${AEGIS_EXECUTABLE}")
    message(FATAL_ERROR "AEGIS_EXECUTABLE must name the built Windows executable")
endif()
if(NOT DEFINED AEGIS_DESTINATION OR NOT IS_DIRECTORY "${AEGIS_DESTINATION}")
    message(FATAL_ERROR "AEGIS_DESTINATION must name an existing package staging directory")
endif()

set(_search_directories)
if(DEFINED AEGIS_DLL_DIRECTORY AND IS_DIRECTORY "${AEGIS_DLL_DIRECTORY}")
    list(APPEND _search_directories "${AEGIS_DLL_DIRECTORY}")
endif()

file(GET_RUNTIME_DEPENDENCIES
    EXECUTABLES "${AEGIS_EXECUTABLE}"
    RESOLVED_DEPENDENCIES_VAR _resolved_dependencies
    UNRESOLVED_DEPENDENCIES_VAR _unresolved_dependencies
    PRE_EXCLUDE_REGEXES "api-ms-.*" "ext-ms-.*" "Azure.*" "Hvsi.*" "Pdm.*" "wpax.*"
    POST_EXCLUDE_REGEXES ".*[Ww]indows.*"
    DIRECTORIES ${_search_directories}
)

if(_unresolved_dependencies)
    set(_filtered_unresolved)
    foreach(_item IN LISTS _unresolved_dependencies)
        string(TOLOWER "${_item}" _lower)
        if(NOT (_lower MATCHES "azure" OR _lower MATCHES "hvsi" OR _lower MATCHES "pdm" OR _lower MATCHES "wpax" OR _lower MATCHES "api-ms" OR _lower MATCHES "ext-ms"))
            list(APPEND _filtered_unresolved "${_item}")
        endif()
    endforeach()
    if(_filtered_unresolved)
        message(FATAL_ERROR "Windows runtime dependencies could not be resolved: ${_filtered_unresolved}")
    endif()
endif()

foreach(_dependency IN LISTS _resolved_dependencies)
    if(EXISTS "${_dependency}")
        file(COPY "${_dependency}" DESTINATION "${AEGIS_DESTINATION}")
    endif()
endforeach()

list(LENGTH _resolved_dependencies _dependency_count)
message(STATUS "Staged ${_dependency_count} non-system Windows runtime DLL dependencies")
