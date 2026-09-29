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
    PRE_EXCLUDE_REGEXES "api-ms-win-.*" "ext-ms-win-.*"
    POST_EXCLUDE_REGEXES ".*[Ww]indows[/\\\\](System32|WinSxS)[/\\\\].*"
    DIRECTORIES ${_search_directories}
)

if(_unresolved_dependencies)
    message(FATAL_ERROR "Windows runtime dependencies could not be resolved: ${_unresolved_dependencies}")
endif()

foreach(_dependency IN LISTS _resolved_dependencies)
    if(EXISTS "${_dependency}")
        file(COPY "${_dependency}" DESTINATION "${AEGIS_DESTINATION}")
    endif()
endforeach()

list(LENGTH _resolved_dependencies _dependency_count)
message(STATUS "Staged ${_dependency_count} non-system Windows runtime DLL dependencies")
