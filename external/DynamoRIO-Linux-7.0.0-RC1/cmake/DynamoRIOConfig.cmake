# **********************************************************
# Copyright (c) 2010-2017 Google, Inc.    All rights reserved.
# Copyright (c) 2009-2010 VMware, Inc.    All rights reserved.
# **********************************************************

# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
#
# * Redistributions of source code must retain the above copyright notice,
#   this list of conditions and the following disclaimer.
#
# * Redistributions in binary form must reproduce the above copyright notice,
#   this list of conditions and the following disclaimer in the documentation
#   and/or other materials provided with the distribution.
#
# * Neither the name of VMware, Inc. nor the names of its contributors may be
#   used to endorse or promote products derived from this software without
#   specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
# AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
# ARE DISCLAIMED. IN NO EVENT SHALL VMWARE, INC. OR CONTRIBUTORS BE LIABLE
# FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
# DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
# SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
# CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
# LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
# OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH
# DAMAGE.

###########################################################################
#
# How to use:
#
# Step 1 of 2: load this file in your client's CMakeLists.txt file:
#
#   find_package(DynamoRIO)
#
# You can optionally specify the version number you need:
#
#   find_package(DynamoRIO 1.4)
#
# If DynamoRIO is not installed in standard system directories, set
# the DynamoRIO_DIR variable to tell find_package() where to find
# DynamoRIO's cmake/ directory:
#
#   cmake -DDynamoRIO_DIR=/path/to/dynamorio/cmake <path/to/myclient/sources>
#
# Step 2 of 2: after you've defined your target, configure it using the
# configure_DynamoRIO_client() function defined in this file.
# For example:
#
#  add_library(myclient SHARED myclient.c)
#  configure_DynamoRIO_client(myclient)
#
###########
#
# Standalone usage:
#
# If instead of a client you are using DynamoRIO as a standalone library,
# use the configure_DynamoRIO_standalone() function:
#
#  add_executable(myapp myapp.c)
#  configure_DynamoRIO_standalone(myapp)
#
# If using the drconfig (dr_config.h) and/or drinject (dr_inject.h) API's,
# you also need to explicitly link with those libraries:
#
#  target_link_libraries(myapp drinjectlib drconfiglib)
#
###########
#
# Decoder usage:
#
# If instead of a client you are using DynamoRIO's static decoder library,
# use the configure_DynamoRIO_decoder() function:
#
#  add_executable(myapp myapp.c)
#  configure_DynamoRIO_decoder(myapp)
#
###########
#
# Static DynamoRIO usage:
#
# If you are statically linking DynamoRIO and your client into your application,
# use the configure_DynamoRIO_static() function:
#
#  add_executable(myapp myapp.c)
#  configure_DynamoRIO_static(myapp)
#
# To link in a separately-built static client and ensure the linker will keep
# its symbols, use:
#
#  use_DynamoRIO_static_client(myapp myclient)
#
###########
#
# Global changes:
#
# Due to CMake limitations, this file must set some global values:
# - include directories
# - compiler flags
#
# In order to set the compiler flags, the base flags are emptied out:
# - CMAKE_C_FLAGS
# - CMAKE_CXX_FLAGS
# - CMAKE_C_FLAGS_${CMAKE_BUILD_TYPE_UPPER}
# - CMAKE_CXX_FLAGS_${CMAKE_BUILD_TYPE_UPPER}
# - CMAKE_C_FLAGS_${CMAKE_CONFIGURATION_TYPES} (for each, uppercase)
# - CMAKE_CXX_FLAGS_${CMAKE_CONFIGURATION_TYPES} (for each, uppercase)
#
# None of the global changes occur on the find_package(); they are only
# implemented on the first configure_DynamoRIO_*() call.  Optionally,
# they can be triggered earlier by calling configure_DynamoRIO_global().
# The original cflag values are saved in variables with the prefix ORIG_
# followed by the variable name (e.g., ORIG_CMAKE_C_FLAGS).
# These flags are set in the configure_DynamoRIO_*() functions via
# PARENT_SCOPE.  If you want to call these functions from another
# function, you must first call configure_DynamoRIO_global() from
# global scope ahead of time.
#
# The compiler flags are not changed when using
# configure_DynamoRIO_decoder().
#
# Various properties of the targets passed to configure_DynamoRIO_*()
# are set, so any prior values will be lost, and if later values are
# added after the configure call they should be appended.
#
# The preprocessor definitions that are added to the compiler flags
# can be retrieved via the function get_DynamoRIO_defines().
#
###########
#
# Optional parameters:
#
# By default, the RPATH is not set for clients, but is set for standalone usage.
# If this variable is set it overrides the default behavior:
#
#  set(DynamoRIO_RPATH ON)
#
# In addition to setting DT_RPATH for ELF files, on Windows or Android this will
# create a <client_basename>.drpath text file that contains a list of paths.  At
# runtime, DynamoRIO's loader will parse this file and add each newline-separated
# path to its list of search paths.  On Android, it is up to the caller to
# convert the build directory paths to remote paths appropriate for the target
# device.
#
# If you are not exporting all global symbols in your Linux client,
# this file tries to automatically determine that and explicitly mark
# required client exports as visible.  The auto-detection can be
# overridden by setting this variable before calling the
# configure_DynamoRIO_client():
#
#  set(DynamoRIO_VISATT ON)
#
# To request the old REG_ enum symbols (which were changed to DR_REG_ to
# avoid conflicts with system headers) set this variable:
#
#  set(DynamoRIO_REG_COMPATIBILITY ON)
#
# To request that PAGE_SIZE and PAGE_START be defined set this variable:
#
#  set(DynamoRIO_PAGE_SIZE_COMPATIBILITY ON)
#
# To request a preferred base even when not targeting 64-bit:
# (the actual base will use PREFERRED_BASE if set)
#
#  set(DynamoRIO_SET_PREFERRED_BASE ON)
#
# On Windows, by default, all clients link with the C library.
# A standalone client or a C++ client (or a client using the drsyms
# static library) must link with the C library.
# A C client, however, can be made more lightweight (and also reduce
# its exposure to transparency corner cases) by avoiding the C library
# by turning off this variable:
#
#  set(DynamoRIO_USE_LIBC OFF)
#
# To request fast IR access (at the cost of binary compatibility):
#
#  set(DynamoRIO_FAST_IR ON)
#
###########
#
# Annotations:
#
# To include DynamoRIO annotations in an application, the annotation source files
# will need to be compiled and linked into the application, and additional
# configuration steps must be taken. Function use_DynamoRIO_annotations()
# simplifies this process. The following example configures `my_target` to use
# annotations, and appends the annotation sources to the list variable `my_target_srcs`
# (which must then be included in the call to add_executable(), add_library(), etc.):
#
#   use_DynamoRIO_annotations(my_target my_target_srcs)
#
# To define custom annotations in a DynamoRIO client, it will be most convenient for
# the target application developers to have a function similar to
# use_DynamoRIO_annotations() that configures their target for use of the custom
# annotations. A recommended approach is to model this new configuration function on
# use_DynamoRIO_annotations(), with the source paths replaced appropriately. The following
# global steps are required to complete the configuration of custom annotations:
#
#   (1) copy the custom annotation sources and headers into the annotation export
#       directory (as specified in the new configuration function).
#   (2) copy "dr_annotations_asm.h" into that same annotation export directory.
#   (3) add the annotation export directory to the includes using include_directories().
#
###########
#
# Exported utility functions:
#
# DynamoRIO_add_rel_rpaths(target library)
#    This function takes in a target and a list of libraries and adds
#    relative rpaths pointing to the directories of the libraries.
#
###########################################################################

# Naming conventions:
# As this is included directly into the user's configuration, we have to be careful
# to avoid namespace conflicts.  Internal (global) variables and helper functions
# should have a "_DR_" prefix.  Public functions and variables should have DynamoRIO
# in the name.

if ("${CMAKE_VERSION}" VERSION_EQUAL "3.0" OR
    "${CMAKE_VERSION}" VERSION_GREATER "3.0")
  # XXX i#1557: update our code to satisfy the changes in 3.x
  cmake_policy(PUSH)
  cmake_policy(SET CMP0026 OLD)
endif ()



# sets CMAKE_COMPILER_IS_CLANG and CMAKE_COMPILER_IS_GNUCC in parent scope
function (_DR_identify_clang)
  # Assume clang behaves like gcc.  CMake 2.6 won't detect clang and will set
  # CMAKE_COMPILER_IS_GNUCC to TRUE, but 2.8 does not.  We prefer the 2.6
  # behavior.
  string(REGEX MATCH "clang" CMAKE_COMPILER_IS_CLANG "${CMAKE_C_COMPILER}")
  if (CMAKE_COMPILER_IS_CLANG)
    set(CMAKE_COMPILER_IS_GNUCC TRUE PARENT_SCOPE)
  else ()
    if (CMAKE_C_COMPILER MATCHES "/cc")
      # CMake 2.8.10 on Mac has CMAKE_C_COMPILER as "/usr/bin/cc"
      execute_process(COMMAND ${CMAKE_C_COMPILER} --version
        OUTPUT_VARIABLE cc_out ERROR_QUIET)
      if (cc_out MATCHES "clang")
        set(CMAKE_COMPILER_IS_CLANG ON)
        set(CMAKE_COMPILER_IS_GNUCC TRUE PARENT_SCOPE)
      endif ()
    endif ()
  endif ()
  set(CMAKE_COMPILER_IS_CLANG ${CMAKE_COMPILER_IS_CLANG} PARENT_SCOPE)
endfunction (_DR_identify_clang)

function (_DR_append_property_string type target name value)
  # XXX: if we require cmake 2.8.6 we can simply use APPEND_STRING
  get_property(cur ${type} ${target} PROPERTY ${name})
  if (cur)
    set(value "${cur} ${value}")
  endif (cur)
  set_property(${type} ${target} PROPERTY ${name} "${value}")
endfunction (_DR_append_property_string)

# Drops the last path element from path and stores it in path_out.
function (_DR_dirname path_out path)
  string(REGEX REPLACE "/[^/]*$" "" path "${path}")
  set(${path_out} "${path}" PARENT_SCOPE)
endfunction (_DR_dirname)

# Takes in a target and a list of libraries and adds relative rpaths
# pointing to the directories of the libraries.
#
# By default, CMake sets an absolute rpath to the build directory, which it
# strips at install time.  By adding our own relative rpath, so long as the
# target and its libraries stay in the same layout relative to each other,
# the loader will be able to find the libraries.  We assume that the layout
# is the same in the build and install directories.
function (DynamoRIO_add_rel_rpaths target)
  if (UNIX AND NOT ANDROID) # No DT_RPATH support on Android
    # Turn off the default CMake rpath setting and add our own LINK_FLAGS.
    set_target_properties(${target} PROPERTIES SKIP_BUILD_RPATH ON)
    foreach (lib ${ARGN})
      # Compute the relative path between the directory of the target and the
      # library it is linked against.
      get_target_property(tgt_path ${target} LOCATION)
      get_target_property(lib_path ${lib} LOCATION)
      _DR_dirname(tgt_path "${tgt_path}")
      _DR_dirname(lib_path "${lib_path}")
      file(RELATIVE_PATH relpath "${tgt_path}" "${lib_path}")

      # Append the new rpath element if it isn't there already.
      if (APPLE)
        # @loader_path seems to work for executables too
        set(new_lflag "-Wl,-rpath,'@loader_path/${relpath}'")
        get_target_property(lflags ${target} LINK_FLAGS)
        # We match the trailing ' to avoid matching a parent dir only
        if (NOT lflags MATCHES "@loader_path/${relpath}'")
          _DR_append_property_string(TARGET ${target} LINK_FLAGS "${new_lflag}")
        endif ()
      else (APPLE)
        set(new_lflag "-Wl,-rpath='$ORIGIN/${relpath}'")
        get_target_property(lflags ${target} LINK_FLAGS)
        if (NOT lflags MATCHES "\$ORIGIN/${relpath}")
          _DR_append_property_string(TARGET ${target} LINK_FLAGS "${new_lflag}")
        endif ()
      endif ()
    endforeach ()
  endif ()
endfunction (DynamoRIO_add_rel_rpaths)

# Check if we're using GNU gold.  We use CMAKE_C_COMPILER in
# CMAKE_C_LINK_EXECUTABLE, so call the compiler instead of CMAKE_LINKER.  That
# way we query the linker that the compiler actually uses.
function (_DR_check_if_linker_is_gnu_gold var_out)
  if (WIN32)
    # We don't support gold on Windows.  We only support the MSVC toolchain.
    set(is_gold OFF)
  else ()
    if (APPLE)
      # Running through gcc results in failing exit code so run ld directly:
      set(linkver ${CMAKE_LINKER};-v)
    else (APPLE)
      set(linkver ${CMAKE_C_COMPILER};-Wl,--version)
    endif (APPLE)
    execute_process(COMMAND ${linkver}
      RESULT_VARIABLE ld_result
      ERROR_QUIET  # gcc's collect2 always writes to stderr, so ignore it.
      OUTPUT_VARIABLE ld_out)
    set(is_gold OFF)
    if (ld_result)
      message("failed to get linker version, assuming ld.bfd (${ld_result})")
    elseif ("${ld_out}" MATCHES "GNU gold")
      set(is_gold ON)
    endif ()
  endif ()
  set(${var_out} ${is_gold} PARENT_SCOPE)
endfunction (_DR_check_if_linker_is_gnu_gold)

function (DynamoRIO_get_target_path_for_execution out target device_base_dir)
  get_target_property(abspath ${target} LOCATION${location_suffix})
  if (NOT ${device_base_dir} STREQUAL "")
    get_filename_component(builddir ${PROJECT_BINARY_DIR} NAME)
    file(RELATIVE_PATH relpath "${PROJECT_BINARY_DIR}" "${abspath}")
    set(${out} ${device_base_dir}/${builddir}/${relpath} PARENT_SCOPE)
  else ()
    set(${out} ${abspath} PARENT_SCOPE)
  endif ()
endfunction (DynamoRIO_get_target_path_for_execution)

function (DynamoRIO_prefix_cmd_if_necessary cmd_out use_ats cmd_in)
  if (ANDROID)
    if (use_ats)
      set(${cmd_out} "adb@shell@${cmd_in}${ARGN}" PARENT_SCOPE)
    else ()
      set(${cmd_out} adb shell ${cmd_in} ${ARGN} PARENT_SCOPE)
    endif ()
  else ()
    set(${cmd_out} ${cmd_in} ${ARGN} PARENT_SCOPE)
  endif ()
endfunction (DynamoRIO_prefix_cmd_if_necessary)

function (DynamoRIO_copy_target_to_device target device_base_dir)
  get_target_property(abspath ${target} LOCATION${location_suffix})
  get_filename_component(builddir ${PROJECT_BINARY_DIR} NAME)
  file(RELATIVE_PATH relpath "${PROJECT_BINARY_DIR}" "${abspath}")
  add_custom_command(TARGET ${target} POST_BUILD
    COMMAND ${ADB} push ${abspath} ${device_base_dir}/${builddir}/${relpath}
    VERBATIM)
endfunction (DynamoRIO_copy_target_to_device)

# On Linux, the individual object files contained by an archive are
# garbage collected by the linker if they are not referenced.  To avoid
# this, we have to use the --whole-archive option with ld.
function(DynamoRIO_force_static_link target lib)
  if (UNIX)
    # CMake ignores libraries starting with '-' and preserves the
    # ordering, so we can pass flags through target_link_libraries, which
    # ensures we have the right CMake dependencies.
    target_link_libraries(${target} -Wl,--whole-archive ${lib} -Wl,--no-whole-archive)
  else ()
    # There is no equivalent for MSVC.  The best we can do is keep a client in place,
    # for our caller in use_DynamoRIO_static_client().
    target_link_libraries(${target} ${lib})
    if (X64)
      set(incname "dr_client_main")
    else ()
      set(incname "_dr_client_main")
    endif ()
    append_property_string(TARGET ${target} LINK_FLAGS "/include:${incname}")
  endif ()
endfunction(DynamoRIO_force_static_link)


if (UNIX)
  _DR_identify_clang()
  if (NOT CMAKE_COMPILER_IS_GNUCC)
    # Our linker script is GNU-specific
    message(FATAL_ERROR "DynamoRIO's CMake configuration only supports the GNU linker on Linux")
  endif (NOT CMAKE_COMPILER_IS_GNUCC)
else (UNIX)
  if (NOT ${COMPILER_BASE_NAME} STREQUAL "cl")
    # Our link flags are Microsoft-specific
    message(FATAL_ERROR "DynamoRIO's CMake configuration only supports the Microsoft compiler on Windows")
  endif (NOT ${COMPILER_BASE_NAME} STREQUAL "cl")
endif (UNIX)

# We'll be included at the same scope as the containing project, so use
# a prefixed var name for globals.
get_filename_component(DynamoRIO_cwd "${CMAKE_CURRENT_LIST_FILE}" PATH)

# Export variables in case client needs custom configuration that
# our exported functions do not provide.
# Additionally, only set if not already defined, to allow
# for further customization.
if (NOT DEFINED DynamoRIO_INCLUDE_DIRS)
  set(DynamoRIO_INCLUDE_DIRS "${DynamoRIO_cwd}/../include")
endif (NOT DEFINED DynamoRIO_INCLUDE_DIRS)

# Officially CMAKE_BUILD_TYPE is supposed to be ignored for VS generators so
# users may not have set it (xref i#1392).
if (NOT DEFINED CMAKE_BUILD_TYPE)
  if (DEBUG)
    set(CMAKE_BUILD_TYPE "Debug")
  else ()
    set(CMAKE_BUILD_TYPE "RelWithDebInfo")
  endif()
endif ()
string(TOUPPER "${CMAKE_BUILD_TYPE}" CMAKE_BUILD_TYPE_UPPER)

if (NOT DEFINED DynamoRIO_USE_LIBC)
  # i#714: the default is now ON
  set(DynamoRIO_USE_LIBC ON)
endif ()

if (CMAKE_SYSTEM_PROCESSOR MATCHES "^arm")
  set(ARM 1) # This means AArch32.
elseif (CMAKE_SYSTEM_PROCESSOR MATCHES "^aarch64")
  set(AARCH64 1)
else ()
  set(X86 1) # This means IA-32 or AMD64
endif ()

if (WIN32 OR ANDROID)
  set(USE_DRPATH ON)
else ()
  set(USE_DRPATH OFF)
endif ()


###########################################################################
#
# Define functions the client can use to set up build parameters:

# For VS generator we need to use a suffix on LOCATION to avoid having
# "$(Configuration)" in the resulting path.
if ("${CMAKE_GENERATOR}" MATCHES "Visual Studio")
  if (DEBUG OR "${CMAKE_BUILD_TYPE}" MATCHES "Debug")
    set(_DR_location_suffix "_DEBUG")
  else ()
    set(_DR_location_suffix "_RELWITHDEBINFO")
  endif ()
else ("${CMAKE_GENERATOR}" MATCHES "Visual Studio")
  set(_DR_location_suffix "")
endif ("${CMAKE_GENERATOR}" MATCHES "Visual Studio")

_DR_check_if_linker_is_gnu_gold(LINKER_IS_GNU_GOLD)

# helper function
function (_DR_get_lang target lang_var)
  # Note that HAS_CXX and LINKER_LANGUAGE are only defined it
  # explicitly set: can't be used to distinguish CXX vs C.
  get_target_property(sources ${target} SOURCES)
  foreach (src ${sources})
    # LANGUAGE, however, is set for us
    get_source_file_property(src_lang ${src} LANGUAGE)
    if (NOT DEFINED tgt_lang)
      set(tgt_lang ${src_lang})
    elseif (${src_lang} MATCHES CXX)
      # If any source file is cxx, mark as cxx
      set(tgt_lang ${src_lang})
    endif (NOT DEFINED tgt_lang)
  endforeach (src)

  set(${lang_var} ${tgt_lang} PARENT_SCOPE)
endfunction (_DR_get_lang)


# helper function
function (_DR_get_size is_cxx x64_var)
  if (is_cxx)
    set(sizeof_void ${CMAKE_CXX_SIZEOF_DATA_PTR})
  else (is_cxx)
    set(sizeof_void ${CMAKE_C_SIZEOF_DATA_PTR})
  endif (is_cxx)

  if ("${sizeof_void}" STREQUAL "")
    message(FATAL_ERROR "unable to determine bitwidth: did earlier ABI tests fail?  check CMakeFiles/CMakeError.log")
  endif ("${sizeof_void}" STREQUAL "")

  if (${sizeof_void} EQUAL 8)
    set(${x64_var} ON PARENT_SCOPE)
  else (${sizeof_void} EQUAL 8)
    set(${x64_var} OFF PARENT_SCOPE)
  endif (${sizeof_void} EQUAL 8)
endfunction (_DR_get_size)

# i#955: support a <basename>.drpath file for loader search paths
function (_DR_get_drpath_name out target)
  get_target_property(client_path ${target} LOCATION${_DR_location_suffix})
  # NAME_WE chops off from the first . instead of the last . so we use regex:
  string(REGEX REPLACE "\\.[^\\.]*$" "" client_base ${client_path})
  set(${out} ${client_base}.drpath PARENT_SCOPE)
endfunction (_DR_get_drpath_name)

function (_DR_set_compile_flags target tgt_cflags)
  # i#850: we do not want the C flags being used for asm objects so we only set
  # on C/C++ files and not on the target.
  # We do want the defines and include dirs to be global (or at least on the
  # asm targets if using cpp2asm...)
  # First, convert "/D FOO" to "/DFOO" for easier list conversion
  string(REGEX REPLACE " /D " " /D" tgt_cflags_list "${tgt_cflags}")
  # Now convert to list
  string(REGEX REPLACE " " ";" tgt_cflags_list "${tgt_cflags_list}")
  foreach (flag ${tgt_cflags_list})
    if (flag MATCHES "^[-/]D" OR flag MATCHES "^[-/]I")
      set(tgt_definc "${tgt_definc} ${flag}")
    else ()
      set(tgt_flags ${tgt_flags} ${flag})
    endif ()
  endforeach (flag)
  get_target_property(srcs ${target} SOURCES)
  foreach (src ${srcs})
    get_source_file_property(lang ${src} LANGUAGE)
    if ("${lang}" STREQUAL "C" OR "${lang}" STREQUAL "CXX" AND
        # do not add COMPILE_FLAGS to an .obj file else VS2008 will try to
        # compile the file!
        NOT src MATCHES "\\.obj$")
      # i#1396: don't double-add in case the same source file is in multiple
      # DR client/standalone targets.
      # We can't do a test of the entire flag set at once b/c we add
      # "-fno-stack-protector" for the client and not for standalone.
      get_source_file_property(cur_flags ${src} COMPILE_FLAGS)
      foreach (flag ${tgt_flags})
        if (NOT cur_flags MATCHES " ${flag}")
          _DR_append_property_string(SOURCE ${src} COMPILE_FLAGS "${flag}")
        endif ()
      endforeach ()
    endif ()
  endforeach (src)

  set_target_properties(${target} PROPERTIES COMPILE_FLAGS "${tgt_definc}")
endfunction(_DR_set_compile_flags)

if (NOT DynamoRIO_INTERNAL)
  # Global config once per project.
  # We want to do this on the find_package() to avoid any additional export
  # sets failing to find these targets (DrMem i#1400), so we try to figure
  # out whether we should take bitwidth from C++ or C globally
  if (CMAKE_CXX_COMPILER_WORKS)
    set(_DR_is_cxx ON)
  else ()
    set(_DR_is_cxx OFF)
  endif ()
  _DR_get_size(${_DR_is_cxx} _DR_is_x64)

  if (_DR_is_x64)
    set(_DR_bits 64)
  else (_DR_is_x64)
    set(_DR_bits 32)
  endif (_DR_is_x64)

  if (DEBUG OR "${CMAKE_BUILD_TYPE}" MATCHES "Debug")
    set(_DR_type debug)
  else ()
    set(_DR_type release)
  endif ()

  # if we were built w/ static drsyms, clients need dependent static libs too
  if (UNIX AND EXISTS "${DynamoRIO_cwd}/../ext/lib${_DR_bits}/${_DR_type}/libdwarf.a")
    add_library(elf STATIC IMPORTED)
    set_property(TARGET elf PROPERTY
      IMPORTED_LOCATION "${DynamoRIO_cwd}/../ext/lib${_DR_bits}/${_DR_type}/libelf.a")
    add_library(dwarf STATIC IMPORTED)
    set_property(TARGET dwarf PROPERTY
      IMPORTED_LOCATION "${DynamoRIO_cwd}/../ext/lib${_DR_bits}/${_DR_type}/libdwarf.a")
    add_library(elftc STATIC IMPORTED)
    set_property(TARGET elftc PROPERTY
      IMPORTED_LOCATION "${DynamoRIO_cwd}/../ext/lib${_DR_bits}/${_DR_type}/libelftc.a")
  endif ()
  if (WIN32 AND EXISTS "${DynamoRIO_cwd}/../ext/lib${_DR_bits}/${_DR_type}/dwarf.lib")
    add_library(dwarf STATIC IMPORTED)
    set_property(TARGET dwarf PROPERTY
      IMPORTED_LOCATION "${DynamoRIO_cwd}/../ext/lib${_DR_bits}/${_DR_type}/dwarf.lib")
    add_library(elftc STATIC IMPORTED)
    set_property(TARGET elftc PROPERTY
      IMPORTED_LOCATION "${DynamoRIO_cwd}/../ext/lib${_DR_bits}/${_DR_type}/elftc.lib")
  endif ()

  # Define imported target for DynamoRIO library, to allow dependencies on
  # the library and trigger client rebuild on DynamoRIO upgrade:
  # We always link to release build.  At runtime debug build can be
  # swapped in instead.
  # We assume _DR_is_x64 can have only one value per configuration.
  include(${DynamoRIO_cwd}/DynamoRIOTarget${_DR_bits}.cmake)

  # i#1804: when running from build dirs we can't easily append to the Target
  # file, so we use a separate Map file and include it here.
  if (EXISTS ${DynamoRIO_cwd}/DynamoRIOMap${_DR_bits}.cmake)
    include(${DynamoRIO_cwd}/DynamoRIOMap${_DR_bits}.cmake)
  endif ()
endif (NOT DynamoRIO_INTERNAL)

# Unfortunately, CMake doesn't support removing flags on a per-target basis,
# or per-target include dirs or link dirs, so we have to make global changes.
# We don't want find_package() to incur those changes: only if a target
# is actually configured.
# The is_cxx parameter does not matter much: this routine can be called
# with is_cxx=OFF and C++ clients will still be configured properly,
# unless the C++ compiler and the C compiler are configured for
# different bitwidths.
function (configure_DynamoRIO_global is_cxx change_flags)
  # We need to perform some global config once per cmake directory.
  # We want it to work even if the caller puts code in a function
  # (=> no PARENT_SCOPE var) and we want to re-execute on each re-config
  # (=> no CACHE INTERNAL).  A global property w/ the listdir in the name
  # fits the bill.  Xref i#1052.
  # CMAKE_CURRENT_LIST_DIR wasn't added until CMake 2.8.3 (i#1056).
  get_filename_component(caller_dir "${CMAKE_CURRENT_LIST_FILE}" PATH)
  get_property(already_configured_listdir GLOBAL PROPERTY
    DynamoRIO_configured_globally_${caller_dir})
  if (NOT DEFINED already_configured_listdir)
    set_property(GLOBAL PROPERTY
      DynamoRIO_configured_globally_${caller_dir} ON)

    # If called from another function, indicate whether to propagate
    # with a variable that does not make it up to global scope
    if (nested_scope)
      set(just_configured ON PARENT_SCOPE)
    endif (nested_scope)

    include_directories(${DynamoRIO_INCLUDE_DIRS})

    if (change_flags)
      # Remove global C flags that are unsafe for a client library.
      # Since CMake does not support removing flags on a per-target basis,
      # we clear the base flags so we can add what we want to each target.
      foreach (config "" ${CMAKE_BUILD_TYPE} ${CMAKE_CONFIGURATION_TYPES})
        if ("${config}" STREQUAL "")
          set(config_upper "")
        else ("${config}" STREQUAL "")
          string(TOUPPER "_${config}" config_upper)
        endif ("${config}" STREQUAL "")
        foreach (var CMAKE_C_FLAGS${config_upper};CMAKE_CXX_FLAGS${config_upper})
          if ("${${var}}" STREQUAL "" OR NOT DEFINED ${var})
            # Empty string will trip the NOT DEFINED ORIG_CMAKE_C_FLAGS check below
            set(${var} " ")
          endif ()
          set(ORIG_${var} "${${var}}" PARENT_SCOPE)
          set(local_${var} "${${var}}")
          if (WIN32)
            # We could limit this global var changing to Windows,
            # but it simplifies cross-platform uses to be symmetric
            if (local_${var} MATCHES "/M[TD]")
              string(REGEX REPLACE "/M[TD]" "/MT" local_${var} "${local_${var}}")
            else ()
              set(local_${var} "${local_${var}} /MT")
            endif ()
            string(REGEX REPLACE "/RTC." "" local_${var} "${local_${var}}")
          endif (WIN32)
          set(CLIENT_${var} "${CLIENT_${var}} ${local_${var}}" PARENT_SCOPE)
          if (UNIX AND X86 AND ${var} MATCHES "-m32")
            set(base_var_value "-m32")
          else ()
            # If we set to "", the default values come back
            set(base_var_value " ")
          endif ()
          set(${var} "${base_var_value}" PARENT_SCOPE)
        endforeach (var)
      endforeach (config)
    endif (change_flags)

  else (NOT DEFINED already_configured_listdir)
    # We can detect failure to propagate to global scope on the 2nd client
    # in the same listdir.
    # XXX: is there any way we can have better support for functions?
    # I spent a while trying to use CACHE INTERNAL FORCE to set the
    # global vars but it has all kinds of weird consequences for other
    # vars based on the original values of the now-cache vars.
    # This behavior varies by generator and I never found a solution
    # that worked for all generators.  Ninja was easy, but VS and Makefiles
    # ended up with ORIG_* set to the blank values, even when ORIG_*
    # was marked as cache.  Plus, Dr. Memory's SAVE_* values ended up
    # w/ the cache value as well.
    if (NOT DEFINED ORIG_CMAKE_C_FLAGS)
      message(FATAL_ERROR "When invoking configure_DynamoRIO_*() from a function, "
        "configure_DynamoRIO_global() must be called from global scope first.")
    endif (NOT DEFINED ORIG_CMAKE_C_FLAGS)
  endif (NOT DEFINED already_configured_listdir)
endfunction (configure_DynamoRIO_global)

# get_DynamoRIO_defines assumes that only defines are added by
# DynamoRIO_extra_cflags
function (DynamoRIO_extra_cflags flags_out extra_cflags tgt_cxx)
  _DR_get_size(${tgt_cxx} tgt_x64)
  if (tgt_x64)
    if (AARCH64)
      set(extra_cflags "${extra_cflags} -DARM_64")
    else ()
      set(extra_cflags "${extra_cflags} -DX86_64")
    endif ()
  else (tgt_x64)
    if (ARM)
      set(extra_cflags "${extra_cflags} -DARM_32")
    else ()
      set(extra_cflags "${extra_cflags} -DX86_32")
    endif ()
  endif (tgt_x64)

  if (UNIX)
    if (APPLE)
      set(extra_cflags "${extra_cflags} -DMACOS")
    else (APPLE)
      set(extra_cflags "${extra_cflags} -DLINUX")
      if (ANDROID)
        set(extra_cflags "${extra_cflags} -DANDROID")
      endif (ANDROID)
    endif (APPLE)
    if (CMAKE_COMPILER_IS_CLANG)
      set(extra_cflags "${extra_cflags} -DCLANG")
    endif (CMAKE_COMPILER_IS_CLANG)
  else (UNIX)
    set(extra_cflags "${extra_cflags} -DWINDOWS")
  endif (UNIX)

  if (DynamoRIO_REG_COMPATIBILITY)
    set(extra_cflags "${extra_cflags} -DDR_REG_ENUM_COMPATIBILITY")
  endif (DynamoRIO_REG_COMPATIBILITY)

  if (DynamoRIO_PAGE_SIZE_COMPATIBILITY)
    set(extra_cflags "${extra_cflags} -DDR_PAGE_SIZE_COMPATIBILITY")
  endif (DynamoRIO_PAGE_SIZE_COMPATIBILITY)

  if (DynamoRIO_FAST_IR)
    set(extra_cflags "${extra_cflags} -DDR_FAST_IR")
    if (NOT tgt_cxx AND CMAKE_COMPILER_IS_GNUCC)
      # we require C99 for our extern inline functions to work properly
      set(extra_cflags "${extra_cflags} -std=gnu99")
    endif ()
  endif (DynamoRIO_FAST_IR)

  set(${flags_out} "${extra_cflags}" PARENT_SCOPE)
endfunction (DynamoRIO_extra_cflags)

function (configure_DynamoRIO_common target is_client x64_var defs_var)
  _DR_get_lang(${target} tgt_lang)
  if (${tgt_lang} MATCHES CXX)
    set(tgt_cxx ON)
  else (${tgt_lang} MATCHES CXX)
    set(tgt_cxx OFF)
  endif (${tgt_lang} MATCHES CXX)

  set(nested_scope ON) # for propagation
  configure_DynamoRIO_global(${tgt_cxx} ON)
  if (just_configured)
    # get around lack of GLOBAL_SCOPE
    set(just_configured ON PARENT_SCOPE)
    foreach (config "" ${CMAKE_BUILD_TYPE} ${CMAKE_CONFIGURATION_TYPES})
      if ("${config}" STREQUAL "")
        set(config_upper "")
      else ("${config}" STREQUAL "")
        string(TOUPPER "_${config}" config_upper)
      endif ("${config}" STREQUAL "")
      foreach (var CMAKE_C_FLAGS${config_upper};CMAKE_CXX_FLAGS${config_upper})
        set(ORIG_${var} "${ORIG_${var}}" PARENT_SCOPE)
        set(CLIENT_${var} "${CLIENT_${var}}" PARENT_SCOPE)
        set(${var} "${${var}}" PARENT_SCOPE)
      endforeach (var)
    endforeach (config)
  endif (just_configured)

  # we ignore per-config flags here
  if (is_client)
    if (tgt_cxx)
      set(tgt_cflags
        "${CLIENT_CMAKE_CXX_FLAGS} ${CLIENT_CMAKE_CXX_FLAGS_${CMAKE_BUILD_TYPE_UPPER}}")
    else (tgt_cxx)
      set(tgt_cflags
        "${CLIENT_CMAKE_C_FLAGS} ${CLIENT_CMAKE_C_FLAGS_${CMAKE_BUILD_TYPE_UPPER}}")
    endif (tgt_cxx)
  else (is_client)
    if (tgt_cxx)
      set(tgt_cflags
        "${ORIG_CMAKE_CXX_FLAGS} ${ORIG_CMAKE_CXX_FLAGS_${CMAKE_BUILD_TYPE_UPPER}}")
    else (tgt_cxx)
      set(tgt_cflags
        "${ORIG_CMAKE_C_FLAGS} ${ORIG_CMAKE_C_FLAGS_${CMAKE_BUILD_TYPE_UPPER}}")
    endif (tgt_cxx)
    if (WIN32)
      # For standalone we want the original flags, but we need to
      # explicitly link in static libc prior to dynamorio.lib to avoid
      # conflicts w/ ntdll forwards, so we don't support dynamic libc
      # (xref i#686) (or /MT since it puts libc last but we manipulate
      # that later).
      if (tgt_cflags MATCHES "/MD")
        string(REGEX REPLACE "/MD" "/MT" tgt_cflags "${tgt_cflags}")
      else ()
        set(tgt_cflags "${tgt_cflags} /MT")
      endif ()
    endif (WIN32)
  endif (is_client)

  if (tgt_cflags MATCHES "/MT" AND tgt_cflags MATCHES "/MTd")
    # Avoid "Command line warning D9025 : overriding '/MT' with '/MTd'"
    # which we get due to our simple concat of CMAKE_C_FLAGS with the _DEBUG version.
    string(REGEX REPLACE "/MT([^d]|$)" "\\1" tgt_cflags "${tgt_cflags}")
  endif ()

  _DR_get_size(${tgt_cxx} tgt_x64)
  DynamoRIO_extra_cflags(tgt_cflags "${tgt_cflags}" ${tgt_cxx})

  if (UNIX)
    if (is_client)

      if (NOT DEFINED DynamoRIO_VISATT)
        # Try to automatically determine visibility
        if ("${tgt_cflags}" MATCHES "-fvisibility=hidden|-fvisibility=internal")
          set(DynamoRIO_VISATT ON)
        endif()
      endif (NOT DEFINED DynamoRIO_VISATT)
      if (DynamoRIO_VISATT)
        set(tgt_cflags "${tgt_cflags} -DUSE_VISIBILITY_ATTRIBUTES")
      endif (DynamoRIO_VISATT)
      if (tgt_cxx)
        set(tgt_link_flags "${tgt_link_flags}")
      endif (tgt_cxx)

      # Do non-lazy runtime binding
      if (APPLE)
        # Especially important on Mac where we do not yet have a private loader
        set(tgt_link_flags "${tgt_link_flags} -Xlinker -bind_at_load")
      else (APPLE)
        set(tgt_link_flags "${tgt_link_flags} -Xlinker -z -Xlinker now")
      endif (APPLE)

      # avoid SElinux text relocation security violations by explicitly requesting PIC
      # i#157, when enable private loader, symbols from default libraries and startfiles
      # are required, so -nostartfiles and -nodefaultlibs should be removed
      set(tgt_link_flags
        "${tgt_link_flags} -fPIC -shared")
      if (NOT CMAKE_COMPILER_IS_CLANG)
        set(tgt_link_flags
          "${tgt_link_flags} -lgcc")
      endif ()

      # i#163: avoid stack-check feature that relies on separate library
      execute_process(COMMAND
        ${CMAKE_C_COMPILER} -v --help
        RESULT_VARIABLE gcc_result
        ERROR_VARIABLE gcc_err
        OUTPUT_VARIABLE gcc_out)
      if (gcc_result)
        if (APPLE AND gcc_err MATCHES "_main\", referenced from")
          # not an error: "-v --help" tries to build w/ no src file for some reason
        else ()
          message(FATAL_ERROR "*** ${CMAKE_C_COMPILER} failed to run: ${gcc_out}\n${gcc_err} ***\n")
        endif ()
      endif (gcc_result)
      string(REGEX MATCH "fstack-protector" flag_present "${gcc_out}")
      if (flag_present)
        set(tgt_cflags "${tgt_cflags} -fno-stack-protector")
      endif (flag_present)

    endif (is_client)

    # i#847 keep stack boundary 4-byte aligned for compatibility.
    # The new gcc may use different stack alignment for using SSE
    # instructions. We make both DynamoRIO and clients use 4-byte
    # stack alignment to avoid any back compatibility issue without
    # using extra stack space or changing performance.
    # On Mac we have to use the ABI's 16-byte alignment, but we have
    # no compatibility there as we're starting fresh.
    # On ARM, '-mpreferred-stack-boundary' is unrecognized.
    # i#1800: '-mpreferred-stack-boundary' is not supported by clang,
    # so clang's build may not run legacy binaries.
    if (NOT tgt_x64 AND NOT APPLE AND NOT ARM AND NOT CMAKE_COMPILER_IS_CLANG)
      set(tgt_cflags "${tgt_cflags} -mpreferred-stack-boundary=2")
    endif (NOT tgt_x64 AND NOT APPLE AND NOT ARM AND NOT CMAKE_COMPILER_IS_CLANG)

    if (NOT APPLE AND NOT ANDROID) # no .gnu.hash support on Android
      # Generate the .hash section in addition to .gnu.hash for every target, to
      # avoid SIGFPE when running binaries on old systems:
      set(tgt_link_flags "${tgt_link_flags} -Wl,--hash-style=both")
    endif ()

    if (NOT DynamoRIO_USE_LIBC AND NOT tgt_cxx AND is_client)
      set(tgt_cflags "${tgt_cflags} -nostdlib")
      if (APPLE)
        # Avoid errors about missing the _chk versions of memcpy, etc.
        set(tgt_link_flags "${tgt_link_flags} -undefined dynamic_lookup")
      endif (APPLE)
    endif ()

    # gcc is invoked for the link step so we have to repeat cflags as well
    set(tgt_link_flags "${tgt_cflags} ${tgt_link_flags}")
  else (UNIX)
    if (tgt_cxx)
      set(tgt_cflags "${tgt_cflags} /EHsc")
    endif (tgt_cxx)
    if (is_client)
      # Avoid bringing in libc and/or kernel32 for stack checks
      set(tgt_cflags "${tgt_cflags} /GS-")
      # FIXME: why isn't /debug showing up: is it
    endif (is_client)
    if (DynamoRIO_USE_LIBC OR tgt_cxx OR NOT is_client)
      # Take advantage of the Windows private loader: no longer need
      # /nodefaultlib or /noentry.
      #
      # However, for i#233, we require static libc for VS2005 and VS2008
      # to avoid SxS.  For simplicity we just require them regardless.
      #
      # Plus, we can't use just /MT for clients or standalone (i#686) b/c it
      # puts libcmt at the end and we hit dup def problems.  We need
      # libcmt to come in before dynamorio to avoid conflicts w/
      # forwarded routines.
      #
      # Note that any client linking with ntdll will have to add it
      # AFTER these are added if any forwarded routines are used.
      #
      # Note that when using a static drsyms library, /noentry
      # results in weird "missing _main" even when linking "/dll"
      # so we no longer use it
      if (tgt_cxx)
        set(tgt_link_flags "${tgt_link_flags} /nodefaultlib:libcmt")
      else (tgt_cxx)
        set(tgt_link_flags "${tgt_link_flags} /nodefaultlib")
      endif (tgt_cxx)
      if (DEBUG OR "${CMAKE_BUILD_TYPE}" MATCHES "Debug")
        set(static_libc libcmtd)
        if (tgt_cxx)
          set(static_libc libcpmtd ${static_libc})
        endif ()
        # https://blogs.msdn.microsoft.com/vcblog/2015/03/03/introducing-the-universal-crt
        if (NOT (MSVC_VERSION LESS 1900)) # GREATER_EQUAL is cmake 3.7+ only
          set(static_libc ${static_libc} libvcruntimed.lib libucrtd.lib)
        endif ()
        # libcmt has symbols libcmtd does not so we need all files compiled w/ _DEBUG
        set(tgt_cflags "${tgt_cflags} -D_DEBUG")
      else ()
        set(static_libc libcmt)
        if (tgt_cxx)
          set(static_libc libcpmt ${static_libc})
        endif ()
        # https://blogs.msdn.microsoft.com/vcblog/2015/03/03/introducing-the-universal-crt
        if (NOT (MSVC_VERSION LESS 1900)) # GREATER_EQUAL is cmake 3.7+ only
          set(static_libc ${static_libc} libvcruntime.lib libucrt.lib)
        endif ()
      endif ()
      target_link_libraries(${target} ${static_libc})
    else ()
      set(tgt_link_flags "${tgt_link_flags} /nodefaultlib /noentry")
    endif ()
  endif (UNIX)

  # DynamoRIOTarget.cmake added the "dynamorio" imported target
  target_link_libraries(${target} dynamorio)

  if (DEFINED DynamoRIO_RPATH)
    set(use_rpath ${DynamoRIO_RPATH})
  else (DEFINED DynamoRIO_RPATH)
    if (is_client)
      # We don't want an rpath as it makes it hard to switch
      # between debug and release libraries at runtime
      set(use_rpath OFF)
    else (is_client)
      # Standalone app is run without drdeploy script to set
      # LD_LIBRARY_PATH, so default to rpath.  Even though it
      # makes it more painful to switch to the debug library,
      # that's rarely needed for standalone.
      set(use_rpath ON)
    endif (is_client)
  endif (DEFINED DynamoRIO_RPATH)
  if (use_rpath)
    DynamoRIO_add_rel_rpaths(${target} dynamorio)
    if (USE_DRPATH AND is_client) # doesn't make sense for standalone
      # Create the .drpath file our loader uses
      get_target_property(libpath dynamorio LOCATION${_DR_location_suffix})
      get_filename_component(libdir ${libpath} PATH)
      _DR_get_drpath_name(drpath_file ${target})
      file(WRITE ${drpath_file} "${libdir}\n")
    endif ()
  else (use_rpath)
    set_target_properties(${target} PROPERTIES
      SKIP_BUILD_RPATH ON)
  endif (use_rpath)

  # Append LINK_FLAGS
  _DR_append_property_string(TARGET ${target} LINK_FLAGS "${tgt_link_flags}")

  # Pass data to caller
  set(${x64_var} ${tgt_x64} PARENT_SCOPE)
  set(${defs_var} "${tgt_cflags}" PARENT_SCOPE)

endfunction (configure_DynamoRIO_common)


function (configure_DynamoRIO_client target)
  # We clear LINK_FLAGS and let the helper routines append to them:
  set_target_properties(${target} PROPERTIES LINK_FLAGS "")
  configure_DynamoRIO_common(${target} ON tgt_x64 tgt_cflags)
  if (just_configured)
    # get around lack of GLOBAL_SCOPE
    # do NOT set just_configured in global scope
    foreach (config "" ${CMAKE_BUILD_TYPE} ${CMAKE_CONFIGURATION_TYPES})
      if ("${config}" STREQUAL "")
        set(config_upper "")
      else ("${config}" STREQUAL "")
        string(TOUPPER "_${config}" config_upper)
      endif ("${config}" STREQUAL "")
      foreach (var CMAKE_C_FLAGS${config_upper};CMAKE_CXX_FLAGS${config_upper})
        set(ORIG_${var} "${ORIG_${var}}" PARENT_SCOPE)
        set(CLIENT_${var} "${CLIENT_${var}}" PARENT_SCOPE)
        set(${var} "${${var}}" PARENT_SCOPE)
      endforeach (var)
    endforeach (config)
  endif (just_configured)

  if (tgt_x64 OR DynamoRIO_SET_PREFERRED_BASE)
    # While we now have private loaders that mean we don't need a preferred
    # base in the lower 2GB, on Windows it's more efficient to avoid
    # relocation by doing so.
    # Naturally for multiple clients different addresses should be used.
    # We suggest using the range 0x72000000-0x75000000.
    if (NOT DEFINED PREFERRED_BASE)
      set(PREFERRED_BASE 0x72000000)
    endif ()
    if (APPLE)
      set(LD_FLAGS "-arch x86_64 -image_base ${PREFERRED_BASE}")
    elseif (UNIX)
      if (LINKER_IS_GNU_GOLD)
        # Gold doesn't have a default version script for us to edit.  However,
        # it has a handy command line flag that does exactly what we want.  Note
        # that gnu ld has -Ttext as well, but it is very different.
        # XXX: gnu ld added an equivalent -Ttext-segment to binutils 2.20 in
        # 2009.  We could switch to that if we ever drop support for old
        # linkers.
        set(PREFERRED_BASE_FLAGS "-Wl,-Ttext=${PREFERRED_BASE}")
      else (LINKER_IS_GNU_GOLD)
        # We use a linker script to set the preferred base
        set(LD_SCRIPT ${CMAKE_CURRENT_BINARY_DIR}/${target}.ldscript)
        # We do NOT add ${LD_SCRIPT} as an ADDITIONAL_MAKE_CLEAN_FILES since it's
        # configure-time built not make-time built
        if (X86)
          set(LD_FLAGS "-melf_x86_64")
        elseif (ARM)
          set(LD_FLAGS "-marmelf_linux_eabi")
        elseif (AARCH64)
          set(LD_FLAGS "-maarch64linux")
        endif ()

        # In order to just tweak the default linker script we start with exactly that.
        separate_arguments(LD_FLAGS)
        execute_process(COMMAND
          ${CMAKE_LINKER} ${LD_FLAGS} --verbose
          RESULT_VARIABLE ld_result
          ERROR_VARIABLE ld_error
          OUTPUT_VARIABLE string)
        if (ld_result OR ld_error)
          message(FATAL_ERROR "*** ${CMAKE_LINKER} failed: ***\n${ld_error}")
        endif (ld_result OR ld_error)

        # Strip out just the SECTIONS{} portion
        string(REGEX REPLACE ".*(SECTIONS.*\n\\}).*" "\\1" string "${string}")
        # Find and replace the default base
        string(REGEX MATCH "= *[^{\\.\n]+(0x[0-9]+)\\)? *\\+ *SIZEOF_HEADERS"
          default_base "${string}")
        if ("${default_base}" STREQUAL "")
          message(FATAL_ERROR "unsupported ld version: please file this bug")
        endif()
        string(REGEX REPLACE ".*(0x[0-9]+).*" "\\1" default_base "${default_base}")
        string(REGEX REPLACE "${default_base}" "${PREFERRED_BASE}" string "${string}")
        string(REGEX REPLACE "(\n{)" "\\1\n  . = ${PREFERRED_BASE};" string "${string}")
        file(WRITE ${LD_SCRIPT} "${string}")

        # -dT is preferred, available on ld 2.18+: we could check for it
        set(LD_SCRIPT_OPTION "-T")
        set(PREFERRED_BASE_FLAGS "-Xlinker ${LD_SCRIPT_OPTION} -Xlinker \"${LD_SCRIPT}\"")
      endif (LINKER_IS_GNU_GOLD)
    else (APPLE)
      set(PREFERRED_BASE_FLAGS "/base:${PREFERRED_BASE} /dynamicbase:no")
    endif (APPLE)
    _DR_append_property_string(TARGET ${target} LINK_FLAGS "${PREFERRED_BASE_FLAGS}")
  endif (tgt_x64 OR DynamoRIO_SET_PREFERRED_BASE)

  _DR_set_compile_flags(${target} "${tgt_cflags}")

  # TODO: a nice feature would be to check the client for libc imports or
  # other not-recommended properties

endfunction (configure_DynamoRIO_client)


function (configure_DynamoRIO_standalone target)
  # We don't clear LINK_FLAGS b/c we assume standalone doesn't need to have
  # flags removed.  Usually the target LINK_FLAGS is empty at this point anyway.
  configure_DynamoRIO_common(${target} OFF tgt_x64 tgt_cflags)
  # get around lack of GLOBAL_SCOPE
  foreach (config "" ${CMAKE_BUILD_TYPE} ${CMAKE_CONFIGURATION_TYPES})
    if ("${config}" STREQUAL "")
      set(config_upper "")
    else ("${config}" STREQUAL "")
      string(TOUPPER "_${config}" config_upper)
    endif ("${config}" STREQUAL "")
    foreach (var CMAKE_C_FLAGS${config_upper};CMAKE_CXX_FLAGS${config_upper})
      set(ORIG_${var} "${ORIG_${var}}" PARENT_SCOPE)
      set(CLIENT_${var} "${CLIENT_${var}}" PARENT_SCOPE)
      set(${var} "${${var}}" PARENT_SCOPE)
    endforeach (var)
  endforeach (config)

  if (ANDROID)
    set(tgt_cflags ${tgt_cflags} "-fPIE -pie")
  endif (ANDROID)
  _DR_set_compile_flags(${target} "${tgt_cflags} -DDYNAMORIO_STANDALONE")
  # LINK_FLAGS are appended by the helper routines above

endfunction (configure_DynamoRIO_standalone)


function (configure_DynamoRIO_decoder target)
  _DR_get_lang(${target} tgt_lang)
  if (${tgt_lang} MATCHES CXX)
    set(tgt_cxx ON)
  else (${tgt_lang} MATCHES CXX)
    set(tgt_cxx OFF)
  endif (${tgt_lang} MATCHES CXX)

  # we do not need propagation so no need to set nested
  configure_DynamoRIO_global(${tgt_cxx} OFF)

  get_target_property(cur_cflags ${target} COMPILE_FLAGS)
  if (NOT cur_cflags)
    set(cur_cflags "")
  endif (NOT cur_cflags)
  DynamoRIO_extra_cflags(cur_cflags "${cur_cflags}" ${tgt_cxx})
  set_target_properties(${target} PROPERTIES COMPILE_FLAGS "${cur_cflags}")

  # DynamoRIOTarget.cmake added the "drdecode" imported target
  target_link_libraries(${target} drdecode)

endfunction (configure_DynamoRIO_decoder)


function (configure_DynamoRIO_static target)
  _DR_get_lang(${target} tgt_lang)
  if (${tgt_lang} MATCHES CXX)
    set(tgt_cxx ON)
  else (${tgt_lang} MATCHES CXX)
    set(tgt_cxx OFF)
  endif (${tgt_lang} MATCHES CXX)

  configure_DynamoRIO_global(${tgt_cxx} OFF)

  get_target_property(cur_cflags ${target} COMPILE_FLAGS)
  if (NOT cur_cflags)
    set(cur_cflags "")
  endif (NOT cur_cflags)
  DynamoRIO_extra_cflags(cur_cflags "${cur_cflags}" ${tgt_cxx})
  if (WIN32)
    # For static DR, we want dllexport and not dllimport for the app API.
    set(cur_cflags "${cur_cflags} -DDR_APP_EXPORTS")
  endif ()
  set_target_properties(${target} PROPERTIES COMPILE_FLAGS "${cur_cflags}")
  if (ANDROID)
    # The Android linker is not exporting the weak symbol _USES_DR_VERSION_.
    # We use --dynamic-list-data to do so.
    # Actually the Linux linker is exporting the entire DR API symbol set:
    # should we pass -Wl,--export-dynamic here to match it?
    _DR_append_property_string(TARGET ${target} LINK_FLAGS "-Wl,--dynamic-list-data")
  endif ()

  target_link_libraries(${target} dynamorio_static)
  if (UNIX)
    # i#2070: avoid pulling libdynamorio.so
    # Assuming LINK_FLAGS goes before target_link_libraries.
    _DR_append_property_string(TARGET ${target} LINK_FLAGS "-Wl,--as-needed")
  endif ()
endfunction (configure_DynamoRIO_static)

function (use_DynamoRIO_static_client target client)
  DynamoRIO_force_static_link(${target} ${client})
endfunction (use_DynamoRIO_static_client)

function (get_DynamoRIO_defines outvar is_cxx)
  # We assume that only defines are added by DynamoRIO_extra_cflags,
  # otherwise, we need construct a new list and extract defines from
  # extra_cflags.
  DynamoRIO_extra_cflags(extra_cflags "" ${is_cxx})
  set(${outvar} "${extra_cflags}" PARENT_SCOPE)
endfunction (get_DynamoRIO_defines)

###########################################################################
#
# To disable linking to an executable extension via use_DynamoRIO_extension():
# set(DynamoRIO_EXT_${extname}_NOLIB ON)
# in your ${extname}Config.cmake file
set(DynamoRIO_EXT_drgui_NOLIB ON)
set(DynamoRIO_EXT_droption_NOLIB ON)
# Not really an extension, just for including drmemtrace.h
# via use_DynamoRIO_extension(target, drmemtrace_static)
set(DynamoRIO_EXT_drmemtrace_static_NOLIB ON)

# DynamoRIO Extensions
function (use_DynamoRIO_extension target extname)
  if (NOT DynamoRIO_INTERNAL)
    # We only support Extensions as imported targets that have already
    # been added:
    if (NOT TARGET ${extname} AND NOT DynamoRIO_EXT_${extname}_NOLIB)
      message(FATAL_ERROR "DynamoRIO Extension \"${extname}\" not found")
    endif ()
    # See whether this Extension is packaged with DynamoRIO:
    if (UNIX)
      file(GLOB libs "${DynamoRIO_cwd}/../ext/lib*/*/lib${extname}.*")
    else (UNIX)
      file(GLOB libs "${DynamoRIO_cwd}/../ext/lib*/*/${extname}.*")
    endif (UNIX)
    if (NOT libs OR DynamoRIO_EXT_${extname}_INC)
      # Support for 3rd party Extensions: caller calls find_package()
      # to set up the imported targets for the libraries and to set
      # DynamoRIO_EXT_${extname}_INC.
      include_directories(${DynamoRIO_EXT_${extname}_INC})
    else ()
      # Local extensions are exported in the same cmake file as DynamoRIO
      # so we do not need to include another file here.
      include_directories(${DynamoRIO_cwd}/../ext/include)
    endif ()
  else (NOT DynamoRIO_INTERNAL)
    # support building from build dir for our own samples, and from
    # build dir for a client that includes our sources as a sub-project,
    # in which case DynamoRIO_SOURCE_DIR will automatically be set:
    if ("${extname}" MATCHES "_static$")
      # support additional targets with "_static" appended
      string(REGEX REPLACE "_static$" "" ext_dir "${extname}")
    else ()
      set(ext_dir "${extname}")
    endif ()
    # To support drreg.h including drvector.h we need all the headers
    # in one spot, so we prefer to point at build dir copy:
    if (EXISTS "${PROJECT_BINARY_DIR}/ext/include")
      include_directories(${PROJECT_BINARY_DIR}/ext/include)
    elseif (EXISTS "${PROJECT_BINARY_DIR}/../../ext/include")
      # Two up from api/samples/
      include_directories(${PROJECT_BINARY_DIR}/../../ext/include)
    elseif (EXISTS "${DynamoRIO_BINARY_DIR}") # where DR is a subpackage
      include_directories(${DynamoRIO_BINARY_DIR}/ext/include)
    endif ()
  endif (NOT DynamoRIO_INTERNAL)

  if (DynamoRIO_RPATH AND NOT DynamoRIO_EXT_${extname}_NOLIB)
    DynamoRIO_add_rel_rpaths(${target} ${extname})
    if (USE_DRPATH)
      get_target_property(libpath ${extname} LOCATION${_DR_location_suffix})
      get_filename_component(libdir ${libpath} PATH)
      _DR_get_drpath_name(drpath_file ${target})
      if (EXISTS ${drpath_file})
        # File should have been created fresh when configured.
        # If it's not there, this is probably a standalone app, for which
        # a .drpath file is useless.
        # XXX: in the future we may add support for relative dirs but for
        # now we only support absolute.
        file(READ ${drpath_file} cur_contents)
        string(FIND ${cur_contents} ${libdir} cur_found)
        if (cur_found LESS 0) # -1 if not found
          file(APPEND ${drpath_file} "${libdir}\n")
        endif ()
      endif ()
    endif (USE_DRPATH)
  else ()
    set_target_properties(${target} PROPERTIES SKIP_BUILD_RPATH ON)
  endif ()

  if (NOT DynamoRIO_EXT_${extname}_NOLIB)
    target_link_libraries(${target} ${extname})
  endif (NOT DynamoRIO_EXT_${extname}_NOLIB)

endfunction (use_DynamoRIO_extension)

# For clients to configure their custom annotations
function (configure_DynamoRIO_annotation_sources srcs)
  if (UNIX)
    foreach (src ${srcs})
      _DR_append_property_string(SOURCE ${src} COMPILE_FLAGS
        "-O0 -Wno-unused-variable -Wno-return-type")
    endforeach (src ${srcs})
  else (UNIX)
    # /wd4715: disable warning for "not all control paths return a value"
    foreach (src ${srcs})
      _DR_append_property_string(SOURCE ${src} COMPILE_FLAGS "/Od /Ob0 /GL- /wd4715")
    endforeach (src ${srcs})
  endif (UNIX)
endfunction (configure_DynamoRIO_annotation_sources srcs)

# For configuring target applications that use default DynamoRIO annotations
function (use_DynamoRIO_annotations target target_srcs)
  set(dr_annotation_dir "${DynamoRIO_cwd}/../include/annotations")
  set(dr_annotation_srcs "${dr_annotation_dir}/dr_annotations.c")
  configure_DynamoRIO_annotation_sources("${dr_annotation_srcs}")
  set(${target_srcs} ${${target_srcs}} ${dr_annotation_srcs} PARENT_SCOPE)
endfunction (use_DynamoRIO_annotations target target_srcs)

# Support co-located DRMF without having to separately specify it
if (NOT DrMemoryFramework_DIR AND EXISTS "${DynamoRIO_DIR}/../drmemory/drmf")
  set(DrMemoryFramework_DIR "${DynamoRIO_DIR}/../drmemory/drmf")
  find_package(DrMemoryFramework)
endif ()

if ("${CMAKE_VERSION}" VERSION_EQUAL "3.0" OR
    "${CMAKE_VERSION}" VERSION_GREATER "3.0")
  cmake_policy(POP)
endif ()
