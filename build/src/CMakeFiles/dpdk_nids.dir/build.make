# CMAKE generated file: DO NOT EDIT!
# Generated by "Unix Makefiles" Generator, CMake Version 3.22

# Delete rule output on recipe failure.
.DELETE_ON_ERROR:

#=============================================================================
# Special targets provided by cmake.

# Disable implicit rules so canonical targets will work.
.SUFFIXES:

# Disable VCS-based implicit rules.
% : %,v

# Disable VCS-based implicit rules.
% : RCS/%

# Disable VCS-based implicit rules.
% : RCS/%,v

# Disable VCS-based implicit rules.
% : SCCS/s.%

# Disable VCS-based implicit rules.
% : s.%

.SUFFIXES: .hpux_make_needs_suffix_list

# Command-line flag to silence nested $(MAKE).
$(VERBOSE)MAKESILENT = -s

#Suppress display of executed commands.
$(VERBOSE).SILENT:

# A target that is always out of date.
cmake_force:
.PHONY : cmake_force

#=============================================================================
# Set environment variables for the build.

# The shell in which to execute make rules.
SHELL = /bin/sh

# The CMake executable.
CMAKE_COMMAND = /usr/bin/cmake

# The command to remove a file.
RM = /usr/bin/cmake -E rm -f

# Escaping for special characters.
EQUALS = =

# The top-level source directory on which CMake was run.
CMAKE_SOURCE_DIR = /home/work/clionProject/QingtengCode/dpdk-based-nids

# The top-level build directory on which CMake was run.
CMAKE_BINARY_DIR = /home/work/clionProject/QingtengCode/dpdk-based-nids/build

# Include any dependencies generated for this target.
include src/CMakeFiles/dpdk_nids.dir/depend.make
# Include any dependencies generated by the compiler for this target.
include src/CMakeFiles/dpdk_nids.dir/compiler_depend.make

# Include the progress variables for this target.
include src/CMakeFiles/dpdk_nids.dir/progress.make

# Include the compile flags for this target's objects.
include src/CMakeFiles/dpdk_nids.dir/flags.make

src/CMakeFiles/dpdk_nids.dir/main.c.o: src/CMakeFiles/dpdk_nids.dir/flags.make
src/CMakeFiles/dpdk_nids.dir/main.c.o: ../src/main.c
src/CMakeFiles/dpdk_nids.dir/main.c.o: src/CMakeFiles/dpdk_nids.dir/compiler_depend.ts
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/work/clionProject/QingtengCode/dpdk-based-nids/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_1) "Building C object src/CMakeFiles/dpdk_nids.dir/main.c.o"
	cd /home/work/clionProject/QingtengCode/dpdk-based-nids/build/src && /usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -MD -MT src/CMakeFiles/dpdk_nids.dir/main.c.o -MF CMakeFiles/dpdk_nids.dir/main.c.o.d -o CMakeFiles/dpdk_nids.dir/main.c.o -c /home/work/clionProject/QingtengCode/dpdk-based-nids/src/main.c

src/CMakeFiles/dpdk_nids.dir/main.c.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/dpdk_nids.dir/main.c.i"
	cd /home/work/clionProject/QingtengCode/dpdk-based-nids/build/src && /usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E /home/work/clionProject/QingtengCode/dpdk-based-nids/src/main.c > CMakeFiles/dpdk_nids.dir/main.c.i

src/CMakeFiles/dpdk_nids.dir/main.c.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/dpdk_nids.dir/main.c.s"
	cd /home/work/clionProject/QingtengCode/dpdk-based-nids/build/src && /usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S /home/work/clionProject/QingtengCode/dpdk-based-nids/src/main.c -o CMakeFiles/dpdk_nids.dir/main.c.s

src/CMakeFiles/dpdk_nids.dir/global_data.c.o: src/CMakeFiles/dpdk_nids.dir/flags.make
src/CMakeFiles/dpdk_nids.dir/global_data.c.o: ../src/global_data.c
src/CMakeFiles/dpdk_nids.dir/global_data.c.o: src/CMakeFiles/dpdk_nids.dir/compiler_depend.ts
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/work/clionProject/QingtengCode/dpdk-based-nids/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_2) "Building C object src/CMakeFiles/dpdk_nids.dir/global_data.c.o"
	cd /home/work/clionProject/QingtengCode/dpdk-based-nids/build/src && /usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -MD -MT src/CMakeFiles/dpdk_nids.dir/global_data.c.o -MF CMakeFiles/dpdk_nids.dir/global_data.c.o.d -o CMakeFiles/dpdk_nids.dir/global_data.c.o -c /home/work/clionProject/QingtengCode/dpdk-based-nids/src/global_data.c

src/CMakeFiles/dpdk_nids.dir/global_data.c.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/dpdk_nids.dir/global_data.c.i"
	cd /home/work/clionProject/QingtengCode/dpdk-based-nids/build/src && /usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E /home/work/clionProject/QingtengCode/dpdk-based-nids/src/global_data.c > CMakeFiles/dpdk_nids.dir/global_data.c.i

src/CMakeFiles/dpdk_nids.dir/global_data.c.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/dpdk_nids.dir/global_data.c.s"
	cd /home/work/clionProject/QingtengCode/dpdk-based-nids/build/src && /usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S /home/work/clionProject/QingtengCode/dpdk-based-nids/src/global_data.c -o CMakeFiles/dpdk_nids.dir/global_data.c.s

src/CMakeFiles/dpdk_nids.dir/pidfile.c.o: src/CMakeFiles/dpdk_nids.dir/flags.make
src/CMakeFiles/dpdk_nids.dir/pidfile.c.o: ../src/pidfile.c
src/CMakeFiles/dpdk_nids.dir/pidfile.c.o: src/CMakeFiles/dpdk_nids.dir/compiler_depend.ts
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/work/clionProject/QingtengCode/dpdk-based-nids/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_3) "Building C object src/CMakeFiles/dpdk_nids.dir/pidfile.c.o"
	cd /home/work/clionProject/QingtengCode/dpdk-based-nids/build/src && /usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -MD -MT src/CMakeFiles/dpdk_nids.dir/pidfile.c.o -MF CMakeFiles/dpdk_nids.dir/pidfile.c.o.d -o CMakeFiles/dpdk_nids.dir/pidfile.c.o -c /home/work/clionProject/QingtengCode/dpdk-based-nids/src/pidfile.c

src/CMakeFiles/dpdk_nids.dir/pidfile.c.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/dpdk_nids.dir/pidfile.c.i"
	cd /home/work/clionProject/QingtengCode/dpdk-based-nids/build/src && /usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E /home/work/clionProject/QingtengCode/dpdk-based-nids/src/pidfile.c > CMakeFiles/dpdk_nids.dir/pidfile.c.i

src/CMakeFiles/dpdk_nids.dir/pidfile.c.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/dpdk_nids.dir/pidfile.c.s"
	cd /home/work/clionProject/QingtengCode/dpdk-based-nids/build/src && /usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S /home/work/clionProject/QingtengCode/dpdk-based-nids/src/pidfile.c -o CMakeFiles/dpdk_nids.dir/pidfile.c.s

src/CMakeFiles/dpdk_nids.dir/common.c.o: src/CMakeFiles/dpdk_nids.dir/flags.make
src/CMakeFiles/dpdk_nids.dir/common.c.o: ../src/common.c
src/CMakeFiles/dpdk_nids.dir/common.c.o: src/CMakeFiles/dpdk_nids.dir/compiler_depend.ts
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/work/clionProject/QingtengCode/dpdk-based-nids/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_4) "Building C object src/CMakeFiles/dpdk_nids.dir/common.c.o"
	cd /home/work/clionProject/QingtengCode/dpdk-based-nids/build/src && /usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -MD -MT src/CMakeFiles/dpdk_nids.dir/common.c.o -MF CMakeFiles/dpdk_nids.dir/common.c.o.d -o CMakeFiles/dpdk_nids.dir/common.c.o -c /home/work/clionProject/QingtengCode/dpdk-based-nids/src/common.c

src/CMakeFiles/dpdk_nids.dir/common.c.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/dpdk_nids.dir/common.c.i"
	cd /home/work/clionProject/QingtengCode/dpdk-based-nids/build/src && /usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E /home/work/clionProject/QingtengCode/dpdk-based-nids/src/common.c > CMakeFiles/dpdk_nids.dir/common.c.i

src/CMakeFiles/dpdk_nids.dir/common.c.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/dpdk_nids.dir/common.c.s"
	cd /home/work/clionProject/QingtengCode/dpdk-based-nids/build/src && /usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S /home/work/clionProject/QingtengCode/dpdk-based-nids/src/common.c -o CMakeFiles/dpdk_nids.dir/common.c.s

src/CMakeFiles/dpdk_nids.dir/scheduler.c.o: src/CMakeFiles/dpdk_nids.dir/flags.make
src/CMakeFiles/dpdk_nids.dir/scheduler.c.o: ../src/scheduler.c
src/CMakeFiles/dpdk_nids.dir/scheduler.c.o: src/CMakeFiles/dpdk_nids.dir/compiler_depend.ts
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/work/clionProject/QingtengCode/dpdk-based-nids/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_5) "Building C object src/CMakeFiles/dpdk_nids.dir/scheduler.c.o"
	cd /home/work/clionProject/QingtengCode/dpdk-based-nids/build/src && /usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -MD -MT src/CMakeFiles/dpdk_nids.dir/scheduler.c.o -MF CMakeFiles/dpdk_nids.dir/scheduler.c.o.d -o CMakeFiles/dpdk_nids.dir/scheduler.c.o -c /home/work/clionProject/QingtengCode/dpdk-based-nids/src/scheduler.c

src/CMakeFiles/dpdk_nids.dir/scheduler.c.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/dpdk_nids.dir/scheduler.c.i"
	cd /home/work/clionProject/QingtengCode/dpdk-based-nids/build/src && /usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E /home/work/clionProject/QingtengCode/dpdk-based-nids/src/scheduler.c > CMakeFiles/dpdk_nids.dir/scheduler.c.i

src/CMakeFiles/dpdk_nids.dir/scheduler.c.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/dpdk_nids.dir/scheduler.c.s"
	cd /home/work/clionProject/QingtengCode/dpdk-based-nids/build/src && /usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S /home/work/clionProject/QingtengCode/dpdk-based-nids/src/scheduler.c -o CMakeFiles/dpdk_nids.dir/scheduler.c.s

src/CMakeFiles/dpdk_nids.dir/netif.c.o: src/CMakeFiles/dpdk_nids.dir/flags.make
src/CMakeFiles/dpdk_nids.dir/netif.c.o: ../src/netif.c
src/CMakeFiles/dpdk_nids.dir/netif.c.o: src/CMakeFiles/dpdk_nids.dir/compiler_depend.ts
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/work/clionProject/QingtengCode/dpdk-based-nids/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_6) "Building C object src/CMakeFiles/dpdk_nids.dir/netif.c.o"
	cd /home/work/clionProject/QingtengCode/dpdk-based-nids/build/src && /usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -MD -MT src/CMakeFiles/dpdk_nids.dir/netif.c.o -MF CMakeFiles/dpdk_nids.dir/netif.c.o.d -o CMakeFiles/dpdk_nids.dir/netif.c.o -c /home/work/clionProject/QingtengCode/dpdk-based-nids/src/netif.c

src/CMakeFiles/dpdk_nids.dir/netif.c.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/dpdk_nids.dir/netif.c.i"
	cd /home/work/clionProject/QingtengCode/dpdk-based-nids/build/src && /usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E /home/work/clionProject/QingtengCode/dpdk-based-nids/src/netif.c > CMakeFiles/dpdk_nids.dir/netif.c.i

src/CMakeFiles/dpdk_nids.dir/netif.c.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/dpdk_nids.dir/netif.c.s"
	cd /home/work/clionProject/QingtengCode/dpdk-based-nids/build/src && /usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S /home/work/clionProject/QingtengCode/dpdk-based-nids/src/netif.c -o CMakeFiles/dpdk_nids.dir/netif.c.s

# Object files for target dpdk_nids
dpdk_nids_OBJECTS = \
"CMakeFiles/dpdk_nids.dir/main.c.o" \
"CMakeFiles/dpdk_nids.dir/global_data.c.o" \
"CMakeFiles/dpdk_nids.dir/pidfile.c.o" \
"CMakeFiles/dpdk_nids.dir/common.c.o" \
"CMakeFiles/dpdk_nids.dir/scheduler.c.o" \
"CMakeFiles/dpdk_nids.dir/netif.c.o"

# External object files for target dpdk_nids
dpdk_nids_EXTERNAL_OBJECTS =

src/dpdk_nids: src/CMakeFiles/dpdk_nids.dir/main.c.o
src/dpdk_nids: src/CMakeFiles/dpdk_nids.dir/global_data.c.o
src/dpdk_nids: src/CMakeFiles/dpdk_nids.dir/pidfile.c.o
src/dpdk_nids: src/CMakeFiles/dpdk_nids.dir/common.c.o
src/dpdk_nids: src/CMakeFiles/dpdk_nids.dir/scheduler.c.o
src/dpdk_nids: src/CMakeFiles/dpdk_nids.dir/netif.c.o
src/dpdk_nids: src/CMakeFiles/dpdk_nids.dir/build.make
src/dpdk_nids: src/CMakeFiles/dpdk_nids.dir/link.txt
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --bold --progress-dir=/home/work/clionProject/QingtengCode/dpdk-based-nids/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_7) "Linking C executable dpdk_nids"
	cd /home/work/clionProject/QingtengCode/dpdk-based-nids/build/src && $(CMAKE_COMMAND) -E cmake_link_script CMakeFiles/dpdk_nids.dir/link.txt --verbose=$(VERBOSE)

# Rule to build all files generated by this target.
src/CMakeFiles/dpdk_nids.dir/build: src/dpdk_nids
.PHONY : src/CMakeFiles/dpdk_nids.dir/build

src/CMakeFiles/dpdk_nids.dir/clean:
	cd /home/work/clionProject/QingtengCode/dpdk-based-nids/build/src && $(CMAKE_COMMAND) -P CMakeFiles/dpdk_nids.dir/cmake_clean.cmake
.PHONY : src/CMakeFiles/dpdk_nids.dir/clean

src/CMakeFiles/dpdk_nids.dir/depend:
	cd /home/work/clionProject/QingtengCode/dpdk-based-nids/build && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /home/work/clionProject/QingtengCode/dpdk-based-nids /home/work/clionProject/QingtengCode/dpdk-based-nids/src /home/work/clionProject/QingtengCode/dpdk-based-nids/build /home/work/clionProject/QingtengCode/dpdk-based-nids/build/src /home/work/clionProject/QingtengCode/dpdk-based-nids/build/src/CMakeFiles/dpdk_nids.dir/DependInfo.cmake --color=$(COLOR)
.PHONY : src/CMakeFiles/dpdk_nids.dir/depend

