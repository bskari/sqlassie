#!/bin/bash
# Creates an archive suitable for decompressing and compiling SQLassie.

# Create these so users don't need to install Flex or Bison
lexer_and_parser_targets="parser.tab.cpp parser.tab.hpp huginParser.tab.cpp huginParser.tab.hpp huginScanner.yy.cpp huginScanner.yy.hpp scanner.yy.cpp scanner.yy.hpp"

c_header_only_files="version.h getpass.h warnUnusedResult.h"
cpp_header_only_files="accumulator.hpp nullptr.hpp AutoPtrWithOperatorParens.hpp CacheMap.hpp"
makefile_files="Makefile.sqlassie Makefile.dependencies"

make clean

# Make the Flex and Bison targets
for i in $lexer_and_parser_targets ;
do
	echo make $i ;
	make $i ;
done

exclude_files=$(echo ".o\$ $lexer_and_parser_targets")
exclude_files=$(echo "$exclude_files" | sed 's/^/(/' | sed 's/$/)/' | sed 's/ /|/')

base_temp_dir=$(mktemp -d)
temp_dir=$base_temp_dir/sqlassie
mkdir $temp_dir

source_files=$(make -j 1 -d --dry-run sqlassie | grep 'Considering target' | awk '{print $4}' | sed 's/`//' | sed "s/'\\.//" | grep -v '.o$')
source_files="$dlib_files $makefile_files $c_header_only_files $cpp_header_only_files $source_files"

# Copy necessary files to the directory
cp Makefile.gcc $temp_dir/Makefile
cp sqlassie.conf $temp_dir/
cp -R dlib $temp_dir/dlib
for i in "$source_files" ;
do
	cp $i $temp_dir ;
done
makefile_header='
ifeq "$(VERSION)" "PROFILE"
CXXFLAGS = $(PROFILE_CXXFLAGS) $(WARNING_CXXFLAGS)
CXXFLAGS_NO_WARNINGS = $(PROFILE_CXXFLAGS)
else
ifeq "$(VERSION)" "DEBUG"
CXXFLAGS = $(DEBUG_CXXFLAGS) $(WARNING_CXXFLAGS)
CXXFLAGS_NO_WARNINGS = $(DEBUG_CXXFLAGS)
else
ifeq "$(VERSION)" "RELEASE"
CXXFLAGS = $(RELEASE_CXXFLAGS) $(WARNING_CXXFLAGS)
CXXFLAGS_NO_WARNINGS = $(RELEASE_CXXFLAGS)
OPTIONAL_STRIP = strip
endif
endif
endif
'

echo -e "$makefile_header \ninclude Makefile.sqlassie\ninclude Makefile.dependencies" > $temp_dir/Makefile.common

pushd $base_temp_dir && tar -cvjf sqlassie.tar.bz2 sqlassie && popd && mv $base_temp_dir/sqlassie.tar.bz2 .
exit 0

rm -rf $base_temp_dir
