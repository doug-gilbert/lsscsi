#!/bin/sh

cd src || exit
./cmake_del_artifacts.sh
cd ..

cd doc || exit
./cmake_del_artifacts.sh
cd ..

cd scripts || exit
./cmake_del_artifacts.sh
cd ..

rm -rf \
	build \
	CMakeCache.txt \
	CMakeFiles \
	CPackConfig.cmake \
	CPackSourceConfig.cmake \
	CMakeFiles \
	_CPack_Packages \
	cmake_install.cmake \
	CTestTestfile.cmake \
	DartConfiguration.tcl \
	install_manifest.txt \
	ls_name_value_rd \
	lsscsi \
	lsscsi.8.gz \
	lsscsi_json.8.gz \
	ls_name_value.8.gz \
	ls_name_value_rd.8.gz \
	Testing \
	Makefile

