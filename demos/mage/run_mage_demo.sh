#!/bin/bash
rm -rf build 
rm -rf mage.bin
rm -rf occlum_instance_1
rm -rf occlum_instance_2

mkdir build && cd build
cmake ../ -DCMAKE_CXX_COMPILER=occlum-g++
make 
cd ..
cp build/mage_demo .

mkdir occlum_instance_1 && cd occlum_instance_1
occlum init && rm -rf image
copy_bom -f ../mage.yaml --root image --include-dir /opt/occlum/etc/template
cp ../Occlum1.json Occlum.json
occlum build
cd ..

mkdir occlum_instance_2 && cd occlum_instance_2
occlum init && rm -rf image
copy_bom -f ../mage.yaml --root image --include-dir /opt/occlum/etc/template
cp ../Occlum2.json Occlum.json
occlum build
cd ..

cd occlum_instance_1
occlum build --genmage ../mage.bin
cd ..

cd occlum_instance_2
occlum build --genmage ../mage.bin
cd ..

cd occlum_instance_1
occlum build --signmage ../mage.bin
cd ..

cd occlum_instance_2
occlum build --signmage ../mage.bin
cd ..

cd occlum_instance_1
occlum run /bin/mage_demo 1 2
cd ..

cd occlum_instance_2
occlum run /bin/mage_demo 1 1
cd ..