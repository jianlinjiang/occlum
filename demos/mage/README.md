# A Demo for MAGE: Mutual Attestation for a Group of Enclaves without Trusted Third Parties

Notice: Intel SGX SDK/PSW should support mage.

## Build Occlum with mage support
```
OCCLUM_RELEASE_BUILD=1 SGX_MAGE=1 make 
```

## Build `mage_demo` with CMake
```
mkdir build && cd build
cmake ../ -DCMAKE_CXX_COMPILER=occlum-g++
make
cd ..
cp build/mage_demo .
```
The resulting `mage_demo` can be found in the current directory.

## Build occlum instance with `mage_demo`.

### first occlum_instance: occlum_instance_1

```
mkdir occlum_instance_1 && cd occlum_instance_1
occlum init && rm -rf image
copy_bom -f ../mage.yaml --root image --include-dir /opt/occlum/etc/template
cp ../Occlum1.json Occlum.json
occlum build
cd ..
```

### second occlum_instance: occlum_instance_2

```
mkdir occlum_instance_2 && cd occlum_instance_2
occlum init && rm -rf image
copy_bom -f ../mage.yaml --root image --include-dir /opt/occlum/etc/template
cp ../Occlum2.json Occlum.json
occlum build
cd ..
```

### generate mage info for occlum instances

```
cd occlum_instance_1
occlum build --genmage ../mage.bin
cd ..

cd occlum_instance_2
occlum build --genmage ../mage.bin
cd ..
```

### sign mage for occlum instances

```
cd occlum_instance_1
occlum build --signmage ../mage.bin
cd ..

cd occlum_instance_2
occlum build --signmage ../mage.bin
cd ..
```

##  run mage_demo in occlum

```
cd occlum_instance_1
occlum run /bin/mage_demo 1
cd ..

cd occlum_instance_2
occlum run /bin/mage_demo 0
```

The `mage_demo` print the mrenclave of the other occlum instance.