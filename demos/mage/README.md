# A Demo for MAGE: Mutual Attestation for a Group of Enclaves without Trusted Third Parties

Notice: Intel SGX SDK/PSW should support mage.

1. Build `mage_demo` with CMake
```
mkdir build && cd build
cmake ../ -DCMAKE_C_COMPILER=occlum-gcc
make
cd ..
cp build/mage_demo .
```

Either way, the resulting `mage_demo` can be found in the current directory.

2. Build occlum instance with `mage_demo`.

first occlum: occlum_workspace0

```
mkdir occlum_workspace0 && cd occlum_workspace0
occlum init && rm -rf image
copy_bom -f ../mage.yaml --root image --include-dir /opt/occlum/etc/template
occlum build
cd ..
```

second occlum: occlum_workspace1

```
mkdir occlum_workspace1 && cd occlum_workspace1
occlum init && rm -rf image
copy_bom -f ../mage.yaml --root image --include-dir /opt/occlum/etc/template
occlum build
cd ..
```

generate mage info for occlum instances

```
cd occlum_workspace0
/opt/occlum/sgxsdk-tools/bin/x64/sgx_sign genmage -key /opt/occlum/etc/template/Enclave.pem -config build/Enclave.xml -enclave build/lib/libocclum-libos.so.0 -out build/lib/libocclum-libos.signed.so -mageout ../mage.bin
cd ..

cd occlum_workspace1
/opt/occlum/sgxsdk-tools/bin/x64/sgx_sign genmage -key /opt/occlum/etc/template/Enclave.pem -config build/Enclave.xml -enclave build/lib/libocclum-libos.so.0 -out build/lib/libocclum-libos.signed.so -mageout ../mage.bin
cd ..

```

sign mage for occlum instances

```
cd occlum_workspace0
/opt/occlum/sgxsdk-tools/bin/x64/sgx_sign signmage -key /opt/occlum/etc/template/Enclave.pem -config build/Enclave.xml -enclave build/lib/libocclum-libos.so.0 -out build/lib/libocclum-libos.signed.so -magein ../mage.bin
cd ..

cd occlum_workspace1
/opt/occlum/sgxsdk-tools/bin/x64/sgx_sign signmage -key /opt/occlum/etc/template/Enclave.pem -config build/Enclave.xml -enclave build/lib/libocclum-libos.so.0 -out build/lib/libocclum-libos.signed.so -magein ../mage.bin
cd ..
```

3.  run mage_demo in occlum

```
cd occlum_workspace0
occlum run /bin/mage_demo 1
cd ..

cd occlum_workspace1
occlum run /bin/mage_demo 0
```

The `mage_demo` print the mrenclave of the other occlum instance.