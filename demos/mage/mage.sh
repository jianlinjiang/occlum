rm -rf mage.bin
cd occlum_workspace
occlum build -f 
/opt/occlum/sgxsdk-tools/bin/x64/sgx_sign genmage -key /opt/occlum/etc/template/Enclave.pem -config build/Enclave.xml -enclave build/lib/libocclum-libos.so.0 -out build/lib/libocclum-libos.signed.so -mageout ../mage.bin
cd ..
cd occlum_workspace1
occlum build -f 
/opt/occlum/sgxsdk-tools/bin/x64/sgx_sign genmage -key /opt/occlum/etc/template/Enclave.pem -config build/Enclave.xml -enclave build/lib/libocclum-libos.so.0 -out build/lib/libocclum-libos.signed.so -mageout ../mage.bin
cd ..
cd occlum_workspace
/opt/occlum/sgxsdk-tools/bin/x64/sgx_sign signmage -key /opt/occlum/etc/template/Enclave.pem -config build/Enclave.xml -enclave build/lib/libocclum-libos.so.0 -out build/lib/libocclum-libos.signed.so -magein ../mage.bin
cd ..
cd occlum_workspace1 
/opt/occlum/sgxsdk-tools/bin/x64/sgx_sign signmage -key /opt/occlum/etc/template/Enclave.pem -config build/Enclave.xml -enclave build/lib/libocclum-libos.so.0 -out build/lib/libocclum-libos.signed.so -magein ../mage.bin
cd ..