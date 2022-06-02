
#include <sgx_tcrypto.h>
#include <sgx_report.h>
#include <fcntl.h> 
#include <unistd.h> 
#include <sys/ioctl.h>
#include <iostream>
#include <cstring>
typedef struct {
    const uint64_t idx;
    uint8_t *mrenclave;
} sgxioc_mage_derive_mrenclave_arg_t;

typedef struct
{
    const sgx_target_info_t *target_info; // input (optinal)
    const sgx_report_data_t *report_data; // input (optional)
    sgx_report_t *report;                 // output
} sgxioc_create_report_arg_t;

#define SGXIOC_SELF_TARGET _IOR('s', 3, sgx_target_info_t)
#define SGXIOC_CREATE_REPORT _IOWR('s', 4, sgxioc_create_report_arg_t)
#define SGXIOC_MAGE_DERIVE_MRENCLAVE _IOWR('s', 11, sgxioc_mage_derive_mrenclave_arg_t)

int main(int argc, char* argv[]) {
    // open sgx driver
    int sgx_fd; 
    if ( (sgx_fd = open("/dev/sgx", O_RDONLY)) < 0) {
        perror("Can't open sgx device.");
        return -1;
    }

    // get self target
    sgx_target_info_t target_info;
    if (ioctl(sgx_fd, SGXIOC_SELF_TARGET, &target_info) < 0) {
        perror("Can't get self target.");
        return -1;
    }

    sgx_report_t report;
    sgx_report_data_t report_data;
    memset(&report, 0, sizeof(report));
    sgxioc_create_report_arg_t report_arg = {
        .target_info = (const sgx_target_info_t*) &target_info,
        .report_data = (const sgx_report_data_t *) &report_data,
        .report = &report
    };
    if (ioctl(sgx_fd, SGXIOC_CREATE_REPORT, &report_arg) < 0) {
        perror("Can't get enclave report.");
        return -1;
    }
    printf("self mrenclave: ");
    for(int i = 0; i < 32; i++) 
        printf("%02x", report.body.mr_enclave.m[i]);
    printf("\n");

    uint8_t other_mrenclave[32];
    const char* index = argv[1];
    uint64_t idx = std::stoi(index);
    printf("%lu", idx);
    sgxioc_mage_derive_mrenclave_arg_t mage_derive_arg {
        .idx = idx,
        .mrenclave = other_mrenclave
    };
    if (ioctl(sgx_fd, SGXIOC_MAGE_DERIVE_MRENCLAVE, &mage_derive_arg) < 0) {
        perror("Can't derive mrenclave report.");
        return -1;
    }
    printf("the other mrenclave: ");
    for(int i = 0; i < 32; i++) 
        printf("%02x", other_mrenclave[i]);
    printf("\n");

    close(sgx_fd);
    return 0;
}
