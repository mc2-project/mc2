#include <openenclave/host.h>

void fill_report(uint8_t* pem_key, uint8_t* nonce, char** usernames, size_t num_users, uint8_t* report_data); 

oe_result_t verify_remote_report(
        const uint8_t* remote_report,
        size_t remote_report_size,
        const uint8_t* data,
        size_t data_size,
        int check_mrenclave,
        char* expected_mrenclave,
        size_t expected_mrenclave_size,
        int check_mrsigner,
        char* expected_mrsigner,
        size_t expected_mrsigner_size);


