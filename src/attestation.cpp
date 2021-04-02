#include "attestation.h"
#include "crypto.h"
#include <mbedtls/entropy.h>    // mbedtls_entropy_context
#include <mbedtls/ctr_drbg.h>   // mbedtls_ctr_drbg_context
#include <mbedtls/cipher.h>     // MBEDTLS_CIPHER_ID_AES
#include <mbedtls/gcm.h>        // mbedtls_gcm_context
#include <iostream>

static const char* CA_CERT = 
R"( -----BEGIN CERTIFICATE-----
MIID/TCCAmWgAwIBAgIUag4+JmUlpecz79+hB5nWdv8vsuswDQYJKoZIhvcNAQEL
BQAwDzENMAsGA1UEAwwEcm9vdDAeFw0yMDA4MzExNzQ5NDNaFw0zMDA4MjkxNzQ5
NDNaMA8xDTALBgNVBAMMBHJvb3QwggGgMA0GCSqGSIb3DQEBAQUAA4IBjQAwggGI
AoIBgQDGJob5lAEOyq+QDi/6gGxnmkrwWGLApC/jIVTsTt5r7Vp73mn1QBbpovso
kze9ahqU6x+gT8kI7VPavXwN+MjJMzbPKEErvl3XMoY6XPSIaQrEEPJiMEB2wx2y
b5cLC9VqcYryPbrXd5LP5eXqXMoEpxFgOhnXKuMtBotAEMpBS/Uk5pZuzw6IC2BM
+tKqWyma3ZtSy+CRDqOrSGsvtPHAExBxNbGEIg3rRUN7v3FtRcmydKwURMxFVBV+
/UrSDocz6Vq7IBeWQP2ytsX1pcDJyWJd1R78fE6ID8jF7IKnykzc8Bl6YxV+kxwt
du9o13l3fiq+vSi8yb7eckJtkG3OIXQRCRGWyll2KEZvgDW032v30X9W/OdEZWZF
ATLt3ufmS2QdPOxEFt/KeAb8A8Awc05uhYYIK2kvo1i7iikwBD5OevJZdB8108Dr
5UZ4rkhtiClrnIP26shZlzwtMJOQ+TanGB7pinKaf2K6Mq3ZF58OUQ8RsFLyeDL2
7TX+8GECAQOjUzBRMB0GA1UdDgQWBBRQm3Yp9L/SChF+/OJ1E0lZhB3SajAfBgNV
HSMEGDAWgBRQm3Yp9L/SChF+/OJ1E0lZhB3SajAPBgNVHRMBAf8EBTADAQH/MA0G
CSqGSIb3DQEBCwUAA4IBgQBx8ZxK0UuGAq67zQVPn/ddJoqFEvCPRWVGfzOQLaTP
5URHJLFRoSrluZgpxUAuyMfGnoVh5v2aT5mYgBqvx7X+SWJx90weU2rfGzFslvt2
VtPDZcZH2VgN1l2upbor7RpT6K3Fd0Mftw7+YcWTgUo+xffbBuYfBlgcQo/PcfUr
4FbsmP50DGDTTU80JW/icRc0tCCb3MroZe36tZ5nTUrGghwo8c1ICFJNrkdrfGyf
y6PytCbD9desjc24SzI7eu5Y0MmwmfGHUl/KwbZtLNGf3lNhgiI/tbFdo6nBGGrE
ogfdkhe+A8r7o6QtQYzsaLRePeWpu1/yDrxgJySA0E+BhEDn7kNVSpqn3B2gVAHe
Yxxy6HOfCTWMKTkj8pD8B6Swo81vBM1uH2hHdyEWZG80jPgxWVttniYkfv1jIcJW
5zgZ7/HT/3jRSNwARQMEs/vH38Cyntx5TCU4aDgP67fp+SfGf43xEZhxcqoCXzTN
Voyw9vprJOhvJ05ewzhelqQ=
-----END CERTIFICATE-----)";

// TODO: this needs to be tested
bool verify_mrenclave(
        uint8_t* expected_unique_id_buf,
        size_t expected_unique_id_buf_size,
        uint8_t* received_unique_id_buf,
        size_t received_unique_id_buf_size) {

    if (expected_unique_id_buf_size != received_unique_id_buf_size) {
        return false;
    }

    if (memcmp(expected_unique_id_buf, received_unique_id_buf, expected_unique_id_buf_size) != 0) {
        return false;
    }
    return true;
}

bool verify_mrsigner(
    char* siging_public_key_buf,
    size_t siging_public_key_buf_size,
    uint8_t* signer_id_buf,
    size_t signer_id_buf_size) {

    mbedtls_pk_context ctx;
    mbedtls_pk_type_t pk_type;
    mbedtls_rsa_context* rsa_ctx = NULL;
    uint8_t* modulus = NULL;
    size_t modulus_size = 0;
    int res = 0;
    bool ret = false;
    unsigned char* signer = NULL;

    signer = (unsigned char*) malloc(signer_id_buf_size);
    if (signer == NULL) {
        printf("Out of memory\n");
        goto exit;
    }

    mbedtls_pk_init(&ctx);
    res = mbedtls_pk_parse_public_key(
      &ctx,
      (const unsigned char*)siging_public_key_buf,
      siging_public_key_buf_size);
    if (res != 0) {
        printf("mbedtls_pk_parse_public_key failed with %d\n", res);
        goto exit;
    }

    pk_type = mbedtls_pk_get_type(&ctx);
    if (pk_type != MBEDTLS_PK_RSA) {
        printf("mbedtls_pk_get_type had incorrect type: %d\n", res);
        goto exit;
    }

    rsa_ctx = mbedtls_pk_rsa(ctx);
    modulus_size = mbedtls_rsa_get_len(rsa_ctx);
    modulus = (uint8_t*) malloc(modulus_size);
    if (modulus == NULL) {
        printf("malloc for modulus failed with size %zu:\n", modulus_size);
        goto exit;
    }

    res = mbedtls_rsa_export_raw(
        rsa_ctx, modulus, modulus_size, NULL, 0, NULL, 0, NULL, 0, NULL, 0);
    if (res != 0) {
        printf("mbedtls_rsa_export failed with %d\n", res);
        goto exit;
    }

    // Reverse the modulus and compute sha256 on it.
    for (size_t i = 0; i < modulus_size / 2; i++) {
        uint8_t tmp = modulus[i];
        modulus[i] = modulus[modulus_size - 1 - i];
        modulus[modulus_size - 1 - i] = tmp;
    }

    // Calculate the MRSIGNER value which is the SHA256 hash of the
    // little endian representation of the public key modulus. This value
    // is populated by the signer_id sub-field of a parsed oe_report_t's
    // identity field.
    if (compute_sha256(modulus, modulus_size, signer) != 0) {
        goto exit;
    }

    if (memcmp(signer, signer_id_buf, signer_id_buf_size) != 0) {
        printf("mrsigner is not equal!\n");
        for (int i = 0; i < signer_id_buf_size; i++) {
          printf(
              "0x%x - 0x%x\n", (uint8_t)signer[i], (uint8_t)signer_id_buf[i]);
        }
        goto exit;
    }

    ret = true;

    exit:
    if (signer)
        free(signer);

    if (modulus != NULL)
        free(modulus);

    mbedtls_pk_free(&ctx);
    return ret;
}

void fill_report(uint8_t* pem_key, uint8_t* nonce, char** usernames, size_t num_users, uint8_t* report_data) {
    memcpy(report_data, pem_key, CIPHER_PK_SIZE);
    memcpy(report_data + CIPHER_PK_SIZE, nonce, CIPHER_IV_SIZE);
    uint8_t* ptr = report_data + CIPHER_PK_SIZE + CIPHER_IV_SIZE;
    for (int i = 0; i < num_users; i++) {
      size_t len = strlen(usernames[i]) + 1;
      memcpy(ptr, usernames[i], len);
      ptr += len;
    }
}

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
        size_t expected_mrsigner_size) {

    bool ret = false;
    uint8_t sha256[32];

    oe_report_t parsed_report = {0};
    oe_result_t result = OE_OK;

    // 1)  Validate the report's trustworthiness
    // Verify the remote report to ensure its authenticity.
    result = oe_verify_report(NULL, remote_report, remote_report_size, &parsed_report);
    if (result != OE_OK) {
        std::cout << "Remote attestation failed. Remote report verification failed." << std::endl;
        return OE_FAILURE;
    }

    // 2) validate the enclave identity's signed_id is the hash of the public
    // signing key that was used to sign an enclave. Check that the enclave was
    // signed by an trusted entity.
    if (check_mrsigner) {
        bool mrsigner_verifies = verify_mrsigner((char*) expected_mrsigner, expected_mrsigner_size, parsed_report.identity.signer_id, sizeof(parsed_report.identity.signer_id));

        if (!mrsigner_verifies) {
             std::cout << "Remote attestation failed. MRSIGNER value not equal." << std::endl;
             return OE_FAILURE;
        }
    }

    // 3) Check that the enclave's unique ID, i.e. the 256 bit hash of the enclave build log, matches the expected one
    if (check_mrenclave) {
        bool mrenclave_verifies = verify_mrenclave((uint8_t*) expected_mrenclave, expected_mrenclave_size, parsed_report.identity.unique_id, sizeof(parsed_report.identity.unique_id));

        if (!mrenclave_verifies) {
            std::cout << "Remote attestation failed. MRENCLAVE value not equal." << std::endl;
            return OE_FAILURE;
        }
    }

    // check the enclave's product id and security version
    // see enc.conf for values specified when signing the enclave.
    if (parsed_report.identity.product_id[0] != 1) {
        std::cout << "Remote attestation failed. Enclave product ID check failed." << std::endl;
        return OE_FAILURE;
    }

    if (parsed_report.identity.security_version < 1) {
        std::cout << "Remote attestation failed. Enclave security version check failed." << std::endl;;
        return OE_FAILURE;
    }

    // 4) Validate the report data
    //    The report_data has the hash value of the report data
    if (compute_sha256(data, data_size, sha256) != 0) {
        std::cout << "Remote attestation failed. Report data hash validation failed." << std::endl;
        return OE_FAILURE;
    }

    if (memcmp(parsed_report.report_data, sha256, sizeof(sha256)) != 0) {
        std::cout << "Remote attestation failed. SHA256 mismatch. There is likely a client list mismatch." << std::endl; 
        return OE_FAILURE;
    }
    return OE_OK;
 
}

