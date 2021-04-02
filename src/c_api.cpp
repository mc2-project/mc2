#include <iostream>
#include "io.h"
#include "attestation.h"
#include "crypto.h"
#include "base64.h"

// Below types taken from XGBoost
/*! \brief unsigned integer type used for feature index. */
using bst_uint = uint32_t;  // NOLINT
/*! \brief integer type. */
using bst_int = int32_t;    // NOLINT
/*! \brief unsigned long integers */
using bst_ulong = uint64_t;  // NOLINT
/*! \brief float type, used for storing statistics */
using bst_float = float;  // NOLINT

/*! \brief Type for data column (feature) index. */
using bst_feature_t = uint32_t;  // NOLINT

extern "C" void attest(
    uint8_t* pem_key, size_t key_size,
    uint8_t* nonce, size_t nonce_size,
    char** usernames, size_t num_users,
    uint8_t* remote_report, size_t remote_report_size,
    int check_mrenclave, char* expected_mrenclave, size_t expected_mrenclave_size,
    int check_mrsigner, char* expected_mrsigner, size_t expected_mrsigner_size,
    int* result) {

    // Attest the remote report and accompanying key.
    size_t total_len = 0;
    for (int i = 0; i < num_users; i++) {
      total_len += strlen(usernames[i]) + 1;
    }

    size_t report_data_size = key_size + nonce_size + total_len;
    uint8_t report_data[report_data_size];

    fill_report(pem_key, nonce, usernames, num_users, report_data);

    oe_result_t verification_result = verify_remote_report(remote_report, remote_report_size, report_data, report_data_size, check_mrenclave, expected_mrenclave, expected_mrenclave_size, check_mrsigner, expected_mrsigner, expected_mrsigner_size);

    // TODO: Logging with more detailed oe result
    if (verification_result == OE_OK) {
        *result = 1;
    } else {
        *result = 0;
    }
}

extern "C" void encrypt_data_with_pk(char* data, size_t len, uint8_t* pem_key, size_t key_size, uint8_t* encrypted_data, size_t* encrypted_data_size) {
    bool result = false;
    mbedtls_pk_context key;
    int res = -1;

    mbedtls_ctr_drbg_context m_ctr_drbg_context;
    mbedtls_entropy_context m_entropy_context;
    mbedtls_pk_context m_pk_context;
    mbedtls_ctr_drbg_init(&m_ctr_drbg_context);
    mbedtls_entropy_init(&m_entropy_context);
    mbedtls_pk_init(&m_pk_context);
    res = mbedtls_ctr_drbg_seed(
      &m_ctr_drbg_context, mbedtls_entropy_func, &m_entropy_context, NULL, 0);
    res = mbedtls_pk_setup(
      &m_pk_context, mbedtls_pk_info_from_type(MBEDTLS_PK_RSA));

    mbedtls_rsa_context* rsa_context;

    mbedtls_pk_init(&key);

    // Read the given public key.
    key_size = strlen((const char*)pem_key) + 1; // Include ending '\0'.
    res = mbedtls_pk_parse_public_key(&key, pem_key, key_size);

    if (res != 0) {
        mbedtls_pk_free(&key);
        // FIXME: log error
        // LOG(FATAL) << "mbedtls_pk_parse_public_key failed.";
    }

    rsa_context = mbedtls_pk_rsa(key);
    rsa_context->padding = MBEDTLS_RSA_PKCS_V21;
    rsa_context->hash_id = MBEDTLS_MD_SHA256;

    // Encrypt the data.
    res = mbedtls_rsa_pkcs1_encrypt(
      rsa_context,
      mbedtls_ctr_drbg_random,
      &m_ctr_drbg_context,
      MBEDTLS_RSA_PUBLIC,
      len,
      (const unsigned char*) data,
      (unsigned char*) encrypted_data);

    if (res != 0) {
        mbedtls_pk_free(&key);
        // FIXME: log error
        // LOG(FATAL) << "mbedtls_rsa_pkcs1_encrypt failed.";
    }

    *encrypted_data_size = mbedtls_pk_rsa(key)->len;

    mbedtls_pk_free( &m_pk_context );
    mbedtls_ctr_drbg_free( &m_ctr_drbg_context );
    mbedtls_entropy_free( &m_entropy_context );
}

extern "C" void sign_data_with_keyfile(char *keyfile, uint8_t* data, size_t data_size, uint8_t* signature, size_t* sig_len) {
    mbedtls_pk_context pk;
    mbedtls_pk_init( &pk );

    int ret;
    if((ret = mbedtls_pk_parse_keyfile( &pk, keyfile, "")) != 0) {
      // FIXME: log error
        // LOG(FATAL) << "signing failed -- mbedtls_pk_parse_public_keyfile returned " << ret;
        std::cout << "signing failed -- mbedtls_pk_parse_public_keyfile returned " << ret << std::endl;
    }

    ret = sign_data(pk, data, data_size, signature, sig_len);
}

extern "C" void decrypt_enclave_key(char* key, uint8_t* encrypted_key, size_t len, uint8_t** out_key) {
    uint8_t* iv = (uint8_t*) encrypted_key;
    uint8_t* tag = iv + CIPHER_IV_SIZE;
    uint8_t* data = tag + CIPHER_TAG_SIZE;
    uint8_t* output = (uint8_t*) malloc(len);

    decrypt_symm(
        (uint8_t*) key,
        data,
        len,
        iv,
        tag,
        NULL,
        0,
        output);
    *out_key = reinterpret_cast<uint8_t*>(output);
}

extern "C" int decrypt_predictions(char* key, uint8_t* encrypted_preds, size_t num_preds, bst_float** preds) {
    size_t len = num_preds*sizeof(float);
    unsigned char* iv = (unsigned char*)encrypted_preds;
    unsigned char* tag = iv + CIPHER_IV_SIZE;
    unsigned char* data = tag + CIPHER_TAG_SIZE;
    unsigned char* output = (unsigned char*) malloc(len);

    decrypt_symm(
        (uint8_t*) key,
        data,
        len,
        iv,
        tag,
        NULL,
        0,
        output);
    *preds = reinterpret_cast<float*>(output);
    return 0;
}

extern "C" int decrypt_dump(char* key, char** models, bst_ulong length) {
    mbedtls_gcm_context gcm;

    mbedtls_gcm_init(&gcm);
    int ret = mbedtls_gcm_setkey(&gcm,      // GCM context to be initialized
        MBEDTLS_CIPHER_ID_AES,          // cipher to use (a 128-bit block cipher)
        (const unsigned char*) key,     // encryption key
        CIPHER_KEY_SIZE * 8);           // key bits (must be 128, 192, or 256)

    if (ret != 0) {
        printf( "mbedtls_gcm_setkey failed to set the key for AES cipher - returned -0x%04x\n", -ret );
        // LOG(FATAL) << "mbedtls_gcm_setkey failed to set the key for AES cipher - returned " << -ret;
        return -1;
    }

    const char* total_encrypted;
    int out_len;
    for (int i = 0; i < length; i++) {
        total_encrypted = models[i];

        char* p = const_cast<char*>(total_encrypted);
        int iv_pos = 0;
        while(*p != '\0' && *p != ',') {
            p++;
            iv_pos++;
        }
        p++;
        int tag_pos = iv_pos + 1;
        while(*p != '\0' && *p != ',') {
            p++;
            tag_pos++;
        }
        size_t out_len;
        unsigned char tag[CIPHER_TAG_SIZE];
        unsigned char iv[CIPHER_IV_SIZE];

        char* ct = (char *) malloc(strlen(total_encrypted) * sizeof(char));

        out_len = data::base64_decode(total_encrypted, iv_pos, (char *) iv);
        out_len = data::base64_decode(total_encrypted + iv_pos + 1, tag_pos - iv_pos, (char *) tag);
        out_len = data::base64_decode(total_encrypted + tag_pos + 1, strlen(total_encrypted) - tag_pos, ct);

        unsigned char* decrypted = (unsigned char*) malloc((out_len + 1) * sizeof(char));
        int ret = decrypt_symm(
            &gcm,
            (const unsigned char*) ct,
            out_len,
            iv,
            tag,
            NULL,
            0,
            decrypted
        );

        decrypted[out_len] = '\0';
        free(ct);
        if (ret != 0) {
            // LOG(FATAL) << "mbedtls_gcm_auth_decrypt failed with error " << -ret;
            std::cout << "mbedtls_gcm_auth_decrypt failed with error " << -ret << std::endl;
            char error[200];
            mbedtls_strerror(ret, error, 200);
            std::cout << error << std::endl;
            return -1;
        }
        models[i] = (char*) decrypted;
    }
    return 0;
}

extern "C" int verify_signature(uint8_t* pem_key, size_t key_size, uint8_t* data, size_t data_len, uint8_t* signature, size_t sig_len) {
    int res = -1;
    mbedtls_pk_context m_pk_context;
    mbedtls_pk_init(&m_pk_context);

    // Read the given public key.
    res = mbedtls_pk_parse_public_key(&m_pk_context, pem_key, key_size);
    if (res != 0) {
        mbedtls_pk_free(&m_pk_context);
        std::cout << "mbedtls_pk_parse_public_key failed." << std::endl;
        return -1;
    }

    verifySignature(m_pk_context, data, data_len, signature, sig_len);
    mbedtls_pk_free( &m_pk_context );
    return 0;
}

extern "C" void sxgb_encrypt_data(char* plaintext_file, char* encrypted_file, char* key_file, int* result) {
    int status = sxgb_encrypt_file(plaintext_file, encrypted_file, key_file);
    *result = status;
}

extern "C" void sxgb_decrypt_data(char* encrypted_file, char* plaintext_file, char* key_file, int* result) {
    int status = sxgb_decrypt_file(encrypted_file, plaintext_file, key_file);
    *result = status;
}

extern "C" void opaque_encrypt_data(char* plaintext_file, char* schema_file, char* encrypted_file, char* key_file, int* result) {
    OpaqueFileProcessor ofp;
    int status = ofp.opaque_encrypt_file(plaintext_file, schema_file, encrypted_file, key_file);
    *result = status;
}

extern "C" void opaque_decrypt_data(char** encrypted_files, size_t num_encrypted_files, char* plaintext_file, char* key_file, int* result) {
    OpaqueFileProcessor ofp;
    int status = ofp.opaque_decrypt_data(encrypted_files, num_encrypted_files, plaintext_file, key_file);
    *result = status;
}
