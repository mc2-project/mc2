#include <math.h>

#include "base64.h"
#include "io.h"

#include "context.h"
#include "crypto.h"

typedef struct oe_evidence_msg_t {
    uint8_t public_key[CIPHER_PK_SIZE];
    uint8_t nonce[CIPHER_IV_SIZE];
    size_t evidence_size;
    uint8_t evidence[];
} oe_evidence_msg_t;

extern "C" size_t cipher_iv_size() { return CIPHER_IV_SIZE; }

extern "C" size_t rsa_mod_size() { return RSA_MOD_SIZE; }

extern "C" int get_format_settings(uint8_t **format_settings,
                                   size_t *format_settings_size) {
    return Context::getInstance().m_attestation->GetFormatSettings(
        &(Context::getInstance().format_uuid), format_settings,
        format_settings_size);
}

extern "C" size_t cipher_pk_size() { return CIPHER_PK_SIZE; }

extern "C" void get_public_key(uint8_t *evidence_msg, uint8_t *enclave_pem) {
    oe_evidence_msg_t *evidence_msg_t =
        reinterpret_cast<oe_evidence_msg_t *>(evidence_msg);
    memcpy(enclave_pem, evidence_msg_t->public_key, CIPHER_PK_SIZE);
}

extern "C" int attest_evidence(unsigned char *enclave_signer_pem,
                               size_t enclave_signer_pem_size,
                               uint8_t *evidence_msg,
                               size_t evidence_msg_size) {
    oe_evidence_msg_t *evidence_msg_t =
        reinterpret_cast<oe_evidence_msg_t *>(evidence_msg);
    return Context::getInstance().m_attestation->AttestEvidence(
        &(Context::getInstance().format_uuid),
        reinterpret_cast<uint8_t *>(enclave_signer_pem),
        evidence_msg_t->evidence, evidence_msg_t->public_key,
        evidence_msg_t->nonce, enclave_signer_pem_size,
        evidence_msg_t->evidence_size, CIPHER_PK_SIZE);
}

extern "C" size_t sym_enc_size(size_t data_size) {
    return Context::getInstance().m_crypto->SymEncSize(data_size);
}

extern "C" int sym_enc(unsigned char *data, size_t data_size, uint8_t *sym_key,
                       size_t key_size, uint8_t *encrypted_data) {
    return Context::getInstance().m_crypto->SymEnc(
        sym_key, reinterpret_cast<uint8_t *>(data), nullptr, encrypted_data,
        data_size, 0);
}

extern "C" size_t asym_enc_size(size_t data_size) {
    return Context::getInstance().m_crypto->AsymEncSize(data_size);
}

extern "C" int asym_enc(unsigned char *data, size_t data_size, uint8_t *pem_key,
                        size_t key_size, uint8_t *encrypted_data) {
    return Context::getInstance().m_crypto->AsymEnc(
        pem_key, reinterpret_cast<uint8_t *>(data), encrypted_data, data_size);
}

extern "C" size_t asym_sign_size() {
    return Context::getInstance().m_crypto->AsymSignSize();
}

extern "C" int sign_using_keyfile(char *keyfile, uint8_t *data,
                                  size_t data_size, uint8_t *signature) {
    return Context::getInstance().m_crypto->SignUsingKeyfile(
        keyfile, reinterpret_cast<uint8_t *>(data), signature, data_size);
}

extern "C" int verify(uint8_t *pem_key, uint8_t *data, size_t data_size,
                      uint8_t *signature) {
    return Context::getInstance().m_crypto->Verify(pem_key, data, signature,
                                                   data_size);
}

extern "C" int decrypt_dump(char *key, char **models, uint64_t length) {
    const char *total_encrypted;
    int out_len;
    for (int i = 0; i < length; i++) {
        total_encrypted = models[i];

        // Allocate memory to deserialize the ciphertext. Base64 is a wasteful
        // encoding so this buffer will always be large enough.
        uint8_t *ct = new uint8_t[strlen(total_encrypted)];
        auto ct_size =
            data::base64_decode(total_encrypted, strlen(total_encrypted),
                                reinterpret_cast<char *>(ct));

        // Allocate memory for the plaintext
        size_t pt_size = Context::getInstance().m_crypto->SymDecSize(ct_size);
        uint8_t *pt = new uint8_t[ct_size + 1];

        auto ret = Context::getInstance().m_crypto->SymDec(
            reinterpret_cast<uint8_t *>(key), ct, nullptr, pt, ct_size, 0);
        pt[pt_size] = '\0';
        if (ret != 0)
            return ret;

        delete[] ct;
        models[i] = (char *)pt;
    }
    return 0;
}

extern "C" void sxgb_encrypt_data(char *plaintext_file, char *encrypted_file,
                                  char *key_file, int *result) {
    int status = sxgb_encrypt_file(plaintext_file, encrypted_file, key_file);
    *result = status;
}

extern "C" void sxgb_decrypt_data(char *encrypted_file, char *plaintext_file,
                                  char *key_file, int *result) {
    int status = sxgb_decrypt_file(encrypted_file, plaintext_file, key_file);
    *result = status;
}

extern "C" void opaque_encrypt_data(char *plaintext_file, char *schema_file,
                                    char *encrypted_file, char *key_file,
                                    int *result) {
    OpaqueFileProcessor ofp;
    int status = ofp.opaque_encrypt_file(plaintext_file, schema_file,
                                         encrypted_file, key_file);
    *result = status;
}

extern "C" void opaque_decrypt_data(char **encrypted_files,
                                    size_t num_encrypted_files,
                                    char *plaintext_file, char *key_file,
                                    int *result) {
    OpaqueFileProcessor ofp;
    int status = ofp.opaque_decrypt_data(encrypted_files, num_encrypted_files,
                                         plaintext_file, key_file);
    *result = status;
}

extern "C" size_t cipher_key_size() {return CIPHER_KEY_SIZE}