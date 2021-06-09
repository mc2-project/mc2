#include "crypto.h"
#include "flatbuffers/Rows_generated.h"
#include "flatbuffers/EncryptedBlock_generated.h"

// Encrypt a file in Secure XGBoost encryption format
int sxgb_encrypt_file(char* fname, char* e_fname, char* k_fname); 

// Decrypt a file encrypted using Secure XGBoost encryption format
int sxgb_decrypt_file(char* fname, char* d_fname, char* k_fname);

class OpaqueFileProcessor {
public:
    // Encrypt a file in Opaque encryption format
    int opaque_encrypt_file(char* fname, char* schema_file, char* e_fname, char* k_fname);

    // Decrypt a file encrypted using Opaque encryption format
    int opaque_decrypt_data(char** e_fnames, size_t num_encrypted_files, char* d_fname, char* k_fname);

private:
    uint8_t symm_key[CIPHER_KEY_SIZE];
    int num_partitions_outputted = 0;

    std::string output_dir;

    // For encrypted blocks
    // A Flatbuffers builder containing one or more serialized Encrypted Block's
    flatbuffers::FlatBufferBuilder enc_blocks_builder;
    // A vector holding offsets to each built Encrypted Block
    std::vector<flatbuffers::Offset<tuix::EncryptedBlock>> enc_block_offsets;

    // For rows
    // A Flatbuffers builder containing one or more serialized Row's
    flatbuffers::FlatBufferBuilder rows_builder;
    // A vector holding the offsets to each built row
    std::vector<flatbuffers::Offset<tuix::Row>> row_offsets;

    void finish_block();
    void finish_encrypted_blocks();
    void write_schema(std::vector<std::string> column_names, std::vector<std::string> column_types, const char* schema_path);

};
