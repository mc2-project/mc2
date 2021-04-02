#include <algorithm>
#include <assert.h>
#include <fstream>
#include <iomanip>
#include <sstream>
#include <sys/types.h>
#include <sys/stat.h>

#include "base64.h"
#include "csv.hpp"
#include "io.h"
#include "json.hpp"
#include "utils.h"

// for convenience
using json = nlohmann::ordered_json;

#define MAX_BLOCK_SIZE 1000000
#define MAX_ENCRYPTED_BLOCKS_SIZE 1000000000

int sxgb_encrypt_file_with_keybuf(char* fname, char* e_fname, char* key) {
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_entropy_context entropy;
    mbedtls_gcm_context gcm;

    unsigned char iv[CIPHER_IV_SIZE];
    unsigned char tag[CIPHER_TAG_SIZE];

    // Initialize the entropy pool and the random source
    mbedtls_entropy_init( &entropy );
    mbedtls_ctr_drbg_init( &ctr_drbg );

    // Initialize GCM context (just makes references valid) - makes the context ready for mbedtls_gcm_setkey()
    mbedtls_gcm_init(&gcm);

    // The personalization string should be unique to your application in order to add some
    // personalized starting randomness to your random sources.
    std::string pers = "aes generate key for MC^2";

    // CTR_DRBG initial seeding Seed and setup entropy source for future reseeds
    int ret = mbedtls_ctr_drbg_seed( &ctr_drbg, mbedtls_entropy_func, &entropy, (unsigned char *)pers.c_str(), pers.length() );
    if( ret != 0 ) {
        // LOG(FATAL) << "mbedtls_ctr_drbg_seed() failed - returned " << -ret;
        std::cout << "mbedtls_ctr_drbg_seed() failed - returned " << -ret << std::endl;
        return ret;
    }

    // Initialize the GCM context with our key and desired cipher
    ret = mbedtls_gcm_setkey(&gcm,     // GCM context to be initialized
        MBEDTLS_CIPHER_ID_AES,     // cipher to use (a 128-bit block cipher)
        (unsigned char*) key,      // encryption key
        CIPHER_KEY_SIZE * 8);      // key bits (must be 128, 192, or 256)

    if( ret != 0 ) {
    // LOG(FATAL) << "mbedtls_gcm_setkey failed to set the key for AES cipher - returned " << -ret;
        std::cout << "mbedtls_gcm_setkey failed to set the key for AES cipher - returned "  << -ret << std::endl;
        return ret;
    }

    std::ifstream infile(fname);
    std::ofstream myfile;
    myfile.open(e_fname);

    std::string line;
    uint64_t index = 0;
    uint64_t total = 0;

    // Count total number of lines in file
    while (std::getline(infile, line)) {
        // Ignore empty lines
        if (std::all_of(line.begin(), line.end(), isspace))
            continue;
        total++;
    }
    infile.close();

    infile.open(fname);
    while (std::getline(infile, line)) {
        // Ignore empty lines
        if (std::all_of(line.begin(), line.end(), isspace))
            continue;

        index++;
        size_t length = strlen(line.c_str());

        // We use `<index>,<total>` as additional authenticated data to prevent tampering across lines
        std::stringstream ss;
        ss << index << "," << total;
        std::string ss_str = ss.str();

        unsigned char* encrypted = (unsigned char*) malloc(length*sizeof(char));
        ret = encrypt_symm(
            &gcm,
            &ctr_drbg,
            (const unsigned char*)line.c_str(),
            length,
            (unsigned char*)ss_str.c_str(),
            ss_str.length(),
            encrypted,
            iv,
            tag
            );
        if( ret != 0 ) {
            // FIXME: logging
            // LOG(FATAL) << "mbedtls_gcm_crypt_and_tag failed to encrypt the data - returned " << -ret;
            std::cout << "mbedtls_gcm_crypt_and_tag failed to encrypt the data - returned " << -ret << std::endl;
            return ret;
        }
        std::string encoded = data::base64_encode(iv, CIPHER_IV_SIZE);
        myfile
            << index << ","
            << total << ","
            << data::base64_encode(iv, CIPHER_IV_SIZE) << ","
            << data::base64_encode(tag, CIPHER_TAG_SIZE) << ","
            << data::base64_encode(encrypted, length) << "\n";
        free(encrypted);
    }
    infile.close();
    myfile.close();
    return 0;
}

// Input, output, key
int sxgb_encrypt_file(char* fname, char* e_fname, char* k_fname) {
    char key[CIPHER_KEY_SIZE];
    load_key(k_fname, key);
    int result = sxgb_encrypt_file_with_keybuf(fname, e_fname, key);
    return result;
}


int sxgb_decrypt_file_with_keybuf(char* fname, char* d_fname, char* key) {
    mbedtls_gcm_context gcm;

    // Initialize GCM context (just makes references valid) - makes the context ready for mbedtls_gcm_setkey()
    mbedtls_gcm_init(&gcm);
    int ret = mbedtls_gcm_setkey(&gcm,  // GCM context to be initialized
        MBEDTLS_CIPHER_ID_AES,          // cipher to use (a 128-bit block cipher)
        (const unsigned char*) key,     // encryption key
        CIPHER_KEY_SIZE * 8);           // key bits (must be 128, 192, or 256)
    if( ret != 0 ) {
        // FIXME: logging error
        printf( "mbedtls_gcm_setkey failed to set the key for AES cipher - returned -0x%04x\n", -ret );
        // LOG(FATAL) << "mbedtls_gcm_setkey failed to set the key for AES cipher - returned " << -ret;
        return ret;
    }

    std::ifstream infile(fname);
    std::ofstream myfile;
    myfile.open(d_fname);

    std::string line;
    while (std::getline(infile, line)) {
        const char* data = line.c_str();
        int index_pos = 0;
        int total_pos = 0;
        int iv_pos = 0;
        int tag_pos = 0;
        int len = line.length();

        for (int i = 0; i < len; i++) {
            if (data[i] == ',') {
                index_pos = i;
                break;
            }
        }
        for (int i = index_pos + 1; i < len; i++) {
            if (data[i] == ',') {
                total_pos = i;
                break;
            }
        }
        for (int i = total_pos + 1; i < len; i++) {
            if (data[i] == ',') {
                iv_pos = i;
                break;
            }
        }
        for (int i = iv_pos + 1; i < len; i++) {
            if (data[i] == ',') {
                tag_pos = i;
                break;
            }
        }
        assert(0 < index_pos);
        assert(index_pos < total_pos);
        assert(total_pos < iv_pos);
        assert(iv_pos < tag_pos);

        char *aad_str = (char*) malloc (total_pos + 1);
        memcpy(aad_str, data, total_pos);
        aad_str[total_pos] = 0;

        size_t out_len;
        char tag[CIPHER_TAG_SIZE];
        char iv[CIPHER_IV_SIZE];

        char* ct = (char*) malloc(line.size() * sizeof(char));

        out_len = data::base64_decode(data + total_pos + 1, iv_pos - total_pos, iv);
        assert(out_len == CIPHER_IV_SIZE);
        out_len = data::base64_decode(data + iv_pos + 1, tag_pos - iv_pos, tag);
        assert(out_len == CIPHER_TAG_SIZE);
        out_len = data::base64_decode(data + tag_pos + 1, line.size() - tag_pos, ct);

        unsigned char* decrypted = (unsigned char*) malloc((out_len + 1) * sizeof(char));
        int ret = decrypt_symm(
            &gcm,
            (const unsigned char*) ct,
            out_len,
            (unsigned char*) iv,
            (unsigned char*) tag,
            (unsigned char*) aad_str,
            strlen(aad_str),
            decrypted);
        decrypted[out_len] = '\0';
        free(ct);
        if (ret != 0) {
            // FIXME: log error
            // LOG(FATAL) << "mbedtls_gcm_auth_decrypt failed with error " << -ret;
            std::cout << "mbedtls_gcm_auth_decrypt failed with error " << -ret << std::endl;
            return ret;
        }
        myfile << decrypted << "\n";
    }
    infile.close();
    myfile.close();
    return 0;
}

// Input, output, key
int sxgb_decrypt_file(char* fname, char* d_fname, char* k_fname) {
    char key[CIPHER_KEY_SIZE];
    load_key(k_fname, key);
    int result = sxgb_decrypt_file_with_keybuf(fname, d_fname, key);
    return result;
}

int OpaqueFileProcessor::opaque_encrypt_file(char* fname, char* schema_file, char* e_fname, char* k_fname) {
    // Read in user symmetric key
    char key[CIPHER_KEY_SIZE];
    load_key(k_fname, key);

    memcpy(symm_key, (uint8_t*) key, CIPHER_KEY_SIZE);

    output_dir = std::string(e_fname);

    // Read in schema
    std::string schema;
    std::ifstream schema_stream(schema_file);
    if (schema_stream.is_open()) {
        std::getline(schema_stream, schema);
        schema_stream.close();
    }

    // Get types as specified by schema and put them into vector
    std::vector<std::string> column_names;
    std::vector<std::string> types;
    // TODO: add vector to determine whether each column is nullable
    
    std::vector<std::string> column_names_to_types = split(schema, ',');
    for (std::string column : column_names_to_types) {
        std::vector<std::string> one_column = split(column, ':');
        column_names.push_back(one_column[0]);
        types.push_back(one_column[1]);
    }

    // Read in file to encrypt
    csv::CSVFormat format;
    // TODO; support files with no header
    // format.header_row(-1);
    csv::CSVReader reader(fname, format);

    std::vector<flatbuffers::Offset<tuix::Field>> field_offsets;
    int i = 0;

    for (csv::CSVRow& row: reader) { // Input iterator
        for (csv::CSVField& field: row) {
            // Serialize each field in a row
            flatbuffers::Offset<tuix::Field> field_offset;
            std::string field_type = types[i];
            if (field_type == "integer") {
                field_offset = tuix::CreateField(
                    rows_builder,
                    tuix::FieldUnion_IntegerField,
                    tuix::CreateIntegerField(rows_builder, static_cast<int>(field.get<int>())).Union(),
                    false // FIXME: check whether field is null
                );
            } else if (field_type == "long") {
                field_offset = tuix::CreateField(
                    rows_builder,
                    tuix::FieldUnion_LongField,
                    tuix::CreateLongField(rows_builder, static_cast<long>(field.get<long>())).Union(),
                    false // FIXME: check whether field is null
                );
            } else if (field_type == "float") {
                field_offset = tuix::CreateField(
                    rows_builder,
                    tuix::FieldUnion_FloatField,
                    tuix::CreateFloatField(rows_builder, static_cast<float>(field.get<float>())).Union(),
                    false // FIXME: check whether field is null
                );
            } else if (field_type == "double") {
                field_offset = tuix::CreateField(
                    rows_builder,
                    tuix::FieldUnion_DoubleField,
                    tuix::CreateDoubleField(rows_builder, static_cast<double>(field.get<double>())).Union(),
                    false // FIXME: check whether field is null
                );
            } else {
                std::string field_string = field.get<std::string>();
                std::vector<uint8_t> str_vec(field_string.begin(), field_string.end());
                field_offset = tuix::CreateField(
                    rows_builder,
                    tuix::FieldUnion_StringField,
                    tuix::CreateStringFieldDirect(rows_builder, &str_vec, str_vec.size()).Union(),
                    false // FIXME: check whether field is null
                );
            }
            field_offsets.push_back(field_offset);
            i++;
        }
        i = 0;
        row_offsets.push_back(tuix::CreateRowDirect(rows_builder, &field_offsets));
        field_offsets.clear();

        if (rows_builder.GetSize() >= MAX_BLOCK_SIZE) {
            finish_block();
        }
    }

    if (row_offsets.size() > 0) {
        finish_block();
    }

    if (enc_block_offsets.size() > 0) {
        finish_encrypted_blocks();
    }

    // Reset num_partitions_outputted
    num_partitions_outputted = 0;

    std::string output_schema_path = output_dir + std::string("/schema");
    write_schema(column_names, types, output_schema_path.c_str());
    
    return 0;
}

void OpaqueFileProcessor::write_schema(std::vector<std::string> column_names, std::vector<std::string> column_types, const char* schema_path) {
    json j;
    j["type"] = "struct";
    std::vector<json> fields;
    for (int i = 0; i < column_names.size(); i++) {
        json field = {{"name", column_names[i]}, {"type", column_types[i]}, {"nullable", true}};
        fields.push_back(field);
    }
    j["fields"] = fields;
    std::ofstream schema;
    schema.open(schema_path);
    schema << j << std::endl;
    schema.close();
}

void OpaqueFileProcessor::finish_block() {
    rows_builder.Finish(tuix::CreateRowsDirect(rows_builder, &row_offsets));
    uint8_t* serialized_block = rows_builder.GetBufferPointer();
    size_t serialized_block_len = rows_builder.GetSize();

    uint8_t output[serialized_block_len];
    uint8_t iv[CIPHER_IV_SIZE];
    uint8_t tag[CIPHER_TAG_SIZE];

    encrypt_symm(
        symm_key,
        serialized_block,
        serialized_block_len,
        NULL,
        0,
        output,
        iv,
        tag
    );

    size_t enc_rows_size = CIPHER_IV_SIZE + serialized_block_len + CIPHER_TAG_SIZE;

    uint8_t ciphertext[enc_rows_size];
    memcpy(ciphertext, iv, CIPHER_IV_SIZE);
    memcpy(ciphertext + CIPHER_IV_SIZE, output, serialized_block_len);
    memcpy(ciphertext + CIPHER_IV_SIZE + serialized_block_len, tag, CIPHER_TAG_SIZE);

    flatbuffers::Offset<tuix::EncryptedBlock> encrypted_block_offset = tuix::CreateEncryptedBlock(
        enc_blocks_builder,
        row_offsets.size(),
        enc_blocks_builder.CreateVector(ciphertext, enc_rows_size)
    );

    enc_block_offsets.push_back(encrypted_block_offset);

    if (enc_blocks_builder.GetSize() >= MAX_ENCRYPTED_BLOCKS_SIZE) {
        finish_encrypted_blocks();
    }

    // Reset state for rows
    rows_builder.Clear();
    row_offsets.clear();
}

void OpaqueFileProcessor::finish_encrypted_blocks() {
    // Get encrypted data as a buffer
    auto root_offset = tuix::CreateEncryptedBlocksDirect(enc_blocks_builder, &enc_block_offsets);
    enc_blocks_builder.Finish(root_offset);
    uint8_t* encrypted_data = enc_blocks_builder.GetBufferPointer();
    size_t encrypted_data_size = enc_blocks_builder.GetSize();

    // If this is the first partition outputted for this dataset, create directory for encrypted output
    if (num_partitions_outputted == 0) {
        // Create top level directory for output
        int status = mkdir(output_dir.c_str(), S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH);
        if (status != 0) {
            // TODO: throw error
            std::cout << "Failed to created output directory: " << output_dir.c_str() << ". Exit status " << status << std::endl;
        }
        // Create directory for data
        std::string data_dir = output_dir + std::string("/data");
        status = mkdir(data_dir.c_str(), S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH);
        if (status != 0) {
            // TODO: throw error
            std::cout << "Failed to created output directory: " << data_dir.c_str() << ". Exit status " << status << std::endl;
        }
    }

    // Write encrypted data to file
    std::stringstream ss;
    ss << "cpp-part-";
    ss << std::setw(5) << std::setfill('0') << num_partitions_outputted;
    std::string data_path = output_dir + std::string("/data/") + ss.str();
    std::ofstream encrypted_output(data_path.c_str());
    if (encrypted_output.is_open()) {
        encrypted_output.write((const char*) encrypted_data, encrypted_data_size);
        encrypted_output.close();
    } else {
        // TODO: throw error
        std::cout << "Failed to write to file: " << data_path << std::endl;
    }

    // Increment number of partitions
    num_partitions_outputted++;

    enc_blocks_builder.Clear();
    enc_block_offsets.clear();
}

int OpaqueFileProcessor::opaque_decrypt_data(char** e_fnames, size_t num_encrypted_files, char* d_fname, char* k_fname) {
    // Read in user symmetric key
    char key[CIPHER_KEY_SIZE];
    load_key(k_fname, key);
    memcpy(symm_key, (uint8_t*) key, CIPHER_KEY_SIZE);

    // Create CSV writer
    std::ofstream ss(d_fname);
    auto writer = csv::make_csv_writer(ss);

    for (size_t r = 0; r < num_encrypted_files; r++) {
        char* e_fname = e_fnames[r];

        // Read in encrypted file into memory
        std::ifstream infile(e_fname, std::ios::binary);
        infile.seekg(0, std::ios_base::end);
        int file_size = infile.tellg();

        uint8_t* file_buffer = (uint8_t*) malloc(file_size * sizeof(uint8_t));

        infile.seekg(0, std::ios_base::beg);
        infile.read((char*) file_buffer, file_size);
        infile.close();

        auto encrypted_blocks = tuix::GetEncryptedBlocks(file_buffer);

        for (int i = 0; i < encrypted_blocks->blocks()->size(); i++) {
            // Retrieve and decrypt each EncryptedBlock
            auto encrypted_block = encrypted_blocks->blocks()->Get(i);
            uint8_t* enc_rows = (uint8_t*) encrypted_block->enc_rows()->data();

            size_t decrypted_data_len = encrypted_block->enc_rows()->size() - CIPHER_IV_SIZE - CIPHER_TAG_SIZE;

            uint8_t* iv = enc_rows;
            uint8_t* ciphertext = enc_rows + CIPHER_IV_SIZE;
            uint8_t* tag = enc_rows + CIPHER_IV_SIZE + decrypted_data_len;

            uint8_t* plaintext = (uint8_t*) malloc(decrypted_data_len * sizeof(uint8_t));

            int ret = decrypt_symm(
                symm_key,
                ciphertext,
                decrypted_data_len,
                iv,
                tag,
                NULL,
                0,
                plaintext
            );

            auto rows = tuix::GetRows(plaintext);
            for (int j = 0; j < rows->rows()->size(); j++) {
                auto row = rows->rows()->Get(j);
                std::vector<std::string> output_row;
                if (!row->is_dummy()) {
                    for (int k = 0; k < row->field_values()->size(); k++) {
                        auto field = row->field_values()->Get(k);

                        // Below, we use a string stream to prevent unexpected results with to_string()
                        // https://stackoverflow.com/questions/2125880/convert-float-to-stdstring-in-c
                        if (!field->is_null()) {
                            if (field->value_type() == tuix::FieldUnion_IntegerField) {
                                auto field_value = static_cast<const tuix::IntegerField*>(field->value())->value();
                                output_row.push_back(std::to_string(static_cast<int>(field_value)));
                            } else if (field->value_type() == tuix::FieldUnion_LongField) {
                                auto field_value = static_cast<const tuix::LongField*>(field->value())->value();
                                std::ostringstream ss;
                                ss << static_cast<long>(field_value);
                                output_row.push_back(ss.str());
                            } else if (field->value_type() == tuix::FieldUnion_FloatField) {
                                auto field_value = static_cast<const tuix::FloatField*>(field->value())->value();
                                std::ostringstream ss;
                                ss << static_cast<float>(field_value);
                                output_row.push_back(ss.str());
                            } else if (field->value_type() == tuix::FieldUnion_DoubleField) {
                                auto field_value = static_cast<const tuix::DoubleField*>(field->value())->value();
                                std::ostringstream ss;
                                ss << static_cast<double>(field_value);
                                output_row.push_back(ss.str());
                            } else {
                                // Field is a flatbuffers vector
                                std::vector<char> field_string;
                                auto field_value = static_cast<const tuix::StringField*>(field->value())->value();
                                for (int m = 0; m < field_value->size(); m++) {
                                    field_string.push_back((char)field_value->Get(m));
                                }
                                output_row.push_back(std::string(field_string.begin(), field_string.end()));
                            }
                                
                        } 
                    }
                    
                }
                writer << output_row;
            }
            free(plaintext);
        }
        free(file_buffer);
    }

    return 0;
}
