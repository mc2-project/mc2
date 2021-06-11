#include <algorithm>
#include <assert.h>
#include <fstream>
#include <iomanip>
#include <sstream>
#include <sys/stat.h>
#include <sys/types.h>

#include "base64.h"
#include "csv.hpp"
#include "io.h"
#include "json.hpp"
#include "utils.h"

#include "context.h"

// for convenience
using json = nlohmann::ordered_json;

#define MAX_BLOCK_SIZE 1000000
#define MAX_ENCRYPTED_BLOCKS_SIZE 1000000000

int sxgb_encrypt_file_with_keybuf(char *fname, char *e_fname, char *key) {
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

        // We use `<index>,<total>` as additional authenticated data to prevent
        // tampering across lines
        std::stringstream ss;
        ss << index << "," << total;
        std::string aad_str = ss.str();

        // Encrypt the row
        size_t ct_size = Context::getInstance().m_crypto->SymEncSize(length);
        uint8_t *ct = new uint8_t[ct_size];
        auto ret = Context::getInstance().m_crypto->SymEnc(
            reinterpret_cast<const uint8_t *>(key),
            reinterpret_cast<const uint8_t *>(line.c_str()),
            reinterpret_cast<const uint8_t *>(aad_str.c_str()), ct, length,
            aad_str.length());
        if (ret != 0)
            return ret;

        // Encode the ciphertext
        myfile << index << "," << total << ";"
               << data::base64_encode(reinterpret_cast<unsigned char *>(ct),
                                      ct_size)
               << "\n";
        delete[] ct;
    }
    infile.close();
    myfile.close();
    return 0;
}

// Input, output, key
int sxgb_encrypt_file(char *fname, char *e_fname, char *k_fname) {
    char key[CIPHER_KEY_SIZE];
    load_key(k_fname, key);
    int result = sxgb_encrypt_file_with_keybuf(fname, e_fname, key);
    return result;
}

int sxgb_decrypt_file_with_keybuf(char *fname, char *d_fname, char *key) {
    std::ifstream infile(fname);
    std::ofstream myfile;
    myfile.open(d_fname);

    std::string line;
    while (std::getline(infile, line)) {
        const char *data = line.c_str();
        int aad_size = 0;
        int len = line.length();

        // Find the semicolon delimiter to know where ciphertext begins
        for (int i = 0; i < len; i++) {
            if (data[i] == ';') {
                aad_size = i;
                break;
            }
        }
        assert(0 < aad_size);

        // Allocate memory to deserialize the ciphertext. Base64 is a wasteful
        // encoding so this buffer will always be large enough.
        uint8_t *ct =
            new uint8_t[len - (aad_size + 1)]; // + 1 for the semicolon
        auto ct_size =
            data::base64_decode(data + aad_size + 1, len - (aad_size + 1),
                                reinterpret_cast<char *>(ct));

        // Allocate memory for the plaintext
        size_t pt_size = Context::getInstance().m_crypto->SymDecSize(ct_size);
        uint8_t *pt = new uint8_t[pt_size + 1];

        auto ret = Context::getInstance().m_crypto->SymDec(
            reinterpret_cast<const uint8_t *>(key), ct,
            reinterpret_cast<const uint8_t *>(data), pt, ct_size, aad_size);

        // The null character is necessary for the ostream copy
        pt[pt_size] = '\0';
        if (ret != 0)
            return ret;
        myfile << pt << "\n";

        delete[] ct;
        delete[] pt;
    }
    infile.close();
    myfile.close();
    return 0;
}

// Input, output, key
int sxgb_decrypt_file(char *fname, char *d_fname, char *k_fname) {
    char key[CIPHER_KEY_SIZE];
    load_key(k_fname, key);
    int result = sxgb_decrypt_file_with_keybuf(fname, d_fname, key);
    return result;
}

int OpaqueFileProcessor::opaque_encrypt_file(char *fname, char *schema_file,
                                             char *e_fname, char *k_fname) {
    // Read in user symmetric key
    char key[CIPHER_KEY_SIZE];
    load_key(k_fname, key);

    memcpy(symm_key, (uint8_t *)key, CIPHER_KEY_SIZE);

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

    for (csv::CSVRow &row : reader) { // Input iterator
        for (csv::CSVField &field : row) {
            // Serialize each field in a row
            flatbuffers::Offset<tuix::Field> field_offset;
            std::string field_type = types[i];
            if (field_type == "integer") {
                field_offset = tuix::CreateField(
                    rows_builder, tuix::FieldUnion_IntegerField,
                    tuix::CreateIntegerField(rows_builder,
                                             static_cast<int>(field.get<int>()))
                        .Union(),
                    false // FIXME: check whether field is null
                );
            } else if (field_type == "long") {
                field_offset = tuix::CreateField(
                    rows_builder, tuix::FieldUnion_LongField,
                    tuix::CreateLongField(rows_builder,
                                          static_cast<long>(field.get<long>()))
                        .Union(),
                    false // FIXME: check whether field is null
                );
            } else if (field_type == "float") {
                field_offset = tuix::CreateField(
                    rows_builder, tuix::FieldUnion_FloatField,
                    tuix::CreateFloatField(
                        rows_builder, static_cast<float>(field.get<float>()))
                        .Union(),
                    false // FIXME: check whether field is null
                );
            } else if (field_type == "double") {
                field_offset = tuix::CreateField(
                    rows_builder, tuix::FieldUnion_DoubleField,
                    tuix::CreateDoubleField(
                        rows_builder, static_cast<double>(field.get<double>()))
                        .Union(),
                    false // FIXME: check whether field is null
                );
            } else if (field_type == "date") {
                field_offset = tuix::CreateField(
                    rows_builder, tuix::FieldUnion_DateField,
                    tuix::CreateDateField(rows_builder,
                                          date_to_int(field.get()))
                        .Union(),
                    false // FIXME: check whether field is null
                );
            } else {
                std::string field_string = field.get<std::string>();
                std::vector<uint8_t> str_vec(field_string.begin(),
                                             field_string.end());
                field_offset = tuix::CreateField(
                    rows_builder, tuix::FieldUnion_StringField,
                    tuix::CreateStringFieldDirect(rows_builder, &str_vec,
                                                  str_vec.size())
                        .Union(),
                    false // FIXME: check whether field is null
                );
            }
            field_offsets.push_back(field_offset);
            i++;
        }
        i = 0;
        row_offsets.push_back(
            tuix::CreateRowDirect(rows_builder, &field_offsets));
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

void OpaqueFileProcessor::write_schema(std::vector<std::string> column_names,
                                       std::vector<std::string> column_types,
                                       const char *schema_path) {
    json j;
    j["type"] = "struct";
    std::vector<json> fields;
    for (int i = 0; i < column_names.size(); i++) {
        json field = {{"name", column_names[i]},
                      {"type", column_types[i]},
                      {"nullable", true}};
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
    uint8_t *serialized_block = rows_builder.GetBufferPointer();
    size_t serialized_block_len = rows_builder.GetSize();

    size_t ct_size =
        Context::getInstance().m_crypto->SymEncSize(serialized_block_len);
    uint8_t ct[ct_size];

    Context::getInstance().m_crypto->SymEnc(symm_key, serialized_block, NULL,
                                            ct, serialized_block_len, 0);

    flatbuffers::Offset<tuix::EncryptedBlock> encrypted_block_offset =
        tuix::CreateEncryptedBlock(
            enc_blocks_builder, row_offsets.size(),
            enc_blocks_builder.CreateVector(ct, ct_size));

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
    auto root_offset = tuix::CreateEncryptedBlocksDirect(enc_blocks_builder,
                                                         &enc_block_offsets);
    enc_blocks_builder.Finish(root_offset);
    uint8_t *encrypted_data = enc_blocks_builder.GetBufferPointer();
    size_t encrypted_data_size = enc_blocks_builder.GetSize();

    // If this is the first partition outputted for this dataset, create
    // directory for encrypted output
    if (num_partitions_outputted == 0) {
        // Create top level directory for output
        int status =
            mkdir(output_dir.c_str(), S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH);
        if (status != 0) {
            // TODO: throw error
            std::cout << "Failed to created output directory: "
                      << output_dir.c_str() << ". Exit status " << status
                      << std::endl;
        }
        // Create directory for data
        std::string data_dir = output_dir + std::string("/data");
        status = mkdir(data_dir.c_str(), S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH);
        if (status != 0) {
            // TODO: throw error
            std::cout << "Failed to created output directory: "
                      << data_dir.c_str() << ". Exit status " << status
                      << std::endl;
        }
    }

    // Write encrypted data to file
    std::stringstream ss;
    ss << "cpp-part-";
    ss << std::setw(5) << std::setfill('0') << num_partitions_outputted;
    std::string data_path = output_dir + std::string("/data/") + ss.str();
    std::ofstream encrypted_output(data_path.c_str());
    if (encrypted_output.is_open()) {
        encrypted_output.write((const char *)encrypted_data,
                               encrypted_data_size);
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

int OpaqueFileProcessor::opaque_decrypt_data(char **e_fnames,
                                             size_t num_encrypted_files,
                                             char *d_fname, char *k_fname) {
    // Read in user symmetric key
    char key[CIPHER_KEY_SIZE];
    load_key(k_fname, key);
    memcpy(symm_key, (uint8_t *)key, CIPHER_KEY_SIZE);

    // Create CSV writer
    std::ofstream ss(d_fname);
    auto writer = csv::make_csv_writer(ss);

    for (size_t r = 0; r < num_encrypted_files; r++) {
        char *e_fname = e_fnames[r];

        // Read in encrypted file into memory
        std::ifstream infile(e_fname, std::ios::binary);
        infile.seekg(0, std::ios_base::end);
        int file_size = infile.tellg();

        uint8_t *file_buffer = (uint8_t *)malloc(file_size * sizeof(uint8_t));

        infile.seekg(0, std::ios_base::beg);
        infile.read((char *)file_buffer, file_size);
        infile.close();

        auto encrypted_blocks = tuix::GetEncryptedBlocks(file_buffer);

        for (int i = 0; i < encrypted_blocks->blocks()->size(); i++) {
            // Retrieve and decrypt each EncryptedBlock
            auto encrypted_block = encrypted_blocks->blocks()->Get(i);
            uint8_t *ct = (uint8_t *)encrypted_block->enc_rows()->data();

            size_t pt_size = Context::getInstance().m_crypto->SymDecSize(
                encrypted_block->enc_rows()->size());
            uint8_t *pt = new uint8_t[pt_size];

            Context::getInstance().m_crypto->SymDec(
                symm_key, ct, NULL, pt, encrypted_block->enc_rows()->size(), 0);

            auto rows = tuix::GetRows(pt);
            for (int j = 0; j < rows->rows()->size(); j++) {
                auto row = rows->rows()->Get(j);
                std::vector<std::string> output_row;
                if (!row->is_dummy()) {
                    for (int k = 0; k < row->field_values()->size(); k++) {
                        auto field = row->field_values()->Get(k);

                        // Below, we use a string stream to prevent unexpected
                        // results with to_string()
                        // https://stackoverflow.com/questions/2125880/convert-float-to-stdstring-in-c
                        if (!field->is_null()) {
                            if (field->value_type() ==
                                tuix::FieldUnion_IntegerField) {
                                auto field_value =
                                    static_cast<const tuix::IntegerField *>(
                                        field->value())
                                        ->value();
                                output_row.push_back(std::to_string(
                                    static_cast<int>(field_value)));
                            } else if (field->value_type() ==
                                       tuix::FieldUnion_LongField) {
                                auto field_value =
                                    static_cast<const tuix::LongField *>(
                                        field->value())
                                        ->value();
                                std::ostringstream ss;
                                ss << static_cast<long>(field_value);
                                output_row.push_back(ss.str());
                            } else if (field->value_type() ==
                                       tuix::FieldUnion_FloatField) {
                                auto field_value =
                                    static_cast<const tuix::FloatField *>(
                                        field->value())
                                        ->value();
                                output_row.push_back(fmt_floating(field_value));
                            } else if (field->value_type() ==
                                       tuix::FieldUnion_DoubleField) {
                                auto field_value =
                                    static_cast<const tuix::DoubleField *>(
                                        field->value())
                                        ->value();
                                output_row.push_back(fmt_floating(field_value));
                            } else if (field->value_type() ==
                                       tuix::FieldUnion_DateField) {
                                int field_value =
                                    static_cast<const tuix::DateField *>(
                                        field->value())
                                        ->value();
                                output_row.push_back(int_to_date(field_value));
                            } else {
                                // Field is a flatbuffers vector
                                std::vector<char> field_string;
                                auto field_value =
                                    static_cast<const tuix::StringField *>(
                                        field->value())
                                        ->value();
                                for (int m = 0; m < field_value->size(); m++) {
                                    field_string.push_back(
                                        (char)field_value->Get(m));
                                }
                                output_row.push_back(std::string(
                                    field_string.begin(), field_string.end()));
                            }
                        }
                    }
                }
                writer << output_row;
            }
            delete[] pt;
        }
        free(file_buffer);
    }

    return 0;
}
