#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <ctype.h>
#include <iconv.h>
#include <errno.h>

typedef struct {
    char header[5];         // "NESM" + 0x1A
    uint8_t version;        // Version number
    uint8_t total_songs;    // Total number of songs
    uint8_t starting_song;  // Starting song number (1-based)
    uint16_t load_addr;     // Load address (little endian)
    uint16_t init_addr;     // Init address (little endian)
    uint16_t play_addr;     // Play address (little endian)
    char song_name[32];     // Song name (null-terminated)
    char artist_name[32];   // Artist name (null-terminated)
    char copyright[32];     // Copyright (null-terminated)
    uint16_t ntsc_speed;    // NTSC play speed (little endian)
    uint8_t bankswitch[8];  // Bankswitch init values
    uint16_t pal_speed;     // PAL play speed (little endian)
    uint8_t pal_ntsc_flags; // PAL/NTSC flags
    uint8_t sound_chip;     // Extra sound chip support
    uint8_t reserved[4];    // Reserved bytes
} nsf_header_t;

int read_nsf_header(const char* filename, nsf_header_t* header) {
    FILE* file = fopen(filename, "rb");
    if (!file) {
        printf("Error: Cannot open file %s\n", filename);
        return -1;
    }
    
    size_t bytes_read = fread(header, sizeof(nsf_header_t), 1, file);
    fclose(file);
    
    if (bytes_read != 1) {
        printf("Error: Cannot read NSF header\n");
        return -1;
    }
    
    if (strncmp(header->header, "NESM\x1A", 5) != 0) {
        printf("Error: Invalid NSF file format\n");
        return -1;
    }
    
    return 0;
}

char* convert_sjis_to_utf8(const char* sjis_data, int max_len) {
    iconv_t cd = iconv_open("UTF-8", "SHIFT-JIS");
    if (cd == (iconv_t)-1) {
        return NULL;
    }
    
    size_t sjis_len = strnlen(sjis_data, max_len);
    if (sjis_len == 0) {
        iconv_close(cd);
        return NULL;
    }
    
    size_t utf8_len = sjis_len * 4;
    char* utf8_str = malloc(utf8_len + 1);
    if (!utf8_str) {
        iconv_close(cd);
        return NULL;
    }
    
    char* sjis_ptr = (char*)sjis_data;
    char* utf8_ptr = utf8_str;
    size_t sjis_remaining = sjis_len;
    size_t utf8_remaining = utf8_len;
    
    size_t result = iconv(cd, &sjis_ptr, &sjis_remaining, &utf8_ptr, &utf8_remaining);
    
    if (result == (size_t)-1 && errno != EILSEQ && errno != EINVAL) {
        printf("[DEBUG] iconv failed: %s, remaining: %zu\n", strerror(errno), sjis_remaining);
        iconv_close(cd);
        free(utf8_str);
        return NULL;
    }
    
    iconv_close(cd);
    *utf8_ptr = '\0';
    return utf8_str;
}

void print_string_field(const char* field_name, const char* data, int max_len) {
    printf("%s: ", field_name);
    
    if (strnlen(data, max_len) == 0) {
        printf("(empty)\n");
        return;
    }
    
    char* utf8_str = convert_sjis_to_utf8(data, max_len);
    if (utf8_str) {
        printf("\"%s\"", utf8_str);
        free(utf8_str);
    } else {
        printf("\"");
        for (int i = 0; i < max_len && data[i] != '\0'; i++) {
            if (isprint((unsigned char)data[i])) {
                printf("%c", data[i]);
            } else {
                printf("\\x%02X", (unsigned char)data[i]);
            }
        }
        printf("\"");
    }
    
    printf(" [HEX: ");
    for (int i = 0; i < max_len && data[i] != '\0'; i++) {
        printf("%02X ", (unsigned char)data[i]);
        if (i >= 15) {
            printf("...");
            break;
        }
    }
    printf("]\n");
}

void print_nsf_header(const nsf_header_t* header) {
    printf("=== NSF Header Information ===\n");
    printf("Header: %.4s (0x%02X)\n", header->header, (unsigned char)header->header[4]);
    printf("Version: %d\n", header->version);
    printf("Total Songs: %d\n", header->total_songs);
    printf("Starting Song: %d\n", header->starting_song);
    printf("Load Address: 0x%04X\n", header->load_addr);
    printf("Init Address: 0x%04X\n", header->init_addr);
    printf("Play Address: 0x%04X\n", header->play_addr);
    print_string_field("Song Name", header->song_name, 32);
    print_string_field("Artist Name", header->artist_name, 32);
    print_string_field("Copyright", header->copyright, 32);
    printf("NTSC Speed: %d\n", header->ntsc_speed);
    printf("Bankswitch: ");
    for (int i = 0; i < 8; i++) {
        printf("%02X ", header->bankswitch[i]);
    }
    printf("\n");
    printf("PAL Speed: %d\n", header->pal_speed);
    printf("PAL/NTSC Flags: 0x%02X\n", header->pal_ntsc_flags);
    printf("Sound Chip: 0x%02X\n", header->sound_chip);
    printf("==============================\n");
}

int load_nsf_data(const char* filename, nsf_header_t* header, uint8_t** data, size_t* data_size) {
    FILE* file = fopen(filename, "rb");
    if (!file) {
        printf("Error: Cannot open file %s\n", filename);
        return -1;
    }
    
    fseek(file, 0, SEEK_END);
    long file_size = ftell(file);
    fseek(file, 128, SEEK_SET);
    
    *data_size = file_size - 128;
    *data = malloc(*data_size);
    if (!*data) {
        printf("Error: Cannot allocate memory for NSF data\n");
        fclose(file);
        return -1;
    }
    
    size_t bytes_read = fread(*data, 1, *data_size, file);
    fclose(file);
    
    if (bytes_read != *data_size) {
        printf("Error: Cannot read NSF data\n");
        free(*data);
        return -1;
    }
    
    return 0;
}

const char* get_6502_instruction(uint8_t opcode, uint8_t* operand1, uint8_t* operand2, int* inst_size) {
    static char inst_str[32];
    *inst_size = 1;
    *operand1 = 0;
    *operand2 = 0;
    
    switch (opcode) {
        // Basic instructions
        case 0x00: strcpy(inst_str, "BRK"); break;
        case 0x01: strcpy(inst_str, "ORA ($%02X,X)"); *inst_size = 2; break;
        case 0x05: strcpy(inst_str, "ORA $%02X"); *inst_size = 2; break;
        case 0x06: strcpy(inst_str, "ASL $%02X"); *inst_size = 2; break;
        case 0x08: strcpy(inst_str, "PHP"); break;
        case 0x09: strcpy(inst_str, "ORA #$%02X"); *inst_size = 2; break;
        case 0x0A: strcpy(inst_str, "ASL A"); break;
        case 0x0D: strcpy(inst_str, "ORA $%02X%02X"); *inst_size = 3; break;
        case 0x0E: strcpy(inst_str, "ASL $%02X%02X"); *inst_size = 3; break;
        case 0x10: strcpy(inst_str, "BPL $%02X"); *inst_size = 2; break;
        case 0x11: strcpy(inst_str, "ORA ($%02X),Y"); *inst_size = 2; break;
        case 0x15: strcpy(inst_str, "ORA $%02X,X"); *inst_size = 2; break;
        case 0x16: strcpy(inst_str, "ASL $%02X,X"); *inst_size = 2; break;
        case 0x18: strcpy(inst_str, "CLC"); break;
        case 0x19: strcpy(inst_str, "ORA $%02X%02X,Y"); *inst_size = 3; break;
        case 0x1D: strcpy(inst_str, "ORA $%02X%02X,X"); *inst_size = 3; break;
        case 0x1E: strcpy(inst_str, "ASL $%02X%02X,X"); *inst_size = 3; break;
        case 0x20: strcpy(inst_str, "JSR $%02X%02X"); *inst_size = 3; break;
        case 0x21: strcpy(inst_str, "AND ($%02X,X)"); *inst_size = 2; break;
        case 0x24: strcpy(inst_str, "BIT $%02X"); *inst_size = 2; break;
        case 0x25: strcpy(inst_str, "AND $%02X"); *inst_size = 2; break;
        case 0x26: strcpy(inst_str, "ROL $%02X"); *inst_size = 2; break;
        case 0x28: strcpy(inst_str, "PLP"); break;
        case 0x29: strcpy(inst_str, "AND #$%02X"); *inst_size = 2; break;
        case 0x2A: strcpy(inst_str, "ROL A"); break;
        case 0x2C: strcpy(inst_str, "BIT $%02X%02X"); *inst_size = 3; break;
        case 0x2D: strcpy(inst_str, "AND $%02X%02X"); *inst_size = 3; break;
        case 0x2E: strcpy(inst_str, "ROL $%02X%02X"); *inst_size = 3; break;
        case 0x30: strcpy(inst_str, "BMI $%02X"); *inst_size = 2; break;
        case 0x31: strcpy(inst_str, "AND ($%02X),Y"); *inst_size = 2; break;
        case 0x35: strcpy(inst_str, "AND $%02X,X"); *inst_size = 2; break;
        case 0x36: strcpy(inst_str, "ROL $%02X,X"); *inst_size = 2; break;
        case 0x38: strcpy(inst_str, "SEC"); break;
        case 0x39: strcpy(inst_str, "AND $%02X%02X,Y"); *inst_size = 3; break;
        case 0x3D: strcpy(inst_str, "AND $%02X%02X,X"); *inst_size = 3; break;
        case 0x3E: strcpy(inst_str, "ROL $%02X%02X,X"); *inst_size = 3; break;
        case 0x40: strcpy(inst_str, "RTI"); break;
        case 0x41: strcpy(inst_str, "EOR ($%02X,X)"); *inst_size = 2; break;
        case 0x45: strcpy(inst_str, "EOR $%02X"); *inst_size = 2; break;
        case 0x46: strcpy(inst_str, "LSR $%02X"); *inst_size = 2; break;
        case 0x48: strcpy(inst_str, "PHA"); break;
        case 0x49: strcpy(inst_str, "EOR #$%02X"); *inst_size = 2; break;
        case 0x4A: strcpy(inst_str, "LSR A"); break;
        case 0x4C: strcpy(inst_str, "JMP $%02X%02X"); *inst_size = 3; break;
        case 0x4D: strcpy(inst_str, "EOR $%02X%02X"); *inst_size = 3; break;
        case 0x4E: strcpy(inst_str, "LSR $%02X%02X"); *inst_size = 3; break;
        case 0x50: strcpy(inst_str, "BVC $%02X"); *inst_size = 2; break;
        case 0x51: strcpy(inst_str, "EOR ($%02X),Y"); *inst_size = 2; break;
        case 0x55: strcpy(inst_str, "EOR $%02X,X"); *inst_size = 2; break;
        case 0x56: strcpy(inst_str, "LSR $%02X,X"); *inst_size = 2; break;
        case 0x58: strcpy(inst_str, "CLI"); break;
        case 0x59: strcpy(inst_str, "EOR $%02X%02X,Y"); *inst_size = 3; break;
        case 0x5D: strcpy(inst_str, "EOR $%02X%02X,X"); *inst_size = 3; break;
        case 0x5E: strcpy(inst_str, "LSR $%02X%02X,X"); *inst_size = 3; break;
        case 0x60: strcpy(inst_str, "RTS"); break;
        case 0x61: strcpy(inst_str, "ADC ($%02X,X)"); *inst_size = 2; break;
        case 0x65: strcpy(inst_str, "ADC $%02X"); *inst_size = 2; break;
        case 0x66: strcpy(inst_str, "ROR $%02X"); *inst_size = 2; break;
        case 0x68: strcpy(inst_str, "PLA"); break;
        case 0x69: strcpy(inst_str, "ADC #$%02X"); *inst_size = 2; break;
        case 0x6A: strcpy(inst_str, "ROR A"); break;
        case 0x6C: strcpy(inst_str, "JMP ($%02X%02X)"); *inst_size = 3; break;
        case 0x6D: strcpy(inst_str, "ADC $%02X%02X"); *inst_size = 3; break;
        case 0x6E: strcpy(inst_str, "ROR $%02X%02X"); *inst_size = 3; break;
        case 0x70: strcpy(inst_str, "BVS $%02X"); *inst_size = 2; break;
        case 0x71: strcpy(inst_str, "ADC ($%02X),Y"); *inst_size = 2; break;
        case 0x75: strcpy(inst_str, "ADC $%02X,X"); *inst_size = 2; break;
        case 0x76: strcpy(inst_str, "ROR $%02X,X"); *inst_size = 2; break;
        case 0x78: strcpy(inst_str, "SEI"); break;
        case 0x79: strcpy(inst_str, "ADC $%02X%02X,Y"); *inst_size = 3; break;
        case 0x7D: strcpy(inst_str, "ADC $%02X%02X,X"); *inst_size = 3; break;
        case 0x7E: strcpy(inst_str, "ROR $%02X%02X,X"); *inst_size = 3; break;
        case 0x81: strcpy(inst_str, "STA ($%02X,X)"); *inst_size = 2; break;
        case 0x84: strcpy(inst_str, "STY $%02X"); *inst_size = 2; break;
        case 0x85: strcpy(inst_str, "STA $%02X"); *inst_size = 2; break;
        case 0x86: strcpy(inst_str, "STX $%02X"); *inst_size = 2; break;
        case 0x88: strcpy(inst_str, "DEY"); break;
        case 0x8A: strcpy(inst_str, "TXA"); break;
        case 0x8C: strcpy(inst_str, "STY $%02X%02X"); *inst_size = 3; break;
        case 0x8D: strcpy(inst_str, "STA $%02X%02X"); *inst_size = 3; break;
        case 0x8E: strcpy(inst_str, "STX $%02X%02X"); *inst_size = 3; break;
        case 0x90: strcpy(inst_str, "BCC $%02X"); *inst_size = 2; break;
        case 0x91: strcpy(inst_str, "STA ($%02X),Y"); *inst_size = 2; break;
        case 0x94: strcpy(inst_str, "STY $%02X,X"); *inst_size = 2; break;
        case 0x95: strcpy(inst_str, "STA $%02X,X"); *inst_size = 2; break;
        case 0x96: strcpy(inst_str, "STX $%02X,Y"); *inst_size = 2; break;
        case 0x98: strcpy(inst_str, "TYA"); break;
        case 0x99: strcpy(inst_str, "STA $%02X%02X,Y"); *inst_size = 3; break;
        case 0x9A: strcpy(inst_str, "TXS"); break;
        case 0x9D: strcpy(inst_str, "STA $%02X%02X,X"); *inst_size = 3; break;
        case 0xA0: strcpy(inst_str, "LDY #$%02X"); *inst_size = 2; break;
        case 0xA1: strcpy(inst_str, "LDA ($%02X,X)"); *inst_size = 2; break;
        case 0xA2: strcpy(inst_str, "LDX #$%02X"); *inst_size = 2; break;
        case 0xA4: strcpy(inst_str, "LDY $%02X"); *inst_size = 2; break;
        case 0xA5: strcpy(inst_str, "LDA $%02X"); *inst_size = 2; break;
        case 0xA6: strcpy(inst_str, "LDX $%02X"); *inst_size = 2; break;
        case 0xA8: strcpy(inst_str, "TAY"); break;
        case 0xA9: strcpy(inst_str, "LDA #$%02X"); *inst_size = 2; break;
        case 0xAA: strcpy(inst_str, "TAX"); break;
        case 0xAC: strcpy(inst_str, "LDY $%02X%02X"); *inst_size = 3; break;
        case 0xAD: strcpy(inst_str, "LDA $%02X%02X"); *inst_size = 3; break;
        case 0xAE: strcpy(inst_str, "LDX $%02X%02X"); *inst_size = 3; break;
        case 0xB0: strcpy(inst_str, "BCS $%02X"); *inst_size = 2; break;
        case 0xB1: strcpy(inst_str, "LDA ($%02X),Y"); *inst_size = 2; break;
        case 0xB4: strcpy(inst_str, "LDY $%02X,X"); *inst_size = 2; break;
        case 0xB5: strcpy(inst_str, "LDA $%02X,X"); *inst_size = 2; break;
        case 0xB6: strcpy(inst_str, "LDX $%02X,Y"); *inst_size = 2; break;
        case 0xB8: strcpy(inst_str, "CLV"); break;
        case 0xB9: strcpy(inst_str, "LDA $%02X%02X,Y"); *inst_size = 3; break;
        case 0xBA: strcpy(inst_str, "TSX"); break;
        case 0xBC: strcpy(inst_str, "LDY $%02X%02X,X"); *inst_size = 3; break;
        case 0xBD: strcpy(inst_str, "LDA $%02X%02X,X"); *inst_size = 3; break;
        case 0xBE: strcpy(inst_str, "LDX $%02X%02X,Y"); *inst_size = 3; break;
        case 0xC0: strcpy(inst_str, "CPY #$%02X"); *inst_size = 2; break;
        case 0xC1: strcpy(inst_str, "CMP ($%02X,X)"); *inst_size = 2; break;
        case 0xC4: strcpy(inst_str, "CPY $%02X"); *inst_size = 2; break;
        case 0xC5: strcpy(inst_str, "CMP $%02X"); *inst_size = 2; break;
        case 0xC6: strcpy(inst_str, "DEC $%02X"); *inst_size = 2; break;
        case 0xC8: strcpy(inst_str, "INY"); break;
        case 0xC9: strcpy(inst_str, "CMP #$%02X"); *inst_size = 2; break;
        case 0xCA: strcpy(inst_str, "DEX"); break;
        case 0xCC: strcpy(inst_str, "CPY $%02X%02X"); *inst_size = 3; break;
        case 0xCD: strcpy(inst_str, "CMP $%02X%02X"); *inst_size = 3; break;
        case 0xCE: strcpy(inst_str, "DEC $%02X%02X"); *inst_size = 3; break;
        case 0xD0: strcpy(inst_str, "BNE $%02X"); *inst_size = 2; break;
        case 0xD1: strcpy(inst_str, "CMP ($%02X),Y"); *inst_size = 2; break;
        case 0xD5: strcpy(inst_str, "CMP $%02X,X"); *inst_size = 2; break;
        case 0xD6: strcpy(inst_str, "DEC $%02X,X"); *inst_size = 2; break;
        case 0xD8: strcpy(inst_str, "CLD"); break;
        case 0xD9: strcpy(inst_str, "CMP $%02X%02X,Y"); *inst_size = 3; break;
        case 0xDD: strcpy(inst_str, "CMP $%02X%02X,X"); *inst_size = 3; break;
        case 0xDE: strcpy(inst_str, "DEC $%02X%02X,X"); *inst_size = 3; break;
        case 0xE0: strcpy(inst_str, "CPX #$%02X"); *inst_size = 2; break;
        case 0xE1: strcpy(inst_str, "SBC ($%02X,X)"); *inst_size = 2; break;
        case 0xE4: strcpy(inst_str, "CPX $%02X"); *inst_size = 2; break;
        case 0xE5: strcpy(inst_str, "SBC $%02X"); *inst_size = 2; break;
        case 0xE6: strcpy(inst_str, "INC $%02X"); *inst_size = 2; break;
        case 0xE8: strcpy(inst_str, "INX"); break;
        case 0xE9: strcpy(inst_str, "SBC #$%02X"); *inst_size = 2; break;
        case 0xEA: strcpy(inst_str, "NOP"); break;
        case 0xEC: strcpy(inst_str, "CPX $%02X%02X"); *inst_size = 3; break;
        case 0xED: strcpy(inst_str, "SBC $%02X%02X"); *inst_size = 3; break;
        case 0xEE: strcpy(inst_str, "INC $%02X%02X"); *inst_size = 3; break;
        case 0xF0: strcpy(inst_str, "BEQ $%02X"); *inst_size = 2; break;
        case 0xF1: strcpy(inst_str, "SBC ($%02X),Y"); *inst_size = 2; break;
        case 0xF5: strcpy(inst_str, "SBC $%02X,X"); *inst_size = 2; break;
        case 0xF6: strcpy(inst_str, "INC $%02X,X"); *inst_size = 2; break;
        case 0xF8: strcpy(inst_str, "SED"); break;
        case 0xF9: strcpy(inst_str, "SBC $%02X%02X,Y"); *inst_size = 3; break;
        case 0xFD: strcpy(inst_str, "SBC $%02X%02X,X"); *inst_size = 3; break;
        case 0xFE: strcpy(inst_str, "INC $%02X%02X,X"); *inst_size = 3; break;
        default: 
            sprintf(inst_str, "Unknown opcode $%02X", opcode);
            break;
    }
    
    return inst_str;
}

int analyze_song(const char* filename, nsf_header_t* header, int song_num) {
    uint8_t* data;
    size_t data_size;
    
    if (load_nsf_data(filename, header, &data, &data_size) != 0) {
        return -1;
    }
    
    printf("Loaded %zu bytes of NSF data\n", data_size);
    printf("Load Address: $%04X\n", header->load_addr);
    printf("Init Address: $%04X\n", header->init_addr);
    printf("Play Address: $%04X\n", header->play_addr);
    
    printf("\n--- 6502 Disassembly from Init Address ($%04X) ---\n", header->init_addr);
    
    uint16_t pc = header->init_addr;
    uint16_t data_start = header->load_addr;
    
    for (int i = 0; i < 50; i++) {
        if (pc < data_start || (pc - data_start) >= data_size) {
            printf("$%04X: <Out of range>\n", pc);
            break;
        }
        
        uint16_t offset = pc - data_start;
        uint8_t opcode = data[offset];
        uint8_t operand1 = 0, operand2 = 0;
        int inst_size;
        
        if (offset + 1 < data_size) operand1 = data[offset + 1];
        if (offset + 2 < data_size) operand2 = data[offset + 2];
        
        const char* inst_template = get_6502_instruction(opcode, &operand1, &operand2, &inst_size);
        
        printf("$%04X: ", pc);
        for (int j = 0; j < inst_size; j++) {
            if (offset + j < data_size) {
                printf("%02X ", data[offset + j]);
            } else {
                printf("?? ");
            }
        }
        
        for (int j = inst_size; j < 3; j++) {
            printf("   ");
        }
        
        char formatted_inst[64];
        if (inst_size == 2) {
            sprintf(formatted_inst, inst_template, operand1);
        } else if (inst_size == 3) {
            sprintf(formatted_inst, inst_template, operand2, operand1);
        } else {
            strcpy(formatted_inst, inst_template);
        }
        
        printf("%s\n", formatted_inst);
        
        pc += inst_size;
        
        if (opcode == 0x60 || opcode == 0x40) {
            printf("--- End of subroutine ---\n");
            break;
        }
    }
    
    printf("\n--- 6502 Disassembly from Play Address ($%04X) ---\n", header->play_addr);
    
    pc = header->play_addr;
    
    for (int i = 0; i < 30; i++) {
        if (pc < data_start || (pc - data_start) >= data_size) {
            printf("$%04X: <Out of range>\n", pc);
            break;
        }
        
        uint16_t offset = pc - data_start;
        uint8_t opcode = data[offset];
        uint8_t operand1 = 0, operand2 = 0;
        int inst_size;
        
        if (offset + 1 < data_size) operand1 = data[offset + 1];
        if (offset + 2 < data_size) operand2 = data[offset + 2];
        
        const char* inst_template = get_6502_instruction(opcode, &operand1, &operand2, &inst_size);
        
        printf("$%04X: ", pc);
        for (int j = 0; j < inst_size; j++) {
            if (offset + j < data_size) {
                printf("%02X ", data[offset + j]);
            } else {
                printf("?? ");
            }
        }
        
        for (int j = inst_size; j < 3; j++) {
            printf("   ");
        }
        
        char formatted_inst[64];
        if (inst_size == 2) {
            sprintf(formatted_inst, inst_template, operand1);
        } else if (inst_size == 3) {
            sprintf(formatted_inst, inst_template, operand2, operand1);
        } else {
            strcpy(formatted_inst, inst_template);
        }
        
        printf("%s\n", formatted_inst);
        
        pc += inst_size;
        
        if (opcode == 0x60 || opcode == 0x40) {
            printf("--- End of subroutine ---\n");
            break;
        }
    }
    
    free(data);
    return 0;
}

int main(int argc, char* argv[]) {
    if (argc < 2 || argc > 3) {
        printf("Usage: %s <nsf_file> [song_number]\n", argv[0]);
        printf("  If song_number is not specified, only header is displayed\n");
        return 1;
    }
    
    nsf_header_t header;
    if (read_nsf_header(argv[1], &header) != 0) {
        return 1;
    }
    
    print_nsf_header(&header);
    
    int song_num = header.starting_song;
    if (argc == 3) {
        song_num = atoi(argv[2]);
        if (song_num < 1 || song_num > header.total_songs) {
            printf("Error: Song number must be between 1 and %d\n", header.total_songs);
            return 1;
        }
    }
    
    printf("\n=== Analyzing Song %d ===\n", song_num);
    if (analyze_song(argv[1], &header, song_num) != 0) {
        return 1;
    }
    
    return 0;
}