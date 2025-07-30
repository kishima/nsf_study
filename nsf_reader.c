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
        printf("[DEBUG] iconv_open failed: %s\n", strerror(errno));
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

int main(int argc, char* argv[]) {
    if (argc != 2) {
        printf("Usage: %s <nsf_file>\n", argv[0]);
        return 1;
    }
    
    nsf_header_t header;
    if (read_nsf_header(argv[1], &header) == 0) {
        print_nsf_header(&header);
        return 0;
    }
    
    return 1;
}