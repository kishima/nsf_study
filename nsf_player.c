#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <ctype.h>
#include <iconv.h>
#include <errno.h>

#include "lib/Wave_Writer.h"

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

// Simple 6502 CPU state
typedef struct {
    uint8_t A, X, Y, S;     // Registers
    uint16_t PC;            // Program Counter
    uint8_t P;              // Status flags
    uint8_t ram[0x10000];   // 64KB memory space
    uint64_t cycles;        // Cycle counter
    int debug;              // Debug flag
} cpu6502_t;

// Simple NES APU state (simplified)
typedef struct {
    // Pulse channels
    struct {
        uint8_t regs[4];
        int enabled;
        int volume;
        int freq;
    } pulse[2];
    
    // Triangle channel
    struct {
        uint8_t regs[4];
        int enabled;
        int freq;
    } triangle;
    
    // Noise channel
    struct {
        uint8_t regs[4];
        int enabled;
        int volume;
    } noise;
    
    // DMC channel
    struct {
        uint8_t regs[4];
        int enabled;
    } dmc;
    
    uint8_t status;
    float output_buffer[1024];
    int buffer_pos;
} nes_apu_t;

cpu6502_t cpu;
nes_apu_t apu;
nsf_header_t nsf_header;
uint8_t* nsf_data;
size_t nsf_data_size;

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
    char* utf8_str = (char*)malloc(utf8_len + 1);
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
    
    printf("\n");
}

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

int load_nsf_data(const char* filename) {
    FILE* file = fopen(filename, "rb");
    if (!file) {
        printf("Error: Cannot open file %s\n", filename);
        return -1;
    }
    
    fseek(file, 0, SEEK_END);
    long file_size = ftell(file);
    fseek(file, 128, SEEK_SET);
    
    nsf_data_size = file_size - 128;
    nsf_data = (uint8_t*)malloc(nsf_data_size);
    if (!nsf_data) {
        printf("Error: Cannot allocate memory for NSF data\n");
        fclose(file);
        return -1;
    }
    
    size_t bytes_read = fread(nsf_data, 1, nsf_data_size, file);
    fclose(file);
    
    if (bytes_read != nsf_data_size) {
        printf("Error: Cannot read NSF data\n");
        free(nsf_data);
        return -1;
    }
    
    return 0;
}

void cpu_reset() {
    memset(&cpu, 0, sizeof(cpu));
    cpu.S = 0xFF;
    cpu.P = 0x24;
    cpu.PC = nsf_header.init_addr;
    
    // Load NSF data into memory
    uint16_t load_addr = nsf_header.load_addr;
    for (size_t i = 0; i < nsf_data_size && (load_addr + i) < 0x10000; i++) {
        cpu.ram[load_addr + i] = nsf_data[i];
    }
    
    printf("CPU Reset: PC=$%04X, Load Addr=$%04X, Data Size=%zu bytes\n", 
           cpu.PC, load_addr, nsf_data_size);
}

uint8_t cpu_read(uint16_t addr) {
    if (addr >= 0x4000 && addr <= 0x4017) {
        // APU registers - return 0 for now
        return 0;
    }
    return cpu.ram[addr];
}

void cpu_write(uint16_t addr, uint8_t value) {
    if (addr >= 0x4000 && addr <= 0x4017) {
        // APU register write
        if (cpu.debug) {
            printf("APU Write: $%04X = $%02X\n", addr, value);
        }
        
        // Simple APU register handling
        switch (addr) {
            case 0x4000: case 0x4001: case 0x4002: case 0x4003:
                apu.pulse[0].regs[addr - 0x4000] = value;
                break;
            case 0x4004: case 0x4005: case 0x4006: case 0x4007:
                apu.pulse[1].regs[addr - 0x4004] = value;
                break;
            case 0x4008: case 0x4009: case 0x400A: case 0x400B:
                apu.triangle.regs[addr - 0x4008] = value;
                break;
            case 0x400C: case 0x400D: case 0x400E: case 0x400F:
                apu.noise.regs[addr - 0x400C] = value;
                break;
            case 0x4010: case 0x4011: case 0x4012: case 0x4013:
                apu.dmc.regs[addr - 0x4010] = value;
                break;
            case 0x4015:
                apu.status = value;
                if (cpu.debug) {
                    printf("APU Status: $%02X (Pulse1:%d Pulse2:%d Triangle:%d Noise:%d DMC:%d)\n",
                           value, (value&1)!=0, (value&2)!=0, (value&4)!=0, (value&8)!=0, (value&16)!=0);
                }
                break;
            case 0x4017:
                if (cpu.debug) {
                    printf("APU Frame Counter: $%02X\n", value);
                }
                break;
        }
        return;
    }
    
    cpu.ram[addr] = value;
}

const char* get_instruction_name(uint8_t opcode) {
    switch (opcode) {
        case 0x00: return "BRK";
        case 0x20: return "JSR";
        case 0x4C: return "JMP";
        case 0x60: return "RTS";
        case 0x40: return "RTI";
        case 0xA9: return "LDA #";
        case 0xA5: return "LDA zp";
        case 0xAD: return "LDA abs";
        case 0x85: return "STA zp";
        case 0x8D: return "STA abs";
        case 0xA2: return "LDX #";
        case 0xA0: return "LDY #";
        case 0xAA: return "TAX";
        case 0x8A: return "TXA";
        case 0xA8: return "TAY";
        case 0x98: return "TYA";
        case 0x48: return "PHA";
        case 0x68: return "PLA";
        case 0xD0: return "BNE";
        case 0xF0: return "BEQ";
        case 0x30: return "BMI";
        case 0x10: return "BPL";
        case 0xEA: return "NOP";
        default: return "???";
    }
}

int cpu_step() {
    uint16_t pc = cpu.PC;
    uint8_t opcode = cpu_read(pc);
    
    if (cpu.debug) {
        printf("$%04X: %02X      %s   A=%02X X=%02X Y=%02X S=%02X P=%02X\n",
               pc, opcode, get_instruction_name(opcode),
               cpu.A, cpu.X, cpu.Y, cpu.S, cpu.P);
    }
    
    cpu.PC++;
    cpu.cycles++;
    
    // Simple instruction implementation
    switch (opcode) {
        case 0x00: // BRK
            return 0; // Stop execution
            
        case 0x20: { // JSR absolute
            uint16_t addr = cpu_read(cpu.PC) | (cpu_read(cpu.PC + 1) << 8);
            cpu.PC += 2;
            cpu.ram[0x100 + cpu.S] = ((cpu.PC - 1) >> 8) & 0xFF;
            cpu.S--;
            cpu.ram[0x100 + cpu.S] = (cpu.PC - 1) & 0xFF;
            cpu.S--;
            cpu.PC = addr;
            break;
        }
        
        case 0x4C: { // JMP absolute
            uint16_t addr = cpu_read(cpu.PC) | (cpu_read(cpu.PC + 1) << 8);
            cpu.PC = addr;
            break;
        }
        
        case 0x60: // RTS
            cpu.S++;
            cpu.PC = cpu_read(0x100 + cpu.S);
            cpu.S++;
            cpu.PC |= cpu_read(0x100 + cpu.S) << 8;
            cpu.PC++;
            break;
            
        case 0x40: // RTI
            cpu.S++;
            cpu.P = cpu_read(0x100 + cpu.S);
            cpu.S++;
            cpu.PC = cpu_read(0x100 + cpu.S);
            cpu.S++;
            cpu.PC |= cpu_read(0x100 + cpu.S) << 8;
            break;
            
        case 0xA9: // LDA immediate
            cpu.A = cpu_read(cpu.PC++);
            cpu.P = (cpu.P & ~0x82) | (cpu.A == 0 ? 0x02 : 0) | (cpu.A & 0x80);
            break;
            
        case 0xA5: // LDA zero page
            cpu.A = cpu_read(cpu_read(cpu.PC++));
            cpu.P = (cpu.P & ~0x82) | (cpu.A == 0 ? 0x02 : 0) | (cpu.A & 0x80);
            break;
            
        case 0xAD: { // LDA absolute
            uint16_t addr = cpu_read(cpu.PC) | (cpu_read(cpu.PC + 1) << 8);
            cpu.PC += 2;
            cpu.A = cpu_read(addr);
            cpu.P = (cpu.P & ~0x82) | (cpu.A == 0 ? 0x02 : 0) | (cpu.A & 0x80);
            break;
        }
        
        case 0x85: // STA zero page
            cpu_write(cpu_read(cpu.PC++), cpu.A);
            break;
            
        case 0x8D: { // STA absolute
            uint16_t addr = cpu_read(cpu.PC) | (cpu_read(cpu.PC + 1) << 8);
            cpu.PC += 2;
            cpu_write(addr, cpu.A);
            break;
        }
        
        case 0xA2: // LDX immediate
            cpu.X = cpu_read(cpu.PC++);
            cpu.P = (cpu.P & ~0x82) | (cpu.X == 0 ? 0x02 : 0) | (cpu.X & 0x80);
            break;
            
        case 0xA0: // LDY immediate
            cpu.Y = cpu_read(cpu.PC++);
            cpu.P = (cpu.P & ~0x82) | (cpu.Y == 0 ? 0x02 : 0) | (cpu.Y & 0x80);
            break;
            
        case 0xAA: // TAX
            cpu.X = cpu.A;
            cpu.P = (cpu.P & ~0x82) | (cpu.X == 0 ? 0x02 : 0) | (cpu.X & 0x80);
            break;
            
        case 0x8A: // TXA
            cpu.A = cpu.X;
            cpu.P = (cpu.P & ~0x82) | (cpu.A == 0 ? 0x02 : 0) | (cpu.A & 0x80);
            break;
            
        case 0xA8: // TAY
            cpu.Y = cpu.A;
            cpu.P = (cpu.P & ~0x82) | (cpu.Y == 0 ? 0x02 : 0) | (cpu.Y & 0x80);
            break;
            
        case 0x98: // TYA
            cpu.A = cpu.Y;
            cpu.P = (cpu.P & ~0x82) | (cpu.A == 0 ? 0x02 : 0) | (cpu.A & 0x80);
            break;
            
        case 0x48: // PHA
            cpu_write(0x100 + cpu.S, cpu.A);
            cpu.S--;
            break;
            
        case 0x68: // PLA
            cpu.S++;
            cpu.A = cpu_read(0x100 + cpu.S);
            cpu.P = (cpu.P & ~0x82) | (cpu.A == 0 ? 0x02 : 0) | (cpu.A & 0x80);
            break;
            
        case 0xEA: // NOP
            break;
            
        default:
            if (cpu.debug) {
                printf("Unimplemented opcode: $%02X at $%04X\n", opcode, pc);
            }
            cpu.PC += 1; // Skip unknown instruction
            break;
    }
    
    return 1; // Continue execution
}

void generate_audio_sample(float* left, float* right) {
    // Very simple audio generation based on APU state
    float sample = 0.0f;
    
    // Pulse channel 1
    if (apu.status & 1) {
        int freq = apu.pulse[0].regs[2] | ((apu.pulse[0].regs[3] & 0x07) << 8);
        if (freq > 0) {
            sample += 0.1f * (((cpu.cycles / (freq + 1)) % 2) ? 1.0f : -1.0f);
        }
    }
    
    // Pulse channel 2
    if (apu.status & 2) {
        int freq = apu.pulse[1].regs[2] | ((apu.pulse[1].regs[3] & 0x07) << 8);
        if (freq > 0) {
            sample += 0.1f * (((cpu.cycles / (freq + 1)) % 2) ? 1.0f : -1.0f);
        }
    }
    
    // Very basic triangle wave
    if (apu.status & 4) {
        int freq = apu.triangle.regs[2] | ((apu.triangle.regs[3] & 0x07) << 8);
        if (freq > 0) {
            int phase = (cpu.cycles / (freq + 1)) % 4;
            float tri_sample = (phase < 2) ? (phase * 0.5f - 0.5f) : (1.5f - phase * 0.5f);
            sample += 0.05f * tri_sample;
        }
    }
    
    // Clamp sample
    if (sample > 1.0f) sample = 1.0f;
    if (sample < -1.0f) sample = -1.0f;
    
    *left = sample;
    *right = sample;
}

int nsf_init(int song_num) {
    cpu_reset();
    memset(&apu, 0, sizeof(apu));
    
    printf("\n=== Initializing Song %d ===\n", song_num);
    
    // Set song number in A register (0-based)
    cpu.A = song_num - 1;
    cpu.debug = 1; // Enable debug output
    
    // Run initialization routine
    int steps = 0;
    while (cpu_step() && steps < 1000) {
        steps++;
        if (cpu.PC == nsf_header.init_addr + 1000) { // Safety break
            break;
        }
    }
    
    cpu.debug = 0; // Disable debug for play routine
    printf("Initialization completed in %d steps\n", steps);
    
    return 0;
}

int nsf_play_to_wav(const char* output_filename, int duration_seconds) {
    const int sample_rate = 44100;
    const int total_samples = sample_rate * duration_seconds;
    
    // Initialize WAV writer
    wave_open(sample_rate, output_filename);
    
    wave_enable_stereo();
    
    printf("Generating %d seconds of audio to %s...\n", duration_seconds, output_filename);
    
    short buffer[2048];
    int buffer_pos = 0;
    
    for (int sample = 0; sample < total_samples; sample++) {
        // Run play routine at 60Hz (44100/735 ≈ 60Hz)
        if (sample % 735 == 0) {
            cpu.PC = nsf_header.play_addr;
            
            // Run play routine
            int steps = 0;
            while (cpu_step() && steps < 100) {
                steps++;
                if (cpu.PC == 0) break; // RTS completed
            }
        }
        
        // Generate audio sample
        float left, right;
        generate_audio_sample(&left, &right);
        
        // Convert to 16-bit and add to buffer
        buffer[buffer_pos++] = (short)(left * 32767);
        buffer[buffer_pos++] = (short)(right * 32767);
        
        // Write buffer when full
        if (buffer_pos >= 2048) {
            wave_write(buffer, buffer_pos);
            buffer_pos = 0;
        }
        
        // Progress indicator
        if (sample % (sample_rate / 4) == 0) {
            printf("Progress: %d%%\n", (sample * 100) / total_samples);
        }
    }
    
    // Write remaining buffer
    if (buffer_pos > 0) {
        wave_write(buffer, buffer_pos);
    }
    
    wave_close();
    printf("WAV file generated successfully!\n");
    
    return 0;
}

int main(int argc, char* argv[]) {
    if (argc < 2 || argc > 4) {
        printf("Usage: %s <nsf_file> [song_number] [duration_seconds]\n", argv[0]);
        printf("  Default song_number: starting song from NSF\n");
        printf("  Default duration: 30 seconds\n");
        return 1;
    }
    
    if (read_nsf_header(argv[1], &nsf_header) != 0) {
        return 1;
    }
    
    print_nsf_header(&nsf_header);
    
    if (load_nsf_data(argv[1]) != 0) {
        return 1;
    }
    
    int song_num = nsf_header.starting_song;
    if (argc >= 3) {
        song_num = atoi(argv[2]);
        if (song_num < 1 || song_num > nsf_header.total_songs) {
            printf("Error: Song number must be between 1 and %d\n", nsf_header.total_songs);
            return 1;
        }
    }
    
    int duration = 30;
    if (argc >= 4) {
        duration = atoi(argv[3]);
        if (duration < 1 || duration > 300) {
            printf("Error: Duration must be between 1 and 300 seconds\n");
            return 1;
        }
    }
    
    if (nsf_init(song_num) != 0) {
        return 1;
    }
    
    char output_filename[256];
    snprintf(output_filename, sizeof(output_filename), "output_song_%d.wav", song_num);
    
    if (nsf_play_to_wav(output_filename, duration) != 0) {
        return 1;
    }
    
    free(nsf_data);
    return 0;
}