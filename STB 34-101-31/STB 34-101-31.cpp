#include <Windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <cstring> 
#include <cstdint> 
#include <bee2/crypto/belt.h>
#include <bee2/core/mem.h>
#include <bee2/core/util.h>
#include <clocale>
#include <math.h>
#include <vector>
#include <string>
#include <iostream>
#include <iomanip>
#include <chrono>
#include <Psapi.h>
#include <thread>

using namespace std;
using namespace std::chrono;


void xor_blocks(uint8_t* dst, const uint8_t* a, const uint8_t* b, size_t len) {
    for (size_t i = 0; i < len; ++i)
        dst[i] = a[i] ^ b[i];
}


void print_hex(const uint8_t* data, size_t len) {
    for (size_t i = 0; i < len; i++) {
        printf("%02X ", data[i]);
        if ((i + 1) % 16 == 0)
            printf("\n");
    }
    if (len % 16 != 0)
        printf("\n");
}

int hamming_distance(const uint8_t* a, const uint8_t* b, size_t len)
{
    int distance = 0;
    for (size_t i = 0; i < len; i++) {
        uint8_t diff = a[i] ^ b[i];
        while (diff) {
            distance += diff & 1;
            diff >>= 1;
        }
    }
    return distance;
}


double compute_entropy(const uint8_t* data, size_t len) {
    unsigned int freq[256] = { 0 };
    for (size_t i = 0; i < len; i++)
        freq[data[i]]++;

    double entropy = 0.0;
    for (int i = 0; i < 256; i++) {
        if (freq[i] > 0) {
            double p = (double)freq[i] / len;
            entropy -= p * log2(p);
        }
    }
    return entropy;
}

void print_results(const char* modeName, double enc_time, double dec_time,
    double speed_enc, double speed_dec, const vector<uint8_t>& recoveredtext,
    const vector<uint8_t>& plaintext, int bit_diff, double entropy) {
    cout << "Режим: " << modeName
        << "\nВремя шифрования: " << enc_time << " микросекунд"
        << " | Скорость: " << fixed << setprecision(2) << speed_enc << " Байт/мкс"
        << "\nВремя дешифрования: " << dec_time << " микросекунд"
        << " | Скорость: " << fixed << setprecision(2) << speed_dec << " Байт/мкс"
        << "\nСоответствие текста: " << (recoveredtext == plaintext ? "Да" : "НЕТ!")
        << "\n----------------------------------------\n";
    cout << "Bit differences after 1-bit input change: " << bit_diff << " байт" << endl;
    cout << "Ciphertext entropy: " << fixed << setprecision(4) << entropy << " байт" << endl;
}



void ecb_mode(uint8_t* output, const uint8_t* input, size_t len, u32* subkeys, uint8_t* iv, int encrypt) {
    (void)iv;
    uint8_t block[16];
    for (size_t offset = 0; offset < len; offset += 16) {
        size_t block_len = ((len - offset) > 16) ? 16 : (len - offset);
        memcpy(block, input + offset, block_len);
        if (encrypt) {
            beltBlockEncr(block, subkeys);
        }
        else {
            beltBlockDecr(block, subkeys);
        }
        memcpy(output + offset, block, block_len);
    }
}


void cbc_mode(uint8_t* output, const uint8_t* input, size_t len, u32* subkeys, uint8_t* iv, int encrypt) {
    uint8_t s[16];
    memcpy(s, iv, 16);
    beltBlockEncr(s, subkeys); // s ← Fθ(S)
   

    uint8_t block[16], current[16], prev_block[16];
    memcpy(prev_block, s, 16); 

    for (size_t offset = 0; offset < len; offset += 16) {
        size_t block_len = ((len - offset) > 16) ? 16 : (len - offset);

       
        if (encrypt) {
            memcpy(block, input + offset, block_len);
            xor_blocks(block, block, prev_block, block_len);  
            beltBlockEncr(block, subkeys);                    
            memcpy(output + offset, block, block_len);
            memcpy(prev_block, block, block_len);             
        }
        else {
            memcpy(current, input + offset, block_len);
            uint8_t temp[16];
            memcpy(temp, current, block_len);
            beltBlockDecr(current, subkeys);                 
            xor_blocks(current, current, prev_block, block_len); 
            memcpy(output + offset, current, block_len);
            memcpy(prev_block, temp, block_len);    
        }
    }
}



void cfb_mode(uint8_t* output, const uint8_t* input, size_t len, u32* subkeys, uint8_t* iv, int encrypt) {
    uint8_t block[16];
    uint8_t shift_register[16];
    memcpy(shift_register, iv, 16);

    for (size_t offset = 0; offset < len; offset += 16) {
        size_t block_len = ((len - offset) > 16) ? 16 : (len - offset);
        if (encrypt) {
            memcpy(block, shift_register, 16);
            beltBlockEncr(block, subkeys);
            xor_blocks(output + offset, input + offset, block, block_len);
            memcpy(shift_register, output + offset, block_len);
        }
        else {
            memcpy(block, shift_register, 16);
            beltBlockEncr(block, subkeys);
            xor_blocks(output + offset, input + offset, block, block_len);
            memcpy(shift_register, input + offset, block_len);
        }
    }
}

void ctr_mode(uint8_t* output, const uint8_t* input, size_t len, u32* subkeys, uint8_t* iv, int encrypt) {
    uint8_t s[16], counter[16], gamma[16];

    
    memcpy(s, iv, 16);
    beltBlockEncr(s, subkeys);

    memcpy(counter, s, 16); 
    for (size_t offset = 0; offset < len; offset += 16) {
        size_t block_len = ((len - offset) > 16) ? 16 : (len - offset);

        
        memcpy(gamma, counter, 16);
        beltBlockEncr(gamma, subkeys);

        
        xor_blocks(output + offset, input + offset, gamma, block_len);

        
        for (int i = 15; i >= 0; --i) {
            if (++counter[i]) break;
        }
        
    }
}


typedef void (*CryptoModeFunction)(uint8_t* output, const uint8_t* input, size_t len, u32* subkeys, uint8_t* iv, int encrypt);

void benchmark_mode(const char* modeName,
    void (*modeFunc)(uint8_t*, const uint8_t*, size_t, u32*, uint8_t*, int),
    const uint8_t* plaintext,
    size_t len,
    u32* subkeys,
    uint8_t* iv,
    const uint8_t* orig_key) {


    vector<uint8_t> ciphertext(len);
    vector<uint8_t> decrypted(len);

    uint8_t iv_copy1[16], iv_copy2[16];
    memcpy(iv_copy1, iv, 16);
    memcpy(iv_copy2, iv, 16);
    
    auto start_enc = high_resolution_clock::now();
    modeFunc(ciphertext.data(), plaintext, len, subkeys, iv, 1);
    auto end_enc = high_resolution_clock::now();

    vector<uint8_t> recoveredtext(len);
    auto start_dec = high_resolution_clock::now();
    modeFunc(recoveredtext.data(), ciphertext.data(), len, subkeys, iv, 0);
    auto end_dec = high_resolution_clock::now();

    auto duration_encrypt = duration_cast<microseconds>(end_enc - start_enc).count();;
    auto duration_decrypt = duration_cast<microseconds>(end_dec - start_dec).count();

    double speed_enc = static_cast<double>(len / duration_encrypt);
    double speed_dec = static_cast<double>(len / duration_decrypt);

   
    uint8_t mod_key[32];
    memcpy(mod_key, orig_key, 32);
    mod_key[0] ^= 0x80;

    u32 mod_subkeys[40] = { 0 };
    beltKeyExpand((octet*)mod_subkeys, mod_key, 16);

    vector<uint8_t> ciphertext_mod(len);
    modeFunc(ciphertext_mod.data(), plaintext, len, mod_subkeys, iv, 1);

    
    int diff_bits = hamming_distance(ciphertext.data(), ciphertext_mod.data(), len);
    int total_bits = len * 8;
    double avalanche_percent = ((double)diff_bits / total_bits) * 100;

    double entropy_val = compute_entropy(ciphertext.data(), len);
 
    
    print_results(modeName, duration_encrypt, duration_decrypt, speed_enc, speed_dec, recoveredtext, vector<uint8_t>(plaintext, plaintext + len), diff_bits/8, entropy_val);
    cout << "Avalanche effect: " << fixed << setprecision(2) << avalanche_percent << endl;
    cout << endl;
}

int main(void) {
    setlocale(LC_ALL, "Rus");

    vector<string> test_messages = {
      // "Короткий текстгг",
        //string(256 * 256, 'G'),
        string(1024 * 512,'E'),
        string(1024 * 1024, 'A'),
        string(1024 * 2048,'V'),
        string(2048 * 2048, 'T'),
        string(4096 * 4096,'R'),
        //string(16 * 8, 'gf'),
        //string(16 * 12, 'R'),
        //string(16 * 16, 'U'),
       
    };


    vector <size_t> padded_len(test_messages.size()); // Массив для хранения длины
    vector<vector<uint8_t>> ciphertext(test_messages.size());
    vector<vector<uint8_t>> decrypted(test_messages.size());

    uint8_t shortKey[16] = {
        0x34, 0x87, 0x24, 0xA4,
        0xC1, 0xA6, 0x76, 0x67,
        0x15, 0x3D, 0xDE, 0x59,
        0x33, 0x88, 0x42, 0x50
    };

    uint8_t full_key[32];
    memcpy(full_key, shortKey, 16);       
    memcpy(full_key + 16, shortKey, 16);   
    
    u32 subkeys[40] = { 0 };
    beltKeyExpand((octet*)subkeys, full_key, 32);

    uint8_t iv[16] = {
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x01
    };


    for (const auto & msg : test_messages) {
        size_t len = ((msg.size() + 15) / 16) * 16;
        vector<uint8_t> input(len, 0);
        memcpy(input.data(), msg.data(), msg.size());

        cout << "\nТестирование сообщения (" << msg.size() << " байт):\n";

        benchmark_mode("ECB", ecb_mode, input.data(), len, subkeys, iv, full_key);
        benchmark_mode("CBC", cbc_mode, input.data(), len, subkeys, iv, full_key);
        benchmark_mode("CFB", cfb_mode, input.data(), len, subkeys, iv, full_key);
        benchmark_mode("CTR", ctr_mode, input.data(), len, subkeys, iv, full_key);
    }
    return 0;
}
