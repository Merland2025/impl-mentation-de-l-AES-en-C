#include <err.h>
#include <getopt.h>
#include <limits.h>
#include <unistd.h>
#include <sys/types.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#include "AES.h"
#include "mode.h"


// Définir DEFAULT_KEY et DEFAULT_IV
uint8_t DEFAULT_KEY[16] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
};

uint8_t DEFAULT_IV[16] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
};


// Fonction pour lire le contenu d'un fichier
unsigned char *file_content(const char *filename, size_t *size) {
    FILE *file = fopen(filename, "rb");
    if (!file) {
        perror("Error opening file");
        return NULL;
    }

    fseek(file, 0, SEEK_END);
    *size = ftell(file);
    fseek(file, 0, SEEK_SET);

    unsigned char *buffer = (unsigned char *)malloc(*size);
    if (!buffer) {
        fclose(file);
        perror("Memory allocation failed");
        return NULL;
    }

    size_t bytes_read = fread(buffer, 1, *size, file);
    if (bytes_read != *size) {
        fclose(file);
        free(buffer);
        perror("Error reading file");
        return NULL;
    }

    fclose(file);
    return buffer;
}

// Convertit une chaîne hexadécimale en tableau d'octets
uint8_t *hex_content(const unsigned char *hex_string, size_t size) {
    uint8_t *content = (uint8_t *)malloc(size / 2); // Chaque octet en hexadécimal correspond à deux caractères

    if (!content) {
        perror("Memory allocation failed");
        return NULL;
    }

    for (size_t i = 0; i < size / 2; ++i) {
        sscanf((const char *)&hex_string[2 * i], "%2hhx", &content[i]);
    }

    return content;
}


int main(int argc, char **argv) {
    int optc;
    FILE *output_fd = NULL;
    bool decryption = false; 
    bool new_key = false;
    bool new_IV = false;
    uint8_t *key = DEFAULT_KEY; 
    uint8_t *IV = DEFAULT_IV;
    size_t Nk = DEFAULT_KEY_SIZE;
    size_t Nb = DEFAULT_BLOCK_SIZE;
    size_t Nr = DEFAULT_NUMBER_ROUND;
    int mode = DEFAULT_MODE;

    // Options pour les arguments de ligne de commande
    static struct option long_opts[] = {
        {"help", no_argument, NULL, 'h'},
        {"verbose", no_argument, NULL, 'v'},
        {"output", required_argument, NULL, 'o'},
        {"decrypt", no_argument, NULL, 'd'},
        {"IV", required_argument, NULL, 'I'},
        {"mode", required_argument, NULL, 'm'},
        {"key", required_argument, NULL, 'k'},
        {NULL, no_argument, NULL, 0}
    };

    // Analyse des arguments de ligne de commande
    while ((optc = getopt_long(argc, argv, "hdI:o:vm:k:", long_opts, NULL)) != -1) {
        switch (optc) {
            case 'h':
                fprintf(stdout, "Usage:\tAES -k[private key] -m[mode] -o FILE [-v] [-h] [-I[initialization vector]] FILE ...\n"
                                "\tAES -d -k[FILE] -m[N] -o FILE [-v] [-h] [-I[FILE]] FILE ...\n"
                                "Encrypt or decrypt a FILE with AES\n\n"
                                " -d, --decrypt\t\tDecrypt the FILE\n"
                                " -m[N], --mode\t\tHow blocks are chained: ECB=1, CBC=2, CFB=3, OFB=4, GCM=5\n"
                                " -I, --IV[=N]\tInitialization Vector for CBC, CFB, OFB or GCM mode in FILE2\n"
                                " -k, --key\t\tAES' key of size 128, 192 or 256 in FILE3\n"
                                " -o FILE, --output FILE\tWrite result to FILE\n"
                                " -v, --verbose\t\tVerbose output\n"
                                " -h, --help\t\tDisplay this help and exit\n");
                return EXIT_SUCCESS;

            case 'd':
                decryption = true;
                break;

            case 'v':
                // verbose = true;
                break;

            case 'm':
                if (optarg) {
                    mode = strtol(optarg, NULL, 10);
                    if (mode > 5 || mode < 1) {
                        fprintf(stderr, "Invalid mode (use: ECB=1, CBC=2, CFB=3, OFB=4, GCM=5)\n");
                        return EXIT_FAILURE;
                    }
                }
                break;

   case 'k':
    if (optarg) {
        FILE *key_fd = fopen(optarg, "r");
        if (!key_fd) {
            perror("Error opening key file");
            return EXIT_FAILURE;
        }
        
        size_t size;
        unsigned char *visual_key = file_content(optarg, &size);
        if (!visual_key) {
            perror("Error reading key file content");
            fclose(key_fd);
            return EXIT_FAILURE;
        }

        if (size != 16 && size != 24 && size != 32) {
            fprintf(stderr, "Wrong size for the key. Key must be 128, 192, or 256 bits.\n");
            fclose(key_fd);
            free(visual_key);
            return EXIT_FAILURE;
        }

        key = hex_content(visual_key, size);
        if (!key) {
            fprintf(stderr, "Error converting key to hex\n");
            fclose(key_fd);
            free(visual_key);
            return EXIT_FAILURE;
        }

        fclose(key_fd);
        free(visual_key);
        new_key = true;
        Nk = size / 8;
    }
    break;

            case 'I':
                if (optarg) {
                    FILE *iv_fd = fopen(optarg, "r");
                    if (!iv_fd) {
                        perror("Error opening IV file");
                        return EXIT_FAILURE;
                    }
                    
                    size_t size;
                    unsigned char *visual_IV = file_content(optarg, &size);
                    if (!visual_IV) {
                        perror("Error reading IV file content");
                        fclose(iv_fd);
                        return EXIT_FAILURE;
                    }

                    if (size != 32) {
                        fprintf(stderr, "Wrong size for the Initialization Vector\n");
                        fclose(iv_fd);
                        free(visual_IV);
                        return EXIT_FAILURE;
                    }

                    IV = hex_content(visual_IV, size);
                    if (!IV) {
                        fprintf(stderr, "Error converting IV to hex\n");
                        fclose(iv_fd);
                        free(visual_IV);
                        return EXIT_FAILURE;
                    }

                    fclose(iv_fd);
                    free(visual_IV);
                    new_IV = true;
                }
                break;

            case 'o':
                if (optarg) {
                    output_fd = fopen(optarg, "w+");
                    if (!output_fd) {
                        perror("Error opening output file");
                        return EXIT_FAILURE;
                    }
                }
                break;

            default:
                fprintf(stderr, "Invalid option '%s'\n", argv[optind - 1]);
                return EXIT_FAILURE;
        }
    }

    // Détermination du nombre de tours (Nr) en fonction de la taille de la clé (Nk)
    switch (Nk) {
        case 4:
            Nr = 10;
            break;
        case 6:
            Nr = 12;
            break;
        case 8:
            Nr = 14;
            break;
    }

    if (optind >= argc) {
        fprintf(stderr, "Error: no input file given\n");
        return EXIT_FAILURE;
    }

    if (optind < argc) {
        do {
            char *file = argv[optind];
            FILE *input_fd = fopen(file, "r");
            if (!input_fd) {
                perror("Error opening input file");
                if (output_fd) fclose(output_fd);
                return EXIT_FAILURE;
            }

            if (decryption) {
                switch (mode) {
                    case 1:
                        InvECB(key, input_fd, output_fd, Nk, Nr, Nb); 
                        break;
                    case 2:
                        InvCBC(key, IV, input_fd, output_fd, Nk, Nr, Nb); 
                        break;
                    case 3:
                        InvCFB(key, IV, input_fd, output_fd, Nk, Nr, Nb);
                        break;
                    case 4:
                        InvOFB(key, IV, input_fd, output_fd, Nk, Nr, Nb);
                        break;
                    case 5: // Ajout du support pour GCM
                        InvGCM(key, IV, input_fd, output_fd); 
                        break;
                    default:
                        fprintf(stderr, "Mode de déchiffrement non supporté\n");
                        fclose(input_fd);
                        if (output_fd) fclose(output_fd);
                        return EXIT_FAILURE;
                }
            } else {
                switch (mode) {
                    case 1:
                        ECB(key, input_fd, output_fd, Nk, Nr, Nb); 
                        break;
                    case 2:
                        CBC(key, IV, input_fd, output_fd, Nk, Nr, Nb); 
                        break;
                    case 3:
                        CFB(key, IV, input_fd, output_fd, Nk, Nr, Nb);
                        break;
                    case 4:
                        OFB(key, IV, input_fd, output_fd, Nk, Nr, Nb);
                        break;
                    case 5: // Ajout du support pour GCM
                        GCM(key, IV, input_fd, output_fd); 
                        break;
                    default:
                        fprintf(stderr, "Mode de chiffrement non supporté\n");
                        fclose(input_fd);
                        if (output_fd) fclose(output_fd);
                        return EXIT_FAILURE;
                }
            }

            fclose(input_fd);
        } while (++optind < argc);
    }

    if (new_key) free(key);
    if (new_IV) free(IV);
    if (output_fd) fclose(output_fd);

    return EXIT_SUCCESS;
}




