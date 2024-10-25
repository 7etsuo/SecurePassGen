/**
 * @file password.c
 * @brief Cryptographically secure password generator using platform-native CSPRNG
 * 
 * This implementation provides a secure password generation utility that:
 * - Uses platform-specific cryptographic APIs (BCrypt/Security/OpenSSL)
 * - Implements rejection sampling to eliminate modulo bias
 * - Enforces configurable minimum requirements for character types
 * - Uses Fisher-Yates shuffle for uniform distribution
 * - Implements secure memory handling practices
 * 
 * Support for:
 * - Windows (using BCrypt)
 * - macOS (using Security Framework)
 * - Linux (using OpenSSL + getrandom)
 * 
 * @author Tetsuo
 * @date October 25, 2024
 * @version 1.0.0
 * 
 * @copyright Copyright Tetsuo (c) 2024 SecurePassGen
 * @license MIT License
 * 
 * Build Instructions:
 * Windows: gcc password.c -o password.exe -lbcrypt
 * macOS:   gcc password.c -o password -framework Security
 * Linux:   gcc password.c -o password -lcrypto
 * 
 * Usage: ./password <length>
 * 
 * Security Note:
 * SecurePassGen prioritizes security:
 * - Use of cryptographically secure random number generation
 * - Elimination of modulo bias through rejection sampling
 * - Secure memory clearing after use
 * - Minimum password length enforcement
 * - Character type distribution requirements
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>

#if defined(_WIN32) || defined(_WIN64)
#include <windows.h>
#include <bcrypt.h>
#pragma comment(lib, "bcrypt.lib")
#elif defined(__APPLE__)
#include <Security/Security.h>
#elif defined(__linux__)
#include <unistd.h>
#include <sys/random.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#else
#error "Unsupported platform. Only Windows, macOS, and Linux are supported."
#endif

#define MAX_PASSWORD_LENGTH 128
#define MIN_PASSWORD_LENGTH 12
#define ENTROPY_MULTIPLIER 2

#define UPPERCASE "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
#define LOWERCASE "abcdefghijklmnopqrstuvwxyz"
#define NUMBERS "0123456789"
#define SYMBOLS "!@#$%^&*()-_=+[]"

typedef struct
{
    int has_upper;
    int has_lower;
    int has_number;
    int has_symbol;
    int min_upper;
    int min_lower;
    int min_number;
    int min_symbol;
} PasswordRequirements;

void secure_clear(void *v, size_t n);
int get_secure_random_bytes(unsigned char *buffer, size_t length);
void crypto_shuffle(char *arr, size_t n);
char get_unbiased_random_char(const char *charset, size_t charset_size, 
                            unsigned char *entropy_pool, size_t *pool_index, 
                            size_t pool_size);
int is_valid_password(const char *password, int length, const PasswordRequirements *req);
void generate_secure_password(char *password, int length, const PasswordRequirements *req);

/* Fisher-Yates shuffle algorithm */
void crypto_shuffle(char *arr, size_t n)
{
    unsigned char *random_bytes = calloc(n * sizeof(uint32_t), 1);
    if (!random_bytes)
    {
        fprintf(stderr, "Memory allocation failed during shuffle\n");
        exit(EXIT_FAILURE);
    }

    if (get_secure_random_bytes(random_bytes, n * sizeof(uint32_t)) != 0)
    {
        free(random_bytes);
        fprintf(stderr, "Failed to generate random bytes for shuffling\n");
        exit(EXIT_FAILURE);
    }

    for (size_t i = n - 1; i > 0; i--)
    {
        uint32_t random_value;
        memcpy(&random_value, &random_bytes[i * sizeof(uint32_t)], sizeof(uint32_t));
        size_t j = random_value % (i + 1);

        char temp = arr[i];
        arr[i] = arr[j];
        arr[j] = temp;
    }

    secure_clear(random_bytes, n * sizeof(uint32_t));
    free(random_bytes);
}

int get_secure_random_bytes(unsigned char *buffer, size_t length)
{
#if defined(_WIN32) || defined(_WIN64)
    NTSTATUS status = BCryptGenRandom(NULL, buffer, (ULONG)length, BCRYPT_USE_SYSTEM_PREFERRED_RNG);
    return (status < 0) ? -1 : 0;

#elif defined(__APPLE__)
    int result = SecRandomCopyBytes(kSecRandomDefault, length, buffer);
    return (result != 0) ? -1 : 0;

#elif defined(__linux__)
    if (!RAND_poll())
        return -1;

    unsigned char entropy[256];
    if (getrandom(entropy, sizeof(entropy), 0) != sizeof(entropy))
        return -1;
    RAND_seed(entropy, sizeof(entropy));
    secure_clear(entropy, sizeof(entropy));

    if (RAND_bytes(buffer, length) != 1)
        return -1;

    return 0;
#else
    return -1;
#endif
}

/* Unbiased random sampling using rejection sampling */
char get_unbiased_random_char(const char *charset, size_t charset_size, unsigned char *entropy_pool, size_t *pool_index,
                              size_t pool_size)
{
    uint32_t random_value;
    uint32_t max_valid = (uint32_t)-1 - ((uint32_t)-1 % charset_size);

    do
    {
        if (*pool_index + sizeof(uint32_t) > pool_size)
        {
            if (get_secure_random_bytes(entropy_pool, pool_size) != 0)
            {
                fprintf(stderr, "Failed to refill entropy pool\n");
                exit(EXIT_FAILURE);
            }
            *pool_index = 0;
        }

        memcpy(&random_value, &entropy_pool[*pool_index], sizeof(uint32_t));
        *pool_index += sizeof(uint32_t);

    } while (random_value > max_valid);

    return charset[random_value % charset_size];
}

void secure_clear(void *v, size_t n)
{
#if defined(_WIN32) || defined(_WIN64)
    SecureZeroMemory(v, n);
#else
    volatile unsigned char *p = v;
    while (n--)
        *p++ = 0;
#endif
}

int is_valid_password(const char *password, int length, const PasswordRequirements *req)
{
    int upper_count = 0, lower_count = 0, number_count = 0, symbol_count = 0;

    for (int i = 0; i < length; i++)
    {
        if (strchr(UPPERCASE, password[i]))
            upper_count++;
        else if (strchr(LOWERCASE, password[i]))
            lower_count++;
        else if (strchr(NUMBERS, password[i]))
            number_count++;
        else if (strchr(SYMBOLS, password[i]))
            symbol_count++;
    }

    return (upper_count >= req->min_upper) && (lower_count >= req->min_lower) && (number_count >= req->min_number) &&
           (symbol_count >= req->min_symbol);
}

void generate_secure_password(char *password, int length, const PasswordRequirements *req)
{
    if (length < MIN_PASSWORD_LENGTH || length > MAX_PASSWORD_LENGTH)
    {
        fprintf(stderr, "Invalid password length\n");
        exit(EXIT_FAILURE);
    }

    int min_required = req->min_upper + req->min_lower + req->min_number + req->min_symbol;
    if (length < min_required)
    {
        fprintf(stderr, "Password length too short for requirements\n");
        exit(EXIT_FAILURE);
    }

    size_t pool_size = length * ENTROPY_MULTIPLIER * sizeof(uint32_t);
    unsigned char *entropy_pool = calloc(pool_size, 1);
    size_t pool_index = pool_size;

    if (!entropy_pool)
    {
        fprintf(stderr, "Failed to allocate entropy pool\n");
        exit(EXIT_FAILURE);
    }

    do
    {
        int pos = 0;

        for (int i = 0; i < req->min_upper; i++)
            password[pos++] =
                get_unbiased_random_char(UPPERCASE, strlen(UPPERCASE), entropy_pool, &pool_index, pool_size);

        for (int i = 0; i < req->min_lower; i++)
            password[pos++] =
                get_unbiased_random_char(LOWERCASE, strlen(LOWERCASE), entropy_pool, &pool_index, pool_size);

        for (int i = 0; i < req->min_number; i++)
            password[pos++] = get_unbiased_random_char(NUMBERS, strlen(NUMBERS), entropy_pool, &pool_index, pool_size);

        for (int i = 0; i < req->min_symbol; i++)
            password[pos++] = get_unbiased_random_char(SYMBOLS, strlen(SYMBOLS), entropy_pool, &pool_index, pool_size);

        char charset[256] = "";
        if (req->has_upper)
            strcat(charset, UPPERCASE);
        if (req->has_lower)
            strcat(charset, LOWERCASE);
        if (req->has_number)
            strcat(charset, NUMBERS);
        if (req->has_symbol)
            strcat(charset, SYMBOLS);
        size_t charset_size = strlen(charset);

        while (pos < length)
            password[pos++] = get_unbiased_random_char(charset, charset_size, entropy_pool, &pool_index, pool_size);

        password[length] = '\0';

        crypto_shuffle(password, length);

    } while (!is_valid_password(password, length, req));

    secure_clear(entropy_pool, pool_size);
    free(entropy_pool);
}

int main(int argc, char **argv)
{
    if (argc != 2)
    {
        printf("Usage: %s <password_length>\n", argv[0]);
        return 1;
    }

    int length = atoi(argv[1]);
    if (length < MIN_PASSWORD_LENGTH || length > MAX_PASSWORD_LENGTH)
    {
        printf("Password length must be between %d and %d\n", MIN_PASSWORD_LENGTH, MAX_PASSWORD_LENGTH);
        return 1;
    }

    char *password = calloc(length + 1, sizeof(char));
    if (!password)
    {
        fprintf(stderr, "Memory allocation failed\n");
        return 1;
    }

    PasswordRequirements req = {.has_upper = 1,
                                .has_lower = 1,
                                .has_number = 1,
                                .has_symbol = 1,
                                .min_upper = 1,
                                .min_lower = 1,
                                .min_number = 1,
                                .min_symbol = 1};

    generate_secure_password(password, length, &req);
    printf("Generated Secure Password: %s\n", password);

    secure_clear(password, length);
    free(password);
    return 0;
}
