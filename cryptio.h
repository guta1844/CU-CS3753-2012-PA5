/* Ken Sheedlo
 * leetfs Encrypted File System
 * CSCI 3753 P.A. 5
 *
 * File: cryptio.h
 * Headers and definitions for encrypted I/O.
 */

#define CRYPTIO_ENCRYPT     1
#define CRYPTIO_DECRYPT     0
#define CRYPTIO_PASSTHRU    -1

/* int cryptio_initctx(EVP_CIPHER_CTX *ctx, const char *key, int action)
 * 
 * Purpose: Initializes an EVP cipher context.
 * Args: EVP_CIPHER_CTX* ctx    A pointer to the context to be initialized.
 *       const char *key        the key string to use for encryption.
 *       int action             An action (encrypt, decrypt or identity) as
 *                              specified in the EVP spec.
 * Returns: 1 on success, 0 if an error occurs.
 */
int cryptio_initctx(EVP_CIPHER_CTX *ctx, 
                    unsigned char *key, 
                    int action);

/* int cryptio_read(EVP_CIPHER_CTX *ctx, FILE *input, void *buf, size_t bytes)
 * 
 * Purpose: Reads in a block of encrypted file data to a plaintext buffer.
 * Args: EVP_CIPHER_CTX* ctx    The cipher context to use for decryption.
 *       FILE *input            The encrypted file to read and decode.
 *       void *buf              Stores decrypted file data.
 *       size_t bytes           The size of the buffer, in bytes.
 * Returns: 1 on success, 0 if an error occurs or if EOF is reached.
 */
int cryptio_read(EVP_CIPHER_CTX *ctx, FILE *input, void *buf, size_t bytes, 
                    int action, int *outlen);

/* int cryptio_write(EVP_CIPHER_CTX *ctx, FILE *output, void *data, size_t bytes)
 * 
 * Purpose: Reads in a block of encrypted file data to a plaintext buffer.
 * Args: EVP_CIPHER_CTX* ctx    The cipher context to use for decryption.
 *       FILE *output           The encrypted file to write out.
 *       void *data             The data to encrypt and store.
 *       size_t bytes           The size of the buffer, in bytes.
 * Returns: 1 on success, 0 if an error occurs or if EOF is reached.
 */
int cryptio_write(EVP_CIPHER_CTX *ctx, FILE *output, void *data, size_t bytes,
                    int action);
