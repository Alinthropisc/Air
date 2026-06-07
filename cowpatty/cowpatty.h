#pragma once

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>

#include "../defs.h"


#ifdef __cplusplus
extern "C" {
#endif



enum : uint32_t {
    AIR_COWPATTY_MAGIC = 0x43575041u, // "CWPA" little-endian
    AIR_COWPATTY_SSID_MAX = 32u, // IEEE 802.11 max
    AIR_COWPATTY_PMK_LEN = 32u, // PMK always 32 bytes
    AIR_COWPATTY_PASS_MAX = 63u, // WPA password max
    AIR_COWPATTY_ERR_BUF_LEN = 200u, // Error buffer
};


typedef struct AirCowpattyHead {
    uint32_t magic; // AIR_COWPATTY_MAGIC
    uint8_t  reserved[3]; // registry (zero)
    uint8_t  ssid_len; // length ESSID (1..32)
    uint8_t  ssid[AIR_COWPATTY_SSID_MAX]; // ESSID without NUL
} AirCowpattyHead;

// Checking header size
static_assert(sizeof(AirCowpattyHead) == 4 + 3 + 1 + 32,"AirCowpattyHead size mismatch");
static_assert(offsetof(AirCowpattyHead, magic) == 0,  "magic offset");
static_assert(offsetof(AirCowpattyHead, ssid_len) == 7,  "ssid_len offset");
static_assert(offsetof(AirCowpattyHead, ssid) == 8,  "ssid offset");


typedef struct AirCowpattyRecord {
    uint8_t  word_len; // pass length
    char     word[AIR_COWPATTY_PASS_MAX + 1]; // pass + NUL
    uint8_t  pmk[AIR_COWPATTY_PMK_LEN]; // PMK for pass
} AirCowpattyRecord;


typedef struct AirCowpattyFile {
    char ssid[AIR_COWPATTY_SSID_MAX + 1]; // ESSID + NUL
    uint8_t  ssid_len; // Length ESSID
    char _pad[2];
    FILE *fp; // File descriptor*/
    uint64_t record_count; // Entries read
    char error[AIR_COWPATTY_ERR_BUF_LEN]; // Last mistake
} AirCowpattyFile;


typedef enum AirCowpattyStatus : int32_t {
    AIR_COWPATTY_OK =  0,
    AIR_COWPATTY_EOF =  1,// End of file
    AIR_COWPATTY_ERR_IO = -1,// Оinput/output error
    AIR_COWPATTY_ERR_MAGIC = -2,// Wrong magic
    AIR_COWPATTY_ERR_SSID = -3,// SSID doesn't match
    AIR_COWPATTY_ERR_MEM = -4,// No memory
    AIR_COWPATTY_ERR_ARG = -5,// Invalid argument
    AIR_COWPATTY_ERR_CORRUPT = -6,// The file is damaged
} AirCowpattyStatus;


/**
* air_cowpatty_open - Open a hashdb file
*
* @param filename File path
* @param mode Mode ("r" read, "w" write, "a" append)
*
* @return Handle or nullptr on error
* See errno for error information
*/
[[nodiscard]]
AIR_EXPORT AirCowpattyFile *air_cowpatty_open(const char *filename,const char *mode);

/**
* air_cowpatty_close - Close and release the handle
*
* @param cf Handle (may be nullptr)
*/
AIR_EXPORT void air_cowpatty_close(AirCowpattyFile *cf);

/**
* air_cowpatty_read_next - Read the next record
*
* @param cf File descriptor
* @param rec Where to write the read record
*
* @return AIR_COWPATTY_OK - Record read
* @return AIR_COWPATTY_EOF - End of file
* @return AIR_COWPATTY_ERR_* - Error
*/
[[nodiscard]]
AIR_EXPORT AirCowpattyStatus air_cowpatty_read_next(AirCowpattyFile *cf,AirCowpattyRecord *rec);

/**
* air_cowpatty_write - Write a record to the database
*
* @param cf File descriptor (open for writing)
* @param word Password
* @param pmk PMK (32 bytes)
*
* @return AIR_COWPATTY_OK or an error code
*/
[[nodiscard]]
AIR_EXPORT AirCowpattyStatus air_cowpatty_write(AirCowpattyFile *cf,const char *word,const uint8_t pmk[AIR_COWPATTY_PMK_LEN]);

/**
* air_cowpatty_write_head - Write the header
*
* Call once when a new file is created.
*
* @param cf File descriptor
* @param ssid Network ESSID
*/
[[nodiscard]]
AIR_EXPORT AirCowpattyStatus air_cowpatty_write_head(AirCowpattyFile *cf,const char *ssid);

/**
 * air_cowpatty_error - Get error string
 */
[[nodiscard]]
static inline const char *air_cowpatty_error(const AirCowpattyFile *cf)
{
    REQUIRE(cf != nullptr);
    return cf->error;
}

/**
* air_cowpatty_rewind - Rewind the file to the beginning of the recordings
* (after the header)
*/
[[nodiscard]]
AIR_EXPORT AirCowpattyStatus air_cowpatty_rewind(AirCowpattyFile *cf);

/**
* air_cowpatty_count - Count records in a file
*
* Slow - reads the entire file!
* Use for statistics.
*/
[[nodiscard]]
AIR_EXPORT uint64_t air_cowpatty_count(AirCowpattyFile *cf);

#ifdef __cplusplus
}
#endif















































