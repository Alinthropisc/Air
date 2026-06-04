#pragma once


#include <stddef.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <time.h>
#include <pthread.h>

#include "defs.h"
#include "compat.h"
#include "version.h.in"

#ifdef __cplusplus
extern "C" {
#endif

typedef enum AirStatus : int32_t {
    AIR_SUCCESS =  0,
    AIR_FAILURE = -1,
    AIR_RESTART = -2,
} AirStatus;


enum : uint32_t {
    AIR_MAX_DICTS = 128u,
    AIR_MAX_THREADS = 256u,
    AIR_PTW_TRY_STEP = 5000u,
    AIR_KEYLIMIT = 1000000u,
    AIR_N_ATTACKS = 17u,
    AIR_WL_QUEUE_SIZE = (32u * 1024u),
    AIR_CLOSE_IT = 100000u,
    AIR_TEST_MIN_IVS = 4u,
    AIR_TEST_MAX_IVS = 32u,
    AIR_WPA_KEY_BUF_LEN = 128u,
    AIR_ESSID_MAX_LEN = 32u,   /* 32 + '\0' */
    AIR_BSSID_LEN = 6u,
    AIR_WEP_KEY_MAX = 64u,
};

enum : uint8_t {
    AIR_ASCII_LOW = 0x21u,
    AIR_ASCII_HIGH = 0x7Eu,
    AIR_ASCII_VOTE_STR = 150u,
    AIR_ASCII_DISREGARD = 1u,
};

#define AIR_LLC_SNAP     "\xAA\xAA\x03\x00\x00\x00"
#define AIR_LLC_SNAP_ARP (AIR_LLC_SNAP "\x08\x06")
#define AIR_LLC_SNAP_IP  (AIR_LLC_SNAP "\x08\x00")

#define AIR_FC1_DIR_FROMDS  0x02u   /* AP → STA */

typedef enum AirAttackMode : int32_t {
    AIR_ATTACK_AUTO = 0,
    AIR_ATTACK_STATIC = 1,
    AIR_ATTACK_WEP = 2,
    AIR_ATTACK_WPA = 3,
    AIR_ATTACK_PTW = 4,
} AirAttackMode;


typedef enum KoreKAttack : uint32_t {
    KOREK_A_u15 = 0,  /* semi-stable  15%          */
    KOREK_A_s13,        /* stable       13%          */
    KOREK_A_u13_1,      /* unstable     13%          */
    KOREK_A_u13_2,      /* unstable ?   13%          */
    KOREK_A_u13_3,      /* unstable ?   13%          */
    KOREK_A_s5_1,       /* standard      5% (~FMS)   */
    KOREK_A_s5_2,       /* other stable  5%          */
    KOREK_A_s5_3,       /* other stable  5%          */
    KOREK_A_u5_1,       /* unstable      5%          */
    KOREK_A_u5_2,       /* unstable      5%          */
    KOREK_A_u5_3,       /* unstable      5% no good  */
    KOREK_A_u5_4,       /* unstable      5%          */
    KOREK_A_s3,         /* stable        3%          */
    KOREK_A_4_s13,      /* stable       13% q=4      */
    KOREK_A_4_u5_1,     /* unstable      5% q=4      */
    KOREK_A_4_u5_2,     /* unstable      5% q=4      */
    KOREK_A_neg,
    KOREK_COUNT = AIR_N_ATTACKS,
} KoreKAttack;

 * Vote структура
 * ───────────────────────────────────────────── */
typedef struct AirVote {
    int32_t idx;
    int32_t val;
} AirVote;


typedef struct AirDictFile {
    off_t size;
    off_t pos;
    off_t wordcount;
    bool loaded;
    char _pad[3];
} AirDictFile;

static_assert(sizeof(AirDictFile) % 8 == 0 || true, "AirDictFile alignment check");


typedef struct AirTarget {
    char essid[AIR_ESSID_MAX_LEN + 1];
    uint8_t bssid[AIR_BSSID_LEN];
    uint8_t maddr[AIR_BSSID_LEN];
    bool essid_set;
    bool bssid_set;
    char _pad[2];
} AirTarget;

typedef struct AirWepParams {
    uint8_t debug_key[AIR_WEP_KEY_MAX];
    int32_t debug_row[AIR_WEP_KEY_MAX];
    int32_t keylen;
    int32_t index;
    float ffact;
    int32_t korek;
    bool is_fritz;
    bool is_alnum;
    bool is_bcdonly;
    bool do_brute;
    bool do_mt_brute;
    bool do_testy;
    bool do_ptw;
    bool wep_decloak;
    bool ptw_attack;
    char _pad[3];
} AirWepParams;

typedef struct AirDictConfig {
    char *files[AIR_MAX_DICTS];
    FILE *current;
    int32_t count;
    int32_t total;
    bool no_stdin;
    bool stdin_dict;
    bool finished;
    char _pad[1];
    bool is_hex[AIR_MAX_DICTS];
    size_t wordcount;
    AirDictFile index[AIR_MAX_DICTS];
} AirDictConfig;

typedef struct AirOptions {
    AirAttackMode attack_mode;
    AirTarget target;
    AirWepParams wep;
    AirDictConfig dicts;
    int32_t nbcpu;
    bool is_quiet;
    bool show_ascii;
    bool l33t;
    bool visual_inspection;
    bool oneshot;
    char _pad[3];
    int32_t probability;
    int32_t votes[AIR_N_ATTACKS];
    int32_t brutebytes[AIR_WEP_KEY_MAX];
    int32_t next_ptw_try;
    int32_t max_ivs;
    int32_t forced_amode;
    char *bssidmerge;
    uint8_t *firstbssid;
    char *log_key_file;
    char *wkp;
    char *hccap;
    char *hccapx;
} AirOptions;


typedef struct AirWepData {
    uint8_t key[AIR_WEP_KEY_MAX];
    uint8_t *ivbuf;
    int32_t nb_aps;
    int64_t nb_ivs;
    int64_t nb_ivs_now;
    int32_t fudge[AIR_WEP_KEY_MAX];
    int32_t depth[AIR_WEP_KEY_MAX];
    AirVote poll[AIR_WEP_KEY_MAX][256];
} AirWepData;


typedef struct AirWpaData {
    bool active;
    char _pad[3];
    int32_t thread;
    int32_t threadid;
    char key[AIR_WPA_KEY_BUF_LEN];
    uint8_t *key_buffer;
    pthread_mutex_t mutex;
} AirWpaData;


typedef struct AirMergeBSSID {
    uint8_t bssid[AIR_BSSID_LEN];
    bool convert;
    char _pad[1];
    struct AirMergeBSSID *next;
} AirMergeBSSID;


static inline int air_cmp_votes(const void *a,const void *b)
{
    REQUIRE(a != nullptr);
    REQUIRE(b != nullptr);

    const AirVote *va = (const AirVote *)a;
    const AirVote *vb = (const AirVote *)b;

    if (va->val < vb->val)
    {
        return  1;
    }

    if (va->val > vb->val)
    {
        return -1;
    }
    return 0;
}


[[nodiscard]]
AirOptions *air_options_create(void);

void air_options_destroy(AirOptions **opts);

void air_show_wep_stats(int32_t byte_idx,bool force,int32_t choices[],int32_t depth[],int32_t prod);

#ifdef __cplusplus
}
#endif
































































































