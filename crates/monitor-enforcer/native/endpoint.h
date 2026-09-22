#include <stdint.h>
#include <stddef.h>
typedef struct { const unsigned char *data; size_t length; } mon_text;
typedef struct {
    uint32_t pid, version, uid, valid_signature;
    mon_text executable, signing_id, team_id;
    unsigned char cdhash[20];
} mon_process;
typedef struct {
    uint32_t kind, readable, truncated, regular_file;
    uint64_t links, sequence;
    uint32_t has_sequence;
    mon_process process, related;
    mon_text path;
    mon_text cwd;
    uint32_t cwd_truncated;
} mon_event;
typedef uint32_t (*mon_decide)(void *, const mon_event *, uint32_t *);
typedef void (*mon_result)(void *, const mon_event *, uint32_t, uint32_t, uint32_t);
uint32_t mon_preflight(void);
int mon_run(void *, mon_decide, mon_result);
size_t mon_event_size(void);
