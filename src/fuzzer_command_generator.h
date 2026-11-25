#ifndef FUZZER_COMMAND_GENERATOR_H
#define FUZZER_COMMAND_GENERATOR_H

#include <stdint.h>
#include <valkey/valkey.h>
#include "sds.h"

typedef struct FuzzerCommand {
    sds *argv;
    int argc;
    int size;
    int may_block; /* A blocking command outside MULTI: its reply can be held back */
} FuzzerCommand;

/* Fuzzing mode types */
typedef enum {
    FUZZ_MODE_MALFORMED_COMMANDS = (1 << 0),
    FUZZ_MODE_CONFIG_COMMANDS = (1 << 1)
} FuzzMode;

int initFuzzer(valkeyContext *ctx, long long num_keys, int cluster_mode, int fuzz_flags, uint64_t seed);
void cleanupFuzzer(void);
void initThreadClientCtx(int fuzz_flags, int thread_index, int slot);
void resetClientFuzzCtx(void);
void freeClientCtx(void);
FuzzerCommand *generateCmd(void);
void freeCommand(FuzzerCommand *args);
char *printCommand(FuzzerCommand *cmd);

#endif /* FUZZER_COMMAND_GENERATOR_H */
