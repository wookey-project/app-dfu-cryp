#ifndef MAIN_H_
#define MAIN_H_

#include "api/types.h"

typedef struct {
    bool dmain_done;
    bool dmain_hdone;
    bool dmain_fifo_err;
    bool dmain_dm_err;
    bool dmain_tr_err;
    bool dmaout_done;
    bool dmaout_hdone;
    bool dmaout_fifo_err;
    bool dmaout_dm_err;
    bool dmaout_tr_err;
} status_reg_t;

uint32_t get_cycles(void);

#define PROD_CRYPTO_HARD 1

#endif
