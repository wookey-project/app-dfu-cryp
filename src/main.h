/*
 *
 * Copyright 2019 The wookey project team <wookey@ssi.gouv.fr>
 *   - Ryad     Benadjila
 *   - Arnauld  Michelizza
 *   - Mathieu  Renard
 *   - Philippe Thierry
 *   - Philippe Trebuchet
 *
 * This package is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published
 * the Free Software Foundation; either version 3 of the License, or (at
 * ur option) any later version.
 *
 * This package is distributed in the hope that it will be useful, but WITHOUT ANY
 * WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A
 * PARTICULAR PURPOSE. See the GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this package; if not, write to the Free Software Foundation, Inc., 51
 * Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
 *
 */

#ifndef MAIN_H_
#define MAIN_H_

#include "libc/types.h"

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
