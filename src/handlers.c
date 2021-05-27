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

#include "libc/stdio.h"
#include "libc/nostd.h"
#include "libc/types.h"
#include "libc/syscall.h"
#include "main.h"

volatile uint32_t num_dma_in_it = 0;
volatile uint32_t num_dma_out_it = 0;
volatile status_reg_t status_reg = { 0 };

/* DMA handlers to report status to the main thread mode */
void my_cryptin_handler(__attribute__((unused)) uint8_t irq, uint32_t status)
{
    num_dma_in_it++;

    if(status & DMA_FIFO_ERROR){
        status_reg.dmain_fifo_err = true;
    }
    if(status & DMA_DIRECT_MODE_ERROR){
        status_reg.dmain_dm_err = true;
    }
    if(status & DMA_TRANSFER_ERROR){
        status_reg.dmain_tr_err = true;
    }
    if(status & DMA_HALF_TRANSFER){
        status_reg.dmain_hdone = true;
    }
    if(status & DMA_TRANSFER){
        status_reg.dmain_done = true;
    }
}

void my_cryptout_handler(__attribute__((unused)) uint8_t irq, uint32_t status)
{
    num_dma_out_it++;

    if(status & DMA_FIFO_ERROR){
        status_reg.dmaout_fifo_err = true;
    }
    if(status & DMA_DIRECT_MODE_ERROR){
        status_reg.dmaout_dm_err = true;
    }
    if(status & DMA_TRANSFER_ERROR){
        status_reg.dmaout_tr_err = true;
    }
    if(status & DMA_HALF_TRANSFER){
        status_reg.dmaout_hdone = true;
    }
    if(status & DMA_TRANSFER){
        status_reg.dmaout_done = true;
    }
}

