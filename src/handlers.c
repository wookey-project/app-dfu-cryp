#include "api/print.h"
#include "api/types.h"
#include "api/syscall.h"
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

