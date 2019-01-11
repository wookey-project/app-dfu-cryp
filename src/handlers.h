#ifndef HANDLERS_H
#define HANDLERS_H

#include "api/types.h"


extern volatile uint32_t num_dma_in_it;
extern volatile uint32_t num_dma_out_it;
extern volatile status_reg_t status_reg;

void my_cryptin_handler(uint8_t irq, uint32_t status);

void my_cryptout_handler(uint8_t irq, uint32_t status);

#endif
