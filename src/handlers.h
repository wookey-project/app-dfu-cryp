#ifndef HANDLERS_H
#define HANDLERS_H

#include "api/types.h"

void my_cryptin_handler(uint8_t irq, uint32_t status);

void my_cryptout_handler(uint8_t irq, uint32_t status);

#endif
