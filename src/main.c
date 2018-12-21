/**
 * @file main.c
 *
 * \brief Main of dummy
 *
 */


#include "api/syscall.h"
#include "api/print.h"
#include "api/regutils.h"
#include "libcryp.h"
//#include "dma_regs.h"
#include "main.h"
#include "handlers.h"
#include "wookey_ipc.h"
#include "autoconf.h"


#define CRYPTO_MODE CRYP_PRODMODE
#define CRYPTO_DEBUG 1

#ifdef CONFIG_APP_CRYPTO_USE_GETCYCLES
const char *tim = "tim";
#endif

volatile uint32_t numipc = 0;

volatile uint32_t num_dma_in_it = 0;
volatile uint32_t num_dma_out_it = 0;

volatile uint16_t crypto_chunk_size = 0;
volatile uint32_t total_bytes_read = 0;

bool flash_ready = false;
bool usb_ready = false;
bool smart_ready = false;

volatile status_reg_t status_reg = { 0 };

bool is_new_chunk(void)
{
    printf("total bytes read: %x, crypto_chunk_size: %x\n", total_bytes_read, crypto_chunk_size);
    if (total_bytes_read && total_bytes_read % crypto_chunk_size == 0) 
    {
        return true;
    }
    return false;
}

enum shms {
    ID_USB = 0,
    ID_FLASH = 1
};

volatile 

volatile struct {
    uint32_t address;
    uint16_t size;
} shms_tab[2] = { 0 };

uint32_t td_dma = 0;

void my_cryptin_handler(uint8_t irq, uint32_t status);
void my_cryptout_handler(uint8_t irq, uint32_t status);

void encrypt_dma(const uint8_t * data_in, uint8_t * data_out,
                 uint32_t data_len);

#if 1
void init_crypt_dma(const uint8_t * data_in,
                    uint8_t * data_out, uint32_t data_len);
#endif

uint32_t get_cycles(void)
{
    volatile uint32_t *cnt = (uint32_t *) 0x40000024;
 // tim2 samples at 21Mhz (APB1_f / 2), Cortex M4 is at 168Mhz
    return (*cnt * 2 * 4);
}

uint32_t get_duration(uint32_t tim1, uint32_t tim2)
{
    if (tim2 < tim1) {
        return tim2 - tim1;
    }
    return tim1 - tim2;
}

uint8_t id_dfuflash = 0;
uint8_t id_usb = 0;
uint8_t id_smart = 0;

uint32_t dma_in_desc;
uint32_t dma_out_desc;

uint8_t master_key_hash[32] = {0};



/*
 * We use the local -fno-stack-protector flag for main because
 * the stack protection has not been initialized yet.
 *
 * We use _main and not main to permit the usage of exactly *one* arg
 * without compiler complain. argc/argv is not a goot idea in term
 * of size and calculation in a microcontroler
 */
int _main(uint32_t task_id)
{
    char *wellcome_msg = "hello, I'm crypto";
//    char buffer_in[128];
    logsize_t size;
    uint8_t id = 0;
    char ipc_buf[32] = {0};
    const char * inject_order = "INJECT";

    struct sync_command      ipc_sync_cmd;
    struct sync_command_data ipc_sync_cmd_data;

    strncpy(ipc_buf, inject_order, 6);
#ifdef CONFIG_APP_CRYPTO_USE_GETCYCLES
    device_t dev2 = { 0 };
    int      dev_descriptor = 0;
#endif
    e_syscall_ret ret = 0;

    /**
     * Initialization sequence
     */
    printf("%s, my id is %x\n", wellcome_msg, task_id);

#ifdef CONFIG_APP_CRYPTO_USE_GETCYCLES
    strncpy(dev.name, tim, 3);
    dev2.address = 0x40000020;
    dev2.size = 0x20;
    dev2.isr_ctx_only = false;
    dev2.irq_num = 0;
    dev2.gpio_num = 0;

    printf("registering %s driver\n", dev2.name);
    ret = sys_init(INIT_DEVACCESS, &dev2, &dev_descriptor);
    printf("sys_init returns %s !\n", strerror(ret));
#endif

    ret = sys_init(INIT_GETTASKID, "dfusmart", &id_smart);
    printf("smart is task %x !\n", id_smart);

    ret = sys_init(INIT_GETTASKID, "dfuflash", &id_dfuflash);
    printf("sdio is task %x !\n", id_dfuflash);

    ret = sys_init(INIT_GETTASKID, "dfuusb", &id_usb);
    printf("usb is task %x !\n", id_usb);

    cryp_early_init(true, CRYP_USER, CRYP_PRODMODE, (int*) &dma_in_desc, (int*) &dma_out_desc);

    printf("set init as done\n");
    ret = sys_init(INIT_DONE);
    printf("sys_init returns %s !\n", strerror(ret));

    /*******************************************
     * let's synchronize with other tasks
     *******************************************/
    do {
        size = sizeof(struct sync_command);

        /*
         * CRYPTO is a central node, it waits for mostly all tasks
         * (usb, sdio & smart), in any order
         */
        id = ANY_APP;
        do {
            ret = sys_ipc(IPC_RECV_SYNC, &id, &size, (char*)&ipc_sync_cmd);
        } while (ret != SYS_E_DONE);
        if (   ipc_sync_cmd.magic == MAGIC_TASK_STATE_CMD
                && ipc_sync_cmd.state == SYNC_READY) {
            printf("task %x has finished its init phase, acknowledge...\n", id);
        }

        ipc_sync_cmd.magic = MAGIC_TASK_STATE_RESP;
        ipc_sync_cmd.state = SYNC_ACKNOWLEDGE;

        do {
            size = sizeof(struct sync_command);
            ret = sys_ipc(IPC_SEND_SYNC, id, size, (char*)&ipc_sync_cmd);
        } while (ret != SYS_E_DONE);

        if (id == id_smart) { smart_ready = true; }
        if (id == id_usb)   { usb_ready = true; }
        if (id == id_dfuflash)  { flash_ready = true; }

    } while (   (smart_ready == false)
             || (usb_ready   == false)
             || (flash_ready  == false));
    printf("All tasks have finished their initialization, continuing...\n");

    /*******************************************
     * End of full task end_of_init synchronization
     *******************************************/

    /*******************************************
     * Ask smart for key injection and
     * get back key hash
     *******************************************/

    /* Then Syncrhonize with crypto */
    size = sizeof(struct sync_command);

    printf("sending end_of_init synchronization to smart\n");
    ipc_sync_cmd.magic = MAGIC_CRYPTO_INJECT_CMD;
    ipc_sync_cmd.state = SYNC_READY;

    do {
      ret = sys_ipc(IPC_SEND_SYNC, id_smart, size, (char*)&ipc_sync_cmd);
    } while (ret == SYS_E_BUSY);

    id = id_smart;
    size = sizeof(struct sync_command);

    ret = sys_ipc(IPC_RECV_SYNC, &id, &size, (char*)&ipc_sync_cmd_data);

    if (   ipc_sync_cmd_data.magic == MAGIC_CRYPTO_INJECT_RESP
        && ipc_sync_cmd_data.state == SYNC_DONE) {
        printf("key injection done from smart. Hash received.\n");

    } else {
        goto err;
    }
    cryp_init_dma(my_cryptin_handler, my_cryptout_handler, dma_in_desc, dma_out_desc);

    /*******************************************
     * cryptography initialization done.
     * Let start 2nd pase (Flash/Crypto/USB-DFU runtime)
     *******************************************/

    size = sizeof(struct sync_command);

    printf("sending end_of_cryp synchronization to dfuflash\n");
    ipc_sync_cmd.magic = MAGIC_TASK_STATE_CMD;
    ipc_sync_cmd.state = SYNC_READY;

    /* First inform SDIO block that everything is ready... */
    do {
      ret = sys_ipc(IPC_SEND_SYNC, id_dfuflash, size, (char*)&ipc_sync_cmd);
    } while (ret == SYS_E_BUSY);
    printf("sending end_of_cryp to dfuflash done.\n");


    printf("sending end_of_cryp synchronization to usb-dfu\n");
    ipc_sync_cmd.magic = MAGIC_TASK_STATE_CMD;
    ipc_sync_cmd.state = SYNC_READY;

    /* First inform SDIO block that everything is ready... */
    do {
      ret = sys_ipc(IPC_SEND_SYNC, id_usb, size, (char*)&ipc_sync_cmd);
    } while (ret == SYS_E_BUSY);
    printf("sending end_of_cryp to usb-dfu done.\n");


    printf("waiting for end_of_cryp response from USB-DFU & FLASH\n");
    for (uint8_t i = 0; i < 2; ++i) {
        id = ANY_APP;
        size = sizeof(struct sync_command);

        ret = sys_ipc(IPC_RECV_SYNC, &id, &size, (char*)&ipc_sync_cmd);
        if (ret == SYS_E_DONE) {
            if (id == id_usb) {
                if (ipc_sync_cmd.magic == MAGIC_TASK_STATE_RESP
                        && ipc_sync_cmd.state == SYNC_READY) {
                    printf("USB-DFU module is ready\n");
                }
            } else if (id == id_dfuflash) {
                if (ipc_sync_cmd.magic == MAGIC_TASK_STATE_RESP
                        && ipc_sync_cmd.state == SYNC_READY) {
                    printf("FLASH module is ready\n");
                }
            } else {
                    printf("received msg from id %d ??\n", id);
            }
        }
    }


    /*******************************************
     * Syncrhonizing DMA SHM buffer address with USB and SDIO, through IPC
     ******************************************/
    struct dmashm_info {
        uint32_t addr;
        uint16_t size;
    };

    struct dmashm_info shm_info;

    // 2 receptions are waited: one from usb, one from sdio, in whatever order
    for (uint8_t i = 0; i < 2; ++i) {
        id = ANY_APP;
        size = sizeof(struct dmashm_info);

        ret = sys_ipc(IPC_RECV_SYNC, &id, &size, (char*)&shm_info);
        if (ret == SYS_E_DONE) {
            if (id == id_usb) {
                    shms_tab[ID_USB].address = shm_info.addr;
                    shms_tab[ID_USB].size = shm_info.size;
                    printf("received DMA SHM info from USB: @: %x, size: %d\n",
                            shms_tab[ID_USB].address, shms_tab[ID_USB].size);
            } else if (id == id_dfuflash) {
                    shms_tab[ID_FLASH].address = shm_info.addr;
                    shms_tab[ID_FLASH].size = shm_info.size;
                    printf("received DMA SHM info from SDIO: @: %x, size: %d\n",
                            shms_tab[ID_FLASH].address, shms_tab[ID_FLASH].size);
            } else {
                    printf("received msg from id %d ??\n", id);
            }
        }
    }


    /*******************************************
     * Now crypto will wait for IPC orders from USB
     * (read or write access request) and transmit it
     * to FLASH
     * For read:
     *   - when the SDIO read is ok, SDIO will send an IPC to
     *     CRYPTO which will start the CRYP DMA for uncypher
     *     and tell USB, USB will then start DMA transfer of
     *     uncyphered data directly into the USB IP.
     * For write
     *   - when the USB ask for write (when the USB read from
     *     host using USB DMA is done), Crypto will start DMA-based
     *     cyphering and then ask SDIO to read from the output buffer
     *     SDIO DMA will then read from it and write into the SDIO
     *     storage
     *******************************************/
    t_ipc_command ipc_mainloop_cmd = { 0 };
    logsize_t ipcsize = sizeof(ipc_mainloop_cmd);

    struct sync_command_data dataplane_command_rw = { 0 };
    struct sync_command_data dataplane_command_ack = { 0 };
    uint8_t sinker = 0;

    while (1) {
        /* requests can come from USB, SDIO, or SMART */
        sinker = ANY_APP;
        ipcsize = sizeof(ipc_mainloop_cmd);
        // wait for read or write request from USB

        sys_ipc(IPC_RECV_SYNC, &sinker, &ipcsize, (char*)&ipc_mainloop_cmd);

#if CRYPTO_DEBUG
        printf("Received IPC from task %d\n", sinker);
#endif

        switch (ipc_mainloop_cmd.magic) {

            case MAGIC_DATA_RD_DMA_REQ:
                {
                    /***************************************************
                     * Read mode automaton
                     **************************************************/
                    if (sinker != id_usb) {
                        printf("data rd DMA request command only allowed from USB app\n");
                        continue;
                    }

                    dataplane_command_rw = ipc_mainloop_cmd.sync_cmd_data;
                    struct sync_command_data flash_dataplane_command_rw = dataplane_command_rw;


#if CRYPTO_DEBUG
                    printf("[read] sending ipc to flash (%d)\n", id_dfuflash);
#endif

                    ret = sys_ipc(IPC_SEND_SYNC, id_dfuflash, sizeof(struct sync_command_data), (const char*)&flash_dataplane_command_rw);
                    if (ret != SYS_E_DONE) {
                        printf("Error ! unable to send DMA_RD_REQ to flash!\n");
                    }

                    // wait for flash task acknowledge (IPC)
                    sinker = id_dfuflash;
                    ipcsize = sizeof(struct sync_command_data);

                    ret = sys_ipc(IPC_RECV_SYNC, &sinker, &ipcsize, (char*)&dataplane_command_ack);
                    if (ret != SYS_E_DONE) {
                        printf("Error ! unable to receive back DMA_RD_ACK from flash!\n");
                    }

#if CRYPTO_DEBUG
                    printf("[read] received ipc from flash (%d), sending back to usb (%d)\n", sinker, id_usb);
#endif
                    // acknowledge to USB: data has been written to disk (IPC)
                    ret = sys_ipc(IPC_SEND_SYNC, id_usb, sizeof(struct sync_command_data), (const char*)&dataplane_command_ack);
                    if (ret != SYS_E_DONE) {
                        printf("Error ! unable to send back DMA_WR_ACK to usb!\n");
                    }

                    break;

                }

            case MAGIC_DATA_WR_DMA_REQ:
                {
                    /***************************************************
                     * write mode automaton
                     **************************************************/
                    if (sinker != id_usb) {
                        printf("data rd DMA request command only allowed from USB app\n");
                        continue;
                    }

                    dataplane_command_rw = ipc_mainloop_cmd.sync_cmd_data;
                    struct sync_command_data flash_dataplane_command_rw = dataplane_command_rw;

                    /* Ask smart to reinject the key (only for AES) */
                    //write plane, first exec DMA, then ask SDIO for writing
                    if (is_new_chunk()) {
#if CRYPTO_DEBUG
                        printf("===> Asking for reinjection!\n");
#endif
                        /* When switching from DECRYPT to ENCRYPT, we have to inject the key again */
                        id = id_smart;
                        size = sizeof (struct sync_command);
                        ipc_sync_cmd_data.magic = MAGIC_CRYPTO_INJECT_CMD;
                        /* FIXME: this IPC should transmit the current chunk in order to generate its hash */

                        sys_ipc(IPC_SEND_SYNC, id_smart, sizeof(struct sync_command), (char*)&ipc_sync_cmd_data);

                        sys_ipc(IPC_RECV_SYNC, &id, &size, (char*)&ipc_sync_cmd_data);
#if CRYPTO_DEBUG
                        printf("===> Key reinjection done!\n");
#endif
                    }

                    /********* ENCRYPTION LOGIC ************************************************************/
                    /* We have to split our encryption in multiple subencryptions to deal with IV modification
                     * on the crypto block size boundaries
                     */
                    uint32_t chunk_size = dataplane_command_rw.data.u16[0];

                    status_reg.dmaout_done = false;
                    if ((chunk_size > shms_tab[ID_USB].size) ||
                        (chunk_size > shms_tab[ID_USB].size))
                    {
                        printf("Error: chunk size overflows the max supported DMA SHR buffer size\n");   
                        goto err;
                    }
                    cryp_do_dma((const uint8_t *)shms_tab[ID_USB].address, (const uint8_t *)shms_tab[ID_FLASH].address, chunk_size, dma_in_desc, dma_out_desc);
                    while (status_reg.dmaout_done == false){
                        continue;
                    }
                    cryp_wait_for_emtpy_fifos();
                    /****************************************************************************************/

#if CRYPTO_DEBUG
                    printf("[write] CRYP DMA has finished ! %d\n", shms_tab[ID_USB].size);
#endif
                    status_reg.dmaout_done = false;
#if CRYPTO_DEBUG
                    printf("[write] sending ipc to flash (%d)\n", id_dfuflash);
#endif

                    ret = sys_ipc(IPC_SEND_SYNC, id_dfuflash, sizeof(struct sync_command_data), (const char*)&flash_dataplane_command_rw);
                    if (ret != SYS_E_DONE) {
                        printf("Error ! unable to send DMA_WR_REQ to flash!\n");
                    }

                    // wait for flash task acknowledge (IPC)
                    sinker = id_dfuflash;
                    ipcsize = sizeof(struct sync_command_data);

                    ret = sys_ipc(IPC_RECV_SYNC, &sinker, &ipcsize, (char*)&dataplane_command_ack);
                    if (ret != SYS_E_DONE) {
                        printf("Error ! unable to receive back DMA_WR_ACK from flash!\n");
                    }

#if CRYPTO_DEBUG
                    printf("[write] received ipc from flash (%d), sending back to usb (%d)\n", sinker, id_usb);
#endif
                    // set ack magic for write ack
                    dataplane_command_ack.magic = MAGIC_DATA_WR_DMA_ACK;
                    // acknowledge to USB: data has been written to disk (IPC)
                    ret = sys_ipc(IPC_SEND_SYNC, id_usb, sizeof(struct sync_command_data), (const char*)&dataplane_command_ack);
                    if (ret != SYS_E_DONE) {
                        printf("Error ! unable to send back DMA_WR_ACK to usb!\n");
                    }

                    total_bytes_read += chunk_size;
                    break;

                }


            case MAGIC_DFU_HEADER_SEND:
                {
                    /***************************************************
                     * DFUUSB request for smart
                     **************************************************/
                    if (sinker != id_usb) {
                        printf("DFU header request command only allowed from USB app\n");
                        continue;
                    }

                    dataplane_command_rw = ipc_mainloop_cmd.sync_cmd_data;

#if CRYPTO_DEBUG
                    printf("[write] sending ipc to smart (%d)\n", id_smart);
#endif

                    ret = sys_ipc(IPC_SEND_SYNC, id_smart, sizeof(struct sync_command_data), (const char*)&dataplane_command_rw);
                    if (ret != SYS_E_DONE) {
                        printf("Error ! unable to send DFU_HEADER_SEND to smart!\n");
                    }

                    break;

                }

            case MAGIC_DFU_HEADER_VALID:
            case MAGIC_DFU_HEADER_INVALID:
                {
                    /***************************************************
                     * DFUUSB validation from smart
                     **************************************************/
                    if (sinker != id_smart) {
                        printf("DFU header validation command only allowed from Smart app\n");
                        continue;
                    }

                    dataplane_command_rw = ipc_mainloop_cmd.sync_cmd_data;

                    /* if header is valid, get back chunk size from smart */
                    if (ipc_mainloop_cmd.magic == MAGIC_DFU_HEADER_VALID) {
                        crypto_chunk_size = dataplane_command_rw.data.u16[0];
#if CRYPTO_DEBUG
                        printf("chunk size received: %x\n", crypto_chunk_size);
#endif
                    }
#if CRYPTO_DEBUG
                    printf("[write] sending ipc to dfuusb (%d)\n", id_usb);
#endif

                    ret = sys_ipc(IPC_SEND_SYNC, id_usb, sizeof(struct sync_command_data), (const char*)&dataplane_command_rw);
                    if (ret != SYS_E_DONE) {
                        printf("Error ! unable to send DFU_HEADER_VALID to dfuusb!\n");
                    }

                    break;

                }



            default:
                {
                    /***************************************************
                     * Invalid request. Returning invalid to sender
                     **************************************************/
                    printf("invalid request from USB !\n");
                    // returning INVALID magic to USB
                    ipc_mainloop_cmd.magic = MAGIC_INVALID;

                    // acknowledge to USB: data has been written to disk (IPC)
                    ret = sys_ipc(IPC_SEND_SYNC, id_usb, sizeof(t_ipc_command), (const char*)&ipc_mainloop_cmd);
                    if (ret != SYS_E_DONE) {
                        printf("Error ! unable to send back INVALID to usb!\n");
                    }
                    break;

                }
        }

    }

err:
    while (1) {
        sys_yield();
    }
}
