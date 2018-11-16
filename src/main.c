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
#include "aes.h"
#include "wookey_ipc.h"
#include "autoconf.h"

/* Include the AES or TDES header (for CBC-ESSIV IV derivation) */

#ifdef CONFIG_AES256_CBC_ESSIV
#include "aes.h"
#endif
#ifdef CONFIG_TDES_CBC_ESSIV
#include "tdes.h"
#endif

/* The SCSI block size that has been set in the configuration */
#ifdef CONFIG_USB_DEV_SCSI_BLOCK_SIZE_512
#define SCSI_BLOCK_SIZE 512
#else
  #ifdef CONFIG_USB_DEV_SCSI_BLOCK_SIZE_1024
    #define SCSI_BLOCK_SIZE 1024
  #else
    #ifdef CONFIG_USB_DEV_SCSI_BLOCK_SIZE_2048
        #define SCSI_BLOCK_SIZE 2048
    #else
        #ifdef CONFIG_USB_DEV_SCSI_BLOCK_SIZE_4096
            #define SCSI_BLOCK_SIZE 4096
        #else
            #ifdef CONFIG_USB_DEV_SCSI_BLOCK_SIZE_8192
              #define SCSI_BLOCK_SIZE 8192
            #else 
               #error "SCSI block size is not defined!"
            #endif
        #endif
    #endif
  #endif
#endif

volatile uint32_t scsi_block_size = SCSI_BLOCK_SIZE;

/* The size that we get from the SD layer */
volatile uint32_t sdio_block_size = 0;

#define CRYPTO_MODE CRYP_PRODMODE
#define CRYPTO_DEBUG 0

#ifdef CONFIG_APP_CRYPTO_USE_GETCYCLES
const char *tim = "tim";
#endif

volatile uint32_t numipc = 0;

volatile uint32_t num_dma_in_it = 0;
volatile uint32_t num_dma_out_it = 0;

bool sdio_ready = false;
bool usb_ready = false;
bool smart_ready = false;

volatile status_reg_t status_reg = { 0 };

enum shms {
    ID_USB = 0,
    ID_FLASH = 1
};

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

uint8_t id_flash = 0;
uint8_t id_usb = 0;
uint8_t id_smart = 0;
uint8_t id_benchlog = 0;

uint32_t dma_in_desc;
uint32_t dma_out_desc;

uint8_t master_key_hash[32] = {0};


/* Crypto helper to perform the IV derivation for CBC-ESSIV depending
 * on the block address.
 * The diversification varies depending on the underlying block cipher.
 */
int cbc_essiv_iv_derivation(uint32_t sector_number, uint8_t *hkey, unsigned int hkey_len, uint8_t *iv, unsigned int iv_len){
        /* The key hash is not really a secret, we can safely use an unprotected (and faster) AES/TDES algorithm.
         *
         * NOTE: obviously, we cannot use accelerated AES/TDES here since it is already configured with the master key
         * to perform blocks encryption/decryption!
         */

#ifdef CONFIG_AES256_CBC_ESSIV
        uint8_t sector_number_buff[16] = { 0 };
        /* Encode the sector number in big endian 16 bytes */
        uint32_t big_endian_sector_number = to_big32(sector_number);
        sector_number_buff[0] = (big_endian_sector_number >>  0) & 0xff;
        sector_number_buff[1] = (big_endian_sector_number >>  8) & 0xff;
        sector_number_buff[2] = (big_endian_sector_number >> 16) & 0xff;
        sector_number_buff[3] = (big_endian_sector_number >> 24) & 0xff;

        /* Sanity checks */
        if((hkey_len != 32) || (iv_len != 16)){
                goto err;
        }

        aes_context aes_context;
        if(aes_init(&aes_context, hkey, AES256, NULL, ECB, AES_ENCRYPT, AES_SOFT_MBEDTLS, NULL, NULL, -1, -1)){
                goto err;
        }
        if(aes(&aes_context, sector_number_buff, iv, iv_len, -1, -1)){
            goto err;
        }
#else
#ifdef CONFIG_TDES_CBC_ESSIV
        uint8_t sector_number_buff[8] = { 0 };
        /* Encode the sector number in big endian 8 bytes */
        uint32_t big_endian_sector_number = to_big32(sector_number);
        sector_number_buff[0] = (big_endian_sector_number >>  0) & 0xff;
        sector_number_buff[1] = (big_endian_sector_number >>  8) & 0xff;
        sector_number_buff[2] = (big_endian_sector_number >> 16) & 0xff;
        sector_number_buff[3] = (big_endian_sector_number >> 24) & 0xff;

        des3_context des3_context;
        /* Sanity checks */
        if((hkey_len != 24) || (iv_len != 8)){
                goto err;
        }
        des3_set_3keys(&des3_context, &(hkey[0]), &(hkey[8]), &(hkey[16]));
        des3_encrypt(&des3_context, sector_number_buff, iv);

#else
#error "No FDE algorithm has been selected ..."
#endif
#endif        
        return 0;
err:
        return -1;

}



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

    ret = sys_init(INIT_GETTASKID, "dfu-smart", &id_smart);
    printf("smart is task %x !\n", id_smart);

    ret = sys_init(INIT_GETTASKID, "flash", &id_flash);
    printf("sdio is task %x !\n", id_flash);

    ret = sys_init(INIT_GETTASKID, "dfu-usb", &id_usb);
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
        if (id == id_flash)  { sdio_ready = true; }

    } while (   (smart_ready == false)
             || (usb_ready   == false)
             || (sdio_ready  == false));
    printf("All tasks have finished their initialization, continuing...\n");

    /*******************************************
     * End of full task end_of_init synchronization
     *******************************************/

    /*******************************************
     * Ask smart for key injection and
     * get back key hash
     *******************************************/

	unsigned char CBC_ESSIV_h_key[32] = {0};
    /* Then Syncrhonize with crypto */
    size = sizeof(struct sync_command);

    printf("sending end_of_init synchronization to smart\n");
    ipc_sync_cmd.magic = MAGIC_CRYPTO_INJECT_CMD;
    ipc_sync_cmd.state = SYNC_READY;

    do {
      ret = sys_ipc(IPC_SEND_SYNC, id_smart, size, (char*)&ipc_sync_cmd);
    } while (ret == SYS_E_BUSY);

    id = id_smart;
    size = sizeof(struct sync_command_data);

    ret = sys_ipc(IPC_RECV_SYNC, &id, &size, (char*)&ipc_sync_cmd_data);

    if (   ipc_sync_cmd_data.magic == MAGIC_CRYPTO_INJECT_RESP
        && ipc_sync_cmd_data.state == SYNC_DONE) {
        printf("key injection done from smart. Hash received.\n");
        memcpy(CBC_ESSIV_h_key, &ipc_sync_cmd_data.data.u8, ipc_sync_cmd_data.data_size);

#ifdef CRYPTO_DEBUG
        printf("hash received:\n");
        hexdump(CBC_ESSIV_h_key, 32);
#endif
    } else {
        goto err;
    }
    cryp_init_dma(my_cryptin_handler, my_cryptout_handler, dma_in_desc, dma_out_desc);

    /*******************************************
     * cryptography initialization done.
     * Let start 2nd pase (Flash/Crypto/USB-DFU runtime)
     *******************************************/

    size = sizeof(struct sync_command);

    printf("sending end_of_cryp synchronization to flash\n");
    ipc_sync_cmd.magic = MAGIC_TASK_STATE_CMD;
    ipc_sync_cmd.state = SYNC_READY;

    /* First inform SDIO block that everything is ready... */
    do {
      ret = sys_ipc(IPC_SEND_SYNC, id_flash, size, (char*)&ipc_sync_cmd);
    } while (ret == SYS_E_BUSY);
    printf("sending end_of_cryp to flash done.\n");


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
            } else if (id == id_flash) {
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
            } else if (id == id_flash) {
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

    struct dataplane_command dataplane_command_rw = { 0 };
    struct dataplane_command dataplane_command_ack = { MAGIC_DATA_WR_DMA_ACK, 0, 0 };
    uint8_t sinker = 0;

    // Default mode is encryption
#ifdef CONFIG_AES256_CBC_ESSIV
    cryp_init_user(KEY_256, NULL, 0, AES_CBC, ENCRYPT);
#else
#ifdef CONFIG_TDES_CBC_ESSIV 
    cryp_init_user(KEY_192, NULL, 0, TDES_CBC, ENCRYPT);
#else
#error "No FDE algorithm has been selected ..."
#endif
#endif

    while (1) {
        /* requests can come from USB, SDIO, or SMART */
        sinker = ANY_APP;
        ipcsize = sizeof(ipc_mainloop_cmd);
        // wait for read or write request from USB

        sys_ipc(IPC_RECV_SYNC, &sinker, &ipcsize, (char*)&ipc_mainloop_cmd);

        switch (ipc_mainloop_cmd.magic) {


#if 0
            case MAGIC_STORAGE_SCSI_BLOCK_SIZE_CMD:
                {
                    /***************************************************
                     * SDIO/USB block size synchronization
                     **************************************************/
                    if (sinker != id_usb) {
                        printf("block size request command only allowed from USB app\n");
                        continue;
                    }
                    /*
                     * INFO: this line makes a copy of the structure. Not impacting here (init phase) but
                     * should not be used in the dataplane, as it will impact the performances
                     */
                    ipc_sync_cmd_data = ipc_mainloop_cmd.sync_cmd_data;
                    /*
                     * By now, request is sent 'as is' to SDIO. Nevertheless, it would be possible
                     * to clean the struct content to avoid any data leak before transfering the content
                     * to sdio task, behavioring like a filter.
                     */ 
                    sys_ipc(IPC_SEND_SYNC, id_flash, sizeof(struct sync_command_data), (char*)&ipc_sync_cmd_data);

                    id = id_flash;
                    size = sizeof(struct sync_command_data);

                    sys_ipc(IPC_RECV_SYNC, &id, &size, (char*)&ipc_sync_cmd_data);

                    /* Save the block sizes (SDIO and SCSI) since we will need it later */
                    sdio_block_size = ipc_sync_cmd_data.data.u32[0];
                    /* Override the SCSI block size and number */
                    /* FIXME: use a uint64_t to avoid overflows */
                    ipc_sync_cmd_data.data.u32[1] = (ipc_sync_cmd_data.data.u32[1] / scsi_block_size) * ipc_sync_cmd_data.data.u32[0];
                    ipc_sync_cmd_data.data.u32[0] = scsi_block_size;


                    /* now that SDIO has returned, let's return to USB */
                    sys_ipc(IPC_SEND_SYNC, id_usb, sizeof(struct sync_command_data), (char*)&ipc_sync_cmd_data);

                    break;
                }

            case MAGIC_STORAGE_SCSI_BLOCK_NUM_CMD:
                {
                    /***************************************************
                     * SDIO/USB block number synchronization
                     **************************************************/

                    if (sinker != id_usb) {
                        printf("block num request command only allowed from USB app\n");
                        continue;
                    }
                    /* Get the block size */
                    struct sync_command_data ipc_sync_get_block_size = { 0 };
                    ipc_sync_get_block_size.magic = MAGIC_STORAGE_SCSI_BLOCK_SIZE_CMD;
                    sys_ipc(IPC_SEND_SYNC, id_flash, sizeof(struct sync_command_data), (char*)&ipc_sync_get_block_size);
                    id = id_flash;
                    size = sizeof(struct sync_command_data);
                    sys_ipc(IPC_RECV_SYNC, &id, &size, (char*)&ipc_sync_get_block_size);

                    sdio_block_size = ipc_sync_cmd_data.data.u32[0];

                    /*
                     * INFO: this line makes a copy of the structure. Not impacting here (init phase) but
                     * should not be used in the dataplane, as it will impact the performances
                     */
                    ipc_sync_cmd_data = ipc_mainloop_cmd.sync_cmd_data;
                    /*
                     * By now, request is sent 'as is' to SDIO. Nevertheless, it would be possible
                     * to clean the struct content to avoid any data leak before transfering the content
                     * to sdio task, behavioring like a filter.
                     */ 
                    sys_ipc(IPC_SEND_SYNC, id_flash, sizeof(struct sync_command_data), (char*)&ipc_sync_cmd_data);

                    id = id_flash;
                    size = sizeof(struct sync_command_data);

                    sys_ipc(IPC_RECV_SYNC, &id, &size, (char*)&ipc_sync_cmd_data);
		    /* Override the SCSI block number */
                    /* FIXME: use a uint64_t to avoid overflows */
		    ipc_sync_cmd_data.data.u32[1] = (ipc_sync_cmd_data.data.u32[1] / scsi_block_size) * ipc_sync_get_block_size.data.u32[0];

                    /* now that SDIO has returned, let's return to USB */
                    sys_ipc(IPC_SEND_SYNC, id_usb, sizeof(struct sync_command_data), (char*)&ipc_sync_cmd_data);

                    break;
                }
#endif
            case MAGIC_DATA_WR_DMA_REQ:
                {
                    /***************************************************
                     * Write mode automaton
                     **************************************************/
                    if (sinker != id_usb) {
                        printf("data wr DMA request command only allowed from USB app\n");
                        continue;
                    }
                    dataplane_command_rw = ipc_mainloop_cmd.dataplane_cmd;
                    struct dataplane_command sdio_dataplane_command_rw = dataplane_command_rw;
                    uint32_t scsi_num_sectors = dataplane_command_rw.num_sectors;
                    uint32_t scsi_sector_address = dataplane_command_rw.sector_address;
                    sdio_dataplane_command_rw.num_sectors = (scsi_num_sectors * scsi_block_size) / sdio_block_size;
                    sdio_dataplane_command_rw.sector_address = (dataplane_command_rw.sector_address * scsi_block_size) / sdio_block_size;

                    /* Ask smart to reinject the key (only for AES) */
#ifdef CONFIG_AES256_CBC_ESSIV
                    //write plane, first exec DMA, then ask SDIO for writing
                    //
                    if (cryp_get_dir() == DECRYPT) {
#if CRYPTO_DEBUG
                        printf("===> Asking for reinjection!\n");
#endif
                        /* When switching from DECRYPT to ENCRYPT, we have to inject the key again */
                        id = id_smart;
                        size = sizeof (struct sync_command);
                        ipc_sync_cmd_data.magic = MAGIC_CRYPTO_INJECT_CMD;
                        ipc_sync_cmd_data.data.u8[0] = ENCRYPT;
                        ipc_sync_cmd_data.data_size = (uint8_t)1;

                        sys_ipc(IPC_SEND_SYNC, id_smart, sizeof(struct sync_command), (char*)&ipc_sync_cmd_data);

                        sys_ipc(IPC_RECV_SYNC, &id, &size, (char*)&ipc_sync_cmd_data);
#if CRYPTO_DEBUG
                        printf("===> Key reinjection done!\n");
#endif
                    }
#endif


		    /********* ENCRYPTION LOGIC ************************************************************/
		    /* We have to split our encryption in multiple subencryptions to deal with IV modification on the crypto block size boundaries
		     * boundaries.
		     */
		    if((scsi_block_size == 0) || (sdio_block_size == 0)){
			    printf("Error: DMA WR request while the block sizes have not been read!\n");
			    goto err;
		    }
		    uint32_t num_cryp_blocks = scsi_num_sectors;
		    uint32_t usb_address = shms_tab[ID_USB].address;
		    uint32_t sdio_address = shms_tab[ID_FLASH].address;
		    unsigned int i;
		    /* [RB] FIXME: sanity checks on the USB and SDIO buffer sizes that must be compliant! */
		    for(i = 0; i < num_cryp_blocks; i++){
#ifdef CONFIG_AES256_CBC_ESSIV
                uint8_t curr_essiv_iv[16] = { 0 };
                cbc_essiv_iv_derivation((scsi_sector_address + i), CBC_ESSIV_h_key, 32, curr_essiv_iv, 16);
                cryp_init_user(KEY_256, curr_essiv_iv, 16, AES_CBC, ENCRYPT);
#else
#ifdef CONFIG_TDES_CBC_ESSIV
                uint8_t curr_essiv_iv[8] = { 0 };
                cbc_essiv_iv_derivation((scsi_sector_address + i), CBC_ESSIV_h_key, 24, curr_essiv_iv, 8);
                cryp_init_user(KEY_192, curr_essiv_iv, 8, TDES_CBC, ENCRYPT);
#else
#error "No FDE algorithm has been selected ..."
#endif
#endif
                status_reg.dmaout_done = false;
                cryp_do_dma((const uint8_t *)usb_address, (const uint8_t *)sdio_address, scsi_block_size, dma_in_desc, dma_out_desc);
                while (status_reg.dmaout_done == false){
                    continue;
                }
                cryp_wait_for_emtpy_fifos();
			    usb_address  += scsi_block_size;
			    sdio_address += scsi_block_size;
		    }
		    /****************************************************************************************/
#if CRYPTO_DEBUG
                    printf("[write] CRYP DMA has finished ! %d\n", shms_tab[ID_USB].size);
#endif
                    status_reg.dmaout_done = false;
                    // request DMA transfer to SDIO block device (IPC)


                    sys_ipc(IPC_SEND_SYNC, id_flash, sizeof(struct dataplane_command), (const char*)&sdio_dataplane_command_rw);

                    // wait for SDIO task acknowledge (IPC)
                    sinker = id_flash;
                    ipcsize = sizeof(struct dataplane_command);

                    ret = sys_ipc(IPC_RECV_SYNC, &sinker, &ipcsize, (char*)&dataplane_command_ack);

#if CRYPTO_DEBUG
                    printf("[write] received ipc from sdio (%d)\n", sinker);
#endif
                    // set ack magic for write ack
                    dataplane_command_ack.magic = MAGIC_DATA_WR_DMA_ACK;
                    // acknowledge to USB: data has been written to disk (IPC)
                    sys_ipc(IPC_SEND_SYNC, id_usb, sizeof(struct dataplane_command), (const char*)&dataplane_command_ack);

                    break;
                }


            case MAGIC_DATA_RD_DMA_REQ:
                {
                    /***************************************************
                     * Read mode automaton
                     **************************************************/
                    if (sinker != id_usb) {
                        printf("data rd DMA request command only allowed from USB app\n");
                        continue;
                    }
                    dataplane_command_rw = ipc_mainloop_cmd.dataplane_cmd;

                    cryp_wait_for_emtpy_fifos();
                    // first ask SDIO to load data to its own buffer from the SDCard
                    struct dataplane_command sdio_dataplane_command_rw = dataplane_command_rw;
                    uint32_t scsi_num_sectors = dataplane_command_rw.num_sectors;
                    uint32_t scsi_sector_address = dataplane_command_rw.sector_address;
                    sdio_dataplane_command_rw.num_sectors = (scsi_num_sectors * scsi_block_size) / sdio_block_size;
                    sdio_dataplane_command_rw.sector_address = (dataplane_command_rw.sector_address * scsi_block_size) / sdio_block_size;

                    sys_ipc(IPC_SEND_SYNC, id_flash, sizeof(struct dataplane_command), (const char*)&sdio_dataplane_command_rw);

                    // wait for SDIO task acknowledge (IPC)
                    sinker = id_flash;
                    ipcsize = sizeof(struct dataplane_command);

                    ret = sys_ipc(IPC_RECV_SYNC, &sinker, &ipcsize, (char*)&dataplane_command_ack);

#if CRYPTO_DEBUG
                    printf("[read] received ipc from sdio (%d): data loaded\n", sinker);
#endif

#ifdef CONFIG_AES256_CBC_ESSIV
                    /* Prepare the Key (only for AES) */
                    if (cryp_get_dir() == ENCRYPT) {
                        /* When switching from ENCRYPT to DECRYPT, we only have to prepare the key!
                         * We only have to do the key preparation once when multiple decryptions are done.
                         */
#if CRYPTO_DEBUG
                        printf("[read] Preparing AES key\n");
#endif
                        cryp_set_mode(AES_KEY_PREPARE);
                    }
#endif

		    /********* DECRYPTION LOGIC ************************************************************/
		    /* We have to split our decryption in multiple subdecryptions to deal with IV modification on the crypto block size boundaries
		     * boundaries.
		     */
		    if((scsi_block_size == 0) || (sdio_block_size == 0)){
			    printf("Error: DMA DR request while the block sizes have not been read!\n");
			    goto err;
		    }
		    uint32_t num_cryp_blocks = scsi_num_sectors;
		    uint32_t usb_address = shms_tab[ID_USB].address;
		    uint32_t sdio_address = shms_tab[ID_FLASH].address;
		    unsigned int i;
		    /* [RB] FIXME: sanity checks on the USB and SDIO buffer sizes that must be compliant! */
		    for(i = 0; i < num_cryp_blocks; i++){
#ifdef CONFIG_AES256_CBC_ESSIV
                uint8_t curr_essiv_iv[16] = { 0 };
                cbc_essiv_iv_derivation((scsi_sector_address + i), CBC_ESSIV_h_key, 32, curr_essiv_iv, 16);
                cryp_init_user(KEY_256, curr_essiv_iv, 16, AES_CBC, DECRYPT);
#else
#ifdef CONFIG_TDES_CBC_ESSIV
                uint8_t curr_essiv_iv[8] = { 0 };
                cbc_essiv_iv_derivation((scsi_sector_address + i), CBC_ESSIV_h_key, 24, curr_essiv_iv, 8);
                cryp_init_user(KEY_192, curr_essiv_iv, 8, TDES_CBC, DECRYPT);
#else
#error "No FDE algorithm has been selected ..."
#endif
#endif
			    status_reg.dmaout_done = false;
        	    cryp_do_dma((const uint8_t *)sdio_address, (const uint8_t *)usb_address, scsi_block_size, dma_in_desc, dma_out_desc);
	            while (status_reg.dmaout_done == false){
				    continue;
			    }
                cryp_wait_for_emtpy_fifos();
			    usb_address  += scsi_block_size;
			    sdio_address += scsi_block_size;
		    }
		    /****************************************************************************************/


#if CRYPTO_DEBUG
                    printf("[read] CRYP DMA has finished !\n");
#endif
                    // set ack magic for read ack
                    dataplane_command_ack.magic = MAGIC_DATA_RD_DMA_ACK;

                    // acknowledge to USB: data has been written to disk (IPC)
                    sys_ipc(IPC_SEND_SYNC, id_usb, sizeof(struct dataplane_command), (const char*)&dataplane_command_ack);

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
                    sys_ipc(IPC_SEND_SYNC, id_usb, sizeof(t_ipc_command), (const char*)&ipc_mainloop_cmd);
                    break;

                }
        }

    }

err:
    while (1) {
        sys_yield();
    }
}
