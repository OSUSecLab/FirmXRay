/**
    Example code developed based on the Nordic SoftDevice SDK, used for testing purpose only.
**/

#include <nrf.h>
#include <stdint.h>
#include <ble_gap.h>
#include <ble.h>


#define SEC_PARAM_TIMEOUT               30                                          /**< Timeout for Pairing Request or Security Request (in seconds). */
#define SEC_PARAM_BOND                  1                                           /**< Perform bonding. */
#define SEC_PARAM_MITM                  0                                           /**< Man In The Middle protection */
#define SEC_PARAM_IO_CAPABILITIES       BLE_GAP_IO_CAPS_KEYBOARD_DISPLAY            /**< I/O capabilities. */
#define SEC_PARAM_OOB                   1                                           /**< Out Of Band */
#define SEC_PARAM_MIN_KEY_SIZE          7                                           /**< Minimum encryption key size. */
#define SEC_PARAM_MAX_KEY_SIZE          16                                          /**< Maximum encryption key size. */
#define BLE_CONN_HANDLE_INVALID         0xFFFF
#define DEVICE_NAME                     "Nordic_CGMS"                               /**< Name of device. Will be included in the advertising data. */


static ble_gap_sec_params_t             m_sec_params;                               /**< Security requirements for this application. */
static ble_gap_addr_t add;
static uint16_t                         m_conn_handle = BLE_CONN_HANDLE_INVALID;    /**< Handle of the current connection. */
static ble_gap_conn_params_t            gap_conn_params;



/* Initialize security parameters */
static void sec_params_init(void)
{
    m_sec_params.bond         = SEC_PARAM_BOND;
    m_sec_params.mitm         = SEC_PARAM_MITM;
    m_sec_params.lesc		  = 1;
    m_sec_params.keypress	  = 1;
    m_sec_params.io_caps      = SEC_PARAM_IO_CAPABILITIES;
    m_sec_params.oob          = SEC_PARAM_OOB;  
    m_sec_params.min_key_size = SEC_PARAM_MIN_KEY_SIZE;
    m_sec_params.max_key_size = SEC_PARAM_MAX_KEY_SIZE;
}


int main(void)
{
  sec_params_init();

  /* Exchange security parameters during pairing */
  uint32_t                err_code;
  err_code = sd_ble_gap_sec_params_reply(m_conn_handle, BLE_GAP_SEC_STATUS_SUCCESS, &m_sec_params, 0);


  /* Configure advertised address */
  add.addr_type = BLE_GAP_ADDR_TYPE_RANDOM_STATIC;
  add.addr[0] = 0x11;
  add.addr[1] = 0x22;
  add.addr[2] = 0x33;
  add.addr[3] = 0x44;
  add.addr[4] = 0x55;
  add.addr[5] = 0x66;

  err_code = sd_ble_gap_address_set(BLE_GAP_ADDR_CYCLE_MODE_NONE, &add);

  ble_gap_conn_sec_mode_t sec_mode;
  err_code = sd_ble_gap_device_name_set(&sec_mode,
                                          (const uint8_t *)DEVICE_NAME,
                                          strlen(DEVICE_NAME));


  /* Add Service */
  ble_uuid_t ble_uuid_s;
  ble_uuid_s.uuid = 0xFFF0;
  ble_uuid_s.type = 0x01;  
  uint16_t h;

  sd_ble_gatts_service_add(0, &ble_uuid_s, &h);


  /* Add UUID Base */
  ble_uuid128_t bds_base_uuid = {{0xD0, 0x70, 0x1F, 0x19, 0x94, 0xB8, 0xF2, 0x86, 0xF5, 0x4A, 0xF5, 0xFF, 0x00, 0x00, 0x84, 0x56}};
  uint8_t uuid_type = 1;
  err_code = sd_ble_uuid_vs_add(&bds_base_uuid, &uuid_type);



  /* Add Charateristic */
  ble_gatts_attr_md_t attr_md;

  ble_gap_conn_sec_mode_t read_p;
  read_p.sm = 2;
  read_p.lv = 2;

  ble_gap_conn_sec_mode_t write_p;
  write_p.sm = 1;
  write_p.lv = 3;

  attr_md.read_perm  = read_p;
  attr_md.write_perm = write_p;
  attr_md.vloc       = BLE_GATTS_VLOC_USER;
  attr_md.rd_auth    = 0;
  attr_md.wr_auth    = 0;
  attr_md.vlen       = 1;

  ble_gatts_attr_t attr_char_value;

  ble_uuid_t ble_uuid;
  ble_uuid.uuid = 0xFFFF;
  ble_uuid.type = 0x02;

  attr_char_value.p_uuid    = &ble_uuid;
  attr_char_value.p_attr_md = &attr_md;
  attr_char_value.init_len  = 1;
  attr_char_value.init_offs = 0;
  attr_char_value.max_len   = 20;
  uint8_t p_val = 1;
  attr_char_value.p_value   = &p_val;

  ble_gatts_char_handles_t handle;

  ble_gatts_char_md_t const md;

  sd_ble_gatts_characteristic_add(0,
                                         &md,
                                         &attr_char_value,
                                         &handle);


  /* Invoke LESC dhkey reply */
  ble_gap_lesc_dhkey_t const* p_dhkey;
  sd_ble_gap_lesc_dhkey_reply(0, &p_dhkey);



  /* Set device appearance */
  sd_ble_gap_appearance_set(BLE_APPEARANCE_GENERIC_HEART_RATE_SENSOR);
}



