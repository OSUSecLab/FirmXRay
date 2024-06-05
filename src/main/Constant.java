package main;

import java.util.ArrayList;
import java.util.List;

public class Constant {

    // config
    public final static String DIRECTORY_NAME = "/usr/local";
    public final static int MAX_CYCLE_DIVE = 20;
    public final static int MAX_ITERATION = 3;
    public final static int TIMEOUT = 50000;
    public final static int DISASSEMBLE_TIMEOUT = 30;
    public final static int MAX_PATH_COUNT = 30;
    public final static int THRESHOLD = 0x1000;
    public final static int MAX_BASE = Integer.MAX_VALUE;
    public final static int MIN_BASE = -1;
    public final static int STEP = 0x1000;
    public static String MCU;

    // Nordic
    public final static int SD_BLE_GAP_AUTH = 0x7e;
    public final static int BLE_GAP_EVT_SEC_PARAMS_REQ = 0x13;
    public final static int SD_BLE_GAP_ADDR_SET = 0x6c;
    public final static int SD_BLE_GAP_SEC_PARAMS_REPLY = 0x7f;
    public final static int SD_BLE_GAP_LESC_DHKEY_REPLY = 0x81;
    public final static int SD_BLE_GAP_DEVICE_NAME_SET = 0x7c;
    public final static int SD_BLE_OPT_SET = 0x68;
    public final static int SD_BLE_PRIVACY_SET = 0x70;
    public final static int SD_BLE_GAP_WHITELIST_SET = 0x6e;
    public final static int SD_BLE_VERSION_GET = 0x66;
    public final static int SD_BLE_GAP_APPEARANCE_SET = 0x78;
    public final static int SD_BLE_GAP_ENCRYPT = 0x85;
    public final static int SD_BLE_GAP_AUTH_KEY_REPLY = 0x80;
    public final static int SD_BLE_GAP_DEVICE_IDENTITIES_SET = 0x6f;
    public final static int SD_BLE_GAP_KEYPRESS_NOTIFY = 0x82;
    public final static int SD_BLE_GAP_LESC_OOB_DATA_SET = 0x84;
    public final static int BLE_GAP_EVT_PASSKEY_DISPLAY = 0x15;
    public final static int BLE_GAP_EVT_KEY_PRESSED = 0x16;
    public final static int BLE_GAP_EVT_AUTH_KEY_REQUEST = 0x17;
    public final static int SD_BLE_GATTS_SERVICE_ADD = 0xa0;
    public final static int SD_BLE_GATTS_CHARACTERISTIC_ADD = 0xa2;
    public final static int SD_BLE_UUID_VS_ADD = 0x63;


    public final static List<Integer> NORDIC_FUNCTIONS = new ArrayList<>(List.of(SD_BLE_GAP_AUTH, SD_BLE_GAP_ADDR_SET,
            SD_BLE_GAP_SEC_PARAMS_REPLY, SD_BLE_GAP_LESC_DHKEY_REPLY, SD_BLE_GAP_APPEARANCE_SET, SD_BLE_GAP_AUTH_KEY_REPLY,
            SD_BLE_GATTS_SERVICE_ADD, SD_BLE_GATTS_CHARACTERISTIC_ADD, SD_BLE_UUID_VS_ADD));


    // TI
    public final static int TI_PAIRING_MODE = 0x400;
    public final static int TI_MITM_REQ = 0x402;
    public final static int TI_IO_REQ = 0x403;
    public final static int TI_BONDING = 0x406;
    public final static int TI_LESC_CONN = 0x411;
    public final static int TI_DEVICE_ADDR = 0x89;
    public final static int TI_REGISTER_SERVICE = 0xca;

    public final static List<Integer> TI_FUNCTIONS = new ArrayList<>(List.of(TI_PAIRING_MODE, TI_MITM_REQ, TI_IO_REQ,
            TI_BONDING, TI_LESC_CONN, TI_DEVICE_ADDR, TI_REGISTER_SERVICE));


    // Base address
    public final static String ARM_CORTEX_LE_32 = "ARM:LE:32:Cortex";

    // machine code
    public final static byte PUSH = (byte) 0xB5;
    public final static byte STMFD1 = (byte) 0x2D;
    public final static byte STMFD2 = (byte) 0xE9;
    public final static byte E7 = (byte) 0xE7;

    public final static byte PUSH2 = (byte) 0xB4;
    public final static byte E0 = (byte) 0xE0;


    public static List<String> getInitialTargetVars(int api) {
        // return new ArrayList<>(List.of("r2", "sp"));
        switch (api) {
            // NORDIC
            case SD_BLE_GAP_SEC_PARAMS_REPLY:
                return new ArrayList<>(List.of("r1", "r2"));
            case SD_BLE_GAP_AUTH:
                return new ArrayList<>(List.of("r1"));
            case SD_BLE_GAP_ADDR_SET:
                return new ArrayList<>(List.of("r0"));
            case SD_BLE_GAP_LESC_DHKEY_REPLY:
                return null;
            case SD_BLE_GAP_APPEARANCE_SET:
                return new ArrayList<>(List.of("r0"));
            case SD_BLE_GAP_DEVICE_NAME_SET:
                return new ArrayList<>(List.of("r1"));
            case SD_BLE_GAP_ENCRYPT:
                return new ArrayList<>(List.of("r2"));
            case SD_BLE_GAP_AUTH_KEY_REPLY:
                return new ArrayList<>(List.of("r1", "r2"));
            case SD_BLE_GAP_DEVICE_IDENTITIES_SET:
                return new ArrayList<>(List.of("r0", "r1"));
            case SD_BLE_PRIVACY_SET:
                return new ArrayList<>(List.of("r0", "r1"));
            case SD_BLE_GAP_KEYPRESS_NOTIFY:
                return null;
            case SD_BLE_GAP_LESC_OOB_DATA_SET:
                return null;
            case SD_BLE_OPT_SET:
                return new ArrayList<>(List.of("r0", "r1"));
            case BLE_GAP_EVT_PASSKEY_DISPLAY:
                return null;
            case BLE_GAP_EVT_AUTH_KEY_REQUEST:
                return null;
            case BLE_GAP_EVT_KEY_PRESSED:
                return null;
            case SD_BLE_GATTS_SERVICE_ADD:
                return new ArrayList<>(List.of("r0", "r1"));
            case SD_BLE_GATTS_CHARACTERISTIC_ADD:
                return new ArrayList<>(List.of("r2"));
            case SD_BLE_GAP_WHITELIST_SET:
                return new ArrayList<>(List.of("r1"));
            case SD_BLE_UUID_VS_ADD:
                return new ArrayList<>(List.of("r0"));
            // TI
            case TI_BONDING:
            case TI_IO_REQ:
            case TI_LESC_CONN:
            case TI_MITM_REQ:
            case TI_PAIRING_MODE:
                return new ArrayList<>(List.of("r0"));

            case TI_DEVICE_ADDR:
            case TI_REGISTER_SERVICE:
                return new ArrayList<>(List.of("r2"));




        }
        return null;
    }

}
