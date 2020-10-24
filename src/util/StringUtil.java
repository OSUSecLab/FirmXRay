package util;

import ghidra.program.model.address.Address;
import ghidra.program.model.correlate.Hash;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.DataIterator;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryAccessException;
import main.Constant;

import java.util.HashMap;
import java.util.Map;

public class StringUtil {

    public static Map<Address, String> getString(Program program) {
        Map<Address, String> strs = new HashMap<>();
        DataIterator dataIterator = program.getListing().getDefinedData(true);
        while (dataIterator.hasNext()) {
            Data data = dataIterator.next();
            if (data.getDataType().toString().equals("string")) {
                strs.put(data.getAddress(), data.toString());
            }
        }
        return strs;
    }

    public static Map<Address, Long> getVector(Program program) {

        Address current = program.getMinAddress();
        Map<Address, Long> results = new HashMap<>();
        long size = FunctionUtil.getAllFunctions(program).next().getEntryPoint().getUnsignedOffset();
        while (current.getUnsignedOffset() < size) {
            try {
                long val = program.getMemory().getInt(current);
                if (val < Constant.MAX_BASE && val > 0)
                    results.put(current, val);
            }
            catch (MemoryAccessException e) {}
            current = current.add(4);
        }

        return results;
    }

    public static String getAPIName(int api) {
        switch (api) {
            case Constant.SD_BLE_GAP_ADDR_SET:
                return "SD_BLE_GAP_ADDR_SET";
            case Constant.SD_BLE_GAP_APPEARANCE_SET:
                return "SD_BLE_GAP_APPEARANCE_SET";
            case Constant.SD_BLE_GAP_AUTH:
                return "SD_BLE_GAP_AUTH";
            case Constant.SD_BLE_GAP_AUTH_KEY_REPLY:
                return "SD_BLE_GAP_AUTH_KEY_REPLY";
            case Constant.SD_BLE_GAP_LESC_DHKEY_REPLY:
                return "SD_BLE_GAP_LESC_DHKEY_REPLY";
            case Constant.SD_BLE_GAP_SEC_PARAMS_REPLY:
                return "SD_BLE_GAP_SEC_PARAMS_REPLY";
            case Constant.SD_BLE_GATTS_CHARACTERISTIC_ADD:
                return "SD_BLE_GATTS_CHARACTERISTIC_ADD";
            case Constant.SD_BLE_GATTS_SERVICE_ADD:
                return "SD_BLE_GATTS_SERVICE_ADD";
            case Constant.SD_BLE_UUID_VS_ADD:
                return "SD_BLE_UUID_VS_ADD";
            case Constant.TI_BONDING:
                return "GAPBondMgr_SetParameter(Bonding)";
            case Constant.TI_IO_REQ:
                return "GAPBondMgr_SetParameter(IO)";
            case Constant.TI_LESC_CONN:
                return "GAPBondMgr_SetParameter(LESC)";
            case Constant.TI_MITM_REQ:
                return "GAPBondMgr_SetParameter(MITM)";
            case Constant.TI_PAIRING_MODE:
                return "GAPBondMgr_SetParameter(Pairing mode)";
            case Constant.TI_DEVICE_ADDR:
                return "GAP_ConfigDeviceAddr";
            case Constant.TI_REGISTER_SERVICE:
                return "GATTServApp_RegisterService";
            default:
                return "";
        }
    }

}
