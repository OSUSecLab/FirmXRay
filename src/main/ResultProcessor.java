package main;

import core.ExecutionEngine;
import core.STRInsSolver;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.util.DataConverter;
import org.json.JSONObject;
import util.AddressUtil;
import util.FunctionUtil;
import util.InstructionUtil;
import util.NumUtil;

import java.util.List;

public class ResultProcessor {

    public static JSONObject ProcessResult(Program program, int api, ExecutionEngine engine) {
        JSONObject results = new JSONObject();

        // check if solved
        List<String> targetVarSet = Constant.getInitialTargetVars(api);
        JSONObject values = new JSONObject();

        switch (api) {

            // Nordic
            case Constant.SD_BLE_GAP_SEC_PARAMS_REPLY:
                for(String target: targetVarSet) {
                    if (target.equals("r1")) {
                        long val = engine.registers.get("r0");
                        values.put(target, val);
                    }
                    else {
                        long regVal = engine.registers.get(target);
                        values.put(target, regVal);
                        long val = readByteFromMemory(program, engine, regVal, 1);
                        values.put("sec_params", val);
                    }
                }
                break;


            case Constant.SD_BLE_GAP_AUTH:
                for(String target: targetVarSet) {
                    long regVal = engine.registers.get(target);
                    values.put(target, regVal);
                    long val = readByteFromMemory(program, engine, regVal, 1);
                    values.put("sec_params", val);
                }
                break;

            case Constant.SD_BLE_GAP_LESC_DHKEY_REPLY:
                break;

            case Constant.SD_BLE_GAP_ADDR_SET:
                for(String target: targetVarSet) {
                    long val = readIntRegister(program, engine, target);

                    if (engine.solved) {
                        for (int i = 0; i < 6; ++i) {
                            long v = readByteFromMemory(program, engine, val + i, 1);
                            values.put("" + i, v);
                        }
                    }

                    values.put(target, val);
                }
                break;

            case Constant.SD_BLE_GAP_APPEARANCE_SET:
                for(String target: targetVarSet) {
                    long val = engine.registers.get(target);
                    engine.solved = true;
                    values.put(target, val);
                }
                break;

            case Constant.SD_BLE_GAP_DEVICE_NAME_SET:
                for(String target: targetVarSet) {
                    String val = readStringNordic(program, engine, target);
                    values.put(target, val);
                }
                break;

            case Constant.SD_BLE_GAP_ENCRYPT:
                for(String target: targetVarSet) {
                    long val = readIntRegister(program, engine, target);
                    if (engine.solved) {
                        for (int i = 0; i < 16; ++i) {
                            long key = readIntFromMemory(program, engine, val + i);
                            values.put("" + i, key);
                        }
                    }
                    values.put(target, val);
                }
                break;

            case Constant.SD_BLE_GAP_AUTH_KEY_REPLY:
                for(String target: targetVarSet) {
                    if (target.equals("r1")) {
                        long val = engine.registers.get(target);
                        engine.solved = true;
                        values.put(target, val);
                    }
                    else {
                        // r2
                        long val = readIntRegister(program, engine, target);
                        values.put(target, val);
                    }
                }
                break;

            case Constant.SD_BLE_GAP_DEVICE_IDENTITIES_SET:
                for(String target: targetVarSet) {
                    long val = readIntRegister(program, engine, target);
                    values.put(target, val);
                }
                break;

            case Constant.SD_BLE_PRIVACY_SET:
                for(String target: targetVarSet) {
                    long val = readIntRegister(program, engine, target);
                    values.put(target, val);
                    if (target.equals("r0")) {
                        long privacyStructAdd = engine.registers.get("r0");
                        if (engine.solved) {
                            long privacyMode = val;
                            values.put("PrivacyMode", privacyMode);

                            long privateAddType = readIntFromMemory(program, engine, privacyStructAdd + 1);
                            values.put("PrivateAddrType", privateAddType);

                            long privateAddrCycle = readIntFromMemory(program, engine, privacyStructAdd + 2);
                            values.put("PrivateAddrCycle", privateAddrCycle);

                            long irkAddr = readIntFromMemory(program, engine, privacyStructAdd + 4);
                            values.put("IRKAddr", irkAddr);

                            for (int i=0; i<16; ++i) {
                                long key = readIntFromMemory(program, engine, irkAddr + i);
                                values.put("" + i, key);
                            }

                        }
                    }
                }
                break;

            case Constant.SD_BLE_GAP_KEYPRESS_NOTIFY:
                break;

            case Constant.SD_BLE_GAP_LESC_OOB_DATA_SET:
                break;

            case Constant.BLE_GAP_EVT_KEY_PRESSED:
                break;

            case Constant.SD_BLE_OPT_SET:
                for(String target: targetVarSet) {
                    if (target.equals("r0")) {
                        long val = engine.registers.get(target);
                        engine.solved = true;
                        values.put(target, val);
                    }
                    else {
                        // r1
                        long val = readIntRegister(program, engine, target);
                        if (engine.solved) {
                            long keyStructVal = readIntFromMemory(program, engine, val + 4);
                            values.put("OptStruct", keyStructVal);
                        }
                        values.put(target, val);
                    }
                }
                break;

            case Constant.BLE_GAP_EVT_PASSKEY_DISPLAY:
                break;

            case Constant.BLE_GAP_EVT_AUTH_KEY_REQUEST:
                break;

            case Constant.SD_BLE_GATTS_SERVICE_ADD:
                for(String target: targetVarSet) {
                    if (target.equals("r0")) {
                        long val = engine.registers.get(target);
                        engine.solved = true;
                        values.put(target, val);
                    }
                    else {
                        // r1
                        long regVal = engine.registers.get(target);
                        values.put(target, regVal);
                        long val = readByteFromMemory(program, engine, regVal, 2);
                        values.put("UUID", val);
                    }
                }
                break;

            case Constant.SD_BLE_GATTS_CHARACTERISTIC_ADD:
                for(String target: targetVarSet) {
                    // long val = readIntRegister(program, engine, target);
                    long attrStructAdd = engine.registers.get(target);

                    long uuidStructAdd = readIntFromMemory(program, engine, attrStructAdd);
                    long uuid = readByteFromMemory(program, engine, uuidStructAdd, 2);
                    values.put("uuid", uuid);
                    long type = readByteFromMemory(program, engine, uuidStructAdd+2, 1);
                    values.put("type", type);

                    long pAttrStrcutAdd = readIntFromMemory(program, engine,attrStructAdd + 4);
                    long readPerm = readByteFromMemory(program, engine, pAttrStrcutAdd, 1);
                    values.put("readperm", readPerm);

                    long writePerm = readByteFromMemory(program, engine, pAttrStrcutAdd + 1, 1);
                    values.put("writePerm", writePerm);

                    values.put(target, attrStructAdd);
                }
                break;

            case Constant.SD_BLE_GAP_WHITELIST_SET:
                for(String target: targetVarSet) {
                    long val = readIntRegister(program, engine, target);
                    if (engine.solved) {
                        for (int i = 0; i < 6; ++i) {
                            long v = readIntFromMemory(program, engine, val + i);
                            values.put("" + i, v);
                        }
                    }

                    values.put(target, val);

                }
                break;

            case Constant.SD_BLE_UUID_VS_ADD:
                for(String target: targetVarSet) {
                    long val = readIntRegister(program, engine, target);
                    long regVal = engine.registers.get(target);

                    if (engine.solved) {
                        for (int i = 0; i < 4; ++i) {
                            values.put(i + "", readIntFromMemory(program, engine, regVal + i*4));
                        }
                    }
                    // values.put(target, val);
                }
                break;


            // TI

            case Constant.TI_BONDING:
            case Constant.TI_IO_REQ:
            case Constant.TI_LESC_CONN:
            case Constant.TI_MITM_REQ:
            case Constant.TI_PAIRING_MODE:
                for (String target: targetVarSet) {
                    if (target.equals("r0")) {
                        long val = readIntRegister(program, engine, target);
                        long regVal = engine.registers.get(target);

                        values.put(target, val);
                    }
                    break;
                }
                break;

            case Constant.TI_DEVICE_ADDR:
                for (String target: targetVarSet) {
                    if (target.equals("r0")) {
                        long val = readIntRegister(program, engine, target);
                        if (!engine.solved) {
                            // not solved, continue to find r2
                            Address current = engine.path.getFirstIns().getAddress();
                            while (current.getUnsignedOffset() <= FunctionUtil.findFunctionWithAddress(program, current).getBody().getMaxAddress().getUnsignedOffset()) {
                                Instruction ins = program.getListing().getInstructionAt(current);
                                String mnem = InstructionUtil.removePostfix(ins.getMnemonicString());
                                if (ins.toString().contains("r2") || InstructionUtil.isSTRInstruction(mnem)) {
                                    engine.executeInst(ins);
                                    val = readIntRegister(program, engine, target);
                                    if (engine.solved)
                                        break;
                                }
                                current = current.next();
                            }
                        }

                        values.put(target, val);
                    }
                    break;
                }
                break;

            case Constant.TI_REGISTER_SERVICE:
                for (String target: targetVarSet) {
                    if (target.equals("r2")) {
                        long val = engine.registers.get("r2");
                        // long val = readIntRegister(program, engine, target);
                        engine.solved = true;
                        values.put(target, val);
                    }
                    break;
                }
                break;


            default:
                break;
        }

        results.put("Solved", engine.solved);
        results.put("Values", values);
        return results;
    }

    public static long readIntFromMemory(Program program, ExecutionEngine engine, long val) {
        return readByteFromMemory(program, engine, val, 4);
    }

    public static long readByteFromMemory(Program program, ExecutionEngine engine, long val, int numByte) {
        if (engine.memory.keySet().contains(val)) {  // search in execution engine memory
            engine.solved = true;
            return engine.memory.get(val);
        }
        else {
            try {
                // search in program memory
                Address address = AddressUtil.lookupAddress(val, program);
                if (address != null) {
                    long result = program.getMemory().getInt(address);
                    if (result < 0) {
                        // overflow
                        byte[] bytes = new byte[8];
                        int len = program.getMemory().getBytes(address, bytes, 0, numByte);
                        result = DataConverter.getInstance(false).getLong(bytes);
                    }
                    return result;

                } else {
                    // not found in memory
                    // search in solved STR instructions
                    if (STRInsSolver.AddSTRMap.keySet().contains(val)) {
                        engine.solved = true;
                        return STRInsSolver.getValueFromMap(val, numByte);
                    } else {
                        // value not found
                        engine.solved = false;
                        return val;
                    }
                }

            } catch (MemoryAccessException e) {
                // not found in memory
                // search in solved STR instructions
                if (STRInsSolver.AddSTRMap.keySet().contains(val)) {
                    engine.solved = true;
                    return STRInsSolver.getValueFromMap(val, numByte);
                } else {
                    // value not found
                    engine.solved = false;
                    return val;
                }
            }
        }

    }


    public static long readIntRegister(Program program, ExecutionEngine engine, String target) {
        long val = engine.registers.get(target);
        if (val == 0) {
            engine.solved = true;
            return 0;
        }
        else {
            if (engine.memory.keySet().contains(val)) {  // search in execution engine memory
                engine.solved = true;
                return engine.memory.get(val);
            }
            else {
                try {
                    // search in program memory
                    Address address = AddressUtil.lookupAddress(val, program);
                    if (address != null) {
                        long result = program.getMemory().getInt(address);
                        return result;

                    } else {
                        // not found in memory
                        // search in solved STR instructions
                        if (STRInsSolver.AddSTRMap.keySet().contains(val)) {
                            engine.solved = true;
                            return STRInsSolver.getValueFromMap(val, 4);
                        } else {
                            // value not found
                            engine.solved = false;
                            return val;
                        }
                    }

                } catch (MemoryAccessException e) {
                    // not found in memory
                    // search in solved STR instructions
                    if (STRInsSolver.AddSTRMap.keySet().contains(val)) {
                        engine.solved = true;
                        return STRInsSolver.getValueFromMap(val, 4);
                    } else {
                        // value not found
                        engine.solved = false;
                        return val;
                    }
                }
            }
        }
    }

    public static String readStringNordic(Program program, ExecutionEngine engine, String target) {
        long val = engine.registers.get(target);
        String result = "";
        if (val == 0) {
            engine.solved = true;
            return result;
        }
        else {
            if (engine.memory.keySet().contains(val)) {  // search in execution engine memory
                engine.solved = true;
                result = engine.memory.get(val) + "";
                return result;
            }
            else {
                // search in program memory
                Address address = AddressUtil.lookupAddress(val, program);
                if (address != null) {
                    try {
                        result = program.getListing().getDataAt(address).getValue().toString();
                        engine.solved = true;
                    } catch (Exception e) {
                        result = "";
                    }

                    return result;
                }
                else {
                    // not found in memory
                    // search in solved STR instructions
                    if (STRInsSolver.AddSTRMap.keySet().contains(val)) {
                        engine.solved = true;
                        int[] bytes = NumUtil.LongToByteLittleEndian(STRInsSolver.getValueFromMap(val, 4));
                        String str = new String(bytes.toString());
                        return str + "";
                    } else {
                        // value not found
                        engine.solved = false;
                        return result;
                    }
                }
            }
        }
    }


}
