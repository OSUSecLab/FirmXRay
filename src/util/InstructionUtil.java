package util;

import ghidra.program.model.listing.Instruction;

public class InstructionUtil {
    public static StringBuilder insToString(Instruction ins) {

        if (ins == null)
            return null;
        StringBuilder result = new StringBuilder();

        String mnem = ins.getMnemonicString();
        result.append(mnem);
        result.append("\t");

        for (int i=0; i<ins.getNumOperands(); ++i) {
            Object[] operands = ins.getOpObjects(i);
            for(Object ob: operands) {
                result.append(ob.toString());
                result.append(" ");
            }
        }

        // remove last space
        result.substring(0, result.length()-1);
        return result;
    }

    public static String removePostfix(String mnem) {
        // e.g., MOV.W -> MOV
        if (mnem.contains(".")) {
            int index = mnem.indexOf(".");
            mnem = mnem.substring(0, index);
        }
        else if (mnem.endsWith("w")) {
            mnem = mnem.substring(0, mnem.length()-1);
        }

        if (mnem.equals("adds") || mnem.equals("subs") || mnem.equals("ands") || mnem.equals("orrs") || mnem.equals("eors"))
            mnem = mnem.substring(0, mnem.length() - 1);

        return mnem;
    }

    public static boolean isBranchInstruction(String mnem) {
        mnem = InstructionUtil.removePostfix(mnem);
        if (!mnem.startsWith("b"))
            return false;
        if (mnem.equals("bic") || mnem.equals("bfc") || mnem.equals("bfi"))
            return false;
        return true;
    }

    public static boolean isBXInstruction(String mnem) {
        mnem = InstructionUtil.removePostfix(mnem);
        return mnem.startsWith("bx") || mnem.startsWith("blx");
    }

    public static boolean isLDRInstruction(String mnem) {
        mnem = InstructionUtil.removePostfix(mnem);
        if (mnem.equals("ldr"))
            return true;
        else if (mnem.equals("ldrb"))
            return true;
        else if (mnem.equals("ldrh"))
            return true;
        else if (mnem.equals("ldmia"))
            return true;
        else
            return false;
    }

    public static boolean isADRInstruction(String mnem) {
        mnem = InstructionUtil.removePostfix(mnem);
        if (mnem.equals("adr"))
            return true;
        return false;
    }

    public static boolean isSTRInstruction(String mnem) {
        mnem = InstructionUtil.removePostfix(mnem);
        if (mnem.equals("str"))
            return true;
        else if (mnem.equals("strb"))
            return true;
        else if (mnem.equals("strh"))
            return true;
        else
            return false;
    }

    public static boolean isMultipleSTRInstruction(String mnem) {
        mnem = InstructionUtil.removePostfix(mnem);
        if (mnem.equals("stmia"))
            return true;
        else if (mnem.equals("stm"))
            return true;
        else
            return false;
    }
}
