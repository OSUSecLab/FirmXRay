package util;

import ghidra.program.model.address.Address;
import ghidra.program.model.block.*;
import ghidra.program.model.correlate.Block;
import ghidra.program.model.listing.Program;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import main.Constant;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;

public class BlockUtil {

    public static StringBuilder blockToString(CodeBlock b) {
        StringBuilder r = new StringBuilder();
        r.append(b.getName());
        r.append("\t");
        r.append(b.getFirstStartAddress());
        return r;
    }

    public static CodeBlock[] locateBlockWithAddress(Program program, Address address) {
        BasicBlockModel basicBlockModel = new BasicBlockModel(program);
        try {
            CodeBlock[] codeBlocks = basicBlockModel.getCodeBlocksContaining(address, TaskMonitor.DUMMY);
            return codeBlocks;
        } catch (CancelledException e) {
            return null;
        }
    }

    /**
     * Get parent blocks of the current block
     */
    public static List<CodeBlockReference> getPreviousBlocks(CodeBlock codeBlock) {
        List<CodeBlockReference> result = new ArrayList<>();
        try {
            CodeBlockReferenceIterator codeBlockReferenceSourcesIterator = codeBlock.getSources(TaskMonitor.DUMMY);
            while (codeBlockReferenceSourcesIterator.hasNext()) {
                CodeBlockReference codeBlockReference = codeBlockReferenceSourcesIterator.next();
                // CodeBlock codeBlockSource = codeBlockReference.getSourceBlock();
                result.add(codeBlockReference);
            }
            return result;
        } catch (CancelledException e) {
            return null;
        }
    }

    /**
     * Get descendent blocks of the current block
     */
    public static List<CodeBlockReference> getDescentdentBlocks(CodeBlock codeBlock) {
        List<CodeBlockReference> result = new ArrayList<>();
        try {
            CodeBlockReferenceIterator codeBlockReferenceDestsIterator = codeBlock.getDestinations(TaskMonitor.DUMMY);
            while (codeBlockReferenceDestsIterator.hasNext()) {
                CodeBlockReference codeBlockReference = codeBlockReferenceDestsIterator.next();
                // CodeBlock codeBlockDest = codeBlockReference.getDestinationBlock();
                result.add(codeBlockReference);
            }
            return result;
        } catch (CancelledException e) {
            return null;
        }
    }

    /**
     * Determine whether the transfer to next block will lead to cycle visit
     * @param current current block
     * @param next next block to transfer
     * @return is cycle
     */
    public static boolean isCycle(CodeBlock current, CodeBlock next, HashSet<Integer> history) {

        /*
        if (history.contains(current.hashCode()) || history.contains(next.hashCode())) // cycle visit occurs
            return true;
        else if (history.size() >= Constant.MAX_CYCLE_DIVE)
            return true;

        // visit this block
        history.add(next.hashCode());

        // visit previous blocks
        List<CodeBlockReference> cbrs = getPreviousBlocks(next);
        if (cbrs == null || cbrs.size() == 0) // reach the end
            return false;

        boolean result = true;
        for (CodeBlockReference b: cbrs) {
            if (b.getSourceAddress().hashCode() == current.hashCode())
                return true;
            else
                result &= isCycle(current, b.getSourceBlock(), (HashSet<Integer>) history.clone());
            if (!result)
                return result;
        }

        return result;
        */


//        if (history.contains(next.hashCode()))
//            return false;
//        else if (history.size() >= Constant.MAX_CYCLE_DIVE)
//            return true;
//
//        boolean result = false;
//        history.add(next.hashCode());
//        for (CodeBlockReference b: getPreviousBlocks(next)) {
//            if (b.getSourceAddress().hashCode() == current.hashCode())
//                return true;
//            else
//                result |= isCycle(current, b.getSourceBlock(), history);
//            if (result)
//                return result;
//        }
//        history.remove(next.hashCode());
//        return result;
//


        if (history.contains(next.hashCode()))
            return true;
        else if (history.size() >= Constant.MAX_CYCLE_DIVE)
            return false;

        boolean result = true;
        history.add(next.hashCode());

        List<CodeBlockReference> cbrs = getPreviousBlocks(next);
        if (cbrs == null || cbrs.size() == 0)
            return false;

        for (CodeBlockReference b: cbrs) {
            if (b.getSourceAddress().hashCode() == next.hashCode()) // block visit itself
                return true;
            else
                result &= isCycle(next, b.getSourceBlock(), history);
            if (!result)
                return result;
        }
        history.remove(current.hashCode());
        return result;


    }
}
