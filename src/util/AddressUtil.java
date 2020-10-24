package util;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;

import java.util.HashMap;

public class AddressUtil {

    private static AddressUtil addressBook; // singleton
    private HashMap<Long, Address> addressMap;

    private AddressUtil() {}

    public static AddressUtil getInstance() {
        return addressBook;
    }

    public static void init(Program program) {
        if (addressBook != null) {
            return;
        }
        addressBook = new AddressUtil();
        addressBook.addressMap = new HashMap<>();
        for (Address a: program.getMemory().getAddresses(true)) {
            addressBook.addressMap.put(a.getUnsignedOffset(), a);
        }
    }

    public static Address lookupAddress(long address, Program program) {
        if (address < program.getMinAddress().getUnsignedOffset())
            return null;
        else if (address > program.getMaxAddress().getUnsignedOffset())
            return null;

        Address newAdd = program.getAddressMap().getImageBase().getNewAddress(address);
        return newAdd;

    }

}
