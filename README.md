# FirmXRay

A static analysis tool based on [Ghidra](https://ghidra-sre.org/) to detect Bluetooth link layer vulnerabilities from bare-metal firmware.
As proof-of-concept, the current implementation supports firmware (ARM Cortex-M Architecture) developed based on Nordic and TI SDKs (i.e., [SoftDevice](https://infocenter.nordicsemi.com/topic/struct_nrf52/struct/nrf52_softdevices.html?cp=4_5) and [BLE-Stack](https://www.ti.com/tool/BLE-STACK)).

The three main components of FirmXRay are:
 - (1) **Base address recognition**. It can automatically infer the firmware base address using the point-to relation heuristics. The output result will be in ./base/base.txt.
 - (2) **Backward slicing**. FirmXRay will start from the SDK APIs and backward extract the relevant program paths.
 - (3) **Static value computation**. FirmXRay can statically execute ARM instructions to compute the configuration values from the program slices.

For more details, please refer to our paper [FirmXRay: Detecting Bluetooth Link Layer Vulnerabilities From Bare-Metal Firmware](http://web.cse.ohio-state.edu/~wen.423/papers/ccs20_FirmXRay).

## How to run it

FirmXRay is written in Java, and the only dependency is a compiled Ghidra .jar library. To compile such a jar file on your own, please download the Ghidra project and use their build script ([How to do it](https://ghidra-sre.org/InstallationGuide.html#RunJar)).

After the file is sucessfully created, please make sure it locates under **./lib** and is named as **ghidra.jar**.

Next, you can compile the project by simply

```
make
```

Try to run it with

```
make run PATH=<FIRMWARE_PATH> MCU=<Nordic/TI>
```

You can try our running example with

```
make run PATH=examples/Nordic/example_nordic.bin MCU=Nordic
```


## Running Example 

**example_nordic.bin** is a Nordic-based firmware compiled from [main.c](https://github.com/OSUSecLab/FirmXRay/blob/master/examples/Nordic/main.c).
The firmware code invokes several SDK APIs to configure the BLE pairing feature, services, characteristics, and so on.

After running FirmXRay on the above example, you can get the following results saved in ./output

```
{
    "Path": 5,
    "Size": 4475,
    "Time": 12729,
    "Vendor": "Nordic",
    "Base": "00000000",

    "SD_BLE_GAP_SEC_PARAMS_REPLY": [{
        "Solved": true,
        "Values": {
            "r2": 536872044,
            "sec_params": 205,
            "r1": 0
        }
    }],

    "SD_BLE_GATTS_CHARACTERISTIC_ADD": [{
        "Solved": true,
        "Values": {
            "r2": 536937820,
            "readperm": 34,
            "writePerm": 49,
            "type": 2,
            "uuid": 65535
        }
    }],

    "SD_BLE_UUID_VS_ADD": [{
        "Solved": true,
        "Values": {
            "0": 421490896,
            "1": 2264053908,
            "2": 4294265589,
            "3": 1451491328
        }
    }],

    "SD_BLE_GAP_APPEARANCE_SET": [{
        "Solved": true,
        "Values": {"r0": 832}
    }],

    "SD_BLE_GATTS_SERVICE_ADD": [{
        "Solved": true,
        "Values": {
            "UUID": 65520,
            "r0": 0,
            "r1": 536937784
        }
    }],

    "SD_BLE_GAP_LESC_DHKEY_REPLY": [{}]
}
```
The result shows the basic information about the firmware (base address, size, time), and also the resolved function parameter values for each SDK function.
The design of FirmXRay is detailed in our paper. There is also a real-world example of a BLE thermometer firmware 
**BLE_Ear_s130.bin** for you to try.

There is another running example for TI, and you can try it with

```
make run PATH=examples/TI/oad.bin MCU=TI
```

## Citation

If you create a research work that uses our work, please cite our paper:

```
@inproceedings{FirmXRay:CCS,
  title={FirmXRay: Detecting Bluetooth Link Layer Vulnerabilities from Bare-Metal Firmware},
  author={Haohuang Wen and Zhiqiang Lin and Yinqian Zhang},
  booktitle={Proceedings of the 2020 ACM SIGSAC Conference on Computer and Communications Security},
  year={2020}
}
```
