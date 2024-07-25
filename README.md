# crash-qcomipclog
This is a crash utility extension module to parse qcom ipc logs.
To use this module, the `qcom_ipc_logging.ko` must be prepared.

## Getting Started
To build this module from the top-level `crash-version` directory, enter:
```bash
$ cp <path-to>/ipclog.c extensions
$ make extensions 
```

To load the qcom_ipc_logging.ko kernel module, enter:
```bash
crash> mod -s qcom_ipc_logging <path-to-qcom_ipc_logging.ko>
```

To load this module in crash, enter:
```bash
crash> extend ipclog.so
```

To parse qcom ipc logs, enter:
```bash
crash> ipclog
```

The logs will be generated in the ipclog directory under the current path.