# Systems supported
Currently, only Linux works. It's possible that MacOS works, but I do not have
a MacOS machine to test.

As xfreerdp is supported on all three major platforms, Windows support is
planned as well.

# Requirements
Most requirements are through python and can be installed with

    pip3 install -r requirements.txt

You will also need freerdp - this script assumes you're using x and will launch
xfreerdp accordingly. This behavious can be overriden with the `--freerdp-path`
parameter.

**NOTE:** You will need FreeRDP 3.0.0 or later - older versions do not seem
to connect correctly and will terminate the connection. You can download the
newest nightly builds [here](https://github.com/FreeRDP/FreeRDP/wiki/PreBuilds).

# Running
In a shell, simply run:

    ./readyfor.py

if all dependencies are installed, then a QR code will be displayed in a popup. This can be scanned in the camera app or the Ready For app to connect.

# Advanced use
## Command line options
| Option | Description |
|--|--|
| `--no-check-freerdp` | Skip the FreeRDP availability and version check. |
| `--frerdp-path` | Specify an alternative command (such as for Wayland desktops) or an alternative installation path for FreeRDP |
| `-v` | Show more verbose messages in terminal output |
| `-h`, `--help` | Show help message |
| `-r`, `--resolution` | Use a different resolution for RDP (defaults to 1280x720 |
| `-c`, `--config` | Specify a configuration file (see below) |

## Configuration file
If `settings.json` is present in the ReadyForPy, it will automatically be used. Command-line options will override config file options, if they conflict.

The `settings.json` file uses JSON and these options:

| Option | Description | Type |
|----------|------------------|---------|
|`username`| Use a fixed username (rather than randomly generated) for RDP | String |
|`password` | Use a fixed password (rather than randomly generated) for RDP | String |
|`freerdp_path` | Specify an alternative command to use for FreeRDP - similar to --freerdp-path | String |
|`no_check_freerdp` | Skip FreeRDP presence and version check | Boolean |
|`resolution` | Specify custom resolution | String |
