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

There are a number of command line options:

* `--no-check-freerdp` skips the freerdp validation
* `--freerdp-path` is used to specify a different freerdp command
(such as for wayland desktops) or for an alternative installation path
