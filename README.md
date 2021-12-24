# Systems supported
Currently, only Linux works. It's possible that MacOS works, but I do not have a MacOS machine to test.

As xfreerdp is supported on all three major platforms, Windows support is planned as well.

# Requirements
Most requirements are through python and can be installed with

    pip install -r requirements.txt

Two requirements are not available through PyPi:

* qrencode (available, on Debian-based distributions, in apt)
* xfreerdp (version in apt is not new enough. I've tested it with 3.0.0, available [here](https://github.com/FreeRDP/FreeRDP/wiki/PreBuilds))

# Running
In a shell, simply run:

    ./readyfor.py

if all dependencies are installed, then a QR code will be printed to the terminal. This can be scanned in the camera app or the Ready For app to connect.
