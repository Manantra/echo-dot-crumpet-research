#!/usr/bin/env python3
"""Passive USB descriptor watcher for Linux.

Polls /sys/bus/usb/devices and, when a device with the given vendor ID shows
up, saves the kernel's cached copy of its descriptors and strings. It only
reads sysfs files, so it sends no USB traffic to the device.
"""
import argparse
import glob
import json
import os
import time

ROOT = "/sys/bus/usb/devices"
IFACE_SEP = ":"
ATTRS = ("idVendor", "idProduct", "bcdDevice", "manufacturer", "product", "serial",
         "speed", "version", "bMaxPacketSize0", "bNumConfigurations", "bDeviceClass",
         "devnum", "busnum", "bConfigurationValue", "maxchild")
IFACE_ATTRS = ("bInterfaceNumber", "bInterfaceClass", "bInterfaceSubClass",
               "bInterfaceProtocol", "bNumEndpoints", "driver")


def read(path):
    try:
        with open(path, "rb") as fh:
            return fh.read().strip().decode("latin-1")
    except OSError:
        return None


def snapshot(dev):
    info = {a: read(os.path.join(dev, a)) for a in ATTRS}
    try:
        with open(os.path.join(dev, "descriptors"), "rb") as fh:
            info["descriptors_hex"] = fh.read().hex()
    except OSError:
        info["descriptors_hex"] = None
    info["interfaces"] = {}
    for idir in sorted(glob.glob(glob.escape(dev) + IFACE_SEP + "*")):
        entry = {a: read(os.path.join(idir, a)) for a in IFACE_ATTRS[:-1]}
        link = os.path.join(idir, "driver")
        entry["driver"] = os.path.basename(os.path.realpath(link)) if os.path.islink(link) else None
        info["interfaces"][os.path.basename(idir)] = entry
    return info


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--vid", default="0e8d", help="USB vendor ID to watch (hex)")
    p.add_argument("--out", default=os.path.expanduser("~/usbwatch"))
    p.add_argument("--interval", type=float, default=0.02)
    p.add_argument("--seconds", type=float, help="Stop after this long")
    args = p.parse_args()
    os.makedirs(args.out, exist_ok=True)

    seen = {}
    count = 0
    start = time.time()
    log = open(os.path.join(args.out, "events.log"), "a", buffering=1)
    log.write(f"{time.time():.3f} start vid={args.vid} interval={args.interval}\n")
    while args.seconds is None or time.time() - start < args.seconds:
        now = time.time()
        present = {}
        for vf in glob.glob(os.path.join(ROOT, "*", "idVendor")):
            if read(vf) == args.vid:
                present[os.path.dirname(vf)] = True
        for dev in present:
            if dev not in seen:
                count += 1
                snap = snapshot(dev)
                name = os.path.join(args.out, f"event_{count:03d}_{time.strftime('%H%M%S', time.localtime(now))}.json")
                seen[dev] = {"file": name, "first_seen": now, "info": snap}
                with open(name, "w") as fh:
                    json.dump({"first_seen": now, "removed": None, "device": snap}, fh, indent=1)
                log.write(f"{now:.3f} appeared {os.path.basename(dev)} "
                          f"{snap['idVendor']}:{snap['idProduct']} speed={snap['speed']} "
                          f"product={snap['product']!r} file={os.path.basename(name)}\n")
        for dev in list(seen):
            if dev not in present:
                rec = seen.pop(dev)
                rec["removed"] = now
                with open(rec["file"], "w") as fh:
                    json.dump({"first_seen": rec["first_seen"], "removed": rec["removed"],
                               "seconds_present": round(rec["removed"] - rec["first_seen"], 3),
                               "device": rec["info"]}, fh, indent=1)
                log.write(f"{now:.3f} removed {os.path.basename(dev)} present="
                          f"{rec['removed'] - rec['first_seen']:.3f}s\n")
        time.sleep(args.interval)
    log.write(f"{time.time():.3f} stop\n")


if __name__ == "__main__":
    main()
