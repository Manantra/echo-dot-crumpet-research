# Boot chain and exploit research

Conceptual: **BootROM → Preloader → authenticated LK and ATF/TEE → Android**.

[`amonet-koboreru`](https://github.com/R0rt1z2/amonet-koboreru) describes a MediaTek preloader weakness involving sub-image metadata and a storage read callback. Exploitability depends on a *vulnerable* installed preloader and a way to write crafted images to flash.

The project contains `devices/crumpet.c`, but its author states the NAND-based Crumpet port has **not been hardware tested** and is currently on hold. The device definition contains hardcoded patch addresses, which cannot be assumed valid for other builds.

Crumpet uses raw NAND rather than the eMMC setup found on Donut. A logged 2019 NAND partition table does **not** contain `expdb`, although Crumpet's upstream definition specifies `LK_PART_NAME "expdb"`. This discrepancy remains unexplained; do not assume the images are interchangeable.

Sources: [upstream source](https://github.com/R0rt1z2/amonet-koboreru/blob/main/devices/crumpet.c), [maintainer discussion](https://github.com/R0rt1z2/amonet-koboreru/issues/2).
