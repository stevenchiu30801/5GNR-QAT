# Intel QAT with 5G NR Security

## Dependency

The code is verified with the following dependencies.

- Hardware: Intel® C62x Chipset
- Software: Driver v1.7.l.4.9.0-00008

## Usage

Download and install Intel QAT software.

```bash
sudo apt-get install build-essential g++ pkg-config libssl-dev zlib1g-dev libudev-dev
mkdir ~/qat && cd qat
wget https://01.org/sites/default/files/downloads/qat1.7.l.4.9.0-00008.tar.gz
tar -zxof qat1.7.l.4.9.0-00008.tar.gz
./configure
make
sudo make install
sudo service qat_service start
```

Configure QAT devices with `PDCP` endpoint. Take `c6xx_dev0.conf` for example.

```bash
echo '[PDCP]
NumberCyInstances = 2
NumberDcInstances = 0
NumProcesses = 1
LimitDevAccess = 0

Cy0Name = "PDCP0"
Cy0IsPolled = 1
Cy0CoreAffinity = 0

Cy0Name = "PDCP1"
Cy0IsPolled = 1
Cy0CoreAffinity = 1
' | sudo tee -a /etc/c6xx_dev0.conf
```

Clone and build the code for 5G NR security.

```bash
git clone https://github.com/stevenchiu30801/5GNR-QAT.git
cd 5GNR-QAT
make
```

Run

```bash
# Arguments:
#     ALGO        Security algorithm - nea1, nea2 or nea3 (for cipher)
#                                      nia1, nia2 or nia3 (for hash)
#     TESTSET     Test set number - 1 to 5 (not all test sets supported)
sudo ./main [ALGO] [TESTSET]
```
