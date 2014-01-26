/***************************************************************************
*                      ZBOSS ZigBee Pro 2007 stack                         *
*                                                                          *
*          Copyright (c) 2013 DSR Corporation Denver CO, USA.              *
*                       http://www.dsr-wireless.com                        *
*                                                                          *
*          Copyright (c) 2012 DSR Corporation Denver CO, USA.              *
*                       http://www.dsr-wireless.com                        *
*                                                                          *
*          Copyright (c) 2011 DSR Corporation Denver CO, USA.              *
*                       http://www.dsr-wireless.com                        *
*                                                                          *
*                            All rights reserved.                          *
*                                                                          *
*                                                                          *
* ZigBee Pro 2007 stack, also known as ZBOSS (R) ZB stack is available     *
* under either the terms of the Commercial License or the GNU General      *
* Public License version 2.0.  As a recipient of ZigBee Pro 2007 stack,    *
* you may choose which license to receive this code under (except as noted *
* in per-module LICENSE files).                                            *
*                                                                          *
* ZBOSS is a registered trademark of DSR Corporation AKA Data Storage      *
* Research LLC.                                                            *
*                                                                          *
* GNU General Public License Usage                                         *
* This file may be used under the terms of the GNU General Public License  *
* version 2.0 as published by the Free Software Foundation and appearing   *
* in the file LICENSE.GPL included in the packaging of this file.  Please  *
* review the following information to ensure the GNU General Public        *
* License version 2.0 requirements will be met:                            *
* http://www.gnu.org/licenses/old-licenses/gpl-2.0.html.                   *
*                                                                          *
* Commercial Usage                                                         *
* Licensees holding valid DSR Commercial licenses may use this file        *
* in accordance with the DSR Commercial License Agreement provided with    *
* the Software or, alternatively, in accordance with the terms contained   *
* in a written agreement between you and DSR.                              *
****************************************************************************
PURPOSE:
*/
#include "sniffercontroller.h"
#include <QProcess>
#include <QFile>

const qint32 SnifferController::SNIFFER_HEADER_SIZE = 4;
const qint32 SnifferController::SNIFFER_MAX_PAYLOAD_SIZE = 128;
const qint32 SnifferController::SNIFFER_WAIT_DEVICE_CLEAR_TIME = 2000;
const qint32 SnifferController::WIRESHARK_WAIT_FOR_CONNECT_TIME = 30000;
const qint32 SnifferController::WIRESHARK_WAIT_FOR_RECONNECT_TIME = 3000;

SnifferController::SnifferController(QObject *parent) :
    QObject(parent)
{
}

SnifferController::SnifferController(QString portName, bool needWireshark,
                                     QString path, quint8 channel, QObject *parent):
    QObject(parent)
{
    this->portName = portName;
    this->needWireshark = needWireshark;
    this->path = path;
    this->channel = channel;

    bridge = new WiresharkBridge();
    device = new SnifferSerialDevice(portName);
    dumper = new PcapDumper();

    connect(this, SIGNAL(errorOccured(QString)), this, SIGNAL(logMessage(QString)));
    connect(bridge, SIGNAL(wiresharkConnected(QLocalSocket*)), this, SLOT(wiresharkHasConnected(QLocalSocket*)));
    connect(bridge, SIGNAL(wiresharkDisconnected()), this, SLOT(wiresharkHasDisconnected()));

    this->isSniffing = false;
    this->isPayload = false;
    this->bytesLeft = SNIFFER_HEADER_SIZE;

    if (needWireshark)
    {
        wiresharkTimer = new QTimer();
        wiresharkTimer->setSingleShot(true);
        connect(wiresharkTimer, SIGNAL(timeout()), this, SLOT(checkWiresharkConnected()));
    }
}

SnifferController::~SnifferController()
{
    bridge->deleteLater();
    device->deleteLater();
    dumper->deleteLater();
}

bool SnifferController::openDevice()
{
    bool ret;

    qDebug() << "Open device";
    emit logMessage(QString("Open sniffer device at %1.").arg(device->portName()));
    ret = device->open(QSerialPort::ReadWrite);
    if (!ret)
    {
        qDebug() << "Failed to open device";
        emit logMessage(QString("Can't open device at %1: %2.").arg(device->portName(), device->errorMsg()));
    }
    else
    {
        connect(device, SIGNAL(error(QSerialPort::SerialPortError)),
                this, SLOT(deviceError(QSerialPort::SerialPortError)));
    }

    return ret;
}

void SnifferController::startSniffer()
{
    emit syncProcessStart();
    if (openDevice())
    {
        QTimer::singleShot(SNIFFER_WAIT_DEVICE_CLEAR_TIME, this, SLOT(continueStartSniffer()));
    }
    else
    {
        emit syncProcessFinished();
        emit errorOccured("Sniffer device init failed.");
        stopSniffer();
    }
}

void SnifferController::continueStartSniffer()
{
    QProcess *wireshark = new QProcess();
    QStringList arg;

    /* Device init after wait */
    device->clear();
    connect(device, SIGNAL(readyRead()), this, SLOT(deviceReadAvailable()));
    device->stopSnifferDevice();

    if (needWireshark)
    {
        qDebug() << "Starting sniffer with Wireshark";
        emit logMessage("Start wireshark bridge.");
        if (!bridge->startBridge())
        {
            qDebug() << "Failed to start Wireshark bridge";
            emit errorOccured("Failed to start Wireshark bridge.");
        }
        else
        {
            qDebug() << "Bridge started successfully. Starting Wireshark" ;
            emit logMessage(QString("Starting Wireshark..."));

            /* fullServerName is known only after startBridge() */
            arg << "-i" << bridge->fullServerName() << "-k" << "-l";

            wireshark->start(path, arg);
            if (!wireshark->waitForStarted(WIRESHARK_WAIT_FOR_RECONNECT_TIME))
            {
                emit syncProcessFinished();
                emit errorOccured("Failed to start Wireshark.");
            }
            else
            {
                qDebug("Wireshark started success");

                /* It may take long time to initiate capture */
                wiresharkTimer->setInterval(WIRESHARK_WAIT_FOR_CONNECT_TIME);
                wiresharkTimer->start();
            }
        }
    }
    else
    {
        qDebug() << "Start sniffer with Pcap file.";
        QFile *pcap = new QFile(path);

        dumper = new PcapDumper(pcap);

        emit syncProcessFinished();
        if (dumper->initDump())
        {
            emit logMessage(QString("Sniffing to file %1").arg(pcap->fileName()));
            isSniffing = true;
            doSniff();

        }
        else
        {
            emit errorOccured(QString("Failed to open file %1.").arg(pcap->fileName()));
        }

    }
}

void SnifferController::pauseSniffer()
{
    if (device->stopSnifferDevice())
    {
        qDebug() << "Sniffer paused";
        emit logMessage("Pause...");
        isSniffing = false;
    }
    else
    {
        qDebug() << "Failed to pause sniffer";
        emit errorOccured("Failed to pause sniffer device. Stop capture.");
        stopSniffer();
    }
}

void SnifferController::resumeSniffer()
{
    isSniffing = true;
    emit logMessage("Resume.");
    doSniff();
}

void SnifferController::stopSniffer()
{
    qDebug() << "Stopping sniffer";
    emit logMessage("Stop capture...");
    isSniffing = false;

    if (device->isOpen())
    {
        qDebug() << "Stop the device.";
        emit logMessage("Stop the sniffer device");
        device->stopSnifferDevice();
        device->clear();
        device->close();
    }

    if (dumper->isOpen())
    {
        qDebug() << "Stopping the dumper";
        emit logMessage("Close the dump destination.");
        dumper->deinitDump();
    }

    if (bridge->isListening())
    {
        qDebug() << "Stopping the bridge";
        emit logMessage("Stop the bridge.");
        bridge->stopBridge();
    }
}

void SnifferController::doSniff()
{
    if (device->startSnifferDevice(channel))
    {
        qDebug() << "Sniffer started";
        emit logMessage("Start sniffer device.");
    }
    else
    {
        qDebug() << "Failed to start sniffer device";
        emit errorOccured("Failed to start sniffer device. Stop capture.");
        stopSniffer();
    }
}

QString SnifferController::printPacketHex(QByteArray arr)
{
    QString res = "";
    qint8 len = arr.data()[0];

    for (qint16 i = 1; i < len; i++)
    {
        QString sym = QString::number((quint8)arr.data()[i], 16);

        sym = ((quint8)arr.data()[i] < 16 ? QString("0x0%1").arg(sym) : QString("0x%1").arg(sym));

        res.append(sym);
        res.append(" ");
    }

    /* remove last space */
    res = res.remove(res.size() - 1, 1);

    return res;
}


void SnifferController::deviceReadAvailable()
{
    qDebug() << "Read available";

    QByteArray packet = device->readAll();
    quint32 len = packet.length();

    if (len == 0)
    {
        emit errorOccured("Device read error");
        stopSniffer();
    }

    qDebug() << QString("Device read %1 bytes").arg(QString::number(len, 10));

    while (len > 0)
    {
        if (packet.length() >= bytesLeft)
        {
            currentPacket.append(packet.left(bytesLeft));
            packet = packet.right(len - bytesLeft);
            len -= bytesLeft;
            bytesLeft = 0;

            if (isPayload)
            {
                qDebug() << "Payload complete";                
                if (isSniffing)
                {                    
                    dumper->writePacket(currentPacket.data() + 1, packetLen - 1);

                    emit logMessage(QString("Packet received: len %1").arg(QString::number(packetLen, 10)));
                    emit logMessage(printPacketHex(currentPacket));
                }

                isPayload = false;
                bytesLeft = SnifferController::SNIFFER_HEADER_SIZE;
                currentPacket.clear();
            }
            else
            {
                quint8 packetType;

                packetLen = ((SnifferHeaderT *)(currentPacket.data()))->len;
                packetType = ((SnifferHeaderT *)(currentPacket.data()))->type;

                qDebug() << QString("Header complete: len %1, type %2").arg(
                                QString::number(packetLen, 10), QString::number(packetType, 10));

                if (packetLen <= SNIFFER_HEADER_SIZE && packetType != ZB_PACKET_TYPE_COMPLETE)
                {
                    QString deviceError = "";

                    qDebug() << QString("read error %1").arg(QString::number(packetType, 10));
                    if (packetType == ZB_PACKET_TYPE_ERROR_OVERFLOW)
                    {
                        deviceError = "Sniffer overflow: some packets can be missed";
                    }
                    else if (packetType == ZB_PACKET_TYPE_ERROR_BIG_LEN)
                    {
                        deviceError = "Device firmware error";
                    }

                    emit logMessage(QString("Device report about error %1").arg(deviceError));
                    /*stopSniffer();*/
                }
                else if (packetLen > SNIFFER_MAX_PAYLOAD_SIZE || packetType == ZB_PACKET_TYPE_ERROR)
                {
                    QString header = "";
                    qDebug() << QString("Bad header: len %1").arg(QString::number(packetLen, 10));
                    for (int i = 0; i < SNIFFER_HEADER_SIZE; i++)
                    {
                        header.append(QString::number(currentPacket.data()[i], 16));
                    }
                    qDebug() << header;

                    currentPacket = currentPacket.right(currentPacket.size() - 1);
                    bytesLeft = 1;

                }
                else
                {
                    qDebug() << "Normal header";
                    packetLen -= SNIFFER_HEADER_SIZE;
                    isPayload = true;
                    bytesLeft = packetLen;
                    currentPacket.clear();
                }
            }
        }
        else
        {
            currentPacket.append(packet);
            bytesLeft -= len;
            len = 0;

            qDebug() << QString("Completing packet: %1 left").arg(QString::number(bytesLeft, 10));
        }
    }
}

void SnifferController::checkWiresharkConnected()
{
    qDebug() << QString("Check Wireshark connected %1").arg(QString::number(isSniffing, 2));
    if (!isSniffing)
    {
        emit syncProcessFinished();
        emit errorOccured(QString("Wireshark connection timeout. Stop capture."));
        stopSniffer();
    }
}

void SnifferController::wiresharkHasConnected(QLocalSocket *sock)
{
    qDebug() << "Wireshark connected";
    wiresharkTimer->stop();
    emit syncProcessFinished();
    emit logMessage("Wireshark connected.");

    isSniffing = true;
    dumper = new PcapDumper(sock);

    if (dumper->initDump())
    {
        doSniff();
    }
    else
    {
        qDebug() << "Failed to open destination";
        emit logMessage(QString("Can't open Wireshark socket"));
    }
}

void SnifferController::wiresharkHasDisconnected()
{
    qDebug() << "Wireshark disconnected.";

    if (needWireshark)
    {
        if (isSniffing)
        {
            pauseSniffer();
            emit syncProcessStart();
            emit logMessage(QString(
                                "Wireshark has disconnected. The sniffer will be paused for %1 seconds, then stopped"
                                ).arg(QString::number(WIRESHARK_WAIT_FOR_RECONNECT_TIME / 1000, 10)));
            wiresharkTimer->setInterval(WIRESHARK_WAIT_FOR_RECONNECT_TIME);
            wiresharkTimer->start();
        }
    }
}

void SnifferController::deviceError(QSerialPort::SerialPortError err)
{
    emit errorOccured(QString("Sniffer device error %1").arg(device->strSerialError(err)));
    disconnect(device, SIGNAL(readyRead()), this, SLOT(deviceReadAvailable()));
    disconnect(device, SIGNAL(error(QSerialPort::SerialPortError)), this, SLOT(deviceError(QSerialPort::SerialPortError)));
    stopSniffer();
}
