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
#include <QtSerialPort/QSerialPortInfo>
#include <QProcess>
#include <QFileDialog>
#include "snifferwindow.h"
#include "ui_snifferwindow.h"

const QString SnifferWindow::PREFERENCES_NAME = "pref";
const qint32 SnifferWindow::MAX_LOGS_VISIBLE = 100;

SnifferWindow::SnifferWindow(QWidget *parent) :
    QMainWindow(parent),
    ui(new Ui::SnifferWindow)
{
    ui->setupUi(this);

    initSniffingMode();
    initCmbChannel();
    initCmbCom();

    setBttnStartState(BTTN_START);
    loadPreferences();
}

SnifferWindow::~SnifferWindow()
{
    delete ui;
}

void SnifferWindow::initSniffingMode()
{
    connect(ui->rbPcap, SIGNAL(toggled(bool)), this, SLOT(reWriteLPath()));
    connect(ui->rbWireshark, SIGNAL(toggled(bool)), this, SLOT(reWriteLPath()));
}

void SnifferWindow::initCmbCom()
{
    ui->cmbCom->clear();
    foreach (const QSerialPortInfo &info, QSerialPortInfo::availablePorts())
    {
        ui->cmbCom->addItem(QString("%1 (%2)").arg(info.description(), info.portName()),
                            QVariant(info.portName()));
    }
}

void SnifferWindow::initCmbChannel()
{
    /* from min zb channel to max */
    for (uint i = 11; i < 27; i++)
    {
        QString ch = QString::number(i, 16);

        ch = ch.toUpper();
        /* Add zero to the one-number hexademical (0xA -> 0x0A)*/
        if (i < 16)
        {
            ch = QString("0%1").arg(ch);
        }
        ui->cmbChannel->addItem(QString("0x%1 (%2)").arg(ch, QString::number(i, 10)), QVariant(i));
    }
}

void SnifferWindow::loadPreferences()
{
    QFile *pref = new QFile(PREFERENCES_NAME);

    prefferedWs = "";
    prefferedPcap = "";

    if (pref->exists())
    {
        if (pref->open(QIODevice::ReadOnly))
        {
            QTextStream in(pref);
            in.setCodec("UTF-8");

            QString tmp = in.readLine();
            if (!tmp.isNull())
            {
                prefferedWs = tmp;
                tmp = in.readLine();
            }

            if (!tmp.isNull())
            {
                prefferedPcap = tmp;
                tmp = in.readLine();
            }

            if (!tmp.isNull())
            {
                int index = ui->cmbChannel->findData(tmp);

                if (index != -1)
                {
                    ui->cmbChannel->setCurrentIndex(index);
                }

                tmp = in.readLine();
            }

            if (!tmp.isNull())
            {
                int index = ui->cmbCom->findData(tmp);

                if (index != -1)
                {
                    ui->cmbCom->setCurrentIndex(index);
                }
            }

            pref->close();
        }
    }
    ui->lePath->setText(prefferedWs);
}

void SnifferWindow::savePreferences()
{
    QFile *pref = new QFile(PREFERENCES_NAME);

    if (pref->open(QIODevice::WriteOnly))
    {
        QTextStream out(pref);
        out.setCodec("UTF-8");

        out << prefferedWs;
        out << "\n";
        out << prefferedPcap;
        out << "\n";
        out << (uchar)ui->cmbChannel->itemData(ui->cmbChannel->currentIndex()).toUInt();
        out << "\n";
        out << ui->cmbCom->itemData(ui->cmbCom->currentIndex()).toString();

        pref->close();
    }
}

void SnifferWindow::setBttnStartState(BttnStartStateE state)
{
    bttnStartState = state;

    switch (state)
    {
    case BTTN_START:

        ui->bttnStart->setText("Start");
        break;

    case BTTN_PAUSE:

        ui->bttnStart->setText("Pause");
        break;

    case BTTN_RESUME:

        ui->bttnStart->setText("Resume");
        break;
    }
}

void SnifferWindow::on_bttnBrowsePath_clicked()
{
    QFileDialog dialog(this);
    QString invitation = ui->rbWireshark->isChecked() ?
                "Specify the path to Wireshark" : "Specify the path to .pcap file";

    dialog.setFileMode(QFileDialog::AnyFile);
    dialog.setWindowTitle(invitation);
    if (dialog.exec())
    {
        QStringList pathes = dialog.selectedFiles();
        ui->lePath->setText(pathes[0]);
    }
}

void SnifferWindow::on_bttnUp_clicked()
{
    initCmbCom();
}

void SnifferWindow::on_bttnStart_clicked()
{
    QString portName = (ui->cmbCom->count() > 0 ?
                            ui->cmbCom->itemData(ui->cmbCom->currentIndex()).toString() : "");

    uchar channel = (uchar)ui->cmbChannel->itemData(ui->cmbChannel->currentIndex()).toUInt();
    bool needWireshark = ui->rbWireshark->isChecked();
    QString path = ui->lePath->text();

    switch (bttnStartState)
    {

    case BTTN_START:

        if (!ui->lePath->text().isEmpty())
        {
            ui->teLogBrowser->clear();
            setBttnStartState(BTTN_PAUSE);
            refreshToStop();

            if (ui->rbWireshark->isChecked())
            {
                prefferedWs = ui->lePath->text();
            }
            else
            {
                prefferedPcap = ui->lePath->text();
            }

            savePreferences();

            controller = new SnifferController(portName, needWireshark, path, channel);
            connect(controller, SIGNAL(logMessage(QString)), this, SLOT(printLogMessage(QString)));
            connect(controller, SIGNAL(errorOccured(QString)), this, SLOT(refreshToStart()));
            connect(controller, SIGNAL(syncProcessStart()), this, SLOT(freeze()));
            connect(controller, SIGNAL(syncProcessFinished()), this, SLOT(defrost()));

            controller->startSniffer();
        }
        else
        {
            ui->teLogBrowser->append(QString("Specify path to %1").arg(
                        ui->rbWireshark->isChecked() ? "Wireshark" : "Pcap file"));
        }
        break;

    case BTTN_PAUSE:

        setBttnStartState(BTTN_RESUME);

        controller->pauseSniffer();
        break;

    case BTTN_RESUME:

        setBttnStartState(BTTN_PAUSE);

        controller->resumeSniffer();
        break;
    }
}

void SnifferWindow::on_bttnStop_clicked()
{
    controller->stopSniffer();
    refreshToStart();
    setBttnStartState(BTTN_START);
}

void SnifferWindow::on_bttnCancel_clicked()
{
    QApplication::quit();
}

void SnifferWindow::reWriteLPath()
{
    ui->lPath->setText(QString("<b>Specify path to %1</b>").arg(
                             ui->rbWireshark->isChecked() ? "Wireshark" : "Pcap file"));
    ui->lePath->setText(ui->rbWireshark->isChecked() ? prefferedWs : prefferedPcap);
}

void SnifferWindow::printLogMessage(QString msg)
{
    if (ui->teLogBrowser->document()->blockCount() == MAX_LOGS_VISIBLE)
    {
        ui->teLogBrowser->clear();
    }
    ui->teLogBrowser->append(msg);
}

void SnifferWindow::refreshToStart()
{
    controller->deleteLater();
    setBttnStartState(BTTN_START);
    ui->bttnStop->setEnabled(false);
    ui->bttnBrowsePath->setEnabled(true);
    ui->bttnUp->setEnabled(true);
    ui->rbWireshark->setEnabled(true);
    ui->rbPcap->setEnabled(true);
    ui->lePath->setEnabled(true);
    ui->cmbCom->setEnabled(true);
    ui->cmbChannel->setEnabled(true);
}

void SnifferWindow::refreshToStop()
{
    ui->bttnStop->setEnabled(true);
    ui->bttnUp->setEnabled(false);
    ui->bttnBrowsePath->setEnabled(false);
    ui->rbWireshark->setEnabled(false);
    ui->rbPcap->setEnabled(false);
    ui->lePath->setEnabled(false);
    ui->cmbCom->setEnabled(false);
    ui->cmbChannel->setEnabled(false);
}

void SnifferWindow::freeze()
{
    ui->bttnStart->setEnabled(false);
    ui->bttnStop->setEnabled(false);
}

void SnifferWindow::defrost()
{
    ui->bttnStart->setEnabled(true);
    ui->bttnStop->setEnabled(true);
}

void SnifferWindow::closeHandler()
{
    if (bttnStartState != BTTN_START)
    {
        controller->stopSniffer();
    }
}
