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
#ifndef SNIFFERWINDOW_H
#define SNIFFERWINDOW_H

#include <QMainWindow>
#include "sniffercontroller.h"


namespace Ui {
class SnifferWindow;
}

class SnifferWindow : public QMainWindow
{
    Q_OBJECT

public:
    explicit SnifferWindow(QWidget *parent = 0);
    ~SnifferWindow();

signals:

private slots:

    void on_bttnBrowsePath_clicked();

    void on_bttnUp_clicked();

    void on_bttnStart_clicked();

    void on_bttnStop_clicked();

    void on_bttnCancel_clicked();

    void reWriteLPath();

    void printLogMessage(QString msg);

    void refreshToStart();

    void refreshToStop();

    void freeze();

    void defrost();

private:

    enum BttnStartStateE
    {
        BTTN_START = 0,
        BTTN_RESUME = 1,
        BTTN_PAUSE = 2
    };

    static const QString PREFERENCES_NAME;
    static const qint32 MAX_LOGS_VISIBLE;

    Ui::SnifferWindow *ui;
    SnifferController *controller;

    BttnStartStateE bttnStartState;
    QString prefferedWs;
    QString prefferedPcap;

    void initSniffingMode();
    void initCmbCom();
    void initCmbChannel();

    void loadPreferences();
    void savePreferences();

    void setBttnStartState(BttnStartStateE state);

public slots:
    void closeHandler();
};

#endif // SNIFFERWINDOW_H
