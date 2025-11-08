/*****************************************************************************
 *   Copyright (C) 2020 by Bayram KARAHAN                                    *
 *   <bayramk@gmail.com>                                                     *
 *                                                                           *
 *   This program is free software; you can redistribute it and/or modify    *
 *   it under the terms of the GNU General Public License as published by    *
 *   the Free Software Foundation; either version 3 of the License, or       *
 *   (at your option) any later version.                                     *
 *                                                                           *
 *   This program is distributed in the hope that it will be useful,         *
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of          *
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the           *
 *   GNU General Public License for more details.                            *
 *                                                                           *
 *   You should have received a copy of the GNU General Public License       *
 *   along with this program; if not, write to the                           *
 *   Free Software Foundation, Inc.,                                         *
 *   51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA .          *
 *****************************************************************************/
#ifndef AYAR_H
#define AYAR_H
#include<QToolButton>
#include<QCheckBox>
#include<QMessageBox>
#include<QApplication>
#include<QDesktopWidget>

QWidget * MainWindow::ayar()
{
    // qDebug()<<"ayar click";
    QDialog * d = new QDialog();
    d->setWindowTitle(tr("Web Filtresi"));
    d->setFixedSize(QSize(boy*24,boy*18));
   ///d->setStyleSheet("font-size:"+QString::number(font.toInt()-2)+"px;");
    auto appIcon = QIcon(":/icons/webblock.svg");
    d->setWindowIcon(appIcon);
    QRect screenGeometry = QApplication::desktop()->screenGeometry();
    int x = (screenGeometry.width() - d->width())/2;
    int y = (screenGeometry.height() - d->height()) / 2;
    d->move(x, y);
    /***********************************************************************/
    QTableWidget *twlh=new QTableWidget;

    twlh->setFixedSize(QSize(boy*23,boy*13));
    twlh->setColumnCount(5);
    //twlh->setRowCount(0);
    twlh->setHorizontalHeaderItem(0, new QTableWidgetItem(tr("Seç")));
    twlh->setHorizontalHeaderItem(1, new QTableWidgetItem(tr("Index")));
    twlh->setHorizontalHeaderItem(2, new QTableWidgetItem(tr("Engelenen Kelime")));
    twlh->setHorizontalHeaderItem(3, new QTableWidgetItem(""));
    twlh->setHorizontalHeaderItem(4, new QTableWidgetItem(""));

    twlh->setSelectionBehavior(QAbstractItemView::SelectRows);
    twlh->setSelectionMode(QAbstractItemView::SingleSelection);
    //connect(tw, &QTableWidget::cellClicked, this, cellClicked());
    twlh->setRowCount(0);
    twlh->setColumnWidth(0, boy*1);
    twlh->setColumnWidth(1, boy*1);
    twlh->setColumnWidth(2,boy*13);
    twlh->setColumnWidth(3,boy*3);
    twlh->setColumnWidth(4,boy*2);

    DatabaseHelper *db=new DatabaseHelper(localDir+"data/webblock.json");
    QJsonArray dizi=db->Oku();
    int sr=0;

    for (const QJsonValue &item : dizi) {
        QJsonObject veri=item.toObject();

        twlh->setRowCount(twlh->rowCount()+1);
        QCheckBox *mCheck = new QCheckBox();
        mCheck->setFixedWidth(boy*5);
        mCheck->setChecked(false);
        QLineEdit * index = new QLineEdit();
        QLineEdit * word = new QLineEdit();
        QToolButton *saveButton= new QToolButton;
        saveButton->setText(tr("Kaydet"));
        saveButton->setFixedWidth(boy*3);
        connect(saveButton, &QPushButton::clicked, [=]() {
            //qDebug()<<"Değişiklikler Kaydedildi.."<<insertButton->toolTip();
            int numRows = twlh->rowCount();
            for ( int i = 0 ; i < numRows ; i++)
            {
                QCheckBox* mBox = static_cast<QCheckBox*> (twlh->cellWidget(i,0));
                QLineEdit * index = static_cast<QLineEdit*> (twlh->cellWidget(i,1));
                QLineEdit * word = static_cast<QLineEdit*> (twlh->cellWidget(i,2));
                if (index->text()==saveButton->toolTip())
                {
                    QJsonArray dizi=db->Ara("index",saveButton->toolTip());
                    if(dizi.count()>0)
                    {
                        qDebug()<<"Kelime Değiştirilecek."<<saveButton->toolTip();
                        QJsonObject veri;
                        if (mBox->isChecked()) veri["selectedWord"] =true;
                        else veri["selectedWord"] =false;
                        veri["index"] = index->text();
                        veri["word"] = word->text();
                        //qDebug()<<"kelime kayıt"<<veri;
                        db->Sil("index",index->text());
                        db->Ekle(veri);
                    }
                }
            }
            d->close();
            ///webBlockWidget();
        });
        QToolButton *removeButton= new QToolButton;
        removeButton->setText(tr("Sil"));
        removeButton->setFixedWidth(boy*2);
        connect(removeButton, &QPushButton::clicked, [=]() {
            //qDebug()<<"Profil Silindi.."<<networkRemoveButton->toolTip();
            QJsonArray dizi=db->Ara("networkIndex",removeButton->toolTip());
            qDebug()<<"Web Kelime Silinecek."<<removeButton->toolTip();
            db->Sil("index",index->text());
            d->close();
            ///webBlockWidget();
        });



        index->setText(veri.value("index").toString());
        index->setReadOnly(true);
        word->setText(veri.value("word").toString());
        saveButton->setToolTip(index->text());
        twlh->setCellWidget(sr,0,mCheck);
        twlh->setCellWidget(sr,1,index);
        twlh->setCellWidget(sr,2,word);
        twlh->setCellWidget(sr,3,saveButton);
        twlh->setCellWidget(sr,4,removeButton);

        //qDebug()<<"Kayıtlı Host.";
        if(veri.value("selectedWord").toBool())
            mCheck->setChecked(true);
        else
            mCheck->setChecked(false);
        sr++;
    }

    /********************************************************************/
    QToolButton *insertWordButton= new QToolButton;
    insertWordButton->setFixedSize(QSize(boy*5,boy*4));
    insertWordButton->setIconSize(QSize(boy*5,boy*2));
    insertWordButton->setStyleSheet("Text-align:center");
    insertWordButton->setIcon(QIcon(":/icons/add.svg"));
    insertWordButton->setAutoRaise(true);
    insertWordButton->setToolButtonStyle(Qt::ToolButtonTextUnderIcon);
    // newNetworkButton->setFont(f2);
    insertWordButton->setText(tr("Yeni Kelime Ekle"));

    connect(insertWordButton, &QPushButton::clicked, [=]() {
        DatabaseHelper *db=new DatabaseHelper(localDir+"data/webblock.json");
        QJsonObject veri;
        veri["index"] =QString::number(db->getIndex("index"));
        if(db->Oku().size()==0) veri["selectedWord"] =true;
        else veri["selectedWord"] =false;
        veri["word"] = "sample";
        db->Ekle(veri);
        d->close();
        ///webBlockWidget();
    });

    /*********************************************************************/

    QVBoxLayout * vbox = new QVBoxLayout();
    vbox->addWidget(twlh);
    QHBoxLayout * hbox = new QHBoxLayout();
    hbox->addWidget(insertWordButton);
    //hbox->addWidget(webAyarGuncelleButton);

    vbox->addLayout(hbox);

    d->setLayout(vbox);
    //d->exec();
    return d;

}

#endif // AYAR_H
