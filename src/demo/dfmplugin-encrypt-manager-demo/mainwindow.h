#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
#include <QLineEdit>
#include <QTextBrowser>
#include <QPushButton>

class MainWindow : public QMainWindow
{
    Q_OBJECT
public:
    explicit MainWindow(QWidget *parent = nullptr);

private:
    void initUi();
    void initConnect();

    QLineEdit *editInput { Q_NULLPTR };
    QTextBrowser *textBrowser { Q_NULLPTR };
    QPushButton *btnCheckTpm { Q_NULLPTR };
    QPushButton *btnCheckTcm { Q_NULLPTR };
    QPushButton *btnGetRandom { Q_NULLPTR };
    QPushButton *btnCheckAlgo { Q_NULLPTR };
    QPushButton *btnEncrypt { Q_NULLPTR };
    QPushButton *btnDecrypt { Q_NULLPTR };
};

#endif // MAINWINDOW_H
