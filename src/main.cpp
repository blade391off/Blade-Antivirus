#include <QAction>
#include <QApplication>
#include <QCoreApplication>
#include <QDebug>
#include <QDir>
#include <QFileInfo>
#include <QIcon>
#include <QLocalServer>
#include <QLocalSocket>
#include <QMenu>
#include <QQmlApplicationEngine>
#include <QQmlContext>
#include <QQuickWindow>
#include <QSettings>
#include <QStyle>
#include <QSystemTrayIcon>
#include <QUrl>

#include "app/antiviruscontroller.h"

namespace
{
    QString autostartKey()
    {
        return QStringLiteral(
            "HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Run");
    }

    QString autostartValueName()
    {
        return QStringLiteral("BladeAntivirus");
    }

    bool isAutostartEnabled()
    {
        const QSettings registry(autostartKey(), QSettings::NativeFormat);
        return registry.contains(autostartValueName());
    }

    // HKCU\...\Run: per-user, needs no admin rights.
    void setAutostart(bool enabled)
    {
        QSettings registry(autostartKey(), QSettings::NativeFormat);

        if (enabled) {
            registry.setValue(
                autostartValueName(),
                QStringLiteral("\"%1\" --background").arg(
                    QDir::toNativeSeparators(
                        QCoreApplication::applicationFilePath())));
        }
        else {
            registry.remove(autostartValueName());
        }
    }
}

int main(int argc, char* argv[])
{
    // Custom-styled controls need a customizable style.
    qputenv("QT_QUICK_CONTROLS_STYLE", "Basic");

    QApplication app(argc, argv);

    // The app lives in the tray: closing the window must not end the process.
    app.setQuitOnLastWindowClosed(false);

    QCoreApplication::setApplicationName(QStringLiteral("BladeAntivirus"));
    QCoreApplication::setApplicationVersion(QStringLiteral("1.0.0"));
    QCoreApplication::setOrganizationName(QStringLiteral("BladeAntivirus"));

    const bool startHidden =
        app.arguments().contains(QStringLiteral("--background"));

    // ---- single instance --------------------------------------------------
    const QString instanceName = QStringLiteral("BladeAntivirus.SingleInstance");

    {
        QLocalSocket probe;
        probe.connectToServer(instanceName);

        if (probe.waitForConnected(500)) {
            // Another instance is running: ask it to show its window
            // (not for the silent autostart launch) and quit.
            if (!startHidden) {
                probe.write("show");
                probe.waitForBytesWritten(500);
            }
            return 0;
        }
    }

    QLocalServer::removeServer(instanceName);

    QLocalServer instanceServer;
    instanceServer.setSocketOptions(QLocalServer::UserAccessOption);

    if (!instanceServer.listen(instanceName))
        qWarning() << "[BladeAntivirus] single-instance server failed:"
                   << instanceServer.errorString();

    // ---- icons ------------------------------------------------------------
    const QString appDir = QCoreApplication::applicationDirPath();

    QUrl logoUrl;
    for (const QString& name : { QStringLiteral("/logo.ico"), QStringLiteral("/logo.png") }) {
        if (QFileInfo::exists(appDir + name)) {
            if (app.windowIcon().isNull())
                app.setWindowIcon(QIcon(appDir + name));

            if (logoUrl.isEmpty() || name.endsWith(QStringLiteral(".png")))
                logoUrl = QUrl::fromLocalFile(appDir + name);
        }
    }

    QIcon trayIconImage = app.windowIcon();
    if (trayIconImage.isNull())
        trayIconImage = app.style()->standardIcon(QStyle::SP_ComputerIcon);

    // ---- core objects -----------------------------------------------------
    AntivirusController antivirusController;
    QQmlApplicationEngine engine;
    QQuickWindow* window = nullptr;

    const bool trayAvailable = QSystemTrayIcon::isSystemTrayAvailable();

    engine.rootContext()->setContextProperty(
        QStringLiteral("antivirusController"), &antivirusController);
    engine.rootContext()->setContextProperty(
        QStringLiteral("logoUrl"), logoUrl);
    // QML uses this to decide: hide to tray on close, or really quit.
    engine.rootContext()->setContextProperty(
        QStringLiteral("trayAvailable"), trayAvailable);

    const auto showWindow = [&window]() {
        if (!window)
            return;

        if (window->visibility() == QWindow::Minimized)
            window->showNormal();
        else
            window->show();

        window->raise();
        window->requestActivate();
    };

    QObject::connect(
        &instanceServer, &QLocalServer::newConnection, &app,
        [&instanceServer, showWindow]() {
            while (QLocalSocket* socket = instanceServer.nextPendingConnection()) {
                socket->disconnectFromServer();
                socket->deleteLater();
                showWindow();
            }
        });

    QObject::connect(
        &engine,
        &QQmlApplicationEngine::objectCreationFailed,
        &app,
        []() {
            qCritical() << "[BladeAntivirus] QML object creation failed";
            QCoreApplication::exit(1);
        },
        Qt::QueuedConnection);

    QObject::connect(
        &engine,
        &QQmlApplicationEngine::warnings,
        &app,
        [](const QList<QQmlError>& warnings) {
            for (const QQmlError& error : warnings)
                qWarning().noquote() << "[QML]" << error.toString();
        });

    engine.loadFromModule(
        QStringLiteral("BladeAntivirus"),
        QStringLiteral("Main"));

    if (engine.rootObjects().isEmpty()) {
        qCritical() << "[BladeAntivirus] No root QML object (see [QML] warnings above)";
        return 1;
    }

    window = qobject_cast<QQuickWindow*>(engine.rootObjects().constFirst());

    if (!window) {
        qCritical() << "[BladeAntivirus] Root QML object is not a window";
        return 1;
    }

    // ---- tray -------------------------------------------------------------
    // Declared after `app` and before use; the menu outlives the tray icon.
    QMenu trayMenu;
    QSystemTrayIcon tray(trayIconImage);

    if (trayAvailable) {
        QAction* openAction = trayMenu.addAction(QStringLiteral("Open BladeAntivirus"));
        QAction* quickScanAction = trayMenu.addAction(QStringLiteral("Quick scan"));
        QAction* updateAction = trayMenu.addAction(QStringLiteral("Check for updates"));
        trayMenu.addSeparator();
        QAction* autostartAction = trayMenu.addAction(QStringLiteral("Start with Windows"));
        trayMenu.addSeparator();
        QAction* exitAction = trayMenu.addAction(QStringLiteral("Exit"));

        autostartAction->setCheckable(true);
        autostartAction->setChecked(isAutostartEnabled());

        QObject::connect(openAction, &QAction::triggered, &app, showWindow);
        QObject::connect(quickScanAction, &QAction::triggered, &app,
            [&antivirusController]() { antivirusController.startQuickScan(); });
        QObject::connect(updateAction, &QAction::triggered, &app,
            [&antivirusController]() { antivirusController.checkUpdates(); });
        QObject::connect(autostartAction, &QAction::toggled, &app,
            [](bool enabled) { setAutostart(enabled); });
        QObject::connect(exitAction, &QAction::triggered, &app,
            &QCoreApplication::quit);

        QObject::connect(
            &tray, &QSystemTrayIcon::activated, &app,
            [showWindow](QSystemTrayIcon::ActivationReason reason) {
                if (reason == QSystemTrayIcon::Trigger
                    || reason == QSystemTrayIcon::DoubleClick) {
                    showWindow();
                }
            });

        // Tooltip shows the latest status (Windows truncates long tooltips).
        QObject::connect(
            &antivirusController, &AntivirusController::statusChanged, &tray,
            [&tray](const QString& message) {
                tray.setToolTip(
                    QStringLiteral("BladeAntivirus\n") + message.left(100));
            });

        // Background scan found something while the window is hidden.
        QObject::connect(
            &antivirusController, &AntivirusController::scanFinished, &tray,
            [&tray, &window](int, int detected, int) {
                if (detected > 0 && window && !window->isVisible()) {
                    tray.showMessage(
                        QStringLiteral("BladeAntivirus"),
                        QStringLiteral("Threats found: %1. Open the app for details.")
                            .arg(detected),
                        QSystemTrayIcon::Warning,
                        10000);
                }
            });

        tray.setContextMenu(&trayMenu);
        tray.setToolTip(QStringLiteral("BladeAntivirus"));
        tray.show();
    }

    // Autostart launches with --background: stay in the tray.
    // Without a tray the window must be shown or the app is unreachable.
    if (!startHidden || !trayAvailable)
        showWindow();

    return app.exec();
}
