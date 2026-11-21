
#include <QAction>
#include <QApplication>
#include <QColor>
#include <QCoreApplication>
#include <QDebug>
#include <QDir>
#include <QFileInfo>
#include <QIcon>
#include <QMenu>
#include <QQmlApplicationEngine>
#include <QQmlContext>
#include <QQuickWindow>
#include <QSettings>
#include <QStyle>
#include <QSystemTrayIcon>
#include <QUrl>

#include "app/antiviruscontroller.h"
#include "realtime/realtime_protection.h"

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
    qputenv("QT_QUICK_CONTROLS_STYLE", "Basic");

    QApplication app(argc, argv);
    app.setQuitOnLastWindowClosed(false);

    QCoreApplication::setApplicationName(
        QStringLiteral("BladeAntivirus"));

    // BLADE_VERSION comes from CMake (project VERSION) so the window, the
    // installer and the About page cannot drift apart again.
#ifdef BLADE_VERSION
    QCoreApplication::setApplicationVersion(
        QStringLiteral(BLADE_VERSION));
#else
    QCoreApplication::setApplicationVersion(
        QStringLiteral("0.0.0-dev"));
#endif

    QCoreApplication::setOrganizationName(
        QStringLiteral("BladeAntivirus"));

    const bool startHidden =
        app.arguments().contains(QStringLiteral("--background"));

    // Application icon.
    const QString appDir = QCoreApplication::applicationDirPath();
    QUrl logoUrl;

    for (const QString& name : {
             QStringLiteral("/logo.ico"),
             QStringLiteral("/logo.png")
        }) {
        if (QFileInfo::exists(appDir + name)) {
            if (app.windowIcon().isNull())
                app.setWindowIcon(QIcon(appDir + name));

            if (logoUrl.isEmpty() || name.endsWith(QStringLiteral(".png")))
                logoUrl = QUrl::fromLocalFile(appDir + name);
        }
    }

    QIcon trayIconImage = app.windowIcon();

    if (trayIconImage.isNull()) {
        trayIconImage =
            app.style()->standardIcon(QStyle::SP_ComputerIcon);
    }

    // Core objects.
    AntivirusController antivirusController;
    QQmlApplicationEngine engine;
    QQuickWindow* window = nullptr;

    const bool trayAvailable = QSystemTrayIcon::isSystemTrayAvailable();

    engine.rootContext()->setContextProperty(
        QStringLiteral("antivirusController"),
        &antivirusController);

    engine.rootContext()->setContextProperty(
        QStringLiteral("realtimeProtection"),
        antivirusController.realtimeProtection());

    engine.rootContext()->setContextProperty(
        QStringLiteral("logoUrl"),
        logoUrl);

    engine.rootContext()->setContextProperty(
        QStringLiteral("trayAvailable"),
        trayAvailable);

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

    // QML error handling.
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

    // Load main QML window.
    engine.loadFromModule(
        QStringLiteral("BladeAntivirus"),
        QStringLiteral("Main"));

    if (engine.rootObjects().isEmpty()) {
        qCritical()
            << "[BladeAntivirus] No root QML object. Check QML warnings.";
        return 1;
    }

    window = qobject_cast<QQuickWindow*>(
        engine.rootObjects().constFirst());

    if (!window) {
        qCritical()
            << "[BladeAntivirus] Root QML object is not a QQuickWindow";
        return 1;
    }

    // Fully opaque window.
    window->setColor(QColor("#0B0E14"));

    // System tray.
    QMenu trayMenu;
    QSystemTrayIcon tray(trayIconImage);

    QObject::connect(
        &antivirusController, &AntivirusController::threatDetected,
        &app, [&tray](const QString& path, const QString& verdict, const QString& details) {
            tray.showMessage(
                verdict == "MALICIOUS"
                    ? QStringLiteral("Threat detected")
                    : QStringLiteral("Suspicious file"),
                QFileInfo(path).fileName() + QStringLiteral(": ") + details,
                verdict == "MALICIOUS"
                    ? QSystemTrayIcon::Critical
                    : QSystemTrayIcon::Warning,
                8000);
        });

    if (trayAvailable) {
        QAction* openAction =
            trayMenu.addAction(QStringLiteral("Open BladeAntivirus"));

        QAction* quickScanAction =
            trayMenu.addAction(QStringLiteral("Quick scan"));

        QAction* updateAction =
            trayMenu.addAction(QStringLiteral("Check for updates"));

        trayMenu.addSeparator();

        QAction* autostartAction =
            trayMenu.addAction(QStringLiteral("Start with Windows"));

        trayMenu.addSeparator();

        QAction* exitAction =
            trayMenu.addAction(QStringLiteral("Exit"));

        autostartAction->setCheckable(true);
        autostartAction->setChecked(isAutostartEnabled());

        QObject::connect(
            openAction, &QAction::triggered, &app, showWindow);

        QObject::connect(
            quickScanAction, &QAction::triggered, &app,
            [&antivirusController]() {
                antivirusController.startQuickScan();
            });

        QObject::connect(
            updateAction, &QAction::triggered, &app,
            [&antivirusController]() {
                antivirusController.checkUpdates();
            });

        QObject::connect(
            autostartAction, &QAction::toggled, &app,
            [](bool enabled) {
                setAutostart(enabled);
            });

        QObject::connect(
            exitAction, &QAction::triggered,
            &app, &QCoreApplication::quit);

        QObject::connect(
            &tray,
            &QSystemTrayIcon::activated,
            &app,
            [showWindow](QSystemTrayIcon::ActivationReason reason) {
                if (reason == QSystemTrayIcon::Trigger ||
                    reason == QSystemTrayIcon::DoubleClick) {
                    showWindow();
                }
            });

        QObject::connect(
            &antivirusController,
            &AntivirusController::statusChanged,
            &tray,
            [&tray](const QString& message) {
                tray.setToolTip(
                    QStringLiteral("BladeAntivirus\n") +
                    message.left(100));
            });

        QObject::connect(
            &antivirusController,
            &AntivirusController::scanFinished,
            &tray,
            [&tray, &window](int, int detected, int) {
                if (detected > 0 && window && !window->isVisible()) {
                    tray.showMessage(
                        QStringLiteral("BladeAntivirus"),
                        QStringLiteral(
                            "Threats found: %1. Open the app for details.")
                        .arg(detected),
                        QSystemTrayIcon::Warning,
                        10000);
                }
            });

        tray.setContextMenu(&trayMenu);
        tray.setToolTip(QStringLiteral("BladeAntivirus"));
        tray.show();
    }

    // Show the window unless explicitly started in background
    // with an available system tray.
    if (!startHidden || !trayAvailable)
        showWindow();

    return app.exec();
}
