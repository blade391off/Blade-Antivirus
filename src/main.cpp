
#include <QCoreApplication>
#include <QDebug>
#include <QFileInfo>
#include <QGuiApplication>
#include <QIcon>
#include <QObject>
#include <QQmlApplicationEngine>
#include <QQmlContext>
#include <QUrl>

#include "scan_controller.h"
#include "app/antiviruscontroller.h"

int main(int argc, char* argv[])
{
    qputenv("QT_QUICK_CONTROLS_STYLE", "Basic");

    QGuiApplication app(argc, argv);

    QCoreApplication::setApplicationName(
        QStringLiteral("BladeAntivirus"));
    QCoreApplication::setApplicationVersion(
        QStringLiteral("1.0.0"));
    QCoreApplication::setOrganizationName(
        QStringLiteral("BladeAntivirus"));

    const QString appDir =
        QCoreApplication::applicationDirPath();

    
    const QString icoPath =
        appDir + QStringLiteral("/logo.ico");

    if (QFileInfo::exists(icoPath))
        app.setWindowIcon(QIcon(icoPath));

    
    QUrl logoUrl;

    for (const QString& name : {
             QStringLiteral("/logo.png"),
             QStringLiteral("/logo.ico")
        }) {
        const QString path = appDir + name;

        if (QFileInfo::exists(path)) {
            logoUrl = QUrl::fromLocalFile(path);
            break;
        }
    }

    
    AntivirusController antivirusController;
    ScanController scanController;

    QQmlApplicationEngine engine;

    
    engine.rootContext()->setContextProperty(
        QStringLiteral("antivirusController"),
        &antivirusController);

    
    engine.rootContext()->setContextProperty(
        QStringLiteral("scanController"),
        &scanController);

    
    engine.rootContext()->setContextProperty(
        QStringLiteral("logoUrl"),
        logoUrl);

    
    QObject::connect(
        &engine,
        &QQmlApplicationEngine::objectCreationFailed,
        &app,
        []() {
            qCritical()
                << "[BladeAntivirus] QML object creation failed";
            QCoreApplication::exit(1);
        },
        Qt::QueuedConnection);

    
    QObject::connect(
        &engine,
        &QQmlApplicationEngine::warnings,
        &app,
        [](const QList<QQmlError>& warnings) {
            for (const QQmlError& error : warnings) {
                qWarning().noquote()
                    << "[QML]" << error.toString();
            }
        });

    
    engine.loadFromModule(
        QStringLiteral("BladeAntivirus"),
        QStringLiteral("Main"));

    if (engine.rootObjects().isEmpty()) {
        qCritical()
            << "[BladeAntivirus] No root QML object."
            << "Check the QML warnings above.";
        return 1;
    }

    qInfo() << "[BladeAntivirus] Application started.";
    qInfo() << "[BladeAntivirus] Scanner controller registered.";

    return app.exec();
}
