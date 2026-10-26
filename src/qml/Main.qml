
import QtQuick
import QtQuick.Controls
import QtQuick.Dialogs
import QtQuick.Layouts
import QtQuick.Window

ApplicationWindow {
    id: root

    visible: true
    visibility: Window.Windowed
    width: 1180
    height: 760
    minimumWidth: 960
    minimumHeight: 640
    title: "BladeAntivirus"
    color: "#0B0E14"

    property string activePage: "Home"
    property string statusMessage: "Protection ready"
    property bool realTimeProtection: true
    property bool automaticUpdates: true

    property bool scanRunning: false
    property bool scanPaused: false
    property int scanProgress: 0
    property int scannedFiles: 0
    property int totalFiles: 0
    property int detectedThreats: 0
    property string currentScanFile: "Waiting..."
    property string scanMode: "Quick scan"
    property var scanResults: []

    property url logoUrl: "file:///D:/BladeAntivirus/logo.ico"

    readonly property color panel: "#111620"
    readonly property color panelLight: "#171E2A"
    readonly property color borderColor: "#252E3C"
    readonly property color muted: "#8793A5"
    readonly property color accent: "#38D6A3"
    readonly property color blue: "#6C91FF"
    readonly property color danger: "#FF6B78"
    readonly property color warning: "#E9B965"

    Shortcut {
        sequence: "F11"
        onActivated: {
            root.visibility =
                root.visibility === Window.FullScreen
                ? Window.Windowed : Window.FullScreen
        }
    }

    Shortcut {
        sequence: "Escape"
        onActivated: {
            if (root.visibility === Window.FullScreen)
                root.visibility = Window.Windowed
        }
    }

    function navigate(page) {
        activePage = page
    }

    function shortFileName(path) {
        var name = String(path)
        var separator = Math.max(name.lastIndexOf("/"),
                                 name.lastIndexOf("\\"))
        name = name.substring(separator + 1)

        if (name.length > 8)
            return name.substring(0, 7) + "…"

        return name
    }

    function hasScanController() {
        return typeof scanController !== "undefined"
    }

    function prepareScan(mode) {
        if (scanRunning) {
            statusMessage = "A scan is already running."
            return false
        }

        scanMode = mode
        scanProgress = 0
        scannedFiles = 0
        totalFiles = 0
        detectedThreats = 0
        currentScanFile = "Preparing scan..."
        scanResults = []
        scanPaused = false
        statusMessage = "Preparing " + mode.toLowerCase() + "..."
        activePage = "Scan"
        return true
    }

    function runQuickScan() {
        if (!prepareScan("Quick scan"))
            return

        if (!hasScanController()) {
            statusMessage = "Scanner is not connected in main.cpp."
            currentScanFile = "Scanner unavailable"
            return
        }

        if (!scanController.startQuickScan()) {
            statusMessage = "Could not start quick scan."
            currentScanFile = "Unable to start"
        } else {
            scanRunning = true
        }
    }

    function runFullScan() {
        if (!prepareScan("Full scan"))
            return

        if (!hasScanController()) {
            statusMessage = "Scanner is not connected in main.cpp."
            currentScanFile = "Scanner unavailable"
            return
        }

        if (!scanController.startFullScan()) {
            statusMessage = "Could not start full scan."
            currentScanFile = "Unable to start"
        } else {
            scanRunning = true
        }
    }

    function runCustomScan() {
        if (!scanRunning)
            customScanFolderDialog.open()
        else
            statusMessage = "Stop the current scan before starting another."
    }

    function startCustomScan(folderUrl) {
        if (!prepareScan("Custom scan"))
            return

        if (!hasScanController()) {
            statusMessage = "Scanner is not connected in main.cpp."
            currentScanFile = "Scanner unavailable"
            return
        }

        var localPath = folderUrl.toLocalFile()

        if (!localPath || localPath.length === 0) {
            statusMessage = "Invalid folder selected."
            currentScanFile = "Invalid folder"
            return
        }

        if (!scanController.startScan(localPath, true)) {
            statusMessage = "Could not start custom scan."
            currentScanFile = "Unable to start"
        } else {
            scanRunning = true
        }
    }

    function pauseCurrentScan() {
        if (hasScanController() && scanRunning && !scanPaused) {
            scanController.pauseScan()
            scanPaused = true
            statusMessage = "Pause requested..."
        }
    }

    function resumeCurrentScan() {
        if (hasScanController() && scanRunning && scanPaused) {
            scanController.resumeScan()
            scanPaused = false
            statusMessage = "Resuming scan..."
        }
    }

    function stopCurrentScan() {
        if (hasScanController() && scanRunning) {
            scanController.cancelScan()
            statusMessage = "Stopping scan..."
        }
    }

    FolderDialog {
        id: customScanFolderDialog
        title: "Select a folder for custom scan"

        onAccepted: root.startCustomScan(selectedFolder)

        onRejected: {
            root.statusMessage = "Folder selection cancelled."
        }
    }

    Connections {
        target: antivirusController

        function onStatusChanged(message) {
            root.statusMessage = message
        }

        function onScanProgress(message) {
            root.statusMessage = message
        }

        function onScanFinished(scanned, detected, errors) {
            root.statusMessage =
                "Scan finished | Files: " + scanned
                + " | Threats: " + detected
                + " | Errors: " + errors
        }
    }

    Connections {
        target: typeof scanController !== "undefined"
                ? scanController : null

        function onStatusChanged(status) {
            root.statusMessage = status

            if (status === "Scanning")
                root.scanRunning = true

            if (status === "Scan completed"
                    || status === "Scan cancelled"
                    || status === "Failed to load hash database"
                    || status === "No files found") {
                root.scanRunning = false
                root.scanPaused = false
            }
        }

        function onProgressChanged(percentage, checked, total, currentFile) {
            root.scanProgress = Math.max(0, Math.min(100, percentage))
            root.scannedFiles = checked
            root.totalFiles = total
            root.currentScanFile = root.shortFileName(currentFile)
        }

        function onFileChecked(displayName, verdict, details) {
            var updated = root.scanResults.slice()

            updated.unshift({
                "name": root.shortFileName(displayName),
                "verdict": verdict,
                "details": details
            })

            if (updated.length > 200)
                updated.pop()

            root.scanResults = updated
        }

        function onScanFinished(checked, threats, wasCancelled) {
            root.scanRunning = false
            root.scanPaused = false
            root.scannedFiles = checked
            root.detectedThreats = threats

            if (wasCancelled) {
                root.statusMessage = "Scan cancelled."
                root.currentScanFile = "Scan stopped"
            } else {
                root.scanProgress = 100
                root.statusMessage = "Scan completed."
                root.currentScanFile = "Finished"
            }
        }
    }

    Rectangle {
        anchors.fill: parent
        color: root.color

        RowLayout {
            anchors.fill: parent
            spacing: 0

            // SIDEBAR
            Rectangle {
                Layout.preferredWidth: 226
                Layout.fillHeight: true
                color: "#0E121A"
                border.color: "#202735"
                border.width: 1

                ColumnLayout {
                    anchors.fill: parent
                    anchors.margins: 18
                    spacing: 0

                    RowLayout {
                        Layout.fillWidth: true
                        spacing: 11

                        Rectangle {
                            width: 39
                            height: 39
                            radius: 12
                            color: "#15382F"
                            border.color: "#286B57"
                            clip: true

                            Image {
                                id: logoImage
                                anchors.fill: parent
                                source: root.logoUrl
                                fillMode: Image.PreserveAspectCrop
                                smooth: true
                                visible: status === Image.Ready
                            }

                            Text {
                                anchors.centerIn: parent
                                text: "B"
                                visible: logoImage.status !== Image.Ready
                                color: root.accent
                                font.pixelSize: 24
                                font.bold: true
                            }
                        }

                        Column {
                            spacing: 2

                            Text {
                                text: "Blade"
                                color: "#F3F6FA"
                                font.pixelSize: 20
                                font.bold: true
                            }

                            Text {
                                text: "ANTIVIRUS"
                                color: root.muted
                                font.pixelSize: 9
                                font.letterSpacing: 2.2
                            }
                        }
                    }

                    Item { Layout.preferredHeight: 34 }

                    Text {
                        text: "WORKSPACE"
                        color: "#687589"
                        font.pixelSize: 9
                        font.bold: true
                        font.letterSpacing: 1.1
                    }

                    Item { Layout.preferredHeight: 12 }

                    Repeater {
                        model: [
                            { name: "Home", symbol: "⌂" },
                            { name: "Scan", symbol: "⌕" },
                            { name: "Protection", symbol: "◇" },
                            { name: "Quarantine", symbol: "▤" },
                            { name: "Updates", symbol: "↻" }
                        ]

                        delegate: Rectangle {
                            Layout.fillWidth: true
                            Layout.preferredHeight: 45
                            Layout.bottomMargin: 5
                            radius: 9

                            color: root.activePage === modelData.name
                                   ? "#1B2930"
                                   : navMouse.containsMouse
                                     ? "#171E28" : "transparent"

                            Rectangle {
                                width: 3
                                height: 23
                                radius: 2
                                color: root.accent
                                visible: root.activePage === modelData.name
                                anchors.left: parent.left
                                anchors.verticalCenter: parent.verticalCenter
                            }

                            RowLayout {
                                anchors.fill: parent
                                anchors.leftMargin: 14
                                anchors.rightMargin: 12
                                spacing: 12

                                Text {
                                    text: modelData.symbol
                                    color: root.activePage === modelData.name
                                           ? root.accent : "#8995A7"
                                    font.pixelSize: 22
                                    Layout.preferredWidth: 23
                                    horizontalAlignment: Text.AlignHCenter
                                }

                                Text {
                                    text: modelData.name
                                    color: root.activePage === modelData.name
                                           ? "#F0F5F8" : "#A4AFBE"
                                    font.pixelSize: 13
                                    font.weight: root.activePage === modelData.name
                                                 ? Font.DemiBold : Font.Normal
                                    Layout.fillWidth: true
                                }
                            }

                            MouseArea {
                                id: navMouse
                                anchors.fill: parent
                                hoverEnabled: true
                                cursorShape: Qt.PointingHandCursor
                                onClicked: root.navigate(modelData.name)
                            }

                            Behavior on color {
                                ColorAnimation { duration: 130 }
                            }
                        }
                    }

                    Item { Layout.fillHeight: true }

                    Rectangle {
                        Layout.fillWidth: true
                        Layout.preferredHeight: 104
                        radius: 12
                        color: "#131B25"
                        border.color: root.borderColor

                        Column {
                            anchors.fill: parent
                            anchors.margins: 13
                            spacing: 7

                            Row {
                                spacing: 7

                                Rectangle {
                                    width: 7
                                    height: 7
                                    radius: 4
                                    color: root.scanRunning
                                           ? root.blue : root.accent
                                    anchors.verticalCenter: parent.verticalCenter
                                }

                                Text {
                                    text: "SYSTEM"
                                    color: root.muted
                                    font.pixelSize: 10
                                    font.bold: true
                                }
                            }

                            Text {
                                text: "Blade Engine"
                                color: "#E6ECF4"
                                font.pixelSize: 12
                                font.bold: true
                            }

                            Text {
                                text: "Version 1.0.0"
                                color: root.muted
                                font.pixelSize: 11
                            }
                        }
                    }

                    Item { Layout.preferredHeight: 12 }

                    Rectangle {
                        Layout.fillWidth: true
                        Layout.preferredHeight: 42
                        radius: 9
                        color: settingsMouse.containsMouse
                               ? "#1A222E" : "transparent"

                        RowLayout {
                            anchors.fill: parent
                            anchors.leftMargin: 10
                            spacing: 10

                            Text {
                                text: "⚙"
                                color: "#8995A7"
                                font.pixelSize: 19
                            }

                            Text {
                                text: "Settings"
                                color: "#B2BDCB"
                                font.pixelSize: 13
                            }
                        }

                        MouseArea {
                            id: settingsMouse
                            anchors.fill: parent
                            hoverEnabled: true
                            cursorShape: Qt.PointingHandCursor
                            onClicked: root.navigate("Settings")
                        }
                    }
                }
            }

            // MAIN CONTENT
            ColumnLayout {
                Layout.fillWidth: true
                Layout.fillHeight: true
                spacing: 0

                Rectangle {
                    Layout.fillWidth: true
                    Layout.preferredHeight: 69
                    color: "#0E121A"
                    border.color: "#202735"
                    border.width: 1

                    RowLayout {
                        anchors.fill: parent
                        anchors.leftMargin: 29
                        anchors.rightMargin: 29

                        Text {
                            text: root.activePage
                            color: "#F2F5FA"
                            font.pixelSize: 19
                            font.bold: true
                        }

                        Item { Layout.fillWidth: true }

                        Rectangle {
                            radius: 8
                            color: "#151D27"
                            border.color: "#283443"
                            Layout.preferredHeight: 34
                            Layout.preferredWidth: 145

                            Row {
                                anchors.centerIn: parent
                                spacing: 8

                                Rectangle {
                                    width: 7
                                    height: 7
                                    radius: 4
                                    color: root.realTimeProtection
                                           ? root.accent : root.warning
                                    anchors.verticalCenter: parent.verticalCenter
                                }

                                Text {
                                    text: root.realTimeProtection
                                          ? "Protection active" : "Protection off"
                                    color: "#C1CBD7"
                                    font.pixelSize: 10
                                }
                            }
                        }
                    }
                }

                StackLayout {
                    id: pages
                    Layout.fillWidth: true
                    Layout.fillHeight: true

                    currentIndex: {
                        switch (root.activePage) {
                        case "Home": return 0
                        case "Scan": return 1
                        case "Protection": return 2
                        case "Quarantine": return 3
                        case "Updates": return 4
                        default: return 5
                        }
                    }

                    // HOME
                    Flickable {
                        clip: true
                        contentWidth: width
                        contentHeight: dashboardColumn.implicitHeight
                        ScrollBar.vertical: ScrollBar {}

                        ColumnLayout {
                            id: dashboardColumn
                            width: parent.width
                            spacing: 20

                            Item { Layout.preferredHeight: 3 }

                            Rectangle {
                                Layout.fillWidth: true
                                Layout.preferredHeight: 205
                                Layout.leftMargin: 27
                                Layout.rightMargin: 27
                                radius: 17
                                color: "#13251F"
                                border.color: "#23513F"
                                clip: true

                                Rectangle {
                                    width: 280
                                    height: 280
                                    radius: 140
                                    color: "#19392F"
                                    opacity: 0.55
                                    x: parent.width - 190
                                    y: -125
                                }

                                ColumnLayout {
                                    anchors.fill: parent
                                    anchors.margins: 25
                                    spacing: 12

                                    RowLayout {
                                        spacing: 9

                                        Rectangle {
                                            width: 31
                                            height: 31
                                            radius: 9
                                            color: "#204A3B"

                                            Text {
                                                anchors.centerIn: parent
                                                text: "✓"
                                                color: root.accent
                                                font.pixelSize: 20
                                                font.bold: true
                                            }
                                        }

                                        Text {
                                            text: root.realTimeProtection
                                                  ? "YOUR PROTECTION IS ACTIVE"
                                                  : "ATTENTION REQUIRED"
                                            color: root.accent
                                            font.pixelSize: 11
                                            font.bold: true
                                            font.letterSpacing: 1
                                        }
                                    }

                                    Text {
                                        text: root.realTimeProtection
                                              ? "All under control."
                                              : "Check protection settings."
                                        color: "#F0F7F3"
                                        font.pixelSize: 26
                                        font.bold: true
                                    }

                                    Text {
                                        text: "Run a scan to find potential threats."
                                        color: "#A7C4B8"
                                        font.pixelSize: 12
                                        wrapMode: Text.WordWrap
                                    }

                                    Item { Layout.fillHeight: true }

                                    RowLayout {
                                        spacing: 10

                                        Button {
                                            text: "Quick Scan"
                                            onClicked: root.runQuickScan()

                                            background: Rectangle {
                                                radius: 8
                                                color: parent.down
                                                       ? "#24AD80" : root.accent
                                            }

                                            contentItem: Text {
                                                text: parent.text
                                                color: "#071711"
                                                font.pixelSize: 12
                                                font.bold: true
                                                horizontalAlignment: Text.AlignHCenter
                                                verticalAlignment: Text.AlignVCenter
                                            }
                                        }

                                        Button {
                                            text: "Full Scan"
                                            onClicked: root.runFullScan()

                                            background: Rectangle {
                                                radius: 8
                                                color: "#20382F"
                                                border.color: "#35634F"
                                            }

                                            contentItem: Text {
                                                text: parent.text
                                                color: "#D5E9DF"
                                                font.pixelSize: 12
                                                horizontalAlignment: Text.AlignHCenter
                                                verticalAlignment: Text.AlignVCenter
                                            }
                                        }
                                    }
                                }
                            }

                            Text {
                                Layout.leftMargin: 29
                                text: "System Overview"
                                color: "#E7ECF4"
                                font.pixelSize: 16
                                font.bold: true
                            }

                            GridLayout {
                                Layout.fillWidth: true
                                Layout.leftMargin: 27
                                Layout.rightMargin: 27
                                columns: width >= 780 ? 3 : 1
                                columnSpacing: 13
                                rowSpacing: 13

                                Repeater {
                                    model: [
                                        {
                                            title: "Real-time protection",
                                            value: root.realTimeProtection
                                                   ? "Active" : "Off",
                                            detail: "Module status",
                                            symbol: "◇"
                                        },
                                        {
                                            title: "Files scanned",
                                            value: String(root.scannedFiles),
                                            detail: "Current session",
                                            symbol: "↻"
                                        },
                                        {
                                            title: "Threats detected",
                                            value: String(root.detectedThreats),
                                            detail: "Current session",
                                            symbol: "⌕"
                                        }
                                    ]

                                    delegate: Rectangle {
                                        Layout.fillWidth: true
                                        Layout.preferredHeight: 139
                                        radius: 12
                                        color: root.panel
                                        border.color: root.borderColor

                                        ColumnLayout {
                                            anchors.fill: parent
                                            anchors.margins: 15
                                            spacing: 8

                                            Text {
                                                text: modelData.symbol
                                                color: root.blue
                                                font.pixelSize: 22
                                            }

                                            Text {
                                                text: modelData.title
                                                color: "#A7B2C1"
                                                font.pixelSize: 11
                                                wrapMode: Text.WordWrap
                                                Layout.fillWidth: true
                                            }

                                            Text {
                                                text: modelData.value
                                                color: "#EDF2F8"
                                                font.pixelSize: 16
                                                font.bold: true
                                            }

                                            Text {
                                                text: modelData.detail
                                                color: root.muted
                                                font.pixelSize: 10
                                            }
                                        }
                                    }
                                }
                            }

                            Rectangle {
                                Layout.fillWidth: true
                                Layout.leftMargin: 27
                                Layout.rightMargin: 27
                                Layout.bottomMargin: 25
                                Layout.preferredHeight: 76
                                radius: 11
                                color: root.panel
                                border.color: root.borderColor

                                RowLayout {
                                    anchors.fill: parent
                                    anchors.margins: 16
                                    spacing: 12

                                    Text {
                                        text: "i"
                                        color: root.blue
                                        font.pixelSize: 22
                                        font.bold: true
                                    }

                                    ColumnLayout {
                                        Layout.fillWidth: true
                                        spacing: 4

                                        Text {
                                            text: "Blade Engine status"
                                            color: "#E6ECF5"
                                            font.pixelSize: 12
                                            font.bold: true
                                        }

                                        Text {
                                            text: root.statusMessage
                                            color: root.muted
                                            font.pixelSize: 11
                                            wrapMode: Text.WordWrap
                                            Layout.fillWidth: true
                                        }
                                    }
                                }
                            }
                        }
                    }

                    // SCAN — EMBEDDED IN THE MAIN WINDOW
                    Flickable {
                        id: scanFlick
                        clip: true
                        contentWidth: width
                        contentHeight: scanColumn.implicitHeight
                        ScrollBar.vertical: ScrollBar {}

                        ColumnLayout {
                            id: scanColumn
                            width: scanFlick.width
                            spacing: 15

                            Item { Layout.preferredHeight: 2 }

                            RowLayout {
                                Layout.leftMargin: 28
                                Layout.rightMargin: 28
                                Layout.fillWidth: true

                                ColumnLayout {
                                    Layout.fillWidth: true
                                    spacing: 5

                                    Text {
                                        text: "Security Scanner"
                                        color: "#EFF3F8"
                                        font.pixelSize: 23
                                        font.bold: true
                                    }

                                    Text {
                                        text: "Scan your files for known threats."
                                        color: root.muted
                                        font.pixelSize: 12
                                        wrapMode: Text.WordWrap
                                    }
                                }

                                Rectangle {
                                    radius: 9
                                    color: root.scanRunning
                                           ? "#172A40" : "#13251F"
                                    border.color: root.scanRunning
                                                  ? "#314D70" : "#23513F"
                                    implicitWidth: stateText.implicitWidth + 22
                                    implicitHeight: 34

                                    Text {
                                        id: stateText
                                        anchors.centerIn: parent
                                        text: root.scanRunning
                                              ? (root.scanPaused ? "PAUSED" : "SCANNING")
                                              : "READY"
                                        color: root.scanRunning
                                               ? root.blue : root.accent
                                        font.pixelSize: 10
                                        font.bold: true
                                    }
                                }
                            }

                            // Scan type cards
                            RowLayout {
                                Layout.fillWidth: true
                                Layout.leftMargin: 28
                                Layout.rightMargin: 28
                                spacing: 10

                                Repeater {
                                    model: [
                                        {
                                            name: "Quick",
                                            desc: "Quick scan",
                                            symbol: "⌕",
                                            kind: "quick"
                                        },
                                        {
                                            name: "Full",
                                            desc: "Full scan",
                                            symbol: "▦",
                                            kind: "full"
                                        },
                                        {
                                            name: "Custom",
                                            desc: "Choose folder",
                                            symbol: "＋",
                                            kind: "custom"
                                        }
                                    ]

                                    delegate: Rectangle {
                                        Layout.fillWidth: true
                                        Layout.preferredHeight: 83
                                        radius: 12
                                        color: root.scanMode === modelData.desc
                                               ? "#172A28" : root.panel
                                        border.color: root.scanMode === modelData.desc
                                                      ? "#2E8067" : root.borderColor

                                        ColumnLayout {
                                            anchors.fill: parent
                                            anchors.margins: 11
                                            spacing: 5

                                            RowLayout {
                                                spacing: 7

                                                Text {
                                                    text: modelData.symbol
                                                    color: root.accent
                                                    font.pixelSize: 19
                                                }

                                                Text {
                                                    text: modelData.name
                                                    color: "#EAF0F7"
                                                    font.pixelSize: 12
                                                    font.bold: true
                                                }
                                            }

                                            Text {
                                                text: modelData.desc
                                                color: root.muted
                                                font.pixelSize: 10
                                                wrapMode: Text.WordWrap
                                                Layout.fillWidth: true
                                            }
                                        }

                                        MouseArea {
                                            anchors.fill: parent
                                            cursorShape: Qt.PointingHandCursor
                                            onClicked: {
                                                if (modelData.kind === "quick")
                                                    root.runQuickScan()
                                                else if (modelData.kind === "full")
                                                    root.runFullScan()
                                                else
                                                    root.runCustomScan()
                                            }
                                        }
                                    }
                                }
                            }

                            // Main scan progress panel
                            Rectangle {
                                Layout.fillWidth: true
                                Layout.leftMargin: 28
                                Layout.rightMargin: 28
                                Layout.preferredHeight: 252
                                radius: 15
                                color: "#111923"
                                border.color: root.scanRunning
                                              ? "#2A514A" : root.borderColor

                                ColumnLayout {
                                    anchors.fill: parent
                                    anchors.margins: 20
                                    spacing: 13

                                    RowLayout {
                                        Layout.fillWidth: true

                                        ColumnLayout {
                                            Layout.fillWidth: true
                                            spacing: 4

                                            Text {
                                                text: root.scanMode
                                                color: "#F0F4F9"
                                                font.pixelSize: 16
                                                font.bold: true
                                            }

                                            Text {
                                                text: root.scanRunning
                                                      ? (root.scanPaused
                                                         ? "Scan paused"
                                                         : "Checking files...")
                                                      : root.statusMessage
                                                color: root.muted
                                                font.pixelSize: 11
                                                wrapMode: Text.WordWrap
                                                Layout.fillWidth: true
                                            }
                                        }

                                        Text {
                                            text: root.scanProgress + "%"
                                            color: root.accent
                                            font.pixelSize: 25
                                            font.bold: true
                                        }
                                    }

                                    // Progress bar
                                    Rectangle {
                                        Layout.fillWidth: true
                                        height: 8
                                        radius: 4
                                        color: "#242E3B"
                                        clip: true

                                        Rectangle {
                                            width: parent.width
                                                   * root.scanProgress / 100
                                            height: parent.height
                                            radius: 4
                                            color: root.accent

                                            Behavior on width {
                                                NumberAnimation { duration: 180 }
                                            }
                                        }
                                    }

                                    Text {
                                        text: root.currentScanFile
                                        color: "#B7C4D3"
                                        font.pixelSize: 11
                                        elide: Text.ElideRight
                                        Layout.fillWidth: true
                                    }

                                    Rectangle {
                                        Layout.fillWidth: true
                                        height: 1
                                        color: root.borderColor
                                    }

                                    RowLayout {
                                        Layout.fillWidth: true
                                        spacing: 0

                                        ColumnLayout {
                                            Layout.fillWidth: true
                                            spacing: 5

                                            Text {
                                                text: "FILES CHECKED"
                                                color: root.muted
                                                font.pixelSize: 9
                                                font.bold: true
                                            }

                                            Text {
                                                text: root.scannedFiles
                                                color: "#EDF2F8"
                                                font.pixelSize: 20
                                                font.bold: true
                                            }
                                        }

                                        ColumnLayout {
                                            Layout.fillWidth: true
                                            spacing: 5

                                            Text {
                                                text: "TOTAL FILES"
                                                color: root.muted
                                                font.pixelSize: 9
                                                font.bold: true
                                            }

                                            Text {
                                                text: root.totalFiles > 0
                                                      ? root.totalFiles : "—"
                                                color: "#EDF2F8"
                                                font.pixelSize: 20
                                                font.bold: true
                                            }
                                        }

                                        ColumnLayout {
                                            Layout.fillWidth: true
                                            spacing: 5

                                            Text {
                                                text: "THREATS"
                                                color: root.muted
                                                font.pixelSize: 9
                                                font.bold: true
                                            }

                                            Text {
                                                text: root.detectedThreats
                                                color: root.detectedThreats > 0
                                                       ? root.danger : root.accent
                                                font.pixelSize: 20
                                                font.bold: true
                                            }
                                        }
                                    }

                                    RowLayout {
                                        Layout.fillWidth: true
                                        spacing: 8

                                        Button {
                                            text: root.scanPaused
                                                  ? "Resume" : "Pause"
                                            enabled: root.scanRunning
                                            onClicked: {
                                                if (root.scanPaused)
                                                    root.resumeCurrentScan()
                                                else
                                                    root.pauseCurrentScan()
                                            }

                                            background: Rectangle {
                                                radius: 8
                                                color: parent.enabled
                                                       ? "#1C2D42" : "#171E27"
                                                border.color: "#344D6B"
                                            }

                                            contentItem: Text {
                                                text: parent.text
                                                color: parent.enabled
                                                       ? "#DCE8FA" : "#6D7888"
                                                font.pixelSize: 11
                                                horizontalAlignment: Text.AlignHCenter
                                                verticalAlignment: Text.AlignVCenter
                                            }
                                        }

                                        Button {
                                            text: "Stop"
                                            enabled: root.scanRunning
                                            onClicked: root.stopCurrentScan()

                                            background: Rectangle {
                                                radius: 8
                                                color: parent.enabled
                                                       ? "#3A2028" : "#171E27"
                                                border.color: parent.enabled
                                                              ? "#74404B" : "#252E3C"
                                            }

                                            contentItem: Text {
                                                text: parent.text
                                                color: parent.enabled
                                                       ? "#FFB7C0" : "#6D7888"
                                                font.pixelSize: 11
                                                horizontalAlignment: Text.AlignHCenter
                                                verticalAlignment: Text.AlignVCenter
                                            }
                                        }

                                        Item { Layout.fillWidth: true }

                                        Text {
                                            text: root.scanRunning
                                                  ? "Scan in progress"
                                                  : "Scanner ready"
                                            color: root.muted
                                            font.pixelSize: 10
                                        }
                                    }
                                }
                            }

                            // Scan results
                            Rectangle {
                                Layout.fillWidth: true
                                Layout.leftMargin: 28
                                Layout.rightMargin: 28
                                Layout.bottomMargin: 25
                                Layout.preferredHeight: 300
                                radius: 14
                                color: root.panel
                                border.color: root.borderColor
                                clip: true

                                ColumnLayout {
                                    anchors.fill: parent
                                    spacing: 0

                                    RowLayout {
                                        Layout.fillWidth: true
                                        Layout.margins: 16

                                        ColumnLayout {
                                            Layout.fillWidth: true
                                            spacing: 4

                                            Text {
                                                text: "Scan results"
                                                color: "#EAF0F7"
                                                font.pixelSize: 14
                                                font.bold: true
                                            }

                                            Text {
                                                text: root.scanResults.length
                                                      + " recent file results"
                                                color: root.muted
                                                font.pixelSize: 10
                                            }
                                        }

                                        Rectangle {
                                            radius: 7
                                            color: "#1B2533"
                                            implicitWidth: resultCount.implicitWidth + 16
                                            implicitHeight: 27

                                            Text {
                                                id: resultCount
                                                anchors.centerIn: parent
                                                text: root.scanResults.length
                                                color: "#D8E3F2"
                                                font.pixelSize: 11
                                            }
                                        }
                                    }

                                    Rectangle {
                                        Layout.fillWidth: true
                                        height: 1
                                        color: root.borderColor
                                    }

                                    RowLayout {
                                        Layout.fillWidth: true
                                        Layout.leftMargin: 16
                                        Layout.rightMargin: 16
                                        Layout.topMargin: 10
                                        Layout.bottomMargin: 8

                                        Text {
                                            text: "FILE"
                                            color: root.muted
                                            font.pixelSize: 9
                                            font.bold: true
                                            Layout.fillWidth: true
                                        }

                                        Text {
                                            text: "RESULT"
                                            color: root.muted
                                            font.pixelSize: 9
                                            font.bold: true
                                            Layout.preferredWidth: 90
                                            horizontalAlignment: Text.AlignRight
                                        }
                                    }

                                    ListView {
                                        id: scanResultsList
                                        Layout.fillWidth: true
                                        Layout.fillHeight: true
                                        clip: true
                                        model: root.scanResults
                                        spacing: 0

                                        ScrollBar.vertical: ScrollBar {}

                                        delegate: Rectangle {
                                            width: scanResultsList.width
                                            height: 48
                                            color: index % 2 === 0
                                                   ? "#121923" : "#10161F"

                                            RowLayout {
                                                anchors.fill: parent
                                                anchors.leftMargin: 16
                                                anchors.rightMargin: 16
                                                spacing: 10

                                                Rectangle {
                                                    width: 7
                                                    height: 7
                                                    radius: 4
                                                    color: {
                                                        var v = String(modelData.verdict)
                                                                .toUpperCase()
                                                        if (v.indexOf("MALICIOUS") >= 0
                                                                || v.indexOf("THREAT") >= 0
                                                                || v.indexOf("DETECTED") >= 0)
                                                            return root.danger
                                                        if (v.indexOf("SUSPICIOUS") >= 0)
                                                            return root.warning
                                                        return root.accent
                                                    }
                                                }

                                                ColumnLayout {
                                                    Layout.fillWidth: true
                                                    spacing: 3

                                                    Text {
                                                        text: modelData.name
                                                        color: "#E3EAF3"
                                                        font.pixelSize: 11
                                                        elide: Text.ElideRight
                                                        Layout.fillWidth: true
                                                    }

                                                    Text {
                                                        text: modelData.details
                                                        color: root.muted
                                                        font.pixelSize: 9
                                                        elide: Text.ElideRight
                                                        Layout.fillWidth: true
                                                    }
                                                }

                                                Text {
                                                    text: modelData.verdict
                                                    color: {
                                                        var v = String(modelData.verdict)
                                                                .toUpperCase()
                                                        if (v.indexOf("MALICIOUS") >= 0
                                                                || v.indexOf("THREAT") >= 0
                                                                || v.indexOf("DETECTED") >= 0)
                                                            return root.danger
                                                        if (v.indexOf("SUSPICIOUS") >= 0)
                                                            return root.warning
                                                        return root.accent
                                                    }
                                                    font.pixelSize: 9
                                                    font.bold: true
                                                    elide: Text.ElideRight
                                                    Layout.preferredWidth: 90
                                                    horizontalAlignment: Text.AlignRight
                                                }
                                            }
                                        }

                                        Text {
                                            anchors.centerIn: parent
                                            visible: root.scanResults.length === 0
                                            text: root.scanRunning
                                                  ? "Waiting for scan results..."
                                                  : "No results yet. Start a scan to check files."
                                            color: root.muted
                                            font.pixelSize: 11
                                            horizontalAlignment: Text.AlignHCenter
                                        }
                                    }
                                }
                            }
                        }
                    }

                    // PROTECTION
                    Flickable {
                        clip: true
                        contentWidth: width
                        contentHeight: protectionColumn.implicitHeight
                        ScrollBar.vertical: ScrollBar {}

                        ColumnLayout {
                            id: protectionColumn
                            width: parent.width
                            spacing: 16

                            Item { Layout.preferredHeight: 5 }

                            Text {
                                Layout.leftMargin: 28
                                text: "Protection Components"
                                color: "#EFF3F8"
                                font.pixelSize: 21
                                font.bold: true
                            }

                            Text {
                                Layout.leftMargin: 28
                                Layout.rightMargin: 28
                                text: "Configure BladeAntivirus core features."
                                color: root.muted
                                font.pixelSize: 12
                            }

                            Repeater {
                                model: [
                                    {
                                        name: "Real-time protection",
                                        desc: "Main toggle for protection state.",
                                        key: "realtime"
                                    },
                                    {
                                        name: "Automatic updates",
                                        desc: "Allow automatic database updates.",
                                        key: "updates"
                                    }
                                ]

                                delegate: Rectangle {
                                    Layout.fillWidth: true
                                    Layout.leftMargin: 28
                                    Layout.rightMargin: 28
                                    Layout.preferredHeight: 91
                                    radius: 12
                                    color: root.panel
                                    border.color: root.borderColor

                                    RowLayout {
                                        anchors.fill: parent
                                        anchors.margins: 18
                                        spacing: 13

                                        ColumnLayout {
                                            Layout.fillWidth: true
                                            spacing: 6

                                            Text {
                                                text: modelData.name
                                                color: "#E8EDF5"
                                                font.pixelSize: 13
                                                font.bold: true
                                                wrapMode: Text.WordWrap
                                            }

                                            Text {
                                                text: modelData.desc
                                                color: root.muted
                                                font.pixelSize: 11
                                                wrapMode: Text.WordWrap
                                            }
                                        }

                                        Switch {
                                            checked: modelData.key === "realtime"
                                                     ? root.realTimeProtection
                                                     : root.automaticUpdates

                                            onToggled: {
                                                if (modelData.key === "realtime")
                                                    root.realTimeProtection = checked
                                                else
                                                    root.automaticUpdates = checked
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }

                    // QUARANTINE
                    ColumnLayout {
                        spacing: 18

                        Item { Layout.preferredHeight: 5 }

                        Text {
                            Layout.leftMargin: 28
                            text: "Quarantine"
                            color: "#EFF3F8"
                            font.pixelSize: 21
                            font.bold: true
                        }

                        Rectangle {
                            Layout.fillWidth: true
                            Layout.fillHeight: true
                            Layout.leftMargin: 28
                            Layout.rightMargin: 28
                            Layout.bottomMargin: 28
                            radius: 14
                            color: root.panel
                            border.color: root.borderColor

                            Column {
                                anchors.centerIn: parent
                                width: Math.min(parent.width - 40, 370)
                                spacing: 12

                                Rectangle {
                                    width: 58
                                    height: 58
                                    radius: 17
                                    color: "#1D2939"
                                    anchors.horizontalCenter: parent.horizontalCenter

                                    Text {
                                        anchors.centerIn: parent
                                        text: "▤"
                                        color: root.blue
                                        font.pixelSize: 27
                                    }
                                }

                                Text {
                                    width: parent.width
                                    text: "Quarantine is empty"
                                    color: "#E8EDF5"
                                    font.pixelSize: 16
                                    font.bold: true
                                    horizontalAlignment: Text.AlignHCenter
                                }

                                Text {
                                    width: parent.width
                                    text: "Detected items will appear here when quarantine processing is connected."
                                    color: root.muted
                                    font.pixelSize: 11
                                    wrapMode: Text.WordWrap
                                    horizontalAlignment: Text.AlignHCenter
                                }
                            }
                        }
                    }

                    // UPDATES
                    ColumnLayout {
                        spacing: 17

                        Item { Layout.preferredHeight: 5 }

                        Text {
                            Layout.leftMargin: 28
                            text: "Updates"
                            color: "#EFF3F8"
                            font.pixelSize: 21
                            font.bold: true
                        }

                        Rectangle {
                            Layout.fillWidth: true
                            Layout.leftMargin: 28
                            Layout.rightMargin: 28
                            Layout.preferredHeight: 190
                            radius: 14
                            color: root.panel
                            border.color: root.borderColor

                            ColumnLayout {
                                anchors.fill: parent
                                anchors.margins: 21
                                spacing: 11

                                RowLayout {
                                    spacing: 10

                                    Rectangle {
                                        width: 43
                                        height: 43
                                        radius: 12
                                        color: "#1C2B3D"

                                        Text {
                                            anchors.centerIn: parent
                                            text: "↻"
                                            color: root.blue
                                            font.pixelSize: 26
                                        }
                                    }

                                    ColumnLayout {
                                        Layout.fillWidth: true
                                        spacing: 5

                                        Text {
                                            text: "Detection database"
                                            color: "#E9EFF7"
                                            font.pixelSize: 14
                                            font.bold: true
                                        }

                                        Text {
                                            text: "Update status is currently unknown"
                                            color: root.muted
                                            font.pixelSize: 11
                                        }
                                    }
                                }

                                Rectangle {
                                    Layout.fillWidth: true
                                    height: 1
                                    color: root.borderColor
                                }

                                Text {
                                    text: "Update the databases to use the latest threat information."
                                    color: "#AAB5C4"
                                    font.pixelSize: 11
                                    wrapMode: Text.WordWrap
                                    Layout.fillWidth: true
                                }

                                Item { Layout.fillHeight: true }

                                Button {
                                    text: "Check for updates"
                                    onClicked: {
                                        if (typeof antivirusController !== "undefined"
                                                && typeof antivirusController.checkUpdates
                                                   === "function") {
                                            antivirusController.checkUpdates()
                                        } else {
                                            root.statusMessage =
                                                "C++ updater is not connected."
                                        }
                                    }

                                    background: Rectangle {
                                        radius: 8
                                        color: "#1C2D42"
                                        border.color: "#344D6B"
                                    }

                                    contentItem: Text {
                                        text: parent.text
                                        color: "#DCE8FA"
                                        font.pixelSize: 12
                                        horizontalAlignment: Text.AlignHCenter
                                        verticalAlignment: Text.AlignVCenter
                                    }
                                }
                            }
                        }
                    }

                    // SETTINGS
                    Flickable {
                        clip: true
                        contentWidth: width
                        contentHeight: settingsColumn.implicitHeight
                        ScrollBar.vertical: ScrollBar {}

                        ColumnLayout {
                            id: settingsColumn
                            width: parent.width
                            spacing: 16

                            Item { Layout.preferredHeight: 5 }

                            Text {
                                Layout.leftMargin: 28
                                text: "Settings"
                                color: "#EFF3F8"
                                font.pixelSize: 21
                                font.bold: true
                            }

                            Text {
                                Layout.leftMargin: 28
                                text: "Customize BladeAntivirus"
                                color: root.muted
                                font.pixelSize: 12
                            }

                            Rectangle {
                                Layout.fillWidth: true
                                Layout.leftMargin: 28
                                Layout.rightMargin: 28
                                Layout.preferredHeight: 100
                                radius: 12
                                color: root.panel
                                border.color: root.borderColor

                                RowLayout {
                                    anchors.fill: parent
                                    anchors.margins: 18

                                    ColumnLayout {
                                        Layout.fillWidth: true
                                        spacing: 6

                                        Text {
                                            text: "Interface theme"
                                            color: "#E8EDF5"
                                            font.pixelSize: 13
                                            font.bold: true
                                        }

                                        Text {
                                            text: "Blade dark theme"
                                            color: root.muted
                                            font.pixelSize: 11
                                        }
                                    }

                                    Rectangle {
                                        radius: 8
                                        color: "#202A39"
                                        border.color: "#344257"
                                        width: 100
                                        height: 34

                                        Text {
                                            anchors.centerIn: parent
                                            text: "Dark"
                                            color: "#DDE6F3"
                                            font.pixelSize: 11
                                        }
                                    }
                                }
                            }

                            Rectangle {
                                Layout.fillWidth: true
                                Layout.leftMargin: 28
                                Layout.rightMargin: 28
                                Layout.bottomMargin: 25
                                Layout.preferredHeight: 100
                                radius: 12
                                color: root.panel
                                border.color: root.borderColor

                                Column {
                                    anchors.fill: parent
                                    anchors.margins: 18
                                    spacing: 7

                                    Text {
                                        text: "BladeAntivirus"
                                        color: "#E9EFF7"
                                        font.pixelSize: 13
                                        font.bold: true
                                    }

                                    Text {
                                        text: "Version 1.0.0 · Qt Quick"
                                        color: root.muted
                                        font.pixelSize: 11
                                    }

                                    Text {
                                        text: "Local application interface"
                                        color: root.muted
                                        font.pixelSize: 10
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}
