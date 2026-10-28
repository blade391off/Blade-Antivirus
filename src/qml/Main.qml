import QtQuick.Dialogs
import QtQuick.Window
import QtQuick
import QtQuick.Controls
import QtQuick.Layouts

ApplicationWindow {
    id: root

    width: 1180
    height: 760
    minimumWidth: 960
    minimumHeight: 640
    visible: false  // main.cpp shows it (or keeps it in the tray)
    title: "BladeAntivirus"
    color: "#0B0E14"

    onClosing: function(close) {
        // Hide to the tray instead of quitting; "Exit" lives in the tray menu.
        if (trayAvailable) {
            close.accepted = false
            root.hide()
        }
    }

    Shortcut {
        sequence: "F11"
        onActivated: {
            root.visibility =
                root.visibility === Window.FullScreen
                ? Window.Windowed
                : Window.FullScreen
        }
    }

    Shortcut {
        sequence: "Escape"
        onActivated: {
            if (root.visibility === Window.FullScreen)
                root.visibility = Window.Windowed
        }
    }

    FolderDialog {
        id: customScanFolderDialog
        title: "Select a folder for custom scan"

        onAccepted: {
            root.scanKind = "Custom scan"
            antivirusController.startCustomScan(selectedFolder)
        }

        onRejected: {
            root.statusMessage = "Scan cancelled."
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

        function onScanningChanged() {
            if (antivirusController.scanning)
                root.beginScanUi()
        }

        function onScanStats(scanned, detected, suspicious, errors, skipped, elapsedMs, currentFile) {
            root.scanScanned = scanned
            root.scanDetected = detected
            root.scanSuspicious = suspicious
            root.scanErrors = errors
            root.scanSkipped = skipped
            root.scanElapsedMs = elapsedMs
            root.scanCurrentFile = currentFile
        }

        function onFileScanned(path, verdict, sha256, details) {
            if (verdict === "MALICIOUS" || verdict === "SUSPICIOUS")
                threatsModel.append({ path: path, verdict: verdict, sha256: sha256, details: details })
        }

        function onScanSummary(scanned, detected, suspicious, errors, skipped, elapsedMs, stopped, failure) {
            root.scanScanned = scanned
            root.scanDetected = detected
            root.scanSuspicious = suspicious
            root.scanErrors = errors
            root.scanSkipped = skipped
            root.scanElapsedMs = elapsedMs
            root.scanCurrentFile = ""
            root.scanStoppedFlag = stopped
            root.scanFailure = failure
            root.scanDone = true
        }

        function onScanFinished(scanned, detected, errors) {
            root.statusMessage =
                "Scan finished | Files: " + scanned
                + " | Threats: " + detected
                + " | Unreadable: " + errors
        }
    }

    property string activePage: "Home"
    property string statusMessage: "Protection ready"
    property bool realTimeProtection: true
    property bool automaticUpdates: true

    // Scan window state
    property string scanKind: ""
    property int scanScanned: 0
    property int scanDetected: 0
    property int scanSuspicious: 0
    property int scanErrors: 0
    property int scanSkipped: 0
    property double scanElapsedMs: 0
    property string scanCurrentFile: ""
    property string scanFailure: ""
    property bool scanDone: false
    property bool scanStoppedFlag: false
    property bool stopRequested: false

    readonly property color panel: "#111620"
    readonly property color panelLight: "#171E2A"
    readonly property color borderColor: "#252E3C"
    readonly property color muted: "#8793A5"
    readonly property color accent: "#38D6A3"
    readonly property color blue: "#6C91FF"

    function navigate(page) {
        activePage = page
    }

    function pad2(n) {
        return n < 10 ? "0" + n : "" + n
    }

    function formatElapsed(ms) {
        var total = Math.floor(ms / 1000)
        var h = Math.floor(total / 3600)
        var m = Math.floor((total % 3600) / 60)
        var s = total % 60
        return (h > 0 ? h + ":" : "") + pad2(m) + ":" + pad2(s)
    }

    function formatCount(n) {
        return Number(n).toLocaleString(Qt.locale(), "f", 0)
    }

    function beginScanUi() {
        threatsModel.clear()
        scanScanned = 0
        scanDetected = 0
        scanSuspicious = 0
        scanErrors = 0
        scanSkipped = 0
        scanElapsedMs = 0
        scanCurrentFile = ""
        scanFailure = ""
        scanDone = false
        scanStoppedFlag = false
        stopRequested = false
        scanPopup.open()
    }

    function scanTitle() {
        if (scanFailure !== "")
            return "Scan could not run"
        if (!scanDone)
            return stopRequested ? "Stopping scan..."
                                 : (scanKind !== "" ? scanKind : "Scan") + " in progress"
        if (scanStoppedFlag)
            return "Scan stopped"
        if (scanDetected > 0)
            return "Threats found"
        return scanSuspicious > 0 ? "Suspicious files found" : "No threats found"
    }

    function scanSubtitle() {
        if (!scanDone)
            return "Checking files against the Blade database"
        if (scanFailure !== "")
            return "Nothing was scanned"
        return "Checked " + formatCount(scanScanned) + " files in " + formatElapsed(scanElapsedMs)
    }

    function scanTone() {
        if (scanFailure !== "" || (scanDone && scanDetected > 0))
            return "#FF6B6B"
        if (scanDone && scanSuspicious > 0)
            return "#E5B45C"
        if (scanDone)
            return accent
        return blue
    }

    function scanSymbol() {
        if (scanFailure !== "")
            return "✕"
        if (!scanDone)
            return "⌕"
        return (scanDetected > 0 || scanSuspicious > 0) ? "!" : "✓"
    }

    function runQuickScan() {
        scanKind = "Quick scan"
        antivirusController.startQuickScan()
    }

    function runFullScan() {
        scanKind = "Full scan"
        antivirusController.startFullScan()
    }

    function runCustomScan() {
        scanKind = "Custom scan"
        customScanFolderDialog.open()
    }

    Rectangle {
        anchors.fill: parent
        color: root.color

        RowLayout {
            anchors.fill: parent
            spacing: 0

            // Left panel
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
                                source: logoUrl
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
                                   ? "#1B2930" : navMouse.containsMouse
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
                                    color: root.accent
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

            // Main workspace
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
                            Layout.preferredWidth: 135

                            Row {
                                anchors.centerIn: parent
                                spacing: 8

                                Rectangle {
                                    width: 7
                                    height: 7
                                    radius: 4
                                    color: root.realTimeProtection
                                           ? root.accent : "#E5B45C"
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

                                Rectangle {
                                    width: 180
                                    height: 180
                                    radius: 90
                                    color: "#1A493A"
                                    opacity: 0.4
                                    x: parent.width - 125
                                    y: 75
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
                                            text: "  Quick Scan  "
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
                                        { title: "Real-time protection",
                                          value: root.realTimeProtection ? "Active" : "Off",
                                          detail: "Module status",
                                          symbol: "◇" },
                                        { title: "Threat databases",
                                          value: "Not checked",
                                          detail: "Check updates",
                                          symbol: "↻" },
                                        { title: "Last scan",
                                          value: "No data",
                                          detail: "Run the first scan",
                                          symbol: "⌕" }
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

                                    Rectangle {
                                        width: 34
                                        height: 34
                                        radius: 9
                                        color: "#202B3D"

                                        Text {
                                            anchors.centerIn: parent
                                            text: "i"
                                            color: root.blue
                                            font.pixelSize: 18
                                            font.bold: true
                                        }
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
                                        }
                                    }
                                }
                            }
                        }
                    }

                    // SCAN
                    Flickable {
                        clip: true
                        contentWidth: width    
                        contentHeight: scanColumn.implicitHeight
                        ScrollBar.vertical: ScrollBar {}

                        ColumnLayout {
                            id: scanColumn
                            width: parent.width
                            spacing: 17

                            Item { Layout.preferredHeight: 5 }

                            Text {
                                Layout.leftMargin: 28
                                text: "Choose scan type"
                                color: "#EFF3F8"
                                font.pixelSize: 21
                                font.bold: true
                            }

                            Text {
                                Layout.leftMargin: 28
                                Layout.rightMargin: 28
                                text: "Scan files and look for known threats using the Blade engine."
                                color: root.muted
                                font.pixelSize: 12
                                wrapMode: Text.WordWrap
                            }

                            Repeater {
                                model: [
                                    { name: "Quick scan",
                                      desc: "Quick search for threats in selected areas.",
                                      symbol: "⌕", kind: "quick" },
                                    { name: "Full scan",
                                      desc: "Deeper system file scan.",
                                      symbol: "▦", kind: "full" },
                                    { name: "Custom scan",
                                      desc: "Choose specific files and folders to scan.",
                                      symbol: "＋", kind: "custom" }
                                ]

                                delegate: Rectangle {
                                    Layout.fillWidth: true
                                    Layout.leftMargin: 28
                                    Layout.rightMargin: 28
                                    Layout.preferredHeight: 115
                                    radius: 13
                                    color: root.panel
                                    border.color: scanCardMouse.containsMouse
                                                  ? "#3B5265" : root.borderColor

                                    Behavior on border.color {
                                        ColorAnimation { duration: 120 }
                                    }

                                    RowLayout {
                                        anchors.fill: parent
                                        anchors.margins: 19
                                        spacing: 15

                                        Rectangle {
                                            width: 47
                                            height: 47
                                            radius: 12
                                            color: "#1C293B"

                                            Text {
                                                anchors.centerIn: parent
                                                text: modelData.symbol
                                                color: root.blue
                                                font.pixelSize: 25
                                            }
                                        }

                                        ColumnLayout {
                                            Layout.fillWidth: true
                                            spacing: 7

                                            Text {
                                                text: modelData.name
                                                color: "#EAF0F7"
                                                font.pixelSize: 14
                                                font.bold: true
                                            }

                                            Text {
                                                text: modelData.desc
                                                color: root.muted
                                                font.pixelSize: 11
                                                wrapMode: Text.WordWrap
                                                Layout.fillWidth: true
                                            }
                                        }

                                        Button {
                                            text: "Select"
                                            onClicked: {
                                                if (modelData.kind === "quick")
                                                    root.runQuickScan()
                                                else if (modelData.kind === "full")
                                                    root.runFullScan()
                                                else if (modelData.kind === "custom")
                                                    root.runCustomScan()
                                            }

                                            background: Rectangle {
                                                radius: 8
                                                color: parent.down
                                                       ? "#26394E" : "#1A2637"
                                                border.color: "#344760"
                                            }

                                            contentItem: Text {
                                                text: parent.text
                                                color: "#DAE5F7"
                                                font.pixelSize: 11
                                                horizontalAlignment: Text.AlignHCenter
                                                verticalAlignment: Text.AlignVCenter
                                            }
                                        }
                                    }

                                   MouseArea {
                                   id: scanCardMouse
                                   anchors.fill: parent
                                   hoverEnabled: true
                                   acceptedButtons: Qt.NoButton
                                   z: -1
                                   }
                                }
                            }

                            Rectangle {
                                Layout.fillWidth: true
                                Layout.leftMargin: 28
                                Layout.rightMargin: 28
                                Layout.bottomMargin: 24
                                Layout.preferredHeight: 85
                                radius: 12
                                color: "#171E29"
                                border.color: root.borderColor

                                Column {
                                    anchors.fill: parent
                                    anchors.margins: 15
                                    spacing: 6

                                    Text {
                                        text: "Important"
                                        color: "#E9C078"
                                        font.pixelSize: 12
                                        font.bold: true
                                    }

                                        Text {
                                            text: "A progress window with detailed results opens as soon as a scan starts."
                                            color: root.muted
                                            font.pixelSize: 11
                                            wrapMode: Text.WordWrap
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
                                    { name: "Real-time protection",
                                      desc: "Main toggle for protection state.",
                                      key: "realtime" },
                                    { name: "Automatic updates",
                                      desc: "Allow automatic database updates.",
                                      key: "updates" }
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
                                    text: "Detected items will appear here after connecting scan result processing."
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
                                                && typeof antivirusController.checkUpdates === "function") {
                                            antivirusController.checkUpdates()
                                        } else {
                                            root.statusMessage =
                                                "C++ updater is not yet connected to the interface"
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

                Rectangle {
                    Layout.fillWidth: true
                    Layout.preferredHeight: 30
                    color: "#0E121A"
                    border.color: "#202735"
                    border.width: 1

                    Text {
                        anchors.fill: parent
                        anchors.leftMargin: 29
                        anchors.rightMargin: 29
                        verticalAlignment: Text.AlignVCenter
                        text: root.statusMessage
                        color: root.muted
                        font.pixelSize: 11
                        elide: Text.ElideRight
                    }
                }
            }
        }
    }

    ListModel { id: threatsModel }

    component StatCard: Rectangle {
        id: card
        property string label: ""
        property string value: ""
        property color valueColor: "#E8EDF5"

        Layout.fillWidth: true
        Layout.preferredHeight: 74
        radius: 11
        color: root.panelLight
        border.color: root.borderColor

        Column {
            anchors.centerIn: parent
            spacing: 4

            Text {
                anchors.horizontalCenter: parent.horizontalCenter
                text: card.value
                color: card.valueColor
                font.pixelSize: 22
                font.bold: true
            }

            Text {
                anchors.horizontalCenter: parent.horizontalCenter
                text: card.label
                color: root.muted
                font.pixelSize: 10
            }
        }
    }

    Popup {
        id: scanPopup
        parent: Overlay.overlay
        anchors.centerIn: parent
        width: Math.min(680, root.width - 60)
        height: Math.min(580, root.height - 60)
        modal: true
        focus: true
        padding: 0
        closePolicy: root.scanDone
                     ? (Popup.CloseOnEscape | Popup.CloseOnPressOutside)
                     : Popup.NoAutoClose

        Overlay.modal: Rectangle { color: "#B3000000" }

        background: Rectangle {
            radius: 16
            color: root.panel
            border.color: root.borderColor
        }

        contentItem: Item {
            ColumnLayout {
                anchors.fill: parent
                anchors.margins: 24
                spacing: 14

                RowLayout {
                    Layout.fillWidth: true
                    spacing: 14

                    Rectangle {
                        width: 48
                        height: 48
                        radius: 14
                        color: root.panelLight
                        border.color: root.scanTone()

                        Text {
                            anchors.centerIn: parent
                            text: root.scanSymbol()
                            color: root.scanTone()
                            font.pixelSize: 24
                            font.bold: true
                        }
                    }

                    ColumnLayout {
                        Layout.fillWidth: true
                        spacing: 3

                        Text {
                            text: root.scanTitle()
                            color: "#F0F4FA"
                            font.pixelSize: 19
                            font.bold: true
                        }

                        Text {
                            text: root.scanSubtitle()
                            color: root.muted
                            font.pixelSize: 11
                        }
                    }

                    Text {
                        visible: !root.scanDone
                        text: root.formatElapsed(root.scanElapsedMs)
                        color: "#C9D3E0"
                        font.pixelSize: 18
                        font.bold: true
                    }
                }

                ProgressBar {
                    Layout.fillWidth: true
                    visible: !root.scanDone
                    indeterminate: true
                    palette.dark: root.accent
                }

                RowLayout {
                    Layout.fillWidth: true
                    spacing: 10

                    StatCard {
                        label: "Files scanned"
                        value: root.formatCount(root.scanScanned)
                    }

                    StatCard {
                        label: "Threats"
                        value: root.formatCount(root.scanDetected)
                        valueColor: root.scanDetected > 0 ? "#FF6B6B" : root.accent
                    }

                    StatCard {
                        label: "Suspicious"
                        value: root.formatCount(root.scanSuspicious)
                        valueColor: root.scanSuspicious > 0 ? "#E5B45C" : root.accent
                    }

                    StatCard {
                        label: "Unreadable"
                        value: root.formatCount(root.scanErrors)
                    }

                    StatCard {
                        label: "Skipped"
                        value: root.formatCount(root.scanSkipped)
                    }
                }

                ColumnLayout {
                    Layout.fillWidth: true
                    visible: !root.scanDone
                    spacing: 4

                    Text {
                        text: "Currently scanning"
                        color: root.muted
                        font.pixelSize: 10
                    }

                    Text {
                        Layout.fillWidth: true
                        text: root.scanCurrentFile !== "" ? root.scanCurrentFile : "Preparing..."
                        color: "#C3CDDA"
                        font.pixelSize: 11
                        elide: Text.ElideMiddle
                    }
                }

                Text {
                    Layout.fillWidth: true
                    visible: root.scanFailure !== ""
                    text: root.scanFailure
                    color: "#FF8E8E"
                    font.pixelSize: 12
                    wrapMode: Text.WordWrap
                }

                Text {
                    visible: threatsModel.count > 0
                    text: "Detected items (" + threatsModel.count + ")"
                    color: "#FF8E8E"
                    font.pixelSize: 13
                    font.bold: true
                }

                ListView {
                    id: threatList
                    Layout.fillWidth: true
                    Layout.fillHeight: true
                    visible: threatsModel.count > 0
                    clip: true
                    spacing: 8
                    model: threatsModel
                    ScrollBar.vertical: ScrollBar {}

                    delegate: Rectangle {
                        width: ListView.view.width
                        height: 76
                        radius: 10
                        color: model.verdict === "MALICIOUS" ? "#1D1A21" : "#1F1D18"
                        border.color: model.verdict === "MALICIOUS" ? "#4A2A31" : "#4A4128"

                        Rectangle {
                            width: 3
                            height: parent.height - 20
                            radius: 2
                            color: model.verdict === "MALICIOUS" ? "#FF6B6B" : "#E5B45C"
                            anchors.left: parent.left
                            anchors.leftMargin: 6
                            anchors.verticalCenter: parent.verticalCenter
                        }

                        ColumnLayout {
                            anchors.fill: parent
                            anchors.leftMargin: 20
                            anchors.rightMargin: 14
                            spacing: 3

                            Text {
                                Layout.fillWidth: true
                                text: model.path
                                color: "#F0D7DA"
                                font.pixelSize: 12
                                font.bold: true
                                elide: Text.ElideMiddle
                            }

                            Text {
                                Layout.fillWidth: true
                                text: (model.verdict === "MALICIOUS" ? "MALICIOUS · " : "SUSPICIOUS · ") + model.details
                                color: model.verdict === "MALICIOUS" ? "#E7A0A8" : "#E5C98A"
                                font.pixelSize: 11
                                wrapMode: Text.WordWrap
                                maximumLineCount: 2
                                elide: Text.ElideRight
                            }

                            Text {
                                Layout.fillWidth: true
                                text: "SHA-256 " + model.sha256
                                color: "#8A7479"
                                font.pixelSize: 9
                                elide: Text.ElideRight
                            }
                        }
                    }
                }

                Item {
                    Layout.fillHeight: true
                    visible: threatsModel.count === 0
                }

                RowLayout {
                    Layout.fillWidth: true

                    Item { Layout.fillWidth: true }

                    Button {
                        visible: !root.scanDone
                        enabled: !root.stopRequested
                        text: root.stopRequested ? "Stopping..." : "Stop scan"
                        onClicked: {
                            root.stopRequested = true
                            antivirusController.stopScan()
                        }

                        background: Rectangle {
                            radius: 8
                            color: parent.down ? "#7A2F38" : "#5A2830"
                            border.color: "#8E3B46"
                            opacity: parent.enabled ? 1.0 : 0.6
                        }

                        contentItem: Text {
                            text: parent.text
                            color: "#FFD9DD"
                            font.pixelSize: 12
                            font.bold: true
                            horizontalAlignment: Text.AlignHCenter
                            verticalAlignment: Text.AlignVCenter
                        }
                    }

                    Button {
                        visible: root.scanDone
                        text: "  Close  "
                        onClicked: scanPopup.close()

                        background: Rectangle {
                            radius: 8
                            color: parent.down ? "#24AD80" : root.accent
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
                }
            }
        }
    }
}
