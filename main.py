#!/usr/bin/env python3
import sys
import os
import logging
from datetime import datetime
import time
import ipaddress
import threading
from PyQt5.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout, 
                           QHBoxLayout, QPushButton, QLabel, QLineEdit, 
                           QTextEdit, QComboBox, QGroupBox, QGridLayout,
                           QTableWidget, QTableWidgetItem, QHeaderView,
                           QSplitter, QTabWidget, QStatusBar, QAction,
                           QMenuBar, QMenu, QFileDialog, QMessageBox,
                           QProgressBar, QToolTip, QFrame, QSizePolicy,
                           QStyleFactory, QCheckBox)
from PyQt5.QtCore import (QThread, pyqtSignal, Qt, QTimer, QSize, 
                         QRunnable, QObject, pyqtSlot, QThreadPool)
from PyQt5.QtGui import QIcon, QColor, QFont, QPalette

from network_scanner import NetworkScanner
from network_visualizer import NetworkVisualizer, PortVisualizer
from database_manager import DatabaseManager
from mac_lookup import MacLookup

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("network_scanner.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger('main')

class ScanWorkerSignals(QObject):
    """Signals for the scan worker thread"""
    finished = pyqtSignal()
    error = pyqtSignal(str)
    progress = pyqtSignal(str)
    device_found = pyqtSignal(dict)
    scan_result = pyqtSignal(dict)

class DeviceScanWorker(QRunnable):
    """Worker for scanning a single device in parallel"""
    
    def __init__(self, scanner, ip):
        super().__init__()
        self.scanner = scanner
        self.ip = ip
        self.signals = ScanWorkerSignals()
        
    @pyqtSlot()
    def run(self):
        try:
            # Get detailed information
            detailed_info = self.scanner.scan_device(self.ip)
            if detailed_info:
                # Emit signal with this device's info
                self.signals.device_found.emit({self.ip: detailed_info})
            self.signals.finished.emit()
        except Exception as e:
            self.signals.error.emit(f"Error scanning {self.ip}: {str(e)}")
            self.signals.finished.emit()

class ScanWorker(QThread):
    """Worker thread for network scanning operations"""
    scan_complete = pyqtSignal(dict)
    scan_progress = pyqtSignal(str)
    device_discovered = pyqtSignal(dict)  # Signal for real-time updates
    
    def __init__(self, scanner, ip_range, max_threads=10):
        super().__init__()
        self.scanner = scanner
        self.ip_range = ip_range
        self.max_threads = max_threads
        self.should_cancel = False
        self.threadpool = QThreadPool()
        self.threadpool.setMaxThreadCount(max_threads)
        self.devices_result = {}
        self.active_tasks = 0
        self.task_lock = threading.Lock()
    
    def cancel(self):
        """Cancel the running scan"""
        self.should_cancel = True
    
    def run(self):
        try:
            # Emit progress update
            self.scan_progress.emit(f"Discovering devices in {self.ip_range}...")
            
            # Initial ARP discovery
            devices = self.scanner.discover_network(self.ip_range)
            
            if self.should_cancel:
                self.scan_progress.emit("Scan cancelled")
                self.scan_complete.emit(self.devices_result)
                return
            
            # Process each discovered device in parallel
            total = len(devices)
            self.scan_progress.emit(f"Found {total} devices. Starting detailed scan...")
            self.active_tasks = total
            
            if total == 0:
                self.scan_progress.emit("No devices found")
                self.scan_complete.emit({})
                return
            
            for device in devices:
                if self.should_cancel:
                    break
                
                ip = device['ip']
                
                # Create a worker for this device
                worker = DeviceScanWorker(self.scanner, ip)
                worker.signals.device_found.connect(self.handle_device_found)
                worker.signals.finished.connect(self.handle_task_finished)
                worker.signals.error.connect(lambda msg: self.scan_progress.emit(msg))
                
                # Start the worker
                self.threadpool.start(worker)
            
            # Wait for all tasks to complete or cancel
            while self.active_tasks > 0 and not self.should_cancel:
                self.msleep(100)  # Sleep for 100ms to prevent CPU hammering
            
            if self.should_cancel:
                self.scan_progress.emit("Scan cancelled")
            else:
                self.scan_progress.emit("Scan completed")
            
            # Emit final results
            self.scan_complete.emit(self.devices_result)
            
        except Exception as e:
            logger.error(f"Error in scan worker: {e}")
            self.scan_progress.emit(f"Error: {str(e)}")
            self.scan_complete.emit(self.devices_result)
    
    def handle_device_found(self, device_info):
        """Handle discovery of a device from a worker thread"""
        self.devices_result.update(device_info)
        self.device_discovered.emit(device_info)
    
    def handle_task_finished(self):
        """Handle completion of a device scan task"""
        with self.task_lock:
            self.active_tasks -= 1
            remaining = self.active_tasks
        
        # Update progress
        if not self.should_cancel and remaining >= 0:
            self.scan_progress.emit(f"Scanning... {remaining} devices remaining")

class MainWindow(QMainWindow):
    """Main application window"""
    
    def __init__(self):
        super().__init__()
        
        # Initialize database
        self.db_manager = DatabaseManager()
        
        # Initialize MAC lookup service
        self.mac_lookup = MacLookup()
        
        # Initialize scanner
        self.scanner = NetworkScanner(self.db_manager, self.mac_lookup)
        
        # Current device data
        self.current_devices = {}
        
        # Initialize dark theme flag
        self.dark_mode = True
        
        # Set application style for better visuals
        QApplication.setStyle(QStyleFactory.create('Fusion'))
        
        # Initialize UI first
        self.init_ui()
        
        # Apply dark theme after UI is initialized
        self.apply_theme()
        
        # Timer for updating interface
        self.update_timer = QTimer()
        self.update_timer.timeout.connect(self.update_status)
        self.update_timer.start(1000)  # Update every second
        
        # Set window properties
        self.setWindowTitle("Visual Network Scanner")
        self.setGeometry(100, 100, 1200, 800)
        self.setMinimumSize(800, 600)  # Set minimum window size
        
        logger.info("Application initialized")
    
    def apply_theme(self):
        """Apply the current theme (dark or light)"""
        if self.dark_mode:
            # Dark theme
            dark_palette = QPalette()
            
            # Set colors
            dark_palette.setColor(QPalette.Window, QColor(53, 53, 53))
            dark_palette.setColor(QPalette.WindowText, QColor(255, 255, 255))
            dark_palette.setColor(QPalette.Base, QColor(35, 35, 35))
            dark_palette.setColor(QPalette.AlternateBase, QColor(53, 53, 53))
            dark_palette.setColor(QPalette.ToolTipBase, QColor(25, 25, 25))
            dark_palette.setColor(QPalette.ToolTipText, QColor(255, 255, 255))
            dark_palette.setColor(QPalette.Text, QColor(255, 255, 255))
            dark_palette.setColor(QPalette.Button, QColor(53, 53, 53))
            dark_palette.setColor(QPalette.ButtonText, QColor(255, 255, 255))
            dark_palette.setColor(QPalette.BrightText, QColor(255, 0, 0))
            dark_palette.setColor(QPalette.Link, QColor(42, 130, 218))
            dark_palette.setColor(QPalette.Highlight, QColor(42, 130, 218))
            dark_palette.setColor(QPalette.HighlightedText, QColor(255, 255, 255))
            
            # Apply dark palette to the application instance
            QApplication.instance().setPalette(dark_palette)
            
            # Set stylesheet for additional customization
            QApplication.instance().setStyleSheet("""
                QToolTip { color: #ffffff; background-color: #2a82da; border: 1px solid white; }
                QGroupBox { border: 1px solid #555555; border-radius: 3px; margin-top: 1.5ex; }
                QGroupBox::title { subcontrol-origin: margin; subcontrol-position: top center; padding: 0 3px; }
                QTabBar::tab { background: #353535; color: #ffffff; padding: 5px; }
                QTabBar::tab:selected { background: #555555; }
                QHeaderView::section { background-color: #353535; color: white; padding: 4px; }
                QTableView { gridline-color: #555555; }
            """)
            
            # No special handling for visualizers - let them use dark theme too
        else:
            # Light theme - use default style
            QApplication.instance().setPalette(QApplication.style().standardPalette())
            QApplication.instance().setStyleSheet("")
    
    def toggle_theme(self):
        """Toggle between dark and light themes"""
        self.dark_mode = not self.dark_mode
        self.apply_theme()
        
        # Update theme menu item text
        theme_action_text = "Switch to &Light Theme" if self.dark_mode else "Switch to &Dark Theme"
        if hasattr(self, 'theme_action'):
            self.theme_action.setText(theme_action_text)
    
    def init_ui(self):
        """Initialize user interface"""
        # Create central widget and main layout
        central_widget = QWidget()
        main_layout = QVBoxLayout()
        main_layout.setContentsMargins(10, 10, 10, 10)
        main_layout.setSpacing(10)
        
        # Create menu bar
        self.create_menu_bar()
        
        # Create control panel
        control_panel = self.create_control_panel()
        main_layout.addLayout(control_panel)
        
        # Add horizontal separator
        separator = QFrame()
        separator.setFrameShape(QFrame.HLine)
        separator.setFrameShadow(QFrame.Sunken)
        main_layout.addWidget(separator)
        
        # Create splitter for main content area
        content_splitter = QSplitter(Qt.Horizontal)
        
        # Create visualization panel
        vis_panel = self.create_visualization_panel()
        content_splitter.addWidget(vis_panel)
        
        # Create info panel
        info_panel = self.create_info_panel()
        content_splitter.addWidget(info_panel)
        
        # Set initial sizes (60% visualization, 40% info)
        content_splitter.setSizes([600, 400])
        main_layout.addWidget(content_splitter, 1)  # 1 = stretch factor
        
        # Add progress bar
        self.progress_bar = QProgressBar()
        self.progress_bar.setVisible(False)  # Hide initially
        main_layout.addWidget(self.progress_bar)
        
        # Create status bar
        self.status_bar = QStatusBar()
        self.setStatusBar(self.status_bar)
        self.status_bar.showMessage("Ready")
        
        # Set layout
        central_widget.setLayout(main_layout)
        self.setCentralWidget(central_widget)
    
    def create_menu_bar(self):
        """Create application menu bar"""
        menu_bar = self.menuBar()
        
        # File menu
        file_menu = menu_bar.addMenu("&File")
        
        export_action = QAction("&Export Scan Results...", self)
        export_action.triggered.connect(self.export_results)
        file_menu.addAction(export_action)
        
        file_menu.addSeparator()
        
        exit_action = QAction("E&xit", self)
        exit_action.triggered.connect(self.close)
        file_menu.addAction(exit_action)
        
        # Scan menu
        scan_menu = menu_bar.addMenu("&Scan")
        
        quick_scan_action = QAction("&Quick Scan", self)
        quick_scan_action.triggered.connect(self.start_quick_scan)
        scan_menu.addAction(quick_scan_action)
        
        deep_scan_action = QAction("&Deep Scan", self)
        deep_scan_action.triggered.connect(self.start_deep_scan)
        scan_menu.addAction(deep_scan_action)
        
        scan_menu.addSeparator()
        
        self.monitor_action = QAction("Start &Monitoring", self)
        self.monitor_action.triggered.connect(self.toggle_monitoring)
        scan_menu.addAction(self.monitor_action)
        
        # View menu
        view_menu = menu_bar.addMenu("&View")
        
        refresh_action = QAction("&Refresh Display", self)
        refresh_action.triggered.connect(self.refresh_display)
        view_menu.addAction(refresh_action)
        
        view_menu.addSeparator()
        
        # Add theme toggle action
        theme_action_text = "Switch to &Light Theme" if self.dark_mode else "Switch to &Dark Theme"
        self.theme_action = QAction(theme_action_text, self)
        self.theme_action.triggered.connect(self.toggle_theme)
        view_menu.addAction(self.theme_action)
        
        # Help menu
        help_menu = menu_bar.addMenu("&Help")
        
        about_action = QAction("&About", self)
        about_action.triggered.connect(self.show_about)
        help_menu.addAction(about_action)
    
    def create_control_panel(self):
        """Create the control panel with scan controls"""
        layout = QHBoxLayout()
        layout.setSpacing(15)
        
        # IP range input
        ip_group = QGroupBox("Network Range")
        ip_layout = QVBoxLayout()
        
        ip_input_layout = QHBoxLayout()
        self.ip_range_label = QLabel("IP Range:")
        ip_input_layout.addWidget(self.ip_range_label)
        
        self.ip_range_input = QLineEdit("192.168.1.0/24")
        self.ip_range_input.setToolTip("Enter an IP range in CIDR notation (e.g., 192.168.1.0/24)")
        ip_input_layout.addWidget(self.ip_range_input)
        
        ip_layout.addLayout(ip_input_layout)
        
        # Add common networks dropdown
        networks_layout = QHBoxLayout()
        networks_layout.addWidget(QLabel("Common Networks:"))
        
        self.network_combo = QComboBox()
        self.network_combo.addItems([
            "192.168.0.0/24", 
            "192.168.1.0/24", 
            "10.0.0.0/24",
            "172.16.0.0/24"
        ])
        self.network_combo.currentTextChanged.connect(self.set_ip_range)
        networks_layout.addWidget(self.network_combo)
        
        ip_layout.addLayout(networks_layout)
        ip_group.setLayout(ip_layout)
        layout.addWidget(ip_group, 2)  # 2 = stretch factor
        
        # Scan controls
        scan_group = QGroupBox("Scan Controls")
        scan_layout = QVBoxLayout()
        
        # Add real-time visualization option
        self.realtime_viz = QCheckBox("Real-time visualization")
        self.realtime_viz.setToolTip("Update visualization as devices are discovered")
        self.realtime_viz.setChecked(True)
        scan_layout.addWidget(self.realtime_viz)
        
        # Add vendor lookup option
        self.vendor_lookup = QCheckBox("Use MAC vendor lookup")
        self.vendor_lookup.setToolTip("Use online service to identify device manufacturers")
        self.vendor_lookup.setChecked(True)
        scan_layout.addWidget(self.vendor_lookup)
        
        # Create button layout for scan/cancel
        button_layout = QHBoxLayout()
        
        # Scan button with enhanced styling
        self.scan_button = QPushButton("Scan Network")
        self.scan_button.setToolTip("Start scanning the specified IP range")
        self.scan_button.setMinimumHeight(40)
        self.scan_button.clicked.connect(self.start_scan)
        button_layout.addWidget(self.scan_button)
        
        # Cancel button - hidden initially
        self.cancel_button = QPushButton("Cancel")
        self.cancel_button.setToolTip("Cancel the current scan")
        self.cancel_button.setMinimumHeight(40)
        self.cancel_button.clicked.connect(self.cancel_scan)
        self.cancel_button.setVisible(False)  # Hidden initially
        button_layout.addWidget(self.cancel_button)
        
        scan_layout.addLayout(button_layout)
        
        # Monitor toggle with enhanced styling
        self.monitor_button = QPushButton("Start Monitoring")
        self.monitor_button.setToolTip("Start/stop continuous network monitoring")
        self.monitor_button.setMinimumHeight(40)
        self.monitor_button.clicked.connect(self.toggle_monitoring)
        scan_layout.addWidget(self.monitor_button)
        
        scan_group.setLayout(scan_layout)
        layout.addWidget(scan_group, 1)  # 1 = stretch factor
        
        return layout
    
    def set_ip_range(self, value):
        """Set IP range from dropdown selection"""
        self.ip_range_input.setText(value)
    
    def create_visualization_panel(self):
        """Create the network visualization panel"""
        group_box = QGroupBox("Network Visualization")
        layout = QVBoxLayout()
        
        # Create the network visualizer
        self.visualizer = NetworkVisualizer(width=5, height=4)
        self.visualizer.set_node_selected_callback(self.on_node_selected)
        self.visualizer.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)
        layout.addWidget(self.visualizer)
        
        # Add a helpful note
        note = QLabel("Click on a node to view device details. Click outside nodes to deselect.")
        note.setStyleSheet("color: #666666; font-style: italic;")
        note.setAlignment(Qt.AlignCenter)
        layout.addWidget(note)
        
        group_box.setLayout(layout)
        return group_box
    
    def create_info_panel(self):
        """Create the information panel with device details"""
        tabs = QTabWidget()
        
        # Store reference to the tabs widget
        self.detail_tabs = tabs
        
        # Device details tab
        device_tab = QWidget()
        device_layout = QVBoxLayout()
        
        # Add title label
        device_title = QLabel("Selected Device Information")
        device_title.setStyleSheet("font-weight: bold; font-size: 14px;")
        device_title.setAlignment(Qt.AlignCenter)
        device_layout.addWidget(device_title)
        
        self.device_info = QTextEdit()
        self.device_info.setReadOnly(True)
        device_layout.addWidget(self.device_info)
        
        # Add port visualization widget
        port_title = QLabel("Open Ports Visualization")
        port_title.setStyleSheet("font-weight: bold; font-size: 14px;")
        port_title.setAlignment(Qt.AlignCenter)
        device_layout.addWidget(port_title)
        
        self.port_visualizer = PortVisualizer()
        self.port_visualizer.setMinimumHeight(150)
        device_layout.addWidget(self.port_visualizer)
        
        device_tab.setLayout(device_layout)
        tabs.addTab(device_tab, "Device Details")
        
        # Scan log tab
        log_tab = QWidget()
        log_layout = QVBoxLayout()
        
        log_title = QLabel("Scan Activity Log")
        log_title.setStyleSheet("font-weight: bold; font-size: 14px;")
        log_title.setAlignment(Qt.AlignCenter)
        log_layout.addWidget(log_title)
        
        self.scan_log = QTextEdit()
        self.scan_log.setReadOnly(True)
        self.scan_log.setStyleSheet("font-family: monospace;")
        log_layout.addWidget(self.scan_log)
        
        clear_button = QPushButton("Clear Log")
        clear_button.clicked.connect(self.clear_scan_log)
        log_layout.addWidget(clear_button)
        
        log_tab.setLayout(log_layout)
        tabs.addTab(log_tab, "Scan Log")
        
        # Device list tab
        device_list_tab = QWidget()
        device_list_layout = QVBoxLayout()
        
        list_title = QLabel("Discovered Devices")
        list_title.setStyleSheet("font-weight: bold; font-size: 14px;")
        list_title.setAlignment(Qt.AlignCenter)
        device_list_layout.addWidget(list_title)
        
        self.device_table = QTableWidget()
        self.device_table.setColumnCount(5)
        self.device_table.setHorizontalHeaderLabels(["IP Address", "Hostname", "MAC Address", "Type", "OS"])
        self.device_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.device_table.setSelectionBehavior(QTableWidget.SelectRows)
        self.device_table.setEditTriggers(QTableWidget.NoEditTriggers)
        self.device_table.cellClicked.connect(self.on_table_cell_clicked)
        device_list_layout.addWidget(self.device_table)
        
        device_list_tab.setLayout(device_list_layout)
        tabs.addTab(device_list_tab, "Device List")
        
        return tabs
    
    def clear_scan_log(self):
        """Clear the scan log"""
        self.scan_log.clear()
    
    def start_scan(self):
        """Start network scan"""
        ip_range = self.ip_range_input.text().strip()
        
        # Validate IP range
        try:
            ipaddress.ip_network(ip_range, strict=False)
        except ValueError as e:
            QMessageBox.warning(self, "Invalid IP Range", f"The IP range is invalid: {str(e)}")
            return
        
        # Update UI
        self.scan_button.setEnabled(False)
        self.scan_button.setText("Scanning...")
        self.scan_log.append(f"[{datetime.now().strftime('%H:%M:%S')}] Starting scan of {ip_range}")
        
        # Show and reset progress bar
        self.progress_bar.setVisible(True)
        self.progress_bar.setRange(0, 0)  # Indeterminate progress
        
        # Show cancel button
        self.cancel_button.setVisible(True)
        
        # Configure scanner with options
        self.scanner.use_vendor_lookup = self.vendor_lookup.isChecked()
        
        # Clear current devices if not appending to visualization
        if not self.realtime_viz.isChecked():
            self.current_devices = {}
        
        # Create and start worker thread with parallelism
        thread_count = min(20, QThreadPool.globalInstance().maxThreadCount())
        self.scan_worker = ScanWorker(self.scanner, ip_range, max_threads=thread_count)
        self.scan_worker.scan_progress.connect(self.update_scan_progress)
        self.scan_worker.scan_complete.connect(self.handle_scan_complete)
        
        # Connect real-time update signal if enabled
        if self.realtime_viz.isChecked():
            self.scan_worker.device_discovered.connect(self.handle_device_discovered)
        
        self.scan_worker.start()
    
    def cancel_scan(self):
        """Cancel the current scan operation"""
        if hasattr(self, 'scan_worker') and self.scan_worker.isRunning():
            self.scan_log.append(f"[{datetime.now().strftime('%H:%M:%S')}] Cancelling scan...")
            self.scan_worker.cancel()
            self.cancel_button.setEnabled(False)  # Prevent multiple cancellations
    
    def update_scan_progress(self, message):
        """Update scan progress in the log"""
        self.scan_log.append(f"[{datetime.now().strftime('%H:%M:%S')}] {message}")
        self.status_bar.showMessage(message)
        
        # Auto-scroll to the bottom of the log
        self.scan_log.verticalScrollBar().setValue(
            self.scan_log.verticalScrollBar().maximum()
        )
    
    def handle_device_discovered(self, device_info):
        """Handle real-time device discovery updates"""
        # Update current devices dictionary
        self.current_devices.update(device_info)
        
        # Update the visualization with the new device
        self.visualizer.update_graph(self.current_devices)
        
        # Update device table
        self.update_device_table(self.current_devices)
        
        # Update status
        device_ip = list(device_info.keys())[0]
        device_type = device_info[device_ip].get('type', 'unknown')
        self.status_bar.showMessage(f"Discovered {device_type} device at {device_ip}")
    
    def handle_scan_complete(self, devices):
        """Handle scan completion"""
        # Update UI
        self.scan_button.setEnabled(True)
        self.scan_button.setText("Scan Network")
        self.cancel_button.setVisible(False)  # Hide cancel button
        
        # Hide progress bar
        self.progress_bar.setVisible(False)
        
        # Store current devices
        self.current_devices = devices
        
        # Log completion
        device_count = len(devices)
        self.scan_log.append(f"[{datetime.now().strftime('%H:%M:%S')}] Scan completed. Found {device_count} devices.")
        self.status_bar.showMessage(f"Scan completed. Found {device_count} devices.")
        
        # Save devices to database
        self.db_manager.save_devices([info for ip, info in devices.items()])
        
        # Update visualization (if not already updated in real-time)
        if not self.realtime_viz.isChecked():
            self.visualizer.update_graph(devices)
            self.update_device_table(devices)
    
    def update_device_table(self, devices):
        """Update the device table with scan results"""
        self.device_table.setRowCount(0)  # Clear table
        
        row = 0
        for ip, device in devices.items():
            self.device_table.insertRow(row)
            
            ip_item = QTableWidgetItem(ip)
            ip_item.setToolTip(f"IP: {ip}")
            self.device_table.setItem(row, 0, ip_item)
            
            hostname = device.get('hostname', 'Unknown')
            hostname_item = QTableWidgetItem(hostname)
            hostname_item.setToolTip(f"Hostname: {hostname}")
            self.device_table.setItem(row, 1, hostname_item)
            
            mac = device.get('mac', 'Unknown')
            self.device_table.setItem(row, 2, QTableWidgetItem(mac))
            
            device_type = device.get('type', 'Unknown')
            type_item = QTableWidgetItem(device_type.capitalize())
            self.device_table.setItem(row, 3, type_item)
            
            os = device.get('os', 'Unknown')
            os_item = QTableWidgetItem(os)
            self.device_table.setItem(row, 4, os_item)
            
            # Color code rows by device type
            color = self.visualizer.network_graph.node_colors.get(device.get('type', 'unknown'), '#ffffff')
            # Make color more subtle as background
            r, g, b = int(color[1:3], 16), int(color[3:5], 16), int(color[5:7], 16)
            light_color = f"#{r:02x}{g:02x}{b:02x}{40:02x}"  # 25% opacity
            
            for col in range(self.device_table.columnCount()):
                self.device_table.item(row, col).setBackground(QColor(light_color))
            
            row += 1
    
    def on_node_selected(self, node, node_data):
        """Handle node selection in the visualization"""
        if not node or node == 'Internet':
            self.device_info.clear()
            self.port_visualizer.clear_ports()
            return
        
        # Display device information
        info_text = f"<h2>Device: {node}</h2>\n"
        
        if node_data:
            hostname = node_data.get('hostname', 'Unknown')
            mac = node_data.get('mac', 'Unknown')
            device_type = node_data.get('type', 'Unknown')
            os = node_data.get('os', 'Unknown')
            vendor = node_data.get('vendor', 'Unknown')
            
            info_text += f"<p><b>Hostname:</b> {hostname}</p>\n"
            info_text += f"<p><b>MAC Address:</b> {mac}</p>\n"
            if vendor != 'Unknown':
                info_text += f"<p><b>Vendor:</b> {vendor}</p>\n"
            info_text += f"<p><b>Device Type:</b> {device_type}</p>\n"
            info_text += f"<p><b>Operating System:</b> {os}</p>\n"
            
            # Add open ports
            if 'ports' in node_data:
                info_text += "<h3>Open Ports:</h3>\n<ul>\n"
                
                # Update port visualizer
                port_data = []
                
                for port in node_data['ports']:
                    service = f"{port['service']} ({port['product']} {port['version']})" if 'product' in port and port['product'] else port['service']
                    info_text += f"<li><b>{port['port']}:</b> {service}</li>\n"
                    
                    # Add port data for visualization
                    port_data.append({
                        'port': port['port'],
                        'service': port['service'],
                        'state': port.get('state', 'open')
                    })
                
                info_text += "</ul>\n"
                
                # Update port visualization
                self.port_visualizer.update_ports(port_data)
            else:
                self.port_visualizer.clear_ports()
        
        self.device_info.setHtml(info_text)
        
        # Switch to the device details tab
        if hasattr(self, 'detail_tabs'):
            self.detail_tabs.setCurrentIndex(0)  # Switch to first tab (device details)
    
    def on_table_cell_clicked(self, row, column):
        """Handle click on device table"""
        ip = self.device_table.item(row, 0).text()
        self.visualizer.selected_node = ip
        
        # Get node data from graph if available
        if ip in self.visualizer.network_graph.graph.nodes:
            node_data = self.visualizer.network_graph.graph.nodes[ip]
            self.on_node_selected(ip, node_data)
        
        # Refresh visualization to highlight selected node
        self.visualizer.update_graph({n: self.visualizer.network_graph.graph.nodes[n] for n in self.visualizer.network_graph.graph 
                                     if n != 'Internet'})
    
    def toggle_monitoring(self):
        """Toggle continuous network monitoring"""
        if self.scanner.scan_thread and self.scanner.scan_thread.is_alive():
            # Stop monitoring
            self.scanner.stop_continuous_scan()
            self.monitor_button.setText("Start Monitoring")
            self.monitor_action.setText("Start &Monitoring")
            self.scan_log.append(f"[{datetime.now().strftime('%H:%M:%S')}] Monitoring stopped")
            self.status_bar.showMessage("Monitoring stopped")
        else:
            # Start monitoring
            ip_range = self.ip_range_input.text().strip()
            
            # Validate IP range
            try:
                ipaddress.ip_network(ip_range, strict=False)
            except ValueError as e:
                QMessageBox.warning(self, "Invalid IP Range", f"The IP range is invalid: {str(e)}")
                return
            
            success = self.scanner.start_continuous_scan(ip_range, interval=60)
            if success:
                self.monitor_button.setText("Stop Monitoring")
                self.monitor_action.setText("Stop &Monitoring")
                self.scan_log.append(f"[{datetime.now().strftime('%H:%M:%S')}] Started monitoring {ip_range}")
                self.status_bar.showMessage("Monitoring active")
    
    def update_status(self):
        """Update status display (called by timer)"""
        if self.scanner.scan_thread and self.scanner.scan_thread.is_alive():
            self.status_bar.showMessage(f"Monitoring active - Last update: {datetime.now().strftime('%H:%M:%S')}")
    
    def start_quick_scan(self):
        """Perform a quick scan (ARP only)"""
        self.start_scan()
    
    def start_deep_scan(self):
        """Perform a deep scan with service detection"""
        # This would be implemented with more detailed scanning options
        QMessageBox.information(self, "Deep Scan", "Deep scan not implemented in this demo")
    
    def refresh_display(self):
        """Refresh the visualization display"""
        # Re-render current data
        if hasattr(self.visualizer, 'network_graph') and self.visualizer.network_graph.graph:
            self.visualizer.update_graph(
                {n: self.visualizer.network_graph.graph.nodes[n] for n in self.visualizer.network_graph.graph 
                if n != 'Internet'}
            )
    
    def export_results(self):
        """Export scan results to file"""
        # Implement export functionality
        file_name, _ = QFileDialog.getSaveFileName(
            self, "Export Results", "", "CSV Files (*.csv);;JSON Files (*.json);;All Files (*)"
        )
        
        if file_name:
            QMessageBox.information(self, "Export", f"Would export to {file_name} (not implemented in demo)")
    
    def show_about(self):
        """Show about dialog"""
        about_text = """<h2>Visual Network Scanner</h2>
        <p>A network discovery and visualization tool.</p>
        <p>Created by: phantom-kali</p>
        <p>Version: 1.0</p>
        <p>Date: 2025-03-26</p>"""
        
        QMessageBox.about(self, "About Visual Network Scanner", about_text)
    
    def closeEvent(self, event):
        """Handle window close event"""
        # Stop background threads
        if self.scanner.scan_thread and self.scanner.scan_thread.is_alive():
            self.scanner.stop_continuous_scan()
        
        # Accept the close event
        event.accept()

if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = MainWindow()
    window.show()
    sys.exit(app.exec_())