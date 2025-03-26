#!/usr/bin/env python3
import networkx as nx
import matplotlib.pyplot as plt
from matplotlib.backends.backend_qt5agg import FigureCanvasQTAgg as FigureCanvas
from matplotlib.figure import Figure
import random
import matplotlib.colors as mcolors
from PyQt5.QtWidgets import QSizePolicy, QWidget, QVBoxLayout
from PyQt5.QtCore import QSize

class NetworkGraph:
    """Class for creating and manipulating network graphs"""
    
    def __init__(self):
        self.graph = nx.Graph()
        self.positions = {}
        self.node_colors = {
            'router': '#ff7700',      # Orange
            'windows-pc': '#00a2ff',  # Blue
            'linux-pc': '#00cc00',    # Green
            'linux-server': '#008800', # Dark Green
            'mac': '#cccccc',         # Gray
            'mobile': '#cc00cc',      # Purple
            'web-device': '#ffcc00',  # Yellow
            'unknown': '#ff0000',     # Red
            'internet': '#000000'     # Black
        }
    
    def build_graph_from_devices(self, devices, gateway_ip=None):
        """Build a network graph from device information"""
        self.graph.clear()
        
        # Add internet node
        self.graph.add_node('Internet', type='internet')
        
        # Create all device nodes first
        for ip, device in devices.items():
            node_type = device.get('type', 'unknown')
            hostname = device.get('hostname', ip)
            self.graph.add_node(ip, 
                               type=node_type, 
                               hostname=hostname,
                               os=device.get('os', 'Unknown'),
                               mac=device.get('mac', 'Unknown'))
        
        # Determine gateway/router if not specified
        if not gateway_ip:
            for ip, device in devices.items():
                if device.get('type') == 'router':
                    gateway_ip = ip
                    break
        
        # Connect internet to gateway
        if gateway_ip and gateway_ip in self.graph:
            self.graph.add_edge('Internet', gateway_ip, weight=2.0)
            
            # Connect all other devices to gateway
            for ip in devices:
                if ip != gateway_ip:
                    self.graph.add_edge(gateway_ip, ip, weight=1.0)
        else:
            # If no gateway identified, connect everything to internet directly
            for ip in devices:
                self.graph.add_edge('Internet', ip, weight=1.0)
        
        # Calculate positions
        self.positions = nx.spring_layout(self.graph, seed=42)
        
        return self.graph
    
    def get_node_colors(self):
        """Return list of colors for each node based on device type"""
        colors = []
        for node in self.graph.nodes():
            node_type = self.graph.nodes[node].get('type', 'unknown')
            colors.append(self.node_colors.get(node_type, '#888888'))
        return colors

class NetworkVisualizer(FigureCanvas):
    """Qt widget for visualizing network graphs"""
    
    def __init__(self, parent=None, width=8, height=6, dpi=100):
        # Create a figure with dark background
        self.fig = Figure(figsize=(width, height), dpi=dpi)
        self.fig.patch.set_facecolor('#353535')  # Dark background
        self.axes = self.fig.add_subplot(111)
        
        super(NetworkVisualizer, self).__init__(self.fig)
        self.setParent(parent)
        
        # Set size policy to allow the widget to resize properly
        self.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)
        self.updateGeometry()
        
        # Set minimum size to prevent negative dimensions
        self.setMinimumSize(QSize(300, 200))
        
        self.network_graph = NetworkGraph()
        self.selected_node = None
        
        # Connect event handlers
        self.fig.canvas.mpl_connect('pick_event', self.on_pick)
        self.fig.canvas.mpl_connect('button_press_event', self.on_click)
        
        # Callback for when a node is selected
        self.node_selected_callback = None
        
        # Set text colors for dark mode
        plt.rcParams['text.color'] = '#ffffff'
        plt.rcParams['axes.labelcolor'] = '#ffffff'
        plt.rcParams['xtick.color'] = '#ffffff'
        plt.rcParams['ytick.color'] = '#ffffff'
    
    def set_node_selected_callback(self, callback):
        """Set callback function to be called when a node is selected"""
        self.node_selected_callback = callback
    
    def update_graph(self, devices, gateway_ip=None):
        """Update the graph visualization with new device data"""
        if not devices:  # Don't try to update with empty data
            return
            
        self.axes.clear()
        self.network_graph.build_graph_from_devices(devices, gateway_ip)
        
        # Get graph and positions
        graph = self.network_graph.graph
        pos = self.network_graph.positions
        
        # Get node colors based on type
        node_colors = self.network_graph.get_node_colors()
        
        # Draw nodes - store the nodes collection
        nodes = nx.draw_networkx_nodes(graph, pos, 
                              node_color=node_colors,
                              node_size=500,
                              alpha=0.8,
                              ax=self.axes)
        
        # Set the picker property on the nodes collection
        if nodes is not None:
            nodes.set_picker(10)
        
        # Draw edges with better styling - light color for dark theme
        nx.draw_networkx_edges(graph, pos, 
                              width=1.0,
                              alpha=0.7,
                              edge_color='#aaaaaa',  # Light gray for dark theme
                              ax=self.axes)
        
        # Draw labels with better font - use white for dark theme
        labels = {}
        for node in graph.nodes():
            if node == 'Internet':
                labels[node] = node
            else:
                device = graph.nodes[node]
                hostname = device.get('hostname', node)
                labels[node] = hostname
        
        nx.draw_networkx_labels(graph, pos, labels=labels, 
                               font_size=9, 
                               font_weight='bold',
                               font_color='white',  # White text for dark theme
                               ax=self.axes)
        
        # Remove axis
        self.axes.set_axis_off()
        
        # Highlight selected node if any
        if self.selected_node and self.selected_node in graph:
            nx.draw_networkx_nodes(graph, pos,
                                 nodelist=[self.selected_node],
                                 node_color='#ffffff',
                                 node_size=600,
                                 edgecolors='#ffffff',  # White outline
                                 linewidths=2,
                                 ax=self.axes)
        
        # Set dark background for the axes
        self.axes.set_facecolor('#353535')
        
        # Ensure all text is white for dark theme
        for text in self.axes.texts:
            text.set_color('white')
            
        self.fig.tight_layout(pad=0.5)
        self.draw()
    
    def resizeEvent(self, event):
        """Handle resize events to prevent negative figure sizes"""
        # Get new size in inches
        w, h = self.width() / self.fig.dpi, self.height() / self.fig.dpi
        
        # Ensure minimum size
        w = max(1.0, w)
        h = max(1.0, h)
        
        # Update figure size only if it's a valid size
        if w > 0 and h > 0 and w != float('inf') and h != float('inf'):
            self.fig.set_size_inches(w, h, forward=True)
        
        super().resizeEvent(event)
    
    def on_pick(self, event):
        """Handle node picking event"""
        if event.artist.get_label() == "_collection":  # Node collection
            ind = event.ind[0]  # Get the index of the selected node
            node = list(self.network_graph.graph.nodes())[ind]
            self.selected_node = node
            
            # Call the callback if set
            if self.node_selected_callback:
                self.node_selected_callback(node, self.network_graph.graph.nodes[node])
            
            # Redraw to highlight selected node
            self.update_graph({n: self.network_graph.graph.nodes[n] for n in self.network_graph.graph 
                              if n != 'Internet'})
    
    def on_click(self, event):
        """Handle click event (deselection)"""
        if event.inaxes != self.axes:  # Click outside the axes
            self.selected_node = None
            # Call callback with None to indicate deselection
            if self.node_selected_callback:
                self.node_selected_callback(None, None)
            
            # Redraw without selection
            self.update_graph({n: self.network_graph.graph.nodes[n] for n in self.network_graph.graph 
                              if n != 'Internet'})

class PortVisualizer(FigureCanvas):
    """Widget for visualizing open ports"""
    
    def __init__(self, parent=None, width=6, height=1.5, dpi=100):
        self.fig = Figure(figsize=(width, height), dpi=dpi)
        self.fig.patch.set_facecolor('#353535')  # Dark background
        self.axes = self.fig.add_subplot(111)
        
        super(PortVisualizer, self).__init__(self.fig)
        self.setParent(parent)
        
        # Port groups with colors - brighten colors for dark theme
        self.port_colors = {
            'web': '#4285F4',       # HTTP, HTTPS (80, 443, 8080)
            'mail': '#0F9D58',      # SMTP, IMAP, POP3 (25, 143, 110)
            'file': '#F4B400',      # FTP, SMB (21, 445)
            'remote': '#DB4437',    # SSH, RDP, Telnet (22, 3389, 23)
            'database': '#AA46BB',  # MySQL, PostgreSQL, etc (3306, 5432)
            'other': '#aaaaaa'      # Other ports - lighter gray for dark theme
        }
        
        # Common ports and their categories
        self.port_categories = {
            80: 'web', 443: 'web', 8080: 'web', 8000: 'web',
            25: 'mail', 143: 'mail', 110: 'mail', 465: 'mail', 993: 'mail', 995: 'mail',
            21: 'file', 445: 'file', 139: 'file', 20: 'file',
            22: 'remote', 3389: 'remote', 23: 'remote', 5900: 'remote',
            3306: 'database', 5432: 'database', 1521: 'database', 1433: 'database', 27017: 'database'
        }
        
        # Set size policy
        self.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)
        self.updateGeometry()
        
        # Set minimum size to prevent negative dimensions
        self.setMinimumSize(QSize(300, 100))
        
        self.clear_ports()
        
        # Set text colors for dark mode
        plt.rcParams['text.color'] = '#ffffff'
        plt.rcParams['axes.labelcolor'] = '#ffffff'
        plt.rcParams['xtick.color'] = '#ffffff'
        plt.rcParams['ytick.color'] = '#ffffff'
    
    def clear_ports(self):
        """Clear the port visualization"""
        self.axes.clear()
        self.axes.set_axis_off()
        self.axes.text(0.5, 0.5, "No ports to display", 
                      horizontalalignment='center',
                      verticalalignment='center',
                      transform=self.axes.transAxes,
                      fontsize=12,
                      color='white')  # White text for dark theme
        # Set dark background
        self.axes.set_facecolor('#353535')
        self.draw()
    
    def update_ports(self, ports_data):
        """Update the port visualization with new port data"""
        if not ports_data:
            self.clear_ports()
            return
        
        self.axes.clear()
        
        # Sort ports by number
        ports_data.sort(key=lambda x: x['port'])
        
        # Extract port numbers and determine categories
        port_numbers = [p['port'] for p in ports_data]
        categories = [self.port_categories.get(p['port'], 'other') for p in ports_data]
        colors = [self.port_colors[cat] for cat in categories]
        
        # Create horizontal bar chart
        y_pos = range(len(port_numbers))
        self.axes.barh(y_pos, [1] * len(port_numbers), color=colors, alpha=0.8)
        
        # Add port numbers and service names as labels
        for i, port_data in enumerate(ports_data):
            port = port_data['port']
            service = port_data.get('service', '?')
            self.axes.text(0.5, i, f"{port} ({service})", 
                         horizontalalignment='center',
                         verticalalignment='center',
                         color='white', fontweight='bold')
        
        # Set y-tick labels to empty
        self.axes.set_yticks([])
        
        # Set x-tick labels to empty
        self.axes.set_xticks([])
        
        # Remove all spines
        for spine in self.axes.spines.values():
            spine.set_visible(False)
        
        # Add legend with port categories
        legend_items = [plt.Rectangle((0,0), 1, 1, color=self.port_colors[cat], alpha=0.8) 
                        for cat in ['web', 'mail', 'file', 'remote', 'database', 'other']]
        legend_labels = ['Web', 'Mail', 'File', 'Remote', 'Database', 'Other']
        
        self.axes.legend(legend_items, legend_labels, 
                        loc='upper center', bbox_to_anchor=(0.5, -0.05),
                        fancybox=True, shadow=True, ncol=6, fontsize='small')
        
        # Apply tight layout
        self.fig.tight_layout()
        self.draw()
        
        # Set dark background for the axes
        self.axes.set_facecolor('#353535')
    
    def resizeEvent(self, event):
        """Handle resize events to prevent negative figure sizes"""
        # Get new size in inches
        w, h = self.width() / self.fig.dpi, self.height() / self.fig.dpi
        
        # Ensure minimum size
        w = max(1.0, w)
        h = max(0.5, h)
        
        # Update figure size only if it's a valid size
        if w > 0 and h > 0 and w != float('inf') and h != float('inf'):
            self.fig.set_size_inches(w, h, forward=True)
        
        super().resizeEvent(event)