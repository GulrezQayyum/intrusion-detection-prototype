"""
Professional IDS Dashboard using Dash + Plotly
Real-time visualization of network threats and attacks
Modern SOC (Security Operations Center) style interface
"""

import dash
from dash import dcc, html, Input, Output, State, callback
import plotly.graph_objects as go
import plotly.express as px
from plotly.subplots import make_subplots
import threading
import time
from datetime import datetime, timedelta
from collections import deque, defaultdict
import json

from src.capture.sniffer import PacketCapture
from src.detection.rules import DetectionRules
from src.dashboard.callbacks import AlertGenerator

# Initialize components
packet_capture = PacketCapture(interface=None, packet_buffer_size=1000)
detection_rules = DetectionRules()
alert_generator = AlertGenerator(packet_capture, detection_rules, max_alerts=500)

# Initialize Dash app with custom styling
app = dash.Dash(__name__)
app.title = "🔒 IDS Intrusion Detection System"

# Color scheme (modern dark SOC theme)
COLORS = {
    'background': '#0f1419',
    'surface': '#1a1f2e',
    'surface_light': '#252d3d',
    'primary': '#00d4ff',
    'primary_dark': '#00a3cc',
    'high': '#ff4444',
    'medium': '#ff9900',
    'low': '#44ff44',
    'text': '#e0e0e0',
    'text_muted': '#909090',
}

# Start background monitoring
packet_capture.start()
alert_generator.start()

# Global data storage for real-time updates
live_data = {
    'alerts': deque(maxlen=100),
    'traffic_timeline': deque(maxlen=60),
    'network_flows': defaultdict(lambda: {'src': None, 'dst': None, 'count': 0}),
    'packets_per_second': 0,
    'last_update': datetime.now()
}

def update_live_data():
    """Update live data from detection engine - runs in background"""
    while True:
        try:
            # Get recent alerts
            recent_alerts = alert_generator.get_recent_alerts(100)
            live_data['alerts'] = deque(recent_alerts, maxlen=100)
            
            # Update packets per second
            stats = packet_capture.get_statistics()
            live_data['packets_per_second'] = stats.get('packets_per_sec', 0)
            
            # Add to timeline
            current_time = datetime.now()
            live_data['traffic_timeline'].append({
                'time': current_time,
                'count': stats.get('packet_count', 0)
            })
            
            live_data['last_update'] = current_time
            
            time.sleep(0.5)  # Update twice per second
        except Exception as e:
            print(f"Error updating live data: {e}")
            time.sleep(1)

# Start background data update thread
data_thread = threading.Thread(target=update_live_data, daemon=True)
data_thread.start()

# ==================== APP LAYOUT ====================

app.layout = html.Div(
    style={
        'backgroundColor': COLORS['background'],
        'color': COLORS['text'],
        'fontFamily': 'Segoe UI, Arial, sans-serif',
        'minHeight': '100vh',
        'padding': '20px',
    },
    children=[
        # Hidden interval component for real-time updates
        dcc.Interval(id='interval-component', interval=500, n_intervals=0),
        
        # Main container
        html.Div([
            # ============ HEADER ============
            html.Div(
                style={
                    'display': 'flex',
                    'justifyContent': 'space-between',
                    'alignItems': 'center',
                    'marginBottom': '30px',
                    'paddingBottom': '20px',
                    'borderBottom': f'2px solid {COLORS["primary"]}',
                },
                children=[
                    html.Div([
                        html.H1('🔒 INTRUSION DETECTION SYSTEM', 
                                style={'margin': '0 0 5px 0', 'color': COLORS['primary']}),
                        html.P('Real-time Network Threat Detection & Analysis',
                               style={'margin': '0', 'color': COLORS['text_muted'], 'fontSize': '14px'})
                    ]),
                    html.Div(id='threat-level-indicator',
                             style={
                                 'fontSize': '24px',
                                 'padding': '15px 25px',
                                 'borderRadius': '10px',
                                 'backgroundColor': COLORS['surface_light'],
                                 'border': f'2px solid {COLORS["low"]}',
                                 'textAlign': 'center'
                             })
                ]
            ),
            
            # ============ KEY METRICS ROW ============
            html.Div(
                style={'display': 'grid', 'gridTemplateColumns': 'repeat(4, 1fr)', 'gap': '15px', 'marginBottom': '25px'},
                children=[
                    # Metric 1: Packets Per Second
                    html.Div([
                        html.Div('📊 Packets/sec', style={'fontSize': '12px', 'color': COLORS['text_muted']}),
                        html.Div(id='pps-metric', 
                                style={'fontSize': '28px', 'color': COLORS['primary'], 'fontWeight': 'bold', 'marginTop': '5px'})
                    ], style={'padding': '15px', 'backgroundColor': COLORS['surface_light'], 'borderRadius': '8px',
                              'border': f'1px solid {COLORS["primary_dark"]}'}),
                    
                    # Metric 2: Total Alerts
                    html.Div([
                        html.Div('🚨 Total Alerts', style={'fontSize': '12px', 'color': COLORS['text_muted']}),
                        html.Div(id='alerts-metric',
                                style={'fontSize': '28px', 'color': COLORS['high'], 'fontWeight': 'bold', 'marginTop': '5px'})
                    ], style={'padding': '15px', 'backgroundColor': COLORS['surface_light'], 'borderRadius': '8px',
                              'border': f'1px solid {COLORS["high"]}'}),
                    
                    # Metric 3: High Severity Alerts
                    html.Div([
                        html.Div('🔴 High Severity', style={'fontSize': '12px', 'color': COLORS['text_muted']}),
                        html.Div(id='high-severity-metric',
                                style={'fontSize': '28px', 'color': COLORS['high'], 'fontWeight': 'bold', 'marginTop': '5px'})
                    ], style={'padding': '15px', 'backgroundColor': COLORS['surface_light'], 'borderRadius': '8px',
                              'border': f'1px solid {COLORS["high"]}'}),
                    
                    # Metric 4: Suspicious IPs
                    html.Div([
                        html.Div('🎯 Malicious IPs', style={'fontSize': '12px', 'color': COLORS['text_muted']}),
                        html.Div(id='malicious-ips-metric',
                                style={'fontSize': '28px', 'color': COLORS['medium'], 'fontWeight': 'bold', 'marginTop': '5px'})
                    ], style={'padding': '15px', 'backgroundColor': COLORS['surface_light'], 'borderRadius': '8px',
                              'border': f'1px solid {COLORS["medium"]}'}),
                ]
            ),
            
            # ============ MAIN VISUALIZATION GRID ============
            html.Div(
                style={'display': 'grid', 'gridTemplateColumns': '1fr 1fr', 'gap': '20px', 'marginBottom': '25px'},
                children=[
                    # Left: Network Flow Graph
                    html.Div([
                        html.H3('🌐 Network Flow Graph', style={'margin': '0 0 15px 0', 'color': COLORS['primary']}),
                        dcc.Graph(id='network-graph', style={'height': '400px'},
                                 config={'responsive': True, 'displayModeBar': False})
                    ], style={'padding': '20px', 'backgroundColor': COLORS['surface'], 'borderRadius': '12px',
                              'border': f'1px solid {COLORS["surface_light"]}'}),
                    
                    # Right: Real-time Alert Stream
                    html.Div([
                        html.H3('⚡ Live Alert Stream', style={'margin': '0 0 15px 0', 'color': COLORS['primary']}),
                        html.Div(id='alert-stream', 
                                style={
                                    'height': '400px',
                                    'overflowY': 'auto',
                                    'backgroundColor': COLORS['surface_light'],
                                    'borderRadius': '8px',
                                    'padding': '15px',
                                    'fontSize': '12px',
                                    'fontFamily': 'Courier New, monospace',
                                    'border': f'1px solid {COLORS["surface_light"]}'
                                })
                    ], style={'padding': '20px', 'backgroundColor': COLORS['surface'], 'borderRadius': '12px',
                              'border': f'1px solid {COLORS["surface_light"]}'}),
                ]
            ),
            
            # ============ CHARTS ROW ============
            html.Div(
                style={'display': 'grid', 'gridTemplateColumns': '1fr 1fr 1fr', 'gap': '20px', 'marginBottom': '25px'},
                children=[
                    # Chart 1: Traffic Timeline
                    html.Div([
                        html.H3('📈 Traffic Timeline (ECG)', style={'margin': '0 0 15px 0', 'color': COLORS['primary']}),
                        dcc.Graph(id='traffic-timeline', style={'height': '300px'},
                                 config={'responsive': True, 'displayModeBar': False})
                    ], style={'padding': '20px', 'backgroundColor': COLORS['surface'], 'borderRadius': '12px',
                              'border': f'1px solid {COLORS["surface_light"]}'}),
                    
                    # Chart 2: Protocol Distribution
                    html.Div([
                        html.H3('📊 Protocol Distribution', style={'margin': '0 0 15px 0', 'color': COLORS['primary']}),
                        dcc.Graph(id='protocol-pie', style={'height': '300px'},
                                 config={'responsive': True, 'displayModeBar': False})
                    ], style={'padding': '20px', 'backgroundColor': COLORS['surface'], 'borderRadius': '12px',
                              'border': f'1px solid {COLORS["surface_light"]}'}),
                    
                    # Chart 3: Severity Breakdown
                    html.Div([
                        html.H3('🎯 Alert Severity Breakdown', style={'margin': '0 0 15px 0', 'color': COLORS['primary']}),
                        dcc.Graph(id='severity-chart', style={'height': '300px'},
                                 config={'responsive': True, 'displayModeBar': False})
                    ], style={'padding': '20px', 'backgroundColor': COLORS['surface'], 'borderRadius': '12px',
                              'border': f'1px solid {COLORS["surface_light"]}'}),
                ]
            ),
            
            # ============ BOTTOM ROW: IP THREATS & ATTACK TYPES ============
            html.Div(
                style={'display': 'grid', 'gridTemplateColumns': '1fr 1fr', 'gap': '20px'},
                children=[
                    # Left: Top Malicious IPs Heatmap
                    html.Div([
                        html.H3('🗺️ Top Malicious IPs (Threat Heatmap)', style={'margin': '0 0 15px 0', 'color': COLORS['primary']}),
                        dcc.Graph(id='top-ips-heatmap', style={'height': '300px'},
                                 config={'responsive': True, 'displayModeBar': False})
                    ], style={'padding': '20px', 'backgroundColor': COLORS['surface'], 'borderRadius': '12px',
                              'border': f'1px solid {COLORS["surface_light"]}'}),
                    
                    # Right: Attack Types Timeline
                    html.Div([
                        html.H3('🚨 Attack Types Detected', style={'margin': '0 0 15px 0', 'color': COLORS['primary']}),
                        dcc.Graph(id='attack-types-bar', style={'height': '300px'},
                                 config={'responsive': True, 'displayModeBar': False})
                    ], style={'padding': '20px', 'backgroundColor': COLORS['surface'], 'borderRadius': '12px',
                              'border': f'1px solid {COLORS["surface_light"]}'}),
                ]
            ),
        ], style={'maxWidth': '1600px', 'margin': '0 auto'})
    ]
)

# ==================== CALLBACKS ====================

@callback(
    [Output('threat-level-indicator', 'children'),
     Output('threat-level-indicator', 'style'),
     Output('pps-metric', 'children'),
     Output('alerts-metric', 'children'),
     Output('high-severity-metric', 'children'),
     Output('malicious-ips-metric', 'children')],
    Input('interval-component', 'n_intervals')
)
def update_metrics(n):
    """Update key metrics in real-time"""
    try:
        stats = alert_generator.get_alert_statistics()
        threat_level = alert_generator.get_threat_level()
        top_ips = alert_generator.get_top_suspicious_ips(5)
        pps = live_data['packets_per_second']
        
        # Determine threat level color
        threat_colors = {
            'CRITICAL': (COLORS['high'], '🔴 CRITICAL'),
            'HIGH': (COLORS['high'], '🔴 HIGH'),
            'MEDIUM': (COLORS['medium'], '🟡 MEDIUM'),
            'LOW': (COLORS['low'], '🟢 LOW'),
            'SAFE': (COLORS['low'], '🟢 SAFE'),
        }
        
        threat_color, threat_label = threat_colors.get(threat_level, (COLORS['low'], '🟢 SAFE'))
        
        indicator_style = {
            'fontSize': '24px',
            'padding': '15px 25px',
            'borderRadius': '10px',
            'backgroundColor': COLORS['surface_light'],
            'border': f'2px solid {threat_color}',
            'textAlign': 'center',
        }
        
        total_alerts = stats.get('total_alerts', 0)
        high_alerts = stats.get('by_severity', {}).get('HIGH', 0)
        malicious_ip_count = len(top_ips)
        
        return (
            threat_label,
            indicator_style,
            f"{pps:.0f}",
            f"{total_alerts}",
            f"{high_alerts}",
            f"{malicious_ip_count}"
        )
    except Exception as e:
        return "N/A", {}, "0", "0", "0", "0"

@callback(
    Output('alert-stream', 'children'),
    Input('interval-component', 'n_intervals')
)
def update_alert_stream(n):
    """Update live alert stream"""
    try:
        recent_alerts = list(live_data['alerts'])[-20:]  # Get 20 most recent
        
        alert_elements = []
        for alert in reversed(recent_alerts):  # Most recent first
            severity = alert.get('severity', 'LOW')
            severity_emoji = {'HIGH': '🔴', 'MEDIUM': '🟡', 'LOW': '🟢'}.get(severity, '⚪')
            severity_color = {'HIGH': COLORS['high'], 'MEDIUM': COLORS['medium'], 'LOW': COLORS['low']}.get(severity, COLORS['text'])
            
            timestamp = alert.get('timestamp', '')
            src_ip = alert.get('src_ip', 'N/A')
            alert_type = alert.get('type', 'UNKNOWN')
            message = alert.get('message', '')
            
            alert_elements.append(
                html.Div([
                    html.Div(
                        f"{severity_emoji} [{timestamp[11:19]}] {alert_type} from {src_ip}",
                        style={'color': severity_color, 'marginBottom': '3px', 'fontWeight': 'bold'}
                    ),
                    html.Div(message, style={'color': COLORS['text_muted'], 'marginBottom': '8px', 'marginLeft': '20px'})
                ])
            )
        
        return alert_elements if alert_elements else html.Div("No alerts yet...", style={'color': COLORS['text_muted']})
    except Exception as e:
        return html.Div(f"Error: {str(e)}", style={'color': COLORS['high']})

@callback(
    Output('network-graph', 'figure'),
    Input('interval-component', 'n_intervals')
)
def update_network_graph(n):
    """Update network flow graph"""
    try:
        # Get top malicious IPs
        top_ips = alert_generator.get_top_suspicious_ips(5)
        
        if not top_ips:
            # Empty graph
            fig = go.Figure()
            fig.add_trace(go.Scatter(x=[], y=[], mode='markers'))
            fig.update_layout(
                title="No threats detected yet",
                xaxis_showgrid=False,
                yaxis_showgrid=False,
                plot_bgcolor=COLORS['surface'],
                paper_bgcolor=COLORS['surface'],
                font=dict(color=COLORS['text']),
                height=400
            )
            return fig
        
        # Create network nodes and edges
        nodes_x, nodes_y = [], []
        edges_x, edges_y = [], []
        node_colors = []
        node_sizes = []
        node_text = []
        
        # Add center node (our server)
        center_x, center_y = 0, 0
        nodes_x.append(center_x)
        nodes_y.append(center_y)
        node_colors.append(COLORS['primary'])
        node_sizes.append(50)
        node_text.append("🖥️ Our Network")
        
        # Add attacker nodes in circle
        import math
        angle_step = 2 * math.pi / len(top_ips)
        radius = 2
        
        for idx, (ip, alert_count) in enumerate(top_ips):
            angle = idx * angle_step
            x = center_x + radius * math.cos(angle)
            y = center_y + radius * math.sin(angle)
            
            nodes_x.append(x)
            nodes_y.append(y)
            
            # Color based on threat level
            if alert_count > 15:
                node_colors.append(COLORS['high'])
            elif alert_count > 5:
                node_colors.append(COLORS['medium'])
            else:
                node_colors.append(COLORS['low'])
            
            node_sizes.append(min(40 + alert_count * 2, 80))
            node_text.append(f"{ip}<br>Alerts: {alert_count}")
            
            # Draw edge from center to attacker
            edges_x.append(center_x)
            edges_x.append(x)
            edges_x.append(None)
            
            edges_y.append(center_y)
            edges_y.append(y)
            edges_y.append(None)
        
        # Create edges trace
        edge_trace = go.Scatter(
            x=edges_x, y=edges_y,
            mode='lines',
            line=dict(width=1, color=COLORS['primary_dark']),
            hoverinfo='none',
            showlegend=False
        )
        
        # Create nodes trace
        node_trace = go.Scatter(
            x=nodes_x, y=nodes_y,
            mode='markers+text',
            text=['🖥️'] + ['⚠️'] * len(top_ips),
            textposition="middle center",
            hovertext=node_text,
            hoverinfo='text',
            marker=dict(
                size=node_sizes,
                color=node_colors,
                line=dict(width=2, color=COLORS['surface']),
                opacity=0.9
            ),
            showlegend=False
        )
        
        fig = go.Figure(data=[edge_trace, node_trace])
        fig.update_layout(
            title="Network Attack Flow (Red = Threats)",
            showlegend=False,
            hovermode='closest',
            margin=dict(b=20, l=5, r=5, t=40),
            xaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
            yaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
            plot_bgcolor=COLORS['surface'],
            paper_bgcolor=COLORS['surface'],
            font=dict(color=COLORS['text']),
            height=400
        )
        
        return fig
    except Exception as e:
        fig = go.Figure()
        fig.add_annotation(text=f"Error: {str(e)}")
        return fig

@callback(
    Output('traffic-timeline', 'figure'),
    Input('interval-component', 'n_intervals')
)
def update_traffic_timeline(n):
    """Update ECG-style traffic timeline"""
    try:
        if len(live_data['traffic_timeline']) < 2:
            return {
                'data': [],
                'layout': go.Layout(
                    title="Waiting for data...",
                    plot_bgcolor=COLORS['surface'],
                    paper_bgcolor=COLORS['surface'],
                    font=dict(color=COLORS['text']),
                    xaxis=dict(showgrid=False),
                    yaxis=dict(showgrid=False)
                )
            }
        
        timeline_data = list(live_data['traffic_timeline'])
        times = [item['time'].strftime("%H:%M:%S") for item in timeline_data]
        counts = [item['count'] for item in timeline_data]
        
        fig = go.Figure()
        fig.add_trace(go.Scatter(
            x=times, y=counts,
            mode='lines',
            name='Packet Count',
            line=dict(color=COLORS['primary'], width=3),
            fill='tozeroy',
            fillcolor=f'rgba(0, 212, 255, 0.2)',
            hovertemplate='<b>%{x}</b><br>Packets: %{y}<extra></extra>'
        ))
        
        fig.update_layout(
            title="📈 Network Traffic Timeline (ECG Style)",
            xaxis_title="Time",
            yaxis_title="Total Packets",
            plot_bgcolor=COLORS['surface'],
            paper_bgcolor=COLORS['surface'],
            font=dict(color=COLORS['text']),
            hovermode='x unified',
            margin=dict(l=50, r=20, t=40, b=40),
            height=300
        )
        
        return fig
    except Exception as e:
        return go.Figure().add_annotation(text=f"Error: {str(e)}")

@callback(
    Output('protocol-pie', 'figure'),
    Input('interval-component', 'n_intervals')
)
def update_protocol_pie(n):
    """Update protocol distribution pie chart"""
    try:
        stats = packet_capture.get_statistics()
        protocol_dist = stats.get('protocol_distribution', {'TCP': 0, 'UDP': 0, 'ICMP': 0, 'Other': 0})
        
        # Filter out zero values
        filtered_protocols = {k: v for k, v in protocol_dist.items() if v > 0}
        
        if not filtered_protocols:
            filtered_protocols = {'No Data': 1}
        
        colors_list = [COLORS['primary'], COLORS['medium'], COLORS['high'], COLORS['low']]
        
        fig = go.Figure(data=[go.Pie(
            labels=list(filtered_protocols.keys()),
            values=list(filtered_protocols.values()),
            marker=dict(colors=colors_list[:len(filtered_protocols)]),
            hovertemplate='<b>%{label}</b><br>Packets: %{value}<extra></extra>'
        )])
        
        fig.update_layout(
            title="📊 Protocol Distribution",
            plot_bgcolor=COLORS['surface'],
            paper_bgcolor=COLORS['surface'],
            font=dict(color=COLORS['text']),
            margin=dict(l=20, r=20, t=40, b=20),
            height=300
        )
        
        return fig
    except Exception as e:
        return go.Figure().add_annotation(text=f"Error: {str(e)}")

@callback(
    Output('severity-chart', 'figure'),
    Input('interval-component', 'n_intervals')
)
def update_severity_chart(n):
    """Update severity breakdown chart"""
    try:
        stats = alert_generator.get_alert_statistics()
        severity_dist = stats.get('by_severity', {'HIGH': 0, 'MEDIUM': 0, 'LOW': 0})
        
        fig = go.Figure(data=[go.Bar(
            x=list(severity_dist.keys()),
            y=list(severity_dist.values()),
            marker=dict(color=[COLORS['high'], COLORS['medium'], COLORS['low']]),
            hovertemplate='<b>%{x}</b><br>Alerts: %{y}<extra></extra>'
        )])
        
        fig.update_layout(
            title="🎯 Alert Severity Breakdown",
            xaxis_title="Severity Level",
            yaxis_title="Number of Alerts",
            plot_bgcolor=COLORS['surface'],
            paper_bgcolor=COLORS['surface'],
            font=dict(color=COLORS['text']),
            margin=dict(l=50, r=20, t=40, b=40),
            height=300,
            showlegend=False
        )
        
        return fig
    except Exception as e:
        return go.Figure().add_annotation(text=f"Error: {str(e)}")

@callback(
    Output('top-ips-heatmap', 'figure'),
    Input('interval-component', 'n_intervals')
)
def update_ips_heatmap(n):
    """Update top malicious IPs heatmap"""
    try:
        top_ips = alert_generator.get_top_suspicious_ips(10)
        
        if not top_ips:
            fig = go.Figure()
            fig.add_annotation(text="No threats detected")
            return fig
        
        ips = [ip for ip, _ in top_ips]
        counts = [count for _, count in top_ips]
        
        # Create color gradient
        max_count = max(counts) if counts else 1
        colors_list = [f'rgba(255, {int(68 - (count/max_count * 68))}, 68, 0.8)' for count in counts]
        
        fig = go.Figure(data=[go.Bar(
            y=ips,
            x=counts,
            orientation='h',
            marker=dict(color=counts, colorscale='Reds', showscale=False),
            hovertemplate='<b>%{y}</b><br>Threats: %{x}<extra></extra>'
        )])
        
        fig.update_layout(
            title="🗺️ Top Malicious IP Addresses (Threat Heatmap)",
            xaxis_title="Number of Alerts",
            yaxis_title="IP Address",
            plot_bgcolor=COLORS['surface'],
            paper_bgcolor=COLORS['surface'],
            font=dict(color=COLORS['text']),
            margin=dict(l=150, r=20, t=40, b=40),
            height=300,
            showlegend=False
        )
        
        return fig
    except Exception as e:
        return go.Figure().add_annotation(text=f"Error: {str(e)}")

@callback(
    Output('attack-types-bar', 'figure'),
    Input('interval-component', 'n_intervals')
)
def update_attack_types_bar(n):
    """Update attack types bar chart"""
    try:
        stats = alert_generator.get_alert_statistics()
        alert_types = stats.get('by_type', {})
        
        if not alert_types:
            alert_types = {'No Attacks': 0}
        
        fig = go.Figure(data=[go.Bar(
            x=list(alert_types.keys()),
            y=list(alert_types.values()),
            marker=dict(color=COLORS['high']),
            hovertemplate='<b>%{x}</b><br>Count: %{y}<extra></extra>'
        )])
        
        fig.update_layout(
            title="🚨 Attack Types Detected",
            xaxis_title="Attack Type",
            yaxis_title="Number of Detections",
            plot_bgcolor=COLORS['surface'],
            paper_bgcolor=COLORS['surface'],
            font=dict(color=COLORS['text']),
            margin=dict(l=50, r=20, t=40, b=80),
            height=300,
            showlegend=False,
            xaxis_tickangle=-45
        )
        
        return fig
    except Exception as e:
        return go.Figure().add_annotation(text=f"Error: {str(e)}")

if __name__ == '__main__':
    print("\n" + "="*70)
    print("🔒 IDS DASHBOARD STARTING...")
    print("="*70)
    print("\n✅ Packet Capture: RUNNING")
    print("✅ Detection Engine: RUNNING")
    print("✅ Alert Generator: RUNNING")
    print("\n🌐 Dashboard URL: http://localhost:8050")
    print("\nPress Ctrl+C to stop the server")
    print("="*70 + "\n")
    
    app.run(debug=False, host='0.0.0.0', port=8050)
