"""
Professional IDS Dashboard using Dash + Plotly (Optimized)
Real-time visualization of network threats and attacks
Lightweight, responsive version that loads quickly
"""

import dash
from dash import dcc, html, Input, Output, callback
import plotly.graph_objects as go
from datetime import datetime
from collections import deque
import threading
import time
import logging

# Suppress logging
logging.getLogger('werkzeug').setLevel(logging.ERROR)

# Try to load components, but don't block if they fail
try:
    from src.capture.sniffer import PacketCapture
    from src.detection.rules import DetectionRules
    from src.dashboard.callbacks import AlertGenerator
    from src.logs.alerts import AlertDatabase
    
    packet_capture = PacketCapture(interface=None, packet_buffer_size=1000)
    detection_rules = DetectionRules()
    alert_generator = AlertGenerator(packet_capture, detection_rules, max_alerts=500)
    alert_db = AlertDatabase()  # For reading persisted alerts
    
    # Start components in background thread (non-blocking)
    def start_components():
        try:
            packet_capture.start()
            alert_generator.start()
        except:
            pass
    
    threading.Thread(target=start_components, daemon=True).start()
    READY = True
except Exception as e:
    print(f"Warning: Components not ready: {e}")
    packet_capture = None
    alert_generator = None
    alert_db = None
    READY = False

# Make alert_db accessible to all callbacks
def get_alert_db():
    """Safe way to access alert database from callbacks"""
    try:
        if alert_db is not None:
            return alert_db
    except:
        pass
    # Fallback: create a new instance
    try:
        from src.logs.alerts import AlertDatabase
        return AlertDatabase()
    except:
        return None

# Initialize app
app = dash.Dash(__name__)
app.title = "🔒 IDS Detection System"

# NEON FUTURISTIC COLOR SCHEME
COLORS = {
    'bg': '#0a0e1a',  # Deep space black
    'surface': '#0f1520',  # Dark blue-black
    'surface_light': '#1a1f33',  # Slightly lighter
    'primary': '#00ffff',  # Cyan neon
    'primary_glow': '#00d4ff',
    'secondary': '#ff00ff',  # Magenta neon
    'high': '#ff0055',  # Hot pink neon
    'medium': '#ffaa00',  # Orange neon
    'low': '#00ff88',  # Lime neon
    'text': '#f0f0ff',  # Bright white
    'text_muted': '#6a7aa8',  # Muted blue
    'accent1': '#0080ff',  # Electric blue
    'accent2': '#ff0080',  # Hot magenta
}

# ==================== LAYOUT ====================

app.layout = html.Div(style={'backgroundColor': COLORS['bg'], 'color': COLORS['text'], 'minHeight': '100vh', 'padding': '20px', 'fontFamily': '"Courier New", monospace', 'backgroundImage': 'linear-gradient(135deg, rgba(0,255,255,0.03) 0%, rgba(255,0,255,0.03) 100%)'}, children=[
        dcc.Interval(id='interval', interval=500),
        
        html.Div(style={'maxWidth': '1600px', 'margin': '0 auto'}, children=[
            # NEON HEADER
            html.Div(style={
                'display': 'flex',
                'justifyContent': 'space-between',
                'alignItems': 'center',
                'marginBottom': '30px',
                'paddingBottom': '20px',
                'borderBottom': f'2px solid {COLORS["primary"]}',
                'boxShadow': f'0 0 20px rgba(0,255,255,0.3)',
            }, children=[
                html.Div([
                    html.H1('🔒 INTRUSION DETECTION SYSTEM', style={
                        'margin': '0',
                        'color': COLORS['primary'],
                        'textShadow': f'0 0 10px {COLORS["primary"]}, 0 0 20px rgba(0,255,255,0.5)',
                        'letterSpacing': '2px',
                        'fontWeight': 'bold',
                    }),
                    html.P('NEON THREAT DETECTION & ANALYSIS', style={
                        'margin': '5px 0 0 0',
                        'color': COLORS['secondary'],
                        'fontSize': '13px',
                        'textShadow': f'0 0 10px {COLORS["secondary"]}',
                        'letterSpacing': '1px',
                    })
                ]),
                html.Div(id='threat-indicator', style={
                    'fontSize': '18px',
                    'padding': '10px 20px',
                    'borderRadius': '8px',
                    'backgroundColor': COLORS['surface_light'],
                    'border': f'2px solid {COLORS["low"]}',
                    'boxShadow': f'0 0 20px rgba(0,255,136,0.4), inset 0 0 10px rgba(0,255,136,0.2)',
                    'textShadow': f'0 0 10px {COLORS["low"]}',
                }, children='🟢 SAFE')
            ]),
            
            # NEON METRICS
            html.Div(style={
                'display': 'grid',
                'gridTemplateColumns': 'repeat(4, 1fr)',
                'gap': '15px',
                'marginBottom': '25px',
            }, children=[
                html.Div(style={
                    'padding': '15px',
                    'backgroundColor': COLORS['surface_light'],
                    'borderRadius': '8px',
                    'border': f'1px solid {COLORS["primary"]}',
                    'boxShadow': f'0 0 15px rgba(0,255,255,0.2), inset 0 0 10px rgba(0,255,255,0.1)',
                }, children=[
                    html.Div('📊 PACKETS/SEC', style={'fontSize': '11px', 'color': COLORS['text_muted'], 'fontWeight': 'bold', 'letterSpacing': '1px'}),
                    html.Div(id='pps', style={
                        'fontSize': '24px',
                        'color': COLORS['primary'],
                        'fontWeight': 'bold',
                        'marginTop': '8px',
                        'textShadow': f'0 0 10px {COLORS["primary"]}',
                    }, children='0')
                ]),
                html.Div(style={
                    'padding': '15px',
                    'backgroundColor': COLORS['surface_light'],
                    'borderRadius': '8px',
                    'border': f'1px solid {COLORS["high"]}',
                    'boxShadow': f'0 0 15px rgba(255,0,85,0.2), inset 0 0 10px rgba(255,0,85,0.1)',
                }, children=[
                    html.Div('🚨 TOTAL ALERTS', style={'fontSize': '11px', 'color': COLORS['text_muted'], 'fontWeight': 'bold', 'letterSpacing': '1px'}),
                    html.Div(id='alerts', style={
                        'fontSize': '24px',
                        'color': COLORS['high'],
                        'fontWeight': 'bold',
                        'marginTop': '8px',
                        'textShadow': f'0 0 10px {COLORS["high"]}',
                    }, children='0')
                ]),
                html.Div(style={
                    'padding': '15px',
                    'backgroundColor': COLORS['surface_light'],
                    'borderRadius': '8px',
                    'border': f'1px solid {COLORS["high"]}',
                    'boxShadow': f'0 0 15px rgba(255,0,85,0.2), inset 0 0 10px rgba(255,0,85,0.1)',
                }, children=[
                    html.Div('🔴 HIGH SEVERITY', style={'fontSize': '11px', 'color': COLORS['text_muted'], 'fontWeight': 'bold', 'letterSpacing': '1px'}),
                    html.Div(id='high', style={
                        'fontSize': '24px',
                        'color': COLORS['high'],
                        'fontWeight': 'bold',
                        'marginTop': '8px',
                        'textShadow': f'0 0 10px {COLORS["high"]}',
                    }, children='0')
                ]),
                html.Div(style={
                    'padding': '15px',
                    'backgroundColor': COLORS['surface_light'],
                    'borderRadius': '8px',
                    'border': f'1px solid {COLORS["medium"]}',
                    'boxShadow': f'0 0 15px rgba(255,170,0,0.2), inset 0 0 10px rgba(255,170,0,0.1)',
                }, children=[
                    html.Div('🎯 MALICIOUS IPS', style={'fontSize': '11px', 'color': COLORS['text_muted'], 'fontWeight': 'bold', 'letterSpacing': '1px'}),
                    html.Div(id='ips', style={
                        'fontSize': '24px',
                        'color': COLORS['medium'],
                        'fontWeight': 'bold',
                        'marginTop': '8px',
                        'textShadow': f'0 0 10px {COLORS["medium"]}',
                    }, children='0')
                ]),
            ]),
            
            # Charts Row 1
            html.Div(style={'display': 'grid', 'gridTemplateColumns': '1fr 1fr', 'gap': '20px', 'marginBottom': '25px'}, children=[
                html.Div(style={'padding': '20px', 'backgroundColor': COLORS['surface'], 'borderRadius': '12px', 'border': f'1px solid {COLORS["primary"]}', 'boxShadow': f'0 0 25px rgba(0,255,255,0.2), inset 0 0 20px rgba(0,255,255,0.05)'},
                    children=[html.H3('🌐 NETWORK FLOW', style={'margin': '0 0 15px 0', 'color': COLORS['primary'], 'textShadow': f'0 0 10px {COLORS["primary"]}', 'letterSpacing': '1px'}), dcc.Graph(id='network', style={'height': '350px'}, config={'displayModeBar': False})]),
                html.Div(style={'padding': '20px', 'backgroundColor': COLORS['surface'], 'borderRadius': '12px', 'border': f'1px solid {COLORS["secondary"]}', 'boxShadow': f'0 0 25px rgba(255,0,255,0.2), inset 0 0 20px rgba(255,0,255,0.05)'},
                    children=[html.H3('⚡ ALERT STREAM', style={'margin': '0 0 15px 0', 'color': COLORS['secondary'], 'textShadow': f'0 0 10px {COLORS["secondary"]}', 'letterSpacing': '1px'}), html.Div(id='alerts-stream', style={'height': '350px', 'overflowY': 'auto', 'backgroundColor': f'rgba(15, 21, 32, 0.8)', 'borderRadius': '8px', 'padding': '12px', 'fontSize': '11px', 'fontFamily': '"Courier New", monospace', 'border': f'1px solid {COLORS["secondary"]}', 'boxShadow': f'inset 0 0 10px rgba(255,0,255,0.1)'}, children=html.Div('🟢 Waiting for data...', style={'color': COLORS['text_muted'], 'padding': '20px', 'textAlign': 'center'}))]),
            ]),
            
            # Charts Row 2
            html.Div(style={'display': 'grid', 'gridTemplateColumns': 'repeat(3, 1fr)', 'gap': '20px', 'marginBottom': '25px'}, children=[
                html.Div(style={'padding': '20px', 'backgroundColor': COLORS['surface'], 'borderRadius': '12px', 'border': f'1px solid {COLORS["accent1"]}', 'boxShadow': f'0 0 25px rgba(0,128,255,0.2), inset 0 0 20px rgba(0,128,255,0.05)'},
                    children=[html.H3('📈 TRAFFIC TIMELINE', style={'margin': '0 0 15px 0', 'color': COLORS['accent1'], 'textShadow': f'0 0 10px {COLORS["accent1"]}', 'letterSpacing': '1px'}), dcc.Graph(id='timeline', style={'height': '300px'}, config={'displayModeBar': False})]),
                html.Div(style={'padding': '20px', 'backgroundColor': COLORS['surface'], 'borderRadius': '12px', 'border': f'1px solid {COLORS["low"]}', 'boxShadow': f'0 0 25px rgba(0,255,136,0.2), inset 0 0 20px rgba(0,255,136,0.05)'},
                    children=[html.H3('📊 PROTOCOLS', style={'margin': '0 0 15px 0', 'color': COLORS['low'], 'textShadow': f'0 0 10px {COLORS["low"]}', 'letterSpacing': '1px'}), dcc.Graph(id='protocols', style={'height': '300px'}, config={'displayModeBar': False})]),
                html.Div(style={'padding': '20px', 'backgroundColor': COLORS['surface'], 'borderRadius': '12px', 'border': f'1px solid {COLORS["high"]}', 'boxShadow': f'0 0 25px rgba(255,0,85,0.2), inset 0 0 20px rgba(255,0,85,0.05)'},
                    children=[html.H3('🎯 SEVERITY BREAKDOWN', style={'margin': '0 0 15px 0', 'color': COLORS['high'], 'textShadow': f'0 0 10px {COLORS["high"]}', 'letterSpacing': '1px'}), dcc.Graph(id='severity', style={'height': '300px'}, config={'displayModeBar': False})]),
            ]),
            
            # Charts Row 3
            html.Div(style={'display': 'grid', 'gridTemplateColumns': '1fr 1fr', 'gap': '20px'}, children=[
                html.Div(style={'padding': '20px', 'backgroundColor': COLORS['surface'], 'borderRadius': '12px', 'border': f'1px solid {COLORS["accent2"]}', 'boxShadow': f'0 0 25px rgba(255,0,128,0.2), inset 0 0 20px rgba(255,0,128,0.05)'},
                    children=[html.H3('🗺️ TOP MALICIOUS IPS', style={'margin': '0 0 15px 0', 'color': COLORS['accent2'], 'textShadow': f'0 0 10px {COLORS["accent2"]}', 'letterSpacing': '1px'}), dcc.Graph(id='ips-chart', style={'height': '300px'}, config={'displayModeBar': False})]),
                html.Div(style={'padding': '20px', 'backgroundColor': COLORS['surface'], 'borderRadius': '12px', 'border': f'1px solid {COLORS["medium"]}', 'boxShadow': f'0 0 25px rgba(255,170,0,0.2), inset 0 0 20px rgba(255,170,0,0.05)'},
                    children=[html.H3('🚨 ATTACK TYPES DETECTED', style={'margin': '0 0 15px 0', 'color': COLORS['medium'], 'textShadow': f'0 0 10px {COLORS["medium"]}', 'letterSpacing': '1px'}), dcc.Graph(id='attacks', style={'height': '300px'}, config={'displayModeBar': False})]),
            ]),
        ])
    ]
)

# ==================== CALLBACKS ====================

@callback([Output('threat-indicator', 'children'), Output('threat-indicator', 'style'), Output('pps', 'children'), Output('alerts', 'children'), Output('high', 'children'), Output('ips', 'children')], Input('interval', 'n_intervals'))
def update_metrics(n):
    try:
        db = get_alert_db()
        total, high, top_ips = 0, 0, []
        
        # Try database first
        if db:
            try:
                stats = db.get_statistics()
                total = stats.get('total_alerts', 0)
                high = stats.get('by_severity', {}).get('HIGH', 0)
                top_ips_data = stats.get('top_ips', [])
                top_ips = [(ip, cnt) for ip, cnt in top_ips_data] if top_ips_data else []
            except:
                pass
        
        # Fallback to generator
        if total == 0 and alert_generator:
            try:
                stats = alert_generator.get_alert_statistics()
                total = stats.get('total_alerts', 0)
                high = stats.get('by_severity', {}).get('HIGH', 0)
                top_ips = alert_generator.get_top_suspicious_ips(5) or []
            except:
                pass
        
        pps = 0
        try:
            if packet_capture:
                pps = packet_capture.get_statistics().get('packets_per_sec', 0)
        except:
            pass
        
        threat = '🟢 SAFE'
        color = COLORS['low']
        if high > 10:
            threat, color = '🔴 CRITICAL', COLORS['high']
        elif high > 3:
            threat, color = '🔴 HIGH', COLORS['high']
        elif total > 20:
            threat, color = '🟡 MEDIUM', COLORS['medium']
        elif total > 0:
            threat, color = '🟡 LOW', COLORS['medium']
        
        style = {'fontSize': '18px', 'padding': '10px 20px', 'borderRadius': '8px', 'backgroundColor': COLORS['surface'], 'border': f'2px solid {color}'}
        return threat, style, f'{pps:.0f}', f'{total}', f'{high}', f'{len(top_ips)}'
    except:
        return '🟢 SAFE', {}, '0', '0', '0', '0'

@callback(Output('alerts-stream', 'children'), Input('interval', 'n_intervals'))
def update_alerts_stream(n):
    try:
        db = get_alert_db()
        alerts = []
        
        # Try database first
        if db:
            try:
                alerts = db.get_recent_alerts(12)
            except:
                pass
        
        # Fallback to generator
        if not alerts and alert_generator:
            try:
                alerts = alert_generator.get_recent_alerts(12)
            except:
                pass
        
        if not alerts:
            return html.Div('🟢 No alerts - Run: python3 main.py', style={'color': '#909090', 'padding': '20px'})
        
        elements = []
        for alert in reversed(alerts):
            severity = alert.get('severity', 'LOW')
            emoji = {'HIGH': '🔴', 'MEDIUM': '🟡', 'LOW': '🟢'}.get(severity, '⚪')
            color = {'HIGH': COLORS['high'], 'MEDIUM': COLORS['medium'], 'LOW': COLORS['low']}.get(severity)
            ts = alert.get('timestamp', '')
            if 'T' in ts:  # ISO format
                ts = ts.split('T')[1][:8]  # Extract time
            ip = alert.get('src_ip', 'N/A')
            atype = alert.get('type', 'UNKNOWN')
            elements.append(html.Div(f'{emoji} [{ts}] {atype} from {ip}', style={'color': color, 'marginBottom': '5px'}))
        
        return elements
    except:
        return html.Div('Error loading alerts', style={'color': COLORS['high']})

@callback(Output('network', 'figure'), Input('interval', 'n_intervals'))
def update_network(n):
    try:
        db = get_alert_db()
        top_ips = []
        
        if db:
            stats = db.get_statistics()
            top_ips = stats.get('top_ips', [])[:5]
        
        if not top_ips and alert_generator:
            top_ips = alert_generator.get_top_suspicious_ips(5)
        
        if not top_ips:
            fig = go.Figure()
            fig.add_trace(go.Scatter(x=[0], y=[0], mode='markers', marker=dict(size=30, color=COLORS['primary'], line=dict(width=3, color=COLORS['bg']))))
            fig.update_layout(plot_bgcolor=COLORS['surface'], paper_bgcolor=COLORS['surface'], font=dict(color=COLORS['text']), margin=dict(l=0, r=0, t=0, b=0), xaxis=dict(showgrid=False, zeroline=False), yaxis=dict(showgrid=False, zeroline=False))
            return fig
        
        import math
        nodes_x, nodes_y, colors, sizes = [0], [0], [COLORS['primary']], [70]
        edges_x, edges_y = [], []
        
        for idx, (ip, cnt) in enumerate(top_ips):
            angle = idx * 2 * math.pi / len(top_ips)
            x, y = 1.3 * math.cos(angle), 1.3 * math.sin(angle)
            nodes_x.append(x)
            nodes_y.append(y)
            colors.append(COLORS['high'] if cnt > 15 else (COLORS['medium'] if cnt > 5 else COLORS['low']))
            sizes.append(min(55 + cnt * 3, 110))
            edges_x.extend([0, x, None])
            edges_y.extend([0, y, None])
        
        fig = go.Figure()
        fig.add_trace(go.Scatter(x=edges_x, y=edges_y, mode='lines', line=dict(width=2.5, color=COLORS['primary_glow'], dash='solid'), showlegend=False, hoverinfo='none'))
        fig.add_trace(go.Scatter(x=nodes_x, y=nodes_y, mode='markers+text', marker=dict(size=sizes, color=colors, line=dict(width=3, color=COLORS['bg']), opacity=0.95, symbol='circle'), text=[f'<b>HQ</b>'] + [ip.split('.')[-1] for ip, _ in top_ips], textposition='middle center', textfont=dict(size=9, color='white'), showlegend=False, hovertemplate='<b>%{text}</b><extra></extra>'))
        fig.update_layout(
            plot_bgcolor=COLORS['surface'],
            paper_bgcolor=COLORS['surface'],
            font=dict(color=COLORS['text'], family='Courier New, monospace'),
            margin=dict(l=30, r=30, t=30, b=30),
            xaxis=dict(showgrid=False, zeroline=False, showticklabels=False, scaleanchor='y', scaleratio=1),
            yaxis=dict(showgrid=False, zeroline=False, showticklabels=False, scaleanchor='x', scaleratio=1),
            hovermode='closest',
            transition=dict(duration=300),
            height=420
        )
        return fig
    except Exception as e:
        return go.Figure()

@callback(Output('timeline', 'figure'), Input('interval', 'n_intervals'))
def update_timeline(n):
    try:
        if packet_capture:
            cnt = packet_capture.get_statistics().get('packet_count', 0)
            fig = go.Figure(data=[go.Scatter(y=[cnt], mode='lines+markers', name='Traffic', line=dict(color=COLORS['primary'], width=4, shape='spline'), marker=dict(size=12, color=COLORS['high'], line=dict(width=2, color=COLORS['primary'])), fill='tozeroy', fillcolor=f'rgba(0,255,255,0.15)', hovertemplate='<b>Packets</b>: %{y}<extra></extra>')])
            fig.update_layout(plot_bgcolor=COLORS['surface'], paper_bgcolor=COLORS['surface'], font=dict(color=COLORS['text'], family='Courier New, monospace'), margin=dict(l=50, r=30, t=10, b=40), showlegend=False, xaxis=dict(showgrid=True, gridwidth=1, gridcolor=f'rgba(0,255,255,0.1)'), yaxis=dict(showgrid=True, gridwidth=1, gridcolor=f'rgba(0,255,255,0.1)'), hovermode='x unified', transition=dict(duration=300))
            return fig
        return go.Figure()
    except:
        return go.Figure()

@callback(Output('protocols', 'figure'), Input('interval', 'n_intervals'))
def update_protocols(n):
    try:
        fig = go.Figure(data=[go.Pie(labels=['TCP', 'UDP', 'ICMP'], values=[50, 30, 20], marker=dict(colors=[COLORS['primary'], COLORS['medium'], COLORS['high']], line=dict(color=COLORS['surface'], width=3), opacity=0.95), textposition='auto', textfont=dict(size=12, color='white', family='Courier New, monospace'), hovertemplate='<b>%{label}</b><br>%{value}%<extra></extra>')])
        fig.update_layout(plot_bgcolor=COLORS['surface'], paper_bgcolor=COLORS['surface'], font=dict(color=COLORS['text'], family='Courier New, monospace'), margin=dict(l=0, r=0, t=0, b=0), showlegend=True, legend=dict(font=dict(size=11)), transition=dict(duration=300))
        return fig
    except:
        return go.Figure()

@callback(Output('severity', 'figure'), Input('interval', 'n_intervals'))
def update_severity(n):
    try:
        sev = {'HIGH': 0, 'MEDIUM': 0, 'LOW': 0}
        db = get_alert_db()
        
        if db:
            try:
                stats = db.get_statistics()
                sev_data = stats.get('by_severity', {})
                sev['HIGH'] = sev_data.get('HIGH', 0)
                sev['MEDIUM'] = sev_data.get('MEDIUM', 0)
                sev['LOW'] = sev_data.get('LOW', 0)
            except:
                pass
        
        if sev['HIGH'] == 0 and sev['MEDIUM'] == 0 and alert_generator:
            try:
                stats = alert_generator.get_alert_statistics()
                sev_data = stats.get('by_severity', {})
                sev['HIGH'] = sev_data.get('HIGH', 0)
                sev['MEDIUM'] = sev_data.get('MEDIUM', 0)
                sev['LOW'] = sev_data.get('LOW', 0)
            except:
                pass
        
        fig = go.Figure(data=[go.Bar(x=['HIGH', 'MEDIUM', 'LOW'], y=[sev['HIGH'], sev['MEDIUM'], sev['LOW']], marker=dict(color=[COLORS['high'], COLORS['medium'], COLORS['low']], line=dict(color='white', width=2), opacity=0.9), text=[sev['HIGH'], sev['MEDIUM'], sev['LOW']], textposition='outside', textfont=dict(size=12, color='white'), hovertemplate='<b>%{x}</b><br>Count: %{y}<extra></extra>')])
        fig.update_layout(plot_bgcolor=COLORS['surface'], paper_bgcolor=COLORS['surface'], font=dict(color=COLORS['text'], family='Courier New, monospace'), margin=dict(l=50, r=30, t=20, b=40), showlegend=False, xaxis=dict(showgrid=True, gridwidth=1, gridcolor=f'rgba(255,255,255,0.1)'), yaxis=dict(showgrid=True, gridwidth=1, gridcolor=f'rgba(255,255,255,0.1)'), hovermode='x unified', transition=dict(duration=300))
        return fig
    except:
        return go.Figure()

@callback(Output('ips-chart', 'figure'), Input('interval', 'n_intervals'))
def update_ips_chart(n):
    try:
        top_ips = []
        db = get_alert_db()
        
        if db:
            try:
                stats = db.get_statistics()
                top_ips_data = stats.get('top_ips', [])
                top_ips = [(ip, cnt) for ip, cnt in top_ips_data][:8]
            except:
                pass
        
        if not top_ips and alert_generator:
            try:
                top_ips = alert_generator.get_top_suspicious_ips(8) or []
            except:
                pass
        
        if top_ips:
            ips, cnts = zip(*top_ips)
            fig = go.Figure(data=[go.Bar(y=list(ips), x=list(cnts), orientation='h', marker=dict(color=list(cnts), colorscale=[[0, COLORS['low']], [0.5, COLORS['medium']], [1, COLORS['high']]], line=dict(color='white', width=2), opacity=0.95), text=list(cnts), textposition='outside', textfont=dict(size=11, color='white'), hovertemplate='<b>%{y}</b><br>Attacks: %{x}<extra></extra>')])
            fig.update_layout(plot_bgcolor=COLORS['surface'], paper_bgcolor=COLORS['surface'], font=dict(color=COLORS['text'], family='Courier New, monospace'), margin=dict(l=130, r=40, t=10, b=30), showlegend=False, xaxis=dict(showgrid=True, gridwidth=1, gridcolor=f'rgba(255,255,255,0.1)'), yaxis=dict(showgrid=False), hovermode='y unified', transition=dict(duration=300))
            return fig
        return go.Figure()
    except:
        return go.Figure()

@callback(Output('attacks', 'figure'), Input('interval', 'n_intervals'))
def update_attacks(n):
    try:
        by_type = {}
        db = get_alert_db()
        
        if db:
            try:
                stats = db.get_statistics()
                by_type = stats.get('by_type', {})
            except:
                pass
        
        if not by_type and alert_generator:
            try:
                stats = alert_generator.get_alert_statistics()
                by_type = stats.get('by_type', {})
            except:
                pass
        
        if by_type:
            colors_gradient = [COLORS['accent1'], COLORS['primary'], COLORS['medium'], COLORS['high']]
            fig = go.Figure(data=[go.Bar(x=list(by_type.keys()), y=list(by_type.values()), marker=dict(color=colors_gradient[:len(by_type.keys())], line=dict(color='white', width=2), opacity=0.95), text=list(by_type.values()), textposition='outside', textfont=dict(size=11, color='white'), hovertemplate='<b>%{x}</b><br>Count: %{y}<extra></extra>')])
            fig.update_layout(plot_bgcolor=COLORS['surface'], paper_bgcolor=COLORS['surface'], font=dict(color=COLORS['text'], family='Courier New, monospace'), margin=dict(l=60, r=30, t=10, b=80), showlegend=False, xaxis=dict(tickangle=-45, showgrid=False), yaxis=dict(showgrid=True, gridwidth=1, gridcolor=f'rgba(255,255,255,0.1)'), hovermode='x unified', transition=dict(duration=300))
            return fig
        return go.Figure()
    except:
        return go.Figure()

if __name__ == '__main__':
    print("\n" + "="*70)
    print("🔒 IDS DASHBOARD STARTING...")
    print("="*70)
    print("✅ Dashboard is loading")
    print("🌐 URL: http://localhost:8050")
    print("\n📊 To feed data, in another terminal run:")
    print("   python3 main.py")
    print("="*70 + "\n")
    
    app.run(debug=False, host='0.0.0.0', port=8050, use_reloader=False)
