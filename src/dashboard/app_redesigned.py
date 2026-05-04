"""
Professional IDS Dashboard - Redesigned
Real-time network threat visualization with professional UX
Reduced visual noise, clear hierarchy, realistic alert data
"""

import dash
from dash import dcc, html, Input, Output, callback
import plotly.graph_objects as go
from datetime import datetime
import threading
import logging

# Suppress logging
logging.getLogger('werkzeug').setLevel(logging.ERROR)

# Load components
try:
    from src.capture.sniffer import PacketCapture
    from src.detection.rules import DetectionRules
    from src.dashboard.callbacks import AlertGenerator
    from src.logs.alerts import AlertDatabase
    
    packet_capture = PacketCapture(interface=None, packet_buffer_size=1000)
    detection_rules = DetectionRules()
    alert_generator = AlertGenerator(packet_capture, detection_rules, max_alerts=500)
    alert_db = AlertDatabase()
    
    def start_components():
        try:
            packet_capture.start()
            alert_generator.start()
        except:
            pass
    
    threading.Thread(target=start_components, daemon=True).start()
except Exception as e:
    print(f"Warning: Components not ready: {e}")
    packet_capture = None
    alert_generator = None
    alert_db = None

def get_alert_db():
    """Safe database access"""
    try:
        if alert_db is not None:
            return alert_db
    except:
        pass
    try:
        from src.logs.alerts import AlertDatabase
        return AlertDatabase()
    except:
        return None

# SIMPLIFIED COLOR PALETTE
COLORS = {
    'bg': '#0d1117',           # Dark background
    'surface': '#161b22',      # Card background
    'surface_light': '#21262d', # Slightly lighter
    'primary': '#58a6ff',      # Primary blue
    'primary_dark': '#1f6feb',
    'accent': '#79c0ff',       # Lighter blue
    'danger': '#f85149',       # Red for alerts only
    'warning': '#d29922',      # Orange for warnings
    'success': '#3fb950',      # Green
    'text': '#e6edf3',         # Light text
    'text_muted': '#8b949e',   # Muted text
    'border': '#30363d',       # Border color
}

# CSS for micro animations is now in /assets/styles.css - Dash will load it automatically

# Initialize app
app = dash.Dash(__name__)
app.title = "IDS - Intrusion Detection System"

# Store timeline data for historical tracking
timeline_history = {'x': [], 'y': []}

# ==================== LAYOUT ====================

app.layout = html.Div([
    dcc.Interval(id='interval', interval=500),
    
    html.Div(style={'backgroundColor': COLORS['bg'], 'minHeight': '100vh', 'padding': '24px'}, children=[
        html.Div(style={'maxWidth': '1800px', 'margin': '0 auto'}, children=[
            
            # ==================== HEADER ====================
            html.Div(style={
                'marginBottom': '32px',
                'paddingBottom': '24px',
                'borderBottom': f'2px solid {COLORS["border"]}',
            }, children=[
                html.Div(style={'display': 'flex', 'justifyContent': 'space-between', 'alignItems': 'flex-start'}, children=[
                    html.Div(children=[
                        html.H1('Network Intrusion Detection System', style={
                            'margin': '0 0 8px 0',
                            'fontSize': '32px',
                            'fontWeight': '600',
                            'color': COLORS['primary'],
                            'fontFamily': '-apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif',
                        }),
                        html.P('Real-time anomaly detection & threat monitoring', style={
                            'margin': '0',
                            'fontSize': '14px',
                            'color': COLORS['text_muted'],
                            'fontFamily': '-apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif',
                        })
                    ]),
                    html.Div(id='threat-status', className='threat-badge', style={
                        'padding': '12px 20px',
                        'borderRadius': '20px',
                        'backgroundColor': COLORS['surface'],
                        'border': f'2px solid {COLORS["border"]}',
                        'fontSize': '14px',
                        'fontWeight': '600',
                    }, children='🟢 Monitoring')
                ]),
            ]),
            
            # ==================== METRICS ROW ====================
            html.Div(style={
                'display': 'grid',
                'gridTemplateColumns': 'repeat(4, 1fr)',
                'gap': '16px',
                'marginBottom': '32px',
            }, children=[
                # Metric Card - Network Activity
                html.Div(className='metric-card', style={
                    'padding': '24px',
                    'backgroundColor': COLORS['surface'],
                    'borderRadius': '12px',
                    'border': f'2px solid {COLORS["primary"]}',
                }, children=[
                    html.Div('🌐 Network Activity', style={
                        'fontSize': '12px',
                        'fontWeight': '600',
                        'color': COLORS['text_muted'],
                        'textTransform': 'uppercase',
                        'letterSpacing': '0.5px',
                    }),
                    html.Div(id='metric-pps', className='metric-number', style={
                        'fontSize': '36px',
                        'fontWeight': '700',
                        'color': COLORS['primary'],
                        'marginTop': '12px',
                    }, children='0'),
                    html.Div('packets/sec', style={
                        'fontSize': '11px',
                        'color': COLORS['text_muted'],
                        'marginTop': '8px',
                    })
                ]),
                
                # Metric Card - Total Alerts
                html.Div(className='metric-card', style={
                    'padding': '24px',
                    'backgroundColor': COLORS['surface'],
                    'borderRadius': '12px',
                    'border': f'2px solid {COLORS["warning"]}',
                }, children=[
                    html.Div('⚠️ Total Alerts', style={
                        'fontSize': '12px',
                        'fontWeight': '600',
                        'color': COLORS['text_muted'],
                        'textTransform': 'uppercase',
                        'letterSpacing': '0.5px',
                    }),
                    html.Div(id='metric-alerts', className='metric-number', style={
                        'fontSize': '36px',
                        'fontWeight': '700',
                        'color': COLORS['warning'],
                        'marginTop': '12px',
                    }, children='0'),
                    html.Div('detected', style={
                        'fontSize': '11px',
                        'color': COLORS['text_muted'],
                        'marginTop': '8px',
                    })
                ]),
                
                # Metric Card - High Severity
                html.Div(className='metric-card danger-glow', style={
                    'padding': '24px',
                    'backgroundColor': COLORS['surface'],
                    'borderRadius': '12px',
                    'border': f'2px solid {COLORS["danger"]}',
                }, children=[
                    html.Div('🔴 Critical Threats', style={
                        'fontSize': '12px',
                        'fontWeight': '600',
                        'color': COLORS['text_muted'],
                        'textTransform': 'uppercase',
                        'letterSpacing': '0.5px',
                    }),
                    html.Div(id='metric-high', className='metric-number alert', style={
                        'fontSize': '36px',
                        'fontWeight': '700',
                        'color': COLORS['danger'],
                        'marginTop': '12px',
                    }, children='0'),
                    html.Div('high severity', style={
                        'fontSize': '11px',
                        'color': COLORS['text_muted'],
                        'marginTop': '8px',
                    })
                ]),
                
                # Metric Card - Unique Sources
                html.Div(className='metric-card', style={
                    'padding': '24px',
                    'backgroundColor': COLORS['surface'],
                    'borderRadius': '12px',
                    'border': f'2px solid {COLORS["success"]}',
                }, children=[
                    html.Div('👁️ Unique Sources', style={
                        'fontSize': '12px',
                        'fontWeight': '600',
                        'color': COLORS['text_muted'],
                        'textTransform': 'uppercase',
                        'letterSpacing': '0.5px',
                    }),
                    html.Div(id='metric-ips', className='metric-number', style={
                        'fontSize': '36px',
                        'fontWeight': '700',
                        'color': COLORS['success'],
                        'marginTop': '12px',
                    }, children='0'),
                    html.Div('malicious IPs', style={
                        'fontSize': '11px',
                        'color': COLORS['text_muted'],
                        'marginTop': '8px',
                    })
                ]),
            ]),
            
            # ==================== HERO SECTION: ALERT STREAM ====================
            html.Div(className='glow-box', style={
                'marginBottom': '32px',
                'padding': '24px',
                'backgroundColor': COLORS['surface'],
                'borderRadius': '12px',
                'border': f'2px solid {COLORS["primary"]}',
            }, children=[
                html.H2('🚨 Live Threat Alert Stream', style={
                    'margin': '0 0 16px 0',
                    'fontSize': '18px',
                    'fontWeight': '600',
                    'color': COLORS['primary'],
                    'fontFamily': '-apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif',
                }),
                html.Div(id='alert-stream', style={
                    'height': '400px',
                    'overflowY': 'auto',
                    'backgroundColor': f'rgba(13, 17, 23, 0.5)',
                    'borderRadius': '8px',
                    'padding': '16px',
                    'fontSize': '13px',
                    'fontFamily': '"Courier New", monospace',
                    'border': f'1px solid {COLORS["border"]}',
                }, children=html.Div('Waiting for network activity...', style={
                    'color': COLORS['text_muted'],
                    'padding': '24px',
                    'textAlign': 'center',
                }))
            ]),
            
            # ==================== ARCHITECTURE DIAGRAM ====================
            html.Div(className='architecture-flow', style={
                'marginBottom': '32px',
                'padding': '20px',
                'backgroundColor': COLORS['surface'],
                'borderRadius': '12px',
                'border': f'2px solid {COLORS["primary"]}',
            }, children=[
                html.H3('⚙️ System Architecture', style={
                    'margin': '0 0 16px 0',
                    'fontSize': '14px',
                    'fontWeight': '600',
                    'color': COLORS['accent'],
                }),
                html.Div(style={
                    'display': 'flex',
                    'justifyContent': 'space-between',
                    'alignItems': 'center',
                    'padding': '16px',
                    'backgroundColor': 'rgba(88, 166, 255, 0.08)',
                    'borderRadius': '8px',
                }, children=[
                    html.Div('🌐 Network Traffic', style={'fontSize': '13px', 'fontWeight': '500'}),
                    html.Div('→', style={'color': COLORS['text_muted'], 'fontSize': '16px', 'fontWeight': 'bold'}),
                    html.Div('📦 Packet Inspection', style={'fontSize': '13px', 'fontWeight': '500'}),
                    html.Div('→', style={'color': COLORS['text_muted'], 'fontSize': '16px', 'fontWeight': 'bold'}),
                    html.Div('🔍 Anomaly Detection', style={'fontSize': '13px', 'fontWeight': '500'}),
                    html.Div('→', style={'color': COLORS['text_muted'], 'fontSize': '16px', 'fontWeight': 'bold'}),
                    html.Div('📊 Alert Dashboard', style={'fontSize': '13px', 'fontWeight': '500', 'color': COLORS['danger']}),
                ])
            ]),
            
            # ==================== CHARTS GRID ====================
            html.Div(style={
                'display': 'grid',
                'gridTemplateColumns': 'repeat(2, 1fr)',
                'gap': '24px',
                'marginBottom': '24px',
            }, children=[
                # Network Flow
                html.Div(className='chart-container', style={
                    'padding': '20px',
                    'backgroundColor': COLORS['surface'],
                    'borderRadius': '12px',
                    'border': f'2px solid {COLORS["primary"]}',
                }, children=[
                    html.H3('🗺️ Network Topology', style={
                        'margin': '0 0 16px 0',
                        'fontSize': '14px',
                        'fontWeight': '600',
                        'color': COLORS['primary'],
                    }),
                    dcc.Graph(id='network', style={'height': '320px'}, config={'displayModeBar': False})
                ]),
                
                # Severity Distribution
                html.Div(className='chart-container', style={
                    'padding': '20px',
                    'backgroundColor': COLORS['surface'],
                    'borderRadius': '12px',
                    'border': f'2px solid {COLORS["danger"]}',
                }, children=[
                    html.H3('🎯 Alert Severity Distribution', style={
                        'margin': '0 0 16px 0',
                        'fontSize': '14px',
                        'fontWeight': '600',
                        'color': COLORS['danger'],
                    }),
                    dcc.Graph(id='severity', style={'height': '320px'}, config={'displayModeBar': False})
                ]),
            ]),
            
            # ==================== ANALYSIS CHARTS ====================
            html.Div(style={
                'display': 'grid',
                'gridTemplateColumns': 'repeat(3, 1fr)',
                'gap': '24px',
            }, children=[
                # Traffic Timeline
                html.Div(className='chart-container', style={
                    'padding': '20px',
                    'backgroundColor': COLORS['surface'],
                    'borderRadius': '12px',
                    'border': f'2px solid {COLORS["primary"]}',
                }, children=[
                    html.H3('📈 Network Activity Timeline', style={
                        'margin': '0 0 16px 0',
                        'fontSize': '14px',
                        'fontWeight': '600',
                        'color': COLORS['primary'],
                    }),
                    dcc.Graph(id='timeline', style={'height': '280px'}, config={'displayModeBar': False})
                ]),
                
                # Attack Types
                html.Div(className='chart-container', style={
                    'padding': '20px',
                    'backgroundColor': COLORS['surface'],
                    'borderRadius': '12px',
                    'border': f'2px solid {COLORS["warning"]}',
                }, children=[
                    html.H3('⚔️ Detected Attack Types', style={
                        'margin': '0 0 16px 0',
                        'fontSize': '14px',
                        'fontWeight': '600',
                        'color': COLORS['warning'],
                    }),
                    dcc.Graph(id='attacks', style={'height': '280px'}, config={'displayModeBar': False})
                ]),
                
                # Top Sources
                html.Div(className='chart-container', style={
                    'padding': '20px',
                    'backgroundColor': COLORS['surface'],
                    'borderRadius': '12px',
                    'border': f'2px solid {COLORS["danger"]}',
                }, children=[
                    html.H3('🚨 Top Suspicious Sources', style={
                        'margin': '0 0 16px 0',
                        'fontSize': '14px',
                        'fontWeight': '600',
                        'color': COLORS['danger'],
                    }),
                    dcc.Graph(id='ips-chart', style={'height': '280px'}, config={'displayModeBar': False})
                ]),
            ]),
        ])
    ])
])

# ==================== CALLBACKS ====================

THREAT_DESCRIPTIONS = {
    'SYN_FLOOD': 'TCP SYN flood detected - abnormal connection initiation',
    'PORT_SCAN': 'Port scanning behavior detected - reconnaissance activity',
    'PING_FLOOD': 'ICMP flood detected - DoS attack pattern',
    'UDP_FLOOD': 'UDP flood detected - volumetric attack',
    'SUSPICIOUS_PORTS': 'Suspicious port activity detected',
    'UNUSUAL_PACKET_RATE': 'Abnormal packet rate detected',
}

@callback(
    [Output('threat-status', 'children'), Output('threat-status', 'style'), Output('threat-status', 'className'),
     Output('metric-pps', 'children'), Output('metric-alerts', 'children'),
     Output('metric-high', 'children'), Output('metric-ips', 'children')],
    Input('interval', 'n_intervals')
)
def update_metrics(n):
    try:
        db = get_alert_db()
        total, high, top_ips = 0, 0, []
        
        if db:
            stats = db.get_statistics()
            total = stats.get('total_alerts', 0)
            high = stats.get('by_severity', {}).get('HIGH', 0)
            top_ips = stats.get('top_ips', [])
        elif alert_generator:
            stats = alert_generator.get_alert_statistics()
            total = stats.get('total_alerts', 0)
            high = stats.get('by_severity', {}).get('HIGH', 0)
            top_ips = alert_generator.get_top_suspicious_ips(5) or []
        
        pps = 0
        if packet_capture:
            pps = packet_capture.get_statistics().get('packets_per_sec', 0)
        
        status = '🟢 Monitoring'
        color = COLORS['success']
        animation_class = 'threat-badge'
        if high > 10:
            status = '🔴 Critical'
            color = COLORS['danger']
            animation_class = 'threat-badge pulse-alert'
        elif total > 20:
            status = '🟡 Elevated'
            color = COLORS['warning']
            animation_class = 'threat-badge blink-icon'
        elif total > 0:
            status = '🟡 Alert'
            color = COLORS['warning']
            animation_class = 'threat-badge'
        
        style = {
            'padding': '12px 20px',
            'borderRadius': '20px',
            'backgroundColor': COLORS['surface'],
            'border': f'2px solid {color}',
            'fontSize': '14px',
            'fontWeight': '600',
            'color': color,
        }
        
        return status, style, animation_class, f'{pps:.0f}', f'{total}', f'{high}', f'{len(top_ips)}'
    except:
        return '🟢 Monitoring', {}, 'threat-badge', '0', '0', '0', '0'

@callback(Output('alert-stream', 'children'), Input('interval', 'n_intervals'))
def update_alert_stream(n):
    try:
        db = get_alert_db()
        alerts = []
        
        if db:
            alerts = db.get_recent_alerts(15)
        elif alert_generator:
            alerts = alert_generator.get_recent_alerts(15)
        
        if not alerts:
            return html.Div('Waiting for network activity...', style={
                'color': COLORS['text_muted'],
                'padding': '24px',
                'textAlign': 'center',
            })
        
        elements = []
        for alert in reversed(alerts):
            severity = alert.get('severity', 'LOW')
            atype = alert.get('type', 'UNKNOWN')
            ip = alert.get('src_ip', 'Unknown')
            ts = alert.get('timestamp', '')
            
            if 'T' in ts:
                ts = ts.split('T')[1][:8]
            
            # Meaningful threat description
            desc = THREAT_DESCRIPTIONS.get(atype, f'{atype} - suspicious network behavior')
            
            # Color by severity
            if severity == 'HIGH':
                icon, color = '🔴', COLORS['danger']
            elif severity == 'MEDIUM':
                icon, color = '🟡', COLORS['warning']
            else:
                icon, color = '🟢', COLORS['success']
            
            elements.append(html.Div(
                html.Div([
                    html.Span(f'{icon} [{ts}] ', style={'color': color, 'fontWeight': 'bold'}),
                    html.Span(f'{desc}', style={'color': COLORS['text']}),
                    html.Span(f' • Source: {ip}', style={'color': COLORS['text_muted'], 'fontSize': '11px'}),
                ]),
                style={
                    'padding': '10px 12px',
                    'borderLeft': f'3px solid {color}',
                    'marginBottom': '8px',
                    'backgroundColor': f'rgba(88, 166, 255, 0.02)',
                    'borderRadius': '4px',
                    'fontSize': '13px',
                    'fontFamily': '"Courier New", monospace',
                },
                className='alert-item'
            ))
        
        return elements
    except:
        return html.Div('Error loading alerts', style={'color': COLORS['danger']})

@callback(Output('network', 'figure'), Input('interval', 'n_intervals'))
def update_network(n):
    try:
        db = get_alert_db()
        top_ips = []
        
        if db:
            stats = db.get_statistics()
            top_ips = stats.get('top_ips', [])[:5]
        elif alert_generator:
            top_ips = alert_generator.get_top_suspicious_ips(5)
        
        if not top_ips:
            fig = go.Figure()
            fig.add_trace(go.Scatter(x=[0], y=[0], mode='markers',
                marker=dict(size=50, color=COLORS['primary'])))
            fig.update_layout(plot_bgcolor=COLORS['surface'], paper_bgcolor=COLORS['surface'],
                font=dict(color=COLORS['text']), margin=dict(l=0, r=0, t=0, b=0),
                xaxis=dict(showgrid=False, zeroline=False), yaxis=dict(showgrid=False, zeroline=False))
            return fig
        
        import math
        nodes_x, nodes_y, colors, sizes = [0], [0], [COLORS['primary']], [80]
        edges_x, edges_y = [], []
        
        for idx, (ip, cnt) in enumerate(top_ips):
            angle = idx * 2 * math.pi / len(top_ips)
            x, y = 1.5 * math.cos(angle), 1.5 * math.sin(angle)
            nodes_x.append(x)
            nodes_y.append(y)
            
            if cnt > 20:
                color = COLORS['danger']
            elif cnt > 10:
                color = COLORS['warning']
            else:
                color = COLORS['success']
            
            colors.append(color)
            sizes.append(min(60 + cnt * 2, 120))
            edges_x.extend([0, x, None])
            edges_y.extend([0, y, None])
        
        fig = go.Figure()
        fig.add_trace(go.Scatter(x=edges_x, y=edges_y, mode='lines',
            line=dict(width=2, color=COLORS['primary'], dash='solid'),
            showlegend=False, hoverinfo='none'))
        fig.add_trace(go.Scatter(x=nodes_x, y=nodes_y, mode='markers+text',
            marker=dict(size=sizes, color=colors, line=dict(width=2, color=COLORS['bg']), opacity=0.9),
            text=['<b>HQ</b>'] + [ip.split('.')[-1] for ip, _ in top_ips],
            textposition='middle center', textfont=dict(size=10, color='white'),
            showlegend=False, hovertemplate='<b>%{text}</b><extra></extra>'))
        
        fig.update_layout(
            plot_bgcolor=COLORS['surface'], paper_bgcolor=COLORS['surface'],
            font=dict(color=COLORS['text']), margin=dict(l=20, r=20, t=20, b=20),
            xaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
            yaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
            hovermode='closest', transition=dict(duration=300)
        )
        return fig
    except:
        return go.Figure()

@callback(Output('severity', 'figure'), Input('interval', 'n_intervals'))
def update_severity(n):
    try:
        sev = {'HIGH': 0, 'MEDIUM': 0, 'LOW': 0}
        db = get_alert_db()
        
        if db:
            stats = db.get_statistics()
            sev = stats.get('by_severity', {})
        elif alert_generator:
            stats = alert_generator.get_alert_statistics()
            sev = stats.get('by_severity', {})
        
        fig = go.Figure(data=[go.Bar(
            x=['HIGH', 'MEDIUM', 'LOW'],
            y=[sev.get('HIGH', 0), sev.get('MEDIUM', 0), sev.get('LOW', 0)],
            marker=dict(color=[COLORS['danger'], COLORS['warning'], COLORS['success']],
                line=dict(color=COLORS['border'], width=1), opacity=0.9),
            text=[sev.get('HIGH', 0), sev.get('MEDIUM', 0), sev.get('LOW', 0)],
            textposition='outside', textfont=dict(size=12, color=COLORS['text']),
            hovertemplate='<b>%{x}</b><br>Alerts: %{y}<extra></extra>'
        )])
        
        fig.update_layout(
            plot_bgcolor=COLORS['surface'], paper_bgcolor=COLORS['surface'],
            font=dict(color=COLORS['text'], size=12), margin=dict(l=40, r=20, t=20, b=40),
            showlegend=False, xaxis=dict(showgrid=False),
            yaxis=dict(showgrid=True, gridwidth=1, gridcolor=COLORS['border']),
            hovermode='x unified', transition=dict(duration=300)
        )
        return fig
    except:
        return go.Figure()

@callback(Output('timeline', 'figure'), Input('interval', 'n_intervals'))
def update_timeline(n):
    global timeline_history
    try:
        if packet_capture:
            cnt = packet_capture.get_statistics().get('packet_count', 0)
            
            # Add to history (keep last 60 points for 30 seconds of data)
            timeline_history['x'].append(n)
            timeline_history['y'].append(cnt)
            
            if len(timeline_history['x']) > 60:
                timeline_history['x'].pop(0)
                timeline_history['y'].pop(0)
            
            # Only show if we have data
            if len(timeline_history['y']) > 0:
                fig = go.Figure(data=[go.Scatter(
                    x=timeline_history['x'],
                    y=timeline_history['y'],
                    mode='lines+markers',
                    line=dict(color=COLORS['primary'], width=3, shape='spline'),
                    marker=dict(size=6, color=COLORS['danger']),
                    fill='tozeroy',
                    fillcolor=f'rgba(88, 166, 255, 0.1)',
                    hovertemplate='<b>Update #%{x}</b><br><b>Packets</b>: %{y}<extra></extra>'
                )])
            else:
                fig = go.Figure()
            
            fig.update_layout(
                plot_bgcolor=COLORS['surface'],
                paper_bgcolor=COLORS['surface'],
                font=dict(color=COLORS['text']),
                margin=dict(l=40, r=20, t=10, b=30),
                showlegend=False,
                xaxis=dict(showgrid=False, title='Updates'),
                yaxis=dict(showgrid=True, gridwidth=1, gridcolor=COLORS['border'], title='Packet Count'),
                hovermode='x unified',
                transition=dict(duration=300)
            )
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
            stats = db.get_statistics()
            by_type = stats.get('by_type', {})
        elif alert_generator:
            stats = alert_generator.get_alert_statistics()
            by_type = stats.get('by_type', {})
        
        if by_type:
            colors_map = [COLORS['danger'], COLORS['warning'], COLORS['success'], COLORS['primary']]
            fig = go.Figure(data=[go.Bar(
                x=list(by_type.keys()), y=list(by_type.values()),
                marker=dict(color=colors_map[:len(by_type)],
                    line=dict(color=COLORS['border'], width=1), opacity=0.9),
                text=list(by_type.values()), textposition='outside',
                textfont=dict(size=11, color=COLORS['text']),
                hovertemplate='<b>%{x}</b><br>Count: %{y}<extra></extra>'
            )])
            
            fig.update_layout(
                plot_bgcolor=COLORS['surface'], paper_bgcolor=COLORS['surface'],
                font=dict(color=COLORS['text']), margin=dict(l=50, r=20, t=10, b=70),
                showlegend=False, xaxis=dict(tickangle=-45, showgrid=False),
                yaxis=dict(showgrid=True, gridwidth=1, gridcolor=COLORS['border']),
                hovermode='x unified', transition=dict(duration=300)
            )
            return fig
        return go.Figure()
    except:
        return go.Figure()

@callback(Output('ips-chart', 'figure'), Input('interval', 'n_intervals'))
def update_ips_chart(n):
    try:
        top_ips = []
        db = get_alert_db()
        
        if db:
            stats = db.get_statistics()
            top_ips = stats.get('top_ips', [])[:6]
        elif alert_generator:
            top_ips = alert_generator.get_top_suspicious_ips(6) or []
        
        if top_ips:
            ips, cnts = zip(*top_ips)
            fig = go.Figure(data=[go.Bar(
                y=list(ips), x=list(cnts), orientation='h',
                marker=dict(color=list(cnts),
                    colorscale=[[0, COLORS['success']], [0.5, COLORS['warning']], [1, COLORS['danger']]],
                    line=dict(color=COLORS['border'], width=1), opacity=0.9),
                text=list(cnts), textposition='outside',
                textfont=dict(size=11, color=COLORS['text']),
                hovertemplate='<b>%{y}</b><br>Alerts: %{x}<extra></extra>'
            )])
            
            fig.update_layout(
                plot_bgcolor=COLORS['surface'], paper_bgcolor=COLORS['surface'],
                font=dict(color=COLORS['text']), margin=dict(l=110, r=40, t=10, b=30),
                showlegend=False, xaxis=dict(showgrid=True, gridwidth=1, gridcolor=COLORS['border']),
                yaxis=dict(showgrid=False), hovermode='y unified', transition=dict(duration=300)
            )
            return fig
        return go.Figure()
    except:
        return go.Figure()

if __name__ == '__main__':
    print("\n" + "="*70)
    print("🔒 IDS DASHBOARD STARTING")
    print("="*70)
    print("✅ Dashboard is running")
    print("🌐 URL: http://localhost:8050")
    print("\n📊 To feed data, run in another terminal:")
    print("   python3 main.py")
    print("="*70 + "\n")
    
    app.run(debug=False, host='0.0.0.0', port=8050, use_reloader=False)
