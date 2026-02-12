#!/usr/bin/env python3
"""
🐝 BeeWAF Kibana Dashboard Setup
Creates visualizations and a dashboard via the Kibana Saved Objects API.
"""

import requests
import json
import sys

KIBANA = "http://localhost:5601"
HEADERS = {"kbn-xsrf": "true", "Content-Type": "application/json"}
DATA_VIEW_ID = "beewaf-logs-dataview"

def create_saved_objects():
    """Create all visualizations and dashboard via bulk API."""
    
    # ── 1. Pie Chart: Attack Types Distribution ──
    vis_attack_types = {
        "type": "visualization",
        "id": "beewaf-attack-types-pie",
        "attributes": {
            "title": "🔴 Attack Types Distribution",
            "visState": json.dumps({
                "title": "Attack Types Distribution",
                "type": "pie",
                "aggs": [
                    {"id": "1", "enabled": True, "type": "count", "params": {}, "schema": "metric"},
                    {"id": "2", "enabled": True, "type": "terms", "params": {
                        "field": "block_reason",
                        "orderBy": "1",
                        "order": "desc",
                        "size": 20,
                        "otherBucket": True,
                        "otherBucketLabel": "Other",
                        "missingBucket": False,
                        "missingBucketLabel": "Missing"
                    }, "schema": "segment"}
                ],
                "params": {
                    "type": "pie",
                    "addTooltip": True,
                    "addLegend": True,
                    "legendPosition": "right",
                    "isDonut": True,
                    "labels": {"show": True, "values": True, "last_level": True, "truncate": 100}
                }
            }),
            "uiStateJSON": "{}",
            "description": "Distribution of blocked attack types",
            "kibanaSavedObjectMeta": {
                "searchSourceJSON": json.dumps({
                    "index": DATA_VIEW_ID,
                    "query": {"query": "blocked:true OR status_code:403", "language": "kuery"},
                    "filter": []
                })
            }
        },
        "references": [{"id": DATA_VIEW_ID, "name": "kibanaSavedObjectMeta.searchSourceJSON.index", "type": "index-pattern"}]
    }

    # ── 2. Bar Chart: Blocked vs Allowed ──
    vis_blocked_allowed = {
        "type": "visualization",
        "id": "beewaf-blocked-vs-allowed",
        "attributes": {
            "title": "🛡️ Blocked vs Allowed Requests",
            "visState": json.dumps({
                "title": "Blocked vs Allowed Requests",
                "type": "histogram",
                "aggs": [
                    {"id": "1", "enabled": True, "type": "count", "params": {}, "schema": "metric"},
                    {"id": "2", "enabled": True, "type": "date_histogram", "params": {
                        "field": "@timestamp",
                        "calendar_interval": "1m",
                        "min_doc_count": 0,
                        "extended_bounds": {}
                    }, "schema": "segment"},
                    {"id": "3", "enabled": True, "type": "terms", "params": {
                        "field": "status_code",
                        "orderBy": "1",
                        "order": "desc",
                        "size": 5
                    }, "schema": "group"}
                ],
                "params": {
                    "type": "histogram",
                    "grid": {"categoryLines": False},
                    "categoryAxes": [{"id": "CategoryAxis-1", "type": "category", "position": "bottom"}],
                    "valueAxes": [{"id": "ValueAxis-1", "name": "LeftAxis-1", "type": "value", "position": "left"}],
                    "addTooltip": True,
                    "addLegend": True,
                    "legendPosition": "right"
                }
            }),
            "uiStateJSON": "{}",
            "description": "Timeline of blocked vs allowed requests",
            "kibanaSavedObjectMeta": {
                "searchSourceJSON": json.dumps({
                    "index": DATA_VIEW_ID,
                    "query": {"query": "", "language": "kuery"},
                    "filter": []
                })
            }
        },
        "references": [{"id": DATA_VIEW_ID, "name": "kibanaSavedObjectMeta.searchSourceJSON.index", "type": "index-pattern"}]
    }

    # ── 3. Bar Chart: Top Blocked Paths ──
    vis_top_paths = {
        "type": "visualization",
        "id": "beewaf-top-blocked-paths",
        "attributes": {
            "title": "🎯 Top Blocked Paths",
            "visState": json.dumps({
                "title": "Top Blocked Paths",
                "type": "horizontal_bar",
                "aggs": [
                    {"id": "1", "enabled": True, "type": "count", "params": {}, "schema": "metric"},
                    {"id": "2", "enabled": True, "type": "terms", "params": {
                        "field": "http_path.keyword",
                        "orderBy": "1",
                        "order": "desc",
                        "size": 15
                    }, "schema": "segment"}
                ],
                "params": {
                    "type": "horizontal_bar",
                    "addTooltip": True,
                    "addLegend": False,
                    "legendPosition": "right"
                }
            }),
            "uiStateJSON": "{}",
            "description": "Most frequently targeted paths",
            "kibanaSavedObjectMeta": {
                "searchSourceJSON": json.dumps({
                    "index": DATA_VIEW_ID,
                    "query": {"query": "status_code:403", "language": "kuery"},
                    "filter": []
                })
            }
        },
        "references": [{"id": DATA_VIEW_ID, "name": "kibanaSavedObjectMeta.searchSourceJSON.index", "type": "index-pattern"}]
    }

    # ── 4. Metric: Total Requests ──
    vis_total_requests = {
        "type": "visualization",
        "id": "beewaf-total-requests",
        "attributes": {
            "title": "📊 Total Requests",
            "visState": json.dumps({
                "title": "Total Requests",
                "type": "metric",
                "aggs": [
                    {"id": "1", "enabled": True, "type": "count", "params": {}, "schema": "metric"}
                ],
                "params": {
                    "addTooltip": True,
                    "addLegend": False,
                    "type": "metric",
                    "metric": {
                        "percentageMode": False,
                        "colorSchema": "Green to Red",
                        "metricColorMode": "None",
                        "style": {"bgFill": "#000", "bgColor": False, "labelColor": False, "subText": "", "fontSize": 60}
                    }
                }
            }),
            "uiStateJSON": "{}",
            "description": "Total requests processed",
            "kibanaSavedObjectMeta": {
                "searchSourceJSON": json.dumps({
                    "index": DATA_VIEW_ID,
                    "query": {"query": "", "language": "kuery"},
                    "filter": []
                })
            }
        },
        "references": [{"id": DATA_VIEW_ID, "name": "kibanaSavedObjectMeta.searchSourceJSON.index", "type": "index-pattern"}]
    }

    # ── 5. Metric: Total Blocked ──
    vis_total_blocked = {
        "type": "visualization",
        "id": "beewaf-total-blocked",
        "attributes": {
            "title": "🚫 Total Blocked",
            "visState": json.dumps({
                "title": "Total Blocked",
                "type": "metric",
                "aggs": [
                    {"id": "1", "enabled": True, "type": "count", "params": {}, "schema": "metric"}
                ],
                "params": {
                    "addTooltip": True,
                    "addLegend": False,
                    "type": "metric",
                    "metric": {
                        "percentageMode": False,
                        "colorSchema": "Green to Red",
                        "metricColorMode": "Background",
                        "style": {"bgFill": "#ff0000", "bgColor": True, "labelColor": False, "subText": "Attacks Blocked", "fontSize": 60}
                    }
                }
            }),
            "uiStateJSON": "{}",
            "description": "Total blocked requests",
            "kibanaSavedObjectMeta": {
                "searchSourceJSON": json.dumps({
                    "index": DATA_VIEW_ID,
                    "query": {"query": "status_code:403", "language": "kuery"},
                    "filter": []
                })
            }
        },
        "references": [{"id": DATA_VIEW_ID, "name": "kibanaSavedObjectMeta.searchSourceJSON.index", "type": "index-pattern"}]
    }

    # ── 6. Tag Cloud: Attack Tags ──
    vis_tags_cloud = {
        "type": "visualization",
        "id": "beewaf-tags-cloud",
        "attributes": {
            "title": "☁️ Attack Tags Cloud",
            "visState": json.dumps({
                "title": "Attack Tags Cloud",
                "type": "tagcloud",
                "aggs": [
                    {"id": "1", "enabled": True, "type": "count", "params": {}, "schema": "metric"},
                    {"id": "2", "enabled": True, "type": "terms", "params": {
                        "field": "tags",
                        "orderBy": "1",
                        "order": "desc",
                        "size": 30
                    }, "schema": "segment"}
                ],
                "params": {
                    "scale": "linear",
                    "orientation": "single",
                    "minFontSize": 18,
                    "maxFontSize": 72,
                    "showLabel": True
                }
            }),
            "uiStateJSON": "{}",
            "description": "Cloud of attack tags",
            "kibanaSavedObjectMeta": {
                "searchSourceJSON": json.dumps({
                    "index": DATA_VIEW_ID,
                    "query": {"query": "status_code:403", "language": "kuery"},
                    "filter": []
                })
            }
        },
        "references": [{"id": DATA_VIEW_ID, "name": "kibanaSavedObjectMeta.searchSourceJSON.index", "type": "index-pattern"}]
    }

    # ── 7. Pie Chart: HTTP Methods ──
    vis_http_methods = {
        "type": "visualization",
        "id": "beewaf-http-methods",
        "attributes": {
            "title": "📡 HTTP Methods",
            "visState": json.dumps({
                "title": "HTTP Methods",
                "type": "pie",
                "aggs": [
                    {"id": "1", "enabled": True, "type": "count", "params": {}, "schema": "metric"},
                    {"id": "2", "enabled": True, "type": "terms", "params": {
                        "field": "http_method",
                        "orderBy": "1",
                        "order": "desc",
                        "size": 10
                    }, "schema": "segment"}
                ],
                "params": {
                    "type": "pie",
                    "addTooltip": True,
                    "addLegend": True,
                    "legendPosition": "right",
                    "isDonut": False,
                    "labels": {"show": True, "values": True, "last_level": True, "truncate": 100}
                }
            }),
            "uiStateJSON": "{}",
            "description": "Distribution of HTTP methods",
            "kibanaSavedObjectMeta": {
                "searchSourceJSON": json.dumps({
                    "index": DATA_VIEW_ID,
                    "query": {"query": "", "language": "kuery"},
                    "filter": []
                })
            }
        },
        "references": [{"id": DATA_VIEW_ID, "name": "kibanaSavedObjectMeta.searchSourceJSON.index", "type": "index-pattern"}]
    }

    # ── 8. Line Chart: Request Timeline ──
    vis_timeline = {
        "type": "visualization",
        "id": "beewaf-request-timeline",
        "attributes": {
            "title": "📈 Request Timeline",
            "visState": json.dumps({
                "title": "Request Timeline",
                "type": "line",
                "aggs": [
                    {"id": "1", "enabled": True, "type": "count", "params": {}, "schema": "metric"},
                    {"id": "2", "enabled": True, "type": "date_histogram", "params": {
                        "field": "@timestamp",
                        "calendar_interval": "1m",
                        "min_doc_count": 0
                    }, "schema": "segment"}
                ],
                "params": {
                    "type": "line",
                    "grid": {"categoryLines": False},
                    "addTooltip": True,
                    "addLegend": True,
                    "legendPosition": "right"
                }
            }),
            "uiStateJSON": "{}",
            "description": "Request volume over time",
            "kibanaSavedObjectMeta": {
                "searchSourceJSON": json.dumps({
                    "index": DATA_VIEW_ID,
                    "query": {"query": "", "language": "kuery"},
                    "filter": []
                })
            }
        },
        "references": [{"id": DATA_VIEW_ID, "name": "kibanaSavedObjectMeta.searchSourceJSON.index", "type": "index-pattern"}]
    }

    # ── 9. Pie: Status Codes Distribution ──
    vis_status_codes = {
        "type": "visualization",
        "id": "beewaf-status-codes",
        "attributes": {
            "title": "🔢 Status Codes",
            "visState": json.dumps({
                "title": "Status Codes",
                "type": "pie",
                "aggs": [
                    {"id": "1", "enabled": True, "type": "count", "params": {}, "schema": "metric"},
                    {"id": "2", "enabled": True, "type": "terms", "params": {
                        "field": "status_code",
                        "orderBy": "1",
                        "order": "desc",
                        "size": 10
                    }, "schema": "segment"}
                ],
                "params": {
                    "type": "pie",
                    "addTooltip": True,
                    "addLegend": True,
                    "legendPosition": "right",
                    "isDonut": True,
                    "labels": {"show": True, "values": True, "last_level": True, "truncate": 100}
                }
            }),
            "uiStateJSON": "{}",
            "description": "HTTP status code distribution",
            "kibanaSavedObjectMeta": {
                "searchSourceJSON": json.dumps({
                    "index": DATA_VIEW_ID,
                    "query": {"query": "", "language": "kuery"},
                    "filter": []
                })
            }
        },
        "references": [{"id": DATA_VIEW_ID, "name": "kibanaSavedObjectMeta.searchSourceJSON.index", "type": "index-pattern"}]
    }

    # ── 10. Metric: Average Latency ──
    vis_avg_latency = {
        "type": "visualization",
        "id": "beewaf-avg-latency",
        "attributes": {
            "title": "⏱️ Average Latency (ms)",
            "visState": json.dumps({
                "title": "Average Latency",
                "type": "metric",
                "aggs": [
                    {"id": "1", "enabled": True, "type": "avg", "params": {"field": "latency_ms"}, "schema": "metric"}
                ],
                "params": {
                    "addTooltip": True,
                    "addLegend": False,
                    "type": "metric",
                    "metric": {
                        "percentageMode": False,
                        "colorSchema": "Green to Red",
                        "metricColorMode": "None",
                        "style": {"bgFill": "#000", "bgColor": False, "labelColor": False, "subText": "ms", "fontSize": 60}
                    }
                }
            }),
            "uiStateJSON": "{}",
            "description": "Average latency in ms",
            "kibanaSavedObjectMeta": {
                "searchSourceJSON": json.dumps({
                    "index": DATA_VIEW_ID,
                    "query": {"query": "", "language": "kuery"},
                    "filter": []
                })
            }
        },
        "references": [{"id": DATA_VIEW_ID, "name": "kibanaSavedObjectMeta.searchSourceJSON.index", "type": "index-pattern"}]
    }

    # ── 11. Table: Recent Attacks ──
    vis_recent_attacks = {
        "type": "visualization",
        "id": "beewaf-recent-attacks-table",
        "attributes": {
            "title": "🚨 Recent Attacks (Table)",
            "visState": json.dumps({
                "title": "Recent Attacks Table",
                "type": "table",
                "aggs": [
                    {"id": "1", "enabled": True, "type": "count", "params": {}, "schema": "metric"},
                    {"id": "2", "enabled": True, "type": "terms", "params": {
                        "field": "block_reason",
                        "orderBy": "1",
                        "order": "desc",
                        "size": 20
                    }, "schema": "bucket"},
                    {"id": "3", "enabled": True, "type": "terms", "params": {
                        "field": "http_method",
                        "orderBy": "1",
                        "order": "desc",
                        "size": 5
                    }, "schema": "bucket"},
                    {"id": "4", "enabled": True, "type": "terms", "params": {
                        "field": "http_path.keyword",
                        "orderBy": "1",
                        "order": "desc",
                        "size": 10
                    }, "schema": "bucket"}
                ],
                "params": {
                    "perPage": 15,
                    "showPartialRows": False,
                    "showMetricsAtAllLevels": False,
                    "showTotal": True,
                    "totalFunc": "sum",
                    "percentageCol": ""
                }
            }),
            "uiStateJSON": json.dumps({"vis": {"params": {"sort": {"columnIndex": 3, "direction": "desc"}}}}),
            "description": "Table of recent attacks by reason, method, and path",
            "kibanaSavedObjectMeta": {
                "searchSourceJSON": json.dumps({
                    "index": DATA_VIEW_ID,
                    "query": {"query": "status_code:403", "language": "kuery"},
                    "filter": []
                })
            }
        },
        "references": [{"id": DATA_VIEW_ID, "name": "kibanaSavedObjectMeta.searchSourceJSON.index", "type": "index-pattern"}]
    }

    # ── 12. Markdown: WAF Info ──
    vis_info = {
        "type": "visualization",
        "id": "beewaf-info-markdown",
        "attributes": {
            "title": "🐝 BeeWAF Info",
            "visState": json.dumps({
                "title": "BeeWAF Info",
                "type": "markdown",
                "aggs": [],
                "params": {
                    "markdown": "# 🐝 BeeWAF Enterprise v6.0\n\n**Web Application Firewall Dashboard**\n\n---\n\n| Spec | Value |\n|------|-------|\n| **Rules** | 10,041 compiled patterns |\n| **ML Models** | 3 (IF + RF + GB) |\n| **Modules** | 27 security modules |\n| **Compliance** | OWASP, PCI DSS, GDPR, SOC2, NIST, ISO 27001, HIPAA |\n| **Grade** | **A+** (98.2/100) |\n| **FP Rate** | **0%** |",
                    "openLinksInNewTab": False,
                    "fontSize": 12
                }
            }),
            "uiStateJSON": "{}",
            "description": "BeeWAF information panel",
            "kibanaSavedObjectMeta": {
                "searchSourceJSON": json.dumps({"query": {"query": "", "language": "kuery"}, "filter": []})
            }
        },
        "references": []
    }

    all_visualizations = [
        vis_attack_types, vis_blocked_allowed, vis_top_paths,
        vis_total_requests, vis_total_blocked, vis_tags_cloud,
        vis_http_methods, vis_timeline, vis_status_codes,
        vis_avg_latency, vis_recent_attacks, vis_info
    ]

    # ── Create Dashboard ──
    dashboard_panels = []
    panel_configs = [
        # Row 1: Info + Metrics
        {"id": "beewaf-info-markdown", "x": 0, "y": 0, "w": 16, "h": 10},
        {"id": "beewaf-total-requests", "x": 16, "y": 0, "w": 8, "h": 5},
        {"id": "beewaf-total-blocked", "x": 24, "y": 0, "w": 8, "h": 5},
        {"id": "beewaf-avg-latency", "x": 32, "y": 0, "w": 8, "h": 5},
        {"id": "beewaf-status-codes", "x": 16, "y": 5, "w": 16, "h": 10},
        {"id": "beewaf-http-methods", "x": 32, "y": 5, "w": 16, "h": 10},
        # Row 2: Timeline + Blocked/Allowed
        {"id": "beewaf-request-timeline", "x": 0, "y": 10, "w": 24, "h": 12},
        {"id": "beewaf-blocked-vs-allowed", "x": 24, "y": 10, "w": 24, "h": 12},
        # Row 3: Attack details
        {"id": "beewaf-attack-types-pie", "x": 0, "y": 22, "w": 16, "h": 14},
        {"id": "beewaf-tags-cloud", "x": 16, "y": 22, "w": 16, "h": 14},
        {"id": "beewaf-top-blocked-paths", "x": 32, "y": 22, "w": 16, "h": 14},
        # Row 4: Table
        {"id": "beewaf-recent-attacks-table", "x": 0, "y": 36, "w": 48, "h": 16},
    ]

    for i, pc in enumerate(panel_configs):
        panel = {
            "version": "8.11.0",
            "type": "visualization",
            "gridData": {"x": pc["x"], "y": pc["y"], "w": pc["w"], "h": pc["h"], "i": str(i)},
            "panelIndex": str(i),
            "embeddableConfig": {},
            "panelRefName": f"panel_{i}"
        }
        dashboard_panels.append(panel)

    dashboard_references = [
        {"id": pc["id"], "name": f"panel_{i}", "type": "visualization"}
        for i, pc in enumerate(panel_configs)
    ]

    dashboard = {
        "type": "dashboard",
        "id": "beewaf-security-dashboard",
        "attributes": {
            "title": "🐝 BeeWAF Enterprise Security Dashboard",
            "description": "Real-time WAF monitoring: attacks, blocks, latency, and security analytics",
            "panelsJSON": json.dumps(dashboard_panels),
            "optionsJSON": json.dumps({"useMargins": True, "syncColors": False, "syncCursor": True, "syncTooltips": False, "hidePanelTitles": False}),
            "timeRestore": True,
            "timeTo": "now",
            "timeFrom": "now-1h",
            "refreshInterval": {"pause": False, "value": 10000},
            "kibanaSavedObjectMeta": {
                "searchSourceJSON": json.dumps({
                    "query": {"query": "", "language": "kuery"},
                    "filter": []
                })
            }
        },
        "references": dashboard_references
    }

    # ── Bulk create all objects ──
    all_objects = all_visualizations + [dashboard]

    print(f"📤 Creating {len(all_objects)} saved objects in Kibana...")
    
    r = requests.post(
        f"{KIBANA}/api/saved_objects/_bulk_create?overwrite=true",
        headers=HEADERS,
        json=all_objects,
        timeout=30
    )
    
    result = r.json()
    
    if "saved_objects" in result:
        success = sum(1 for obj in result["saved_objects"] if "error" not in obj)
        errors = sum(1 for obj in result["saved_objects"] if "error" in obj)
        print(f"✅ Created: {success}")
        print(f"❌ Errors: {errors}")
        for obj in result["saved_objects"]:
            status = "✅" if "error" not in obj else "❌"
            title = obj.get("attributes", {}).get("title", obj.get("id", "?"))
            if "error" in obj:
                print(f"  {status} {title}: {obj['error'].get('message', 'unknown error')}")
            else:
                print(f"  {status} {title}")
    else:
        print(f"❌ Error: {json.dumps(result, indent=2)}")

    print(f"\n🔗 Dashboard URL:")
    print(f"   http://localhost:5601/app/dashboards#/view/beewaf-security-dashboard")
    print(f"\n🔗 Discover (raw logs):")
    print(f"   http://localhost:5601/app/discover")

if __name__ == "__main__":
    create_saved_objects()
