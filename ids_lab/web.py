"""Read-only local dashboard; all traffic-derived values are rendered as text."""
from collections import defaultdict
import json
from pathlib import Path
import sqlite3
import time

from flask import Flask, g, jsonify, render_template, request

from .rules import load_rules
from .store import connect_readonly, query_events, summary

ROOT = Path(__file__).resolve().parents[1]


def create_app(database="runtime/ids.sqlite3"):
    app = Flask(__name__, template_folder=str(ROOT / "templates"), static_folder=str(ROOT / "static"))
    app.config.update(DATABASE=str(database), MAX_CONTENT_LENGTH=8192)

    @app.before_request
    def database_connection():
        g.db = connect_readonly(app.config["DATABASE"])

    @app.teardown_request
    def close(_error):
        if g.get("db"):
            g.db.close()

    @app.after_request
    def headers(response):
        response.headers["Content-Security-Policy"] = "default-src 'self'; script-src 'self'; style-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Cache-Control"] = "no-store"
        return response

    def filters():
        severity = request.args.get("severity", "")
        detector = request.args.get("detector", "")
        rule = request.args.get("rule", "")
        if severity not in ("", "1", "2", "3", "4") or detector not in ("", "Rule", "ML", "Both"):
            raise ValueError("Invalid filter")
        if rule and rule not in load_rules()["rules"]:
            raise ValueError("Unknown rule")
        return {"severity": severity, "detector": detector, "source": request.args.get("source", "")[:64], "rule": rule, "limit": min(500, max(1, int(request.args.get("limit", 100))))}

    @app.get("/")
    def home():
        return render_template("dashboard.html")

    @app.get("/api/status")
    def status():
        data = summary(g.db)
        sensor = data["state"].get("sensor", {})
        data["capture_active"] = sensor.get("mode") == "live" and sensor.get("status") == "active" and time.time() - sensor.get("heartbeat", 0) < 10
        data["sensor_stale"] = sensor.get("status") == "active" and time.time() - sensor.get("heartbeat", 0) >= 10
        return jsonify(data)

    @app.get("/api/alerts")
    def alerts():
        try:
            return jsonify({"alerts": query_events(g.db, **filters()), "rules": load_rules()["rules"]})
        except ValueError as error:
            return jsonify({"error": str(error)}), 400

    @app.get("/api/incidents")
    def incidents():
        try:
            # Group the most recent bounded set; indicate the limit to clients.
            events = query_events(g.db, **{**filters(), "limit": 500})
        except ValueError as error:
            return jsonify({"error": str(error)}), 400
        grouped = {}
        for event in events:
            key = event["incident_id"]
            if key not in grouped:
                grouped[key] = {"id": key, "src": event["src"], "dst": event["dst"], "first_seen": event["time"],
                                "last_seen": event["last_seen"], "count": 0, "severity": 4, "rule_ids": set(), "ml": False}
            item = grouped[key]
            item["first_seen"] = min(item["first_seen"], event["time"])
            item["last_seen"] = max(item["last_seen"], event["last_seen"])
            item["count"] += 1
            item["severity"] = min(item["severity"], event["severity"])
            item["rule_ids"].update(event["rule_ids"])
            item["ml"] = item["ml"] or bool(event["ml"])
        for item in grouped.values():
            item["rule_ids"] = sorted(item["rule_ids"])
            item["detector"] = "Both" if item["ml"] and item["rule_ids"] else "Rule" if item["rule_ids"] else "ML"
        return jsonify({"incidents": list(grouped.values()), "event_limit": 500})

    @app.get("/api/model")
    def model():
        metadata_path = ROOT / "models/metadata.json"
        metrics_path = ROOT / "reports/model_metrics.json"
        if not metadata_path.exists():
            return jsonify({"status": "unavailable"})
        metadata = json.loads(metadata_path.read_text())
        metadata["metrics"] = json.loads(metrics_path.read_text()) if metrics_path.exists() else {}
        metadata["status"] = summary(g.db)["state"].get("sensor", {}).get("model_status", "not_started")
        return jsonify(metadata)

    return app
