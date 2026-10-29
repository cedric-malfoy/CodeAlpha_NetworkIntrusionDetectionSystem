import argparse
import csv
import json
from pathlib import Path
import signal
import threading


def main():
    parser = argparse.ArgumentParser(description="Custom rule + machine-learning network IDS")
    parser.add_argument("--database", default="runtime/ids.sqlite3")
    commands = parser.add_subparsers(dest="command", required=True)
    replay_parser = commands.add_parser("replay", help="Analyze a PCAP without transmitting packets")
    replay_parser.add_argument("pcap")
    live_parser = commands.add_parser("live", help="Continuously capture an authorized interface")
    live_parser.add_argument("--interface", default="eth0")
    dashboard = commands.add_parser("dashboard")
    dashboard.add_argument("--host", default="127.0.0.1")
    dashboard.add_argument("--port", type=int, default=8088)
    commands.add_parser("status")
    export = commands.add_parser("export")
    export.add_argument("--output", default="artifacts/export")
    args = parser.parse_args()
    if args.command == "replay":
        from .engine import replay
        print(json.dumps(replay(args.pcap, args.database), indent=2))
    elif args.command == "live":
        from .engine import live
        stop = threading.Event()
        for sig in (signal.SIGTERM, signal.SIGINT):
            signal.signal(sig, lambda *_args: stop.set())
        live(args.interface, args.database, stop)
    elif args.command == "dashboard":
        from .web import create_app
        create_app(args.database).run(host=args.host, port=args.port, debug=False, use_reloader=False)
    else:
        from .store import connect_readonly, summary
        connection = connect_readonly(args.database)
        try:
            if args.command == "status":
                print(json.dumps(summary(connection), indent=2))
            else:
                directory = Path(args.output)
                directory.mkdir(parents=True, exist_ok=True)
                (directory / "summary.json").write_text(json.dumps(summary(connection), indent=2))
                with (directory / "alerts.csv").open("w", newline="") as output:
                    writer = csv.writer(output)
                    fields = ["id", "incident_id", "timestamp", "src", "dst", "protocol", "severity", "rule_ids", "ml", "score"]
                    writer.writerow(fields)
                    if connection:
                        for row in connection.execute("SELECT " + ",".join(fields) + " FROM events ORDER BY timestamp"):
                            # Prefix spreadsheet formulas in exported text values.
                            writer.writerow(["'" + value if isinstance(value, str) and value.startswith(("=", "+", "-", "@")) else value for value in row])
                print(f"Exported summary.json and alerts.csv to {directory}")
        finally:
            if connection:
                connection.close()


if __name__ == "__main__":
    main()
