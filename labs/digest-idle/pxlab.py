"""pxlab: Agent-driven lab for investigating px upstream Digest auth failures after idle."""

import argparse
import json
import shutil
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path


def parse_overrides(items):
    "Parse KEY=VAL items into a dict"
    result = {}
    for item in items:
        if "=" not in item:
            raise ValueError(f"expected KEY=VAL, got {item!r}")
        key, val = item.split("=", 1)
        result[key.strip()] = val.strip()
    return result


SQUID_DEFAULTS = {
    "nonce_garbage_interval": "5 minutes",
    "nonce_max_duration": "30 minutes",
    "nonce_max_count": "50",
    "nonce_strictness": "off",
    "check_nonce_count": "on",
    "authenticate_ttl": "1 hour",
    "authenticate_cache_garbage_interval": "1 hour",
    "pconn_timeout": "1 minute",
    "client_idle_pconn_timeout": "2 minutes",
    "debug_options": "ALL,1 29,5",
}

SQUID_TEMPLATE = """\
http_port 3128
auth_param digest program /usr/lib/squid/digest_file_auth /etc/squid/digest_passwd
auth_param digest children 5
auth_param digest realm pxlab
auth_param digest nonce_garbage_interval {nonce_garbage_interval}
auth_param digest nonce_max_duration {nonce_max_duration}
auth_param digest nonce_max_count {nonce_max_count}
auth_param digest nonce_strictness {nonce_strictness}
auth_param digest check_nonce_count {check_nonce_count}
authenticate_ttl {authenticate_ttl}
authenticate_cache_garbage_interval {authenticate_cache_garbage_interval}
pconn_timeout {pconn_timeout}
client_idle_pconn_timeout {client_idle_pconn_timeout}
acl authed proxy_auth REQUIRED
http_access allow authed
http_access deny all
cache deny all
logformat pxlab ACCESS %ts.%03tu %>a:%>p %un %Ss/%>Hs %rm %ru %<Hs "%{{Proxy-Authorization}}>h" "%{{Proxy-Authenticate}}<h"
access_log stdio:/var/log/squid/access.log pxlab
cache_log /var/log/squid/cache.log
debug_options {debug_options}
"""


def render_squid_conf(overrides):
    "Render squid.conf from defaults updated with overrides"
    unknown = set(overrides) - set(SQUID_DEFAULTS)
    if unknown:
        raise KeyError(f"unknown squid option(s): {sorted(unknown)}")
    return SQUID_TEMPLATE.format(**{**SQUID_DEFAULTS, **overrides})


def render_digest_passwd(broken):
    "Render squid digest password file; broken=True makes px's credentials fail"
    return "pxuser:wrong-password\n" if broken else "pxuser:pxpass\n"


def is_ok(result):
    return 200 <= result["status"] < 300


def latch_verdict(direct_after, px_after):
    "Judge whether px stays failed after upstream auth recovered"
    upstream = is_ok(direct_after)
    px = any(is_ok(r) for r in px_after)
    return {"upstream_recovered": upstream, "px_recovered": px, "latched": (not px) if upstream else None}


def should_stop(result, keep_going):
    "Stop a soak run on the first non-2xx result unless keep_going is set"
    if keep_going:
        return False
    return not is_ok(result)


###
# Stack control (runs on the Docker host)

LAB_DIR = Path(__file__).resolve().parent
STATE_DIR = LAB_DIR / ".state"
RUNS_DIR = LAB_DIR / "runs"
CURRENT_RUN = RUNS_DIR / "current"

PX_DEFAULTS = {
    "PX_PASSWORD": "pxpass",
    "PX_DEBUG_AUTH": "1",
}

ORIGIN_URL = "http://origin/"


def compose(*args, capture=False, check=True):
    "Run docker compose in the lab directory"
    cmd = ["docker", "compose", *args]
    return subprocess.run(cmd, cwd=LAB_DIR, check=check, text=True, capture_output=capture)


def utcnow():
    return datetime.now(timezone.utc)


def archive_current_run():
    "Move runs/current to runs/<timestamp> if it has anything in it"
    if CURRENT_RUN.exists() and any(CURRENT_RUN.iterdir()):
        dest = RUNS_DIR / utcnow().strftime("%Y%m%dT%H%M%SZ")
        shutil.move(str(CURRENT_RUN), dest)
        return dest
    return None


def write_state(squid_overrides, px_overrides):
    "Render squid.conf, px.env and settings.json into .state/"
    STATE_DIR.mkdir(exist_ok=True)
    (STATE_DIR / "squid.conf").write_text(render_squid_conf(squid_overrides))
    (STATE_DIR / "digest_passwd").write_text(render_digest_passwd(broken=False))
    px_env = {**PX_DEFAULTS, **{f"PX_{k.upper()}": v for k, v in px_overrides.items()}}
    (STATE_DIR / "px.env").write_text("".join(f"{k}={v}\n" for k, v in px_env.items()))
    settings = {
        "squid": {**SQUID_DEFAULTS, **squid_overrides},
        "px_env": {k: v for k, v in px_env.items() if k != "PX_PASSWORD"},
    }
    (STATE_DIR / "settings.json").write_text(json.dumps(settings, indent=2) + "\n")
    return settings


def cmd_up(args):
    archived = archive_current_run()
    CURRENT_RUN.mkdir(parents=True, exist_ok=True)
    settings = write_state(parse_overrides(args.squid), parse_overrides(args.px))
    shutil.copy(STATE_DIR / "settings.json", CURRENT_RUN / "settings.json")
    compose("down", "--remove-orphans", capture=True)
    compose("up", "-d", "--build", "--force-recreate", capture=True)
    print(json.dumps({"started_at": utcnow().isoformat(), "archived_previous": str(archived), **settings}))


def cmd_down(args):
    compose("down", "--remove-orphans", capture=True)
    print(json.dumps({"stopped_at": utcnow().isoformat()}))


def service_logs(service, since, until):
    "Return log lines of a service between since and until (RFC3339)"
    out = compose(
        "logs",
        "--no-log-prefix",
        "--timestamps",
        "--since",
        since,
        "--until",
        until,
        service,
        capture=True,
        check=False,
    )
    return [line for line in (out.stdout + out.stderr).splitlines() if line]


def probe(url=ORIGIN_URL, via="px", log_margin=1.0):
    "Send one request through px (or squid directly) and return result with surrounding logs"
    proxy = (
        ["-x", "http://px:3128"]
        if via == "px"
        else ["-x", "http://squid:3128", "--proxy-digest", "-U", "pxuser:pxpass"]
    )
    start = utcnow()
    out = compose(
        "exec",
        "-T",
        "client",
        "curl",
        "-sS",
        "-o",
        "/dev/null",
        "-D",
        "-",
        "--max-time",
        "30",
        *proxy,
        "-w",
        "\n%{json}",
        url,
        capture=True,
        check=False,
    )
    end = utcnow()
    head, _, tail = out.stdout.rpartition("\n")
    try:
        info = json.loads(tail)
    except json.JSONDecodeError:
        info = {}
    time.sleep(log_margin)  # let containers flush logs
    since = datetime.fromtimestamp(start.timestamp() - log_margin, timezone.utc).isoformat()
    until = utcnow().isoformat()
    return {
        "ts": start.isoformat(),
        "via": via,
        "url": url,
        "status": int(info.get("http_code", 0) or 0),
        "curl_exit": out.returncode,
        "curl_error": out.stderr.strip(),
        "elapsed": round((end - start).total_seconds(), 3),
        "num_connects": info.get("num_connects"),
        "response_headers": [h for h in head.splitlines() if h.strip()],
        "px_log": service_logs("px", since, until),
        "squid_log": service_logs("squid", since, until),
    }


def append_jsonl(path, record):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a") as f:
        f.write(json.dumps(record) + "\n")


def cmd_probe(args):
    result = probe(args.url, args.via)
    append_jsonl(CURRENT_RUN / "probes.jsonl", result)
    print(json.dumps(result, indent=2))


def cmd_soak(args):
    "Repeat idle -> probe; one compact JSON line per round on stdout, full record in soak.jsonl"
    for round_no in range(1, args.rounds + 1):
        time.sleep(args.idle)
        result = probe(args.url, args.via)
        result["round"] = round_no
        result["idle"] = args.idle
        append_jsonl(CURRENT_RUN / "soak.jsonl", result)
        print(json.dumps({k: result[k] for k in ("round", "ts", "status", "curl_exit", "elapsed")}), flush=True)
        if should_stop(result, args.keep_going):
            print(json.dumps({"stopped": True, "round": round_no, "status": result["status"]}), flush=True)
            return 1
    return 0


def cmd_fault(args):
    print(json.dumps(set_upstream_auth(args.upstream_auth == "broken")))


def set_upstream_auth(broken):
    "Break or restore upstream auth without restarting px (keeps px's in-memory state)"
    # write_text truncates in place, so the single-file bind mount sees the change
    (STATE_DIR / "digest_passwd").write_text(render_digest_passwd(broken))
    # squid keeps verified credentials for authenticate_ttl even across reconfigure,
    # so restart it (px stays up and keeps its in-memory state)
    compose("restart", "squid", capture=True)
    record = {"ts": utcnow().isoformat(), "fault": "upstream_auth", "broken": broken}
    append_jsonl(CURRENT_RUN / "events.jsonl", record)
    return record


def summarize(result):
    return {k: result[k] for k in ("ts", "via", "status")}


def cmd_scenario(args):
    "latch: fail upstream auth N times, restore it, then check whether px recovers"
    steps = []
    steps.append({"step": "baseline", **summarize(probe())})
    set_upstream_auth(broken=True)
    time.sleep(2)
    for _ in range(args.failures):
        steps.append({"step": "upstream_broken", **summarize(probe())})
    set_upstream_auth(broken=False)
    time.sleep(2)
    direct = probe(via="squid")
    steps.append({"step": "upstream_restored", **summarize(direct)})
    if args.wait:
        time.sleep(args.wait)
    px_after = [probe() for _ in range(args.after)]
    steps.extend({"step": "px_after_restore", **summarize(r)} for r in px_after)
    verdict = latch_verdict(direct, px_after)
    record = {"scenario": "latch", "failures": args.failures, "wait": args.wait, "steps": steps, **verdict}
    append_jsonl(CURRENT_RUN / "scenarios.jsonl", record)
    print(json.dumps(record, indent=2))
    return 1 if verdict["latched"] else 0


def cmd_collect(args):
    "Dump full logs into runs/current, then archive it"
    CURRENT_RUN.mkdir(parents=True, exist_ok=True)
    for service in ("px", "squid", "capture"):
        out = compose("logs", "--no-log-prefix", "--timestamps", service, capture=True, check=False)
        (CURRENT_RUN / f"{service}.log").write_text(out.stdout + out.stderr)
    dest = archive_current_run()
    CURRENT_RUN.mkdir(parents=True, exist_ok=True)
    print(json.dumps({"collected": str(dest), "files": sorted(p.name for p in dest.iterdir()) if dest else []}))


def cmd_status(args):
    out = compose("ps", "--all", "--format", "json", capture=True, check=False)
    services = [json.loads(line) for line in out.stdout.splitlines() if line.strip()]
    settings_path = STATE_DIR / "settings.json"
    print(
        json.dumps(
            {
                "services": [{k: s.get(k) for k in ("Service", "State", "Status")} for s in services],
                "settings": json.loads(settings_path.read_text()) if settings_path.exists() else None,
            },
            indent=2,
        )
    )


def main(argv=None):
    parser = argparse.ArgumentParser(prog="pxlab", description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("up", help="(re)create the stack with given settings")
    p.add_argument(
        "--squid", action="append", default=[], metavar="KEY=VAL", help=f"squid option: {sorted(SQUID_DEFAULTS)}"
    )
    p.add_argument("--px", action="append", default=[], metavar="KEY=VAL", help="px option, passed as PX_<KEY> env var")
    p.set_defaults(func=cmd_up)

    sub.add_parser("down", help="stop the stack").set_defaults(func=cmd_down)

    for name, func in (("probe", cmd_probe), ("soak", cmd_soak)):
        p = sub.add_parser(name)
        p.add_argument("--url", default=ORIGIN_URL)
        p.add_argument("--via", choices=["px", "squid"], default="px")
        if name == "soak":
            p.add_argument("--idle", type=float, required=True, help="seconds to wait before each probe")
            p.add_argument("--rounds", type=int, default=10)
            p.add_argument("--keep-going", action="store_true")
        p.set_defaults(func=func)

    p = sub.add_parser("fault", help="inject upstream faults")
    p.add_argument("--upstream-auth", choices=["broken", "ok"], required=True)
    p.set_defaults(func=cmd_fault)

    p = sub.add_parser("scenario", help="run a scripted reproduction; exit 1 if the bug reproduces")
    p.add_argument("name", choices=["latch"])
    p.add_argument("--failures", type=int, default=3, help="probes sent while upstream auth is broken")
    p.add_argument("--wait", type=float, default=0, help="seconds to wait after upstream recovers")
    p.add_argument("--after", type=int, default=2, help="probes sent through px after recovery")
    p.set_defaults(func=cmd_scenario)

    sub.add_parser("collect", help="dump logs and archive runs/current").set_defaults(func=cmd_collect)
    sub.add_parser("status").set_defaults(func=cmd_status)

    args = parser.parse_args(argv)
    return args.func(args) or 0


if __name__ == "__main__":
    sys.exit(main())
