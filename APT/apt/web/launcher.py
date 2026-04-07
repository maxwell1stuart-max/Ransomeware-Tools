"""APT web server launcher."""
import os
import sys


def main():
    port = int(os.environ.get("APT_PORT", 5001))
    host = os.environ.get("APT_HOST", "0.0.0.0")
    workers = int(os.environ.get("APT_WORKERS", 1))

    try:
        import gunicorn.app.base

        class APTApp(gunicorn.app.base.BaseApplication):
            def __init__(self, app, options=None):
                self.options = options or {}
                self.application = app
                super().__init__()

            def load_config(self):
                for k, v in self.options.items():
                    self.cfg.set(k.lower(), v)

            def load(self):
                return self.application

        from apt.web.app import app
        opts = {
            "bind": f"{host}:{port}",
            "workers": workers,
            "worker_class": "gthread",
            "threads": 4,
            "timeout": 600,
            "accesslog": "-",
            "errorlog": "-",
        }
        print(f"APT starting on http://{host}:{port}")
        APTApp(app, opts).run()

    except ImportError:
        from apt.web.app import run_server
        print(f"APT starting on http://{host}:{port} (dev mode)")
        run_server(host=host, port=port, debug="--debug" in sys.argv)


if __name__ == "__main__":
    main()
