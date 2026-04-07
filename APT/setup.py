"""APT — Automated Penetration Toolkit setup."""
from setuptools import setup, find_packages

setup(
    name="apt-toolkit",
    version="1.0.0",
    description="Automated Penetration Toolkit — plug-in, scan, report",
    packages=find_packages(),
    python_requires=">=3.9",
    install_requires=[
        "flask>=3.0.0",
        "flask-cors>=4.0.0",
        "gunicorn>=21.2.0",
        "python-libnmap>=0.7.3",
        "pymetasploit3>=1.0.3",
        "impacket>=0.11.0",
        "requests>=2.31.0",
        "reportlab>=4.0.8",
        "python-dateutil>=2.8.2",
    ],
    entry_points={
        "console_scripts": [
            "apt-gui=apt.web.launcher:main",
        ],
    },
    include_package_data=True,
    package_data={
        "apt": [
            "web/templates/*.html",
            "web/static/css/*.css",
            "web/static/js/*.js",
        ],
    },
)
