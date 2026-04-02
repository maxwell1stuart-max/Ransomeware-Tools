from setuptools import setup, find_packages

setup(
    name="rft",
    version="1.0.0",
    description="Ransomware Forensics Toolkit — AI-powered ransomware analysis for Raspberry Pi",
    packages=find_packages(),
    python_requires=">=3.10",
    install_requires=[
        "anthropic>=0.40.0",
        "rich>=13.7.0",
        "click>=8.1.7",
        "pydantic>=2.5.0",
        "jinja2>=3.1.2",
        "tqdm>=4.66.1",
        "python-dateutil>=2.8.2",
        "xxhash>=3.4.1",
        "psutil>=5.9.6",
    ],
    extras_require={
        "full": [
            "python-evtx>=0.7.4",
            "python-registry>=1.4.0",
            "yara-python>=4.3.1",
            "pefile>=2023.2.7",
            "reportlab>=4.0.8",
            "dnspython>=2.4.2",
        ],
        "dev": [
            "pytest>=7.4.0",
            "pytest-asyncio>=0.21.0",
            "black>=23.0.0",
            "ruff>=0.1.0",
        ],
    },
    entry_points={
        "console_scripts": [
            "rft=rft.cli:main",
            "rft-gui=rft.web.launcher:main",
        ],
    },
    package_data={
        "rft": [
            "knowledge_base/db_schema.sql",
            "reporting/templates/*.json",
            "web/templates/*.html",
            "web/static/css/*.css",
            "web/static/js/*.js",
        ],
    },
    classifiers=[
        "Development Status :: 4 - Beta",
        "Environment :: Console",
        "Intended Audience :: Information Technology",
        "License :: OSI Approved :: MIT License",
        "Operating System :: POSIX :: Linux",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Topic :: Security",
        "Topic :: System :: Systems Administration",
    ],
)
