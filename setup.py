from setuptools import setup, find_packages

setup(
    name='cloudwatchdog',
    version='1.0.0',
    packages=find_packages(),
    include_package_data=True,
    install_requires=[
        # Optional: you can add colorama or others here
    ],
    entry_points={
        'console_scripts': [
            'cloudwatchdog=cloudwatchdog.__main__:main',
        ],
    },
    author="Yousra",
    description="CloudWatchdog - a CLI tool for detecting suspicious cloud activity",
    python_requires='>=3.6',
)
