from flask import Flask

app = Flask(__name__)

@app.route('/devops-bot/uptime')
def uptime():
    return "The system is up and running!"

if __name__ == "__main__":
    app.run()
root@devops-bot:~/devops_bot# cat setup.py
from setuptools import setup, find_packages

setup(
    name='devops-bot',
    version='0.1',
    packages=find_packages(),
    install_requires=[
        'Click',
        'Flask',
        'gunicorn',
        'requests',
        'cryptography',
        'PyYAML',
        'boto3'
    ],
    entry_points='''
        [console_scripts]
        dob=devops_bot.cli:cli
    ''',
)
