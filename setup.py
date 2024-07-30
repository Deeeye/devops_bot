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
        'requests==2.32.3',
        'PyYAML==6.0.1',
        'flask==3.0.3',
        'gunicorn==22.0.0',
        'click==8.1.7',
        'boto3==1.34.145',
        'Flask-SQLAlchemy==3.0.4',
        'Werkzeug>=3.0.0',
        'Flask-Mail==0.9.1',
        'python-dotenv==1.0.0',
        'PyJWT==2.7.0',
        'tabulate==0.8.9',
        'argcomplete',
        'cryptography',
        'psutil',
        'tqdm'
    ],
    entry_points='''
        [console_scripts]
        dob=devops_bot.cli:cli
    ''',
)

