from setuptools import setup, find_packages

setup(
    name='devops_bot',
    version='0.1',
    packages=find_packages(),
    include_package_data=True,
    install_requires=[
        'Click==8.1.7',
        'Flask==3.0.3',
        'gunicorn==22.0.0',
        'requests==2.32.3',
        'cryptography==43.0.0',
        'PyYAML==6.0.1',
        'boto3==1.24.10',  # Make sure to specify the correct version of boto3
        'Flask-SQLAlchemy==3.0.4',
        'Werkzeug>=3.0.0',
        'Flask-Mail==0.9.1',
        'python-dotenv==1.0.0',
        'PyJWT==2.7.0',
        'tabulate==0.8.9',
        'argcomplete==1.12.3',
        'psutil==5.9.1',
        'tqdm==4.62.3'
    ],
    entry_points='''
        [console_scripts]
        dob=devops_bot.cli:cli
    ''',
)

