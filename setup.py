from setuptools import setup

setup(
    name='antishlopcli',
    version='1.0.0',
    description='Anti-vibe coding and security tool',
    author='Arjun Bajpai',
    author_email='ArjunBajpai@tutamail.com',
    packages=['antishlopcli'],
    entry_points={
        'console_scripts': [
            'antishlop=antishlopcli.cli:main',
        ],
    },
    install_requires=[
        'openai',
        'colorama',
        'rich',
        'python-dotenv',
        'langchain==0.3.23',
        'langchain-openai==0.3.12',
        'langgraph==0.2.67',
        'typing-extensions'
    ]
)