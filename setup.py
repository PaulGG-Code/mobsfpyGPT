import setuptools

with open('README.md', 'r') as f:
    long_description = f.read()

setuptools.setup(
    name='mobsfpy',
    version='0.0.1-dev',
    author='lolplz',
    author_email='hackul0s@hotmail.com',
    description='Python CLI and wrapper for the Mobile Security Framework (MobSF) REST-API ',
    license='MIT',
    long_description=long_description,
    long_description_content_type='text/markdown',
    url='https://github.com/paulgg-code/mobsfpyGPT',
    packages=setuptools.find_packages(),
    install_requires=[
        'requests',
        'requests-toolbelt',
        'openai'
    ],
    entry_points={
        'console_scripts': [
            'mobsf = mobsfpy.cli:main'
        ]
    },
    classifiers=[
        'Development Status :: 2 - Pre-Alpha',
        'Environment :: Console',
        'Programming Language :: Python',
        'Programming Language :: Python :: 3',
        'License :: OSI Approved :: MIT License',
        'Natural Language :: English',
        'Operating System :: OS Independent',
        'Topic :: Security',
        'Topic :: Utilities',
    ],
    python_requires='>=3.6',
    keywords='mobsf api cli android ios mobile security analysis openai',
)
