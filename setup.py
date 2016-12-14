#!/usr/bin/env python


import setuptools

setup(name='idawilli',
      version='0.1',
      description='IDA Pro resources, scripts, and configurations.',
      author='Willi Ballenthin',
      author_email='william.ballenthin@fireeye.com',
      license='Apache License (2.0)',
      packages=setuptools.find_packages(),
      classifiers = ["Programming Language :: Python",
                     "Programming Language :: Python :: 2",
                     "Operating System :: OS Independent",
                     "License :: OSI Approved :: Apache Software License"],
     install_requires=[
         'pytest',
     ],
 )

