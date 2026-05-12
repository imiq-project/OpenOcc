import os
from glob import glob
from setuptools import setup

package_name = 'imiq_launch'

data_files = [
    ('share/ament_index/resource_index/packages', ['resource/imiq_launch']),
    (f'share/{package_name}', ['package.xml']),
    (f'share/{package_name}/launch', glob('launch/*.py')),
    (f'share/{package_name}/resource', ['resource/husky.urdf']),
]

for root, _dirs, files in os.walk('worlds'):
    file_paths = [os.path.join(root, f) for f in files]
    if file_paths:
        install_dir = os.path.join(f'share/{package_name}', root)
        data_files.append((install_dir, file_paths))

setup(
    name=package_name,
    version='0.1.0',
    packages=[package_name],
    data_files=data_files,
    install_requires=['setuptools'],
    zip_safe=True,
    description='Webots simulation for IMIQ OCC',
    license='MIT',
)
