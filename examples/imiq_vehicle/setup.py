from setuptools import find_packages, setup

package_name = 'imiq_vehicle'

setup(
    name=package_name,
    version='0.1.0',
    packages=find_packages(exclude=['test']),
    data_files=[
        ('share/ament_index/resource_index/packages',
            ['resource/' + package_name]),
        ('share/' + package_name, ['package.xml']),
    ],
    install_requires=['setuptools'],
    zip_safe=True,
    maintainer='Bjorn',
    maintainer_email='bjorn@todo.todo',
    description='IMIQ vehicle WebRTC/WebTransport client for OCC server communication',
    license='MIT',
    entry_points={
        'console_scripts': [
            'occ = imiq_vehicle.occ:main',
            'occ_dummy = imiq_vehicle.occ:main',
        ],
    },
)
