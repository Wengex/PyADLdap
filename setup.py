from distutils.core import setup

setup(
	name="pyadldap",
	version="0.1.2",
	description="FrameWork for managing Microsoft Active Directory from LDAP",
	author="Jonas Delgado Mesa",
	author_email="jdelgado@yohnah.net",
	url="https://github.com/Wengex/PyADLdap",
	license="GPLv2",
	packages=["pyadldap"],
	long_description=open('README.md').read(),
	install_requires = ['python-ldap']
)
