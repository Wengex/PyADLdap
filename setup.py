from distutils.core import setup

requires = []

try:
	import ldap
except:
	requires.append('python-ldap')

setup(
	name="pyadldap",
	version="0.1.12",
	description="FrameWork for managing Microsoft Active Directory from LDAP",
	author="Jonas Delgado Mesa",
	author_email="jdelgado@yohnah.net",
	url="https://github.com/Wengex/PyADLdap",
	license="GPLv2",
	packages=["pyadldap"],
	long_description=open('README.txt').read(),
	install_requires = requires
)
