# -*- coding: utf-8 -*-

import ldap, random
from socket import gethostbyname
from urlparse import urlparse as getFQDN

from adutils import adUtils

from adobjs import adObjs, adGroups, adComputers, adUsers, adOUs
import getpass


class adLDAP(adUtils):
	''' Principal Class to init the Framework	
	
		 Example:
		 	ad = adLDAP(dcs=[dc1.fqdn,dc2.fqdn,dc3.fqdn,fqdn],username="usernameAD@fqdn",password="secret")

			or

			dictconnection = {
				"dcs" : [dc1.fqdn,dc2.fqdn,dc3.fqdn,fqdn],
				"username" : "usernameAD@fqdn",
				"password" : "secret"
			}
			ad = adLDAP(**dictconnection)
	'''

	def __init__(self,dcs,username,password=None,basedn=None):
		'''Method construct.
			@params:
				(List)dcs : Domain Controller list.
				(String)username : username to Active Directory ldap connect
				(string)password : the username password
				(string)basedn : minimun dcs to ldap connection must be work.

			@return: None
		'''
		if type(dcs) is not list:
			raise Exception("dcs argument is not a valid list")
		self.controller = None
		self.domainControllers = dcs
		self.username = username
		if password == None:
			self.password = getpass.getpass("Password: ")
		else:		
			self.password = password
		self.baseDN = basedn
		if not self.connect():
			raise ldap.INVALID_CREDENTIALS("Invalid Username or Password")

	def __del__(self):
		'''Method destruct.
			@params: None
			@return: None
		'''
		self.ldapConnection.unbind_s()

	def getController(self):
		'''Method to get random DC from domainControllers attribute.
			
			Select a random domain controller to replace FQDN by IP to allways connect same DC.

			@params: None
			@return: None
			@attributes:
				(List)domainControllers = List domain controllers to connect
				(str)controller = Controller selected to connect
				(str)baseDN = if not set baseDN in method construct the method set attribute from FQDN DC
				(bool)secureConnection = set attribute if ldap is secure
		'''
		if not self.controller:
			uri = random.choice(self.domainControllers)
			dc = getFQDN(uri).netloc
			ip = gethostbyname(dc)
			if not self.baseDN:
				self.baseDN = 'dc='+dc.replace('.',',dc=')
			self.controller = uri.replace(dc,ip)
			if self.controller.find('ldaps') > -1:
				self.secureConnection = True
			else:
				self.secureConnection = False
		return self.controller

	def connect(self):
		'''Method to configure minimun ldap parameters and create bind connection
			@params: none
			@return: None
			@attributes: None
		'''
		self.ldapConnection = ldap.initialize(self.getController())
		self.ldapConnection.set_option(ldap.OPT_PROTOCOL_VERSION,3)
		self.ldapConnection.set_option(ldap.OPT_REFERRALS,0)
		if self.secureConnection:
			self.ldapConnection.set_option(ldap.OPT_X_TLS_REQUIRE_CERT, ldap.OPT_X_TLS_ALLOW)
		return self.authentication()

	def authentication(self):
		'''Method to create bind connection and valid user credentials'''
		try:
			self.ldapConnection.simple_bind_s(self.username,self.password)
			return True
		except ldap.INVALID_CREDENTIALS:
			return False


	def getADmaxPwdAge(self):
		'''Method to get maxPwdAge from principal DN'''
		info = self.objs.filter('(objectclass=*)',attr=['maxPwdAge'],ldapscope=ldap.SCOPE_BASE,control_type=False)[0]
		return info.maxpwdage.value

	def getDomainRID(self):
		'''Method to get Domain RID from principal DN'''
		info = self.objs.filter('(objectclass=*)',attr=['objectsid'],ldapscope=ldap.SCOPE_BASE,control_type=False)[0]
		return info.objectsid.value

	@property
	def users(self):
		'''Method like property to init adUser class
			
			Example:
				ad.users.new()

				or

				ad.users.get('(attribute=value)')
		'''
		return adUsers(self)

	@property
	def computers(self):
		'''Method like property to init adComputers class

			Example:
				ad.computers.new()

				or

				ad.computers.get('(attribute=value)')
		'''
		return adComputers(self)
	
	@property
	def groups(self):
		'''Method like property to init adGroups class
			
			Example:
				ad.groups.new()

				or

				ad.groups.get('(attribute=value)')
		'''
		return adGroups(self)

	@property
	def objs(self):
		'''Method like property to init adObjs class

			Example:
				ad.objs.new()

				or

				ad.objs.get('(attribute=value)')
		'''
		return adObjs(self)

	@property
	def ous(self):
		'''Method like property to init adOUs class

			Example:
				ad.ous.new()

				or

				ad.ous.get('(attribute=value)')
		'''
		return adOUs(self)
