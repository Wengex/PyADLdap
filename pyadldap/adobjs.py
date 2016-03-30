# -*- coding: utf-8 -*-
import ldap, json, copy, uuid, decimal, datetime, ldap.modlist
from adobjstype import *

class adObj(object):
	'''Class to represent a LDAP Object using python object attributes like LDAP attributes
	and some methods to manage data on LDAP protocol

		Example:
			obj.dn -> Object LDAP DN attribute
			obj.samaccountname -> Object LDAP sAMAccountName attribute
			obj.description -> Object LDAP description attribute
	'''

	objtype = {}
	newobj = []

	@classmethod
	def is_type(self,data):
		'''This method checks if the data coincide with the object ldap

			@params:
				(dict)data: Dictionary object representing an LDAP object

			@return: (bool) if data is type then return True, else return False
		'''
		for i in self.objtype:
			dt = data.copy().get(i,None)
			obj = self.objtype.copy().get(i)
			if dt != None:
				dt.sort()
				obj.sort()
				if dt == obj:
					return True
		return False
		
	def __init__(self,adldap,dn,data):
		'''Constructor method

			@params:
				(adLDAP)adldap: Instance adLDAP object
				(str)dn: The DN ldap object
				(data)data: LDAP Object attributes dictionary

			@attributes:
				(bool)is_new : set True if the adObj is new to create LDAP object
				(bool)adcomplete: set True if initial object loading is complete
				(adLDAP)adldap : set instance adLDAP object

			@return: None
		'''
		self.is_new = False
		self.adcomplete = False
		self.adldap = adldap
		if dn == None: #NewObj
			for attr in self.newobj:
				setattr(self,attr.lower(),None)
			setattr(self,'container',None)
		else:
			setattr(self,"dn",dn)
			cnt = dn.split(',')[1:]
			setattr(self,"container",",".join(cnt))

		for i in data:
			setattr(self,i.lower(),data[i])
		self.adcomplete = True

	def __repr__(self):
		'''Special method to return repr data
		'''
		return repr(self.dn)

	def __getitem__(self,item):
		'''Special method to get attributes to object like dictionary
			
			@params:
				(string)item : LDAP attribute object representation

			@return: (ADGenericAttr) Return AD Object type LDAP Attribute
		'''
		return self.__dict__[item]

	def __setitem__(self,field,value):
		'''Special method to get attributes to object like dictionary

			@params:
				(string)item : LDAP attribute object representation
				(anyone)value : LDAP value to set attribute object

			@return: None
      '''
	
		setattr(self,field,value)

	def __iter__(self):
		dct = self.__dict__.copy()
		del dct['adcomplete']
		del dct['adldap']
		del dct['is_new']
		return iter(dct)

	def __str__(self):
		'''Special method to print human representation oject

			Example:
				print obj

		'''
		data = self.__dict__.copy()
		del data['adldap']
		del data['adcomplete']
		del data['is_new']
		result = {}
		for i in data:
			result[i] = data[i].humanReadeable()
		return json.dumps(result,ensure_ascii=False, indent=3)

	def __setattr__(self,field,value):
		'''Special method to set Object with Object Types Attributes
		
			@params:
				(string)field : LDAP attribute name object representation
				(anyone)value : set LDAP attribute object value

			@return: None
		'''

		if (field == "adldap") or (field == 'adcomplete') or (field == 'is_new'):
			super(adObj,self).__setattr__(field,value)
			return

		if value == None:
			value = []

		if type(value) != list:
			string = u"%(value)s" % {'value': value.decode('utf-8')}
			if string.strip() == '':
				value = []
			else:
				value = [string]

		adtypes = {
			'dn': dn,
			'msmqsigncertificates' : mSMQSignCertificates,
			'useraccountcontrol' : UserAccountControl,
			'lastlogon' : lastLogon,
			'pwdlastset' : pwdLastSet,
			'lastlogontimestamp' : lastLogonTimeStamp,
			'accountexpires' : accountExpires,
			'badpasswordtime' : badPasswordTime,
			'dscorepropagationdata' : dSCorePropagationData,
			'whenchanged' : WhenChanged,
			'whencreated' : WhenCreated,
			'objectguid' : ObjectGUID,
			'objectsid' : ObjectSid,
			'sidhistory' : sIDHistory,
			'samaccountname' : sAMAccountName,
			'memberof' : memberOf,
			'member' : member,
			'adgenericattr' : adGenericAttr,
			'logonhours' : logonHours,
			'userworkstations' : userWorkStations,
			'manager' : manager,
			'directreports' : directreports,
			'unicodePwd' : unicodePwd,
			'primarygroupid' : PrimaryGroupID,
		}

		try:
			val = adtypes[field](self.adldap,value)
		except:
			val = adtypes['adgenericattr'](self.adldap,value)

		if self.adcomplete:
			val.is_modified = True

		super(adObj,self).__setattr__(field,val)

	@property
	def is_enable(self):
		'''Method to check if LDAP Object is enable (True) or disable (False)
		'''
		if type(self) != adUser:
			raise self.adldap.ObjectNotHaveEnable("Objet not have enable attribute")
		mod = int(self.useraccountcontrol.value) % 8;
		if mod == 0:
			return True
		else:
			return False

	def delete(self):
		'''Method to delete LDAP Object from Active Directory
		'''
		self.adldap.ldapConnection.delete_s(self.dn.value)

	def move(self,newcontainer):
		'''Method to move LDAP object to another container like OU
		
			@params:
				(string)newcontainer : New Active Directory DN cotainer

			@return: None

			Example:
				obj.move("OU=OUNAME,DC=DCPREFIX,DC=DCSUFFIX")
		'''
		#self.adldap.ldapConnection.rename_s(self.dn.value,'cn='+self.cn.value, newcontainer)
		self.container = newcontainer
		self.save()

	def save(self):
		'''Method to create or modify the LDAP object in Active Directory
		
			If adOBJ is a New object then create LDAP object in Active Directory
			If adOBJ is not a new object then modify LDAP object in Active Directory
		'''
		modlist = []
		attrs = self.__dict__.copy()
		del attrs['adldap']
		del attrs['adcomplete']
		isNew = attrs.get('is_new',False)
		try:
			del attrs['is_new']
		except:
			pass

#		if attrs.get('dn',None).value == None:
#			raise self.adldap.NotDNDefinied("Not DN Definied")

		if (attrs.get('cn',None).value == None) or (attrs.get('container',None).value == None):
			raise self.adldap.NotDNDefinied("CN and/or CONTAINER field can not be None")

		if not isNew: #is modify action
			if attrs['dn'].__dict__.get('is_modified',False):
				raise self.adldap.ForbidChangeDN("Can not change DN field. You must use CN and/or CONTAINER attribute. Remove field.")
			cn = False
			cnt = False
			if attrs['cn'].__dict__.get('is_modified',False):
				cn = attrs['cn'].value
				del attrs['cn']
	
			if attrs['container'].__dict__.get('is_modified',False):
				cnt = attrs['container'].value
				del attrs['container']

			for attr in attrs:
				modtype= ldap.MOD_REPLACE
				if attrs[attr].__dict__.get('is_modified',False):
					if attrs.get(attr,None) == None:
						modtype = ldap.MOD_DELETE
					modlist.append((modtype,attr,attrs[attr].raw))
					if (attr.lower() == 'unicodepwd'): #Two times is needed for update password in AD
						modlist.append((modtype,attr,attrs[attr].raw))

			if len(modlist) > 0:
				self.adldap.ldapConnection.modify_s(self.dn.value,modlist)

			if cn:
				self.adldap.ldapConnection.modrdn_s(self.dn.value,'cn='+str(cn),True)
				newdn = 'cn='+str(cn)+','+','.join(self.dn.value.split(',')[1:])
				self.dn = newdn
				del self.dn.is_modified
				del self.cn.is_modified

			if cnt:
				self.adldap.ldapConnection.rename_s(self.dn.value,'cn='+self.cn.value, cnt)
				newdn = 'cn='+self.cn.value+','+cnt
				self.dn = newdn
				del self.dn.is_modified
				del self.container.is_modified

		else:
			cnt = attrs['container'].value
			del attrs['container']
			add = {}
			
			try:
				if (self.is_enable) and (self.__dict__.get("unicodePwd",None) == None):
					raise Exception("Not set Password to new enable object")
			except self.adldap.ObjectNotHaveEnable:
				pass

			for attr in attrs:
				if (attr in self.newobj) and (attrs[attr].value == None):
					raise self.adldap.EmptyAttrNewObj("Empty attributes for new Object "+str(self.newobj))
				add[attr] = attrs[attr].value
			addlist= ldap.modlist.addModlist(add)
			dn = 'CN='+attrs['cn'].value+','+cnt
			self.adldap.ldapConnection.add_s(dn,addlist)


class adUser(adObj):
	'''
		adObj child object class to represent LDAP Users
	'''
	objtype = {
		'objectClass' : ['top','person', 'organizationalPerson', 'user']
	}
	newobj = [
		'objectclass',
		'useraccountcontrol',
		'userprincipalname',
		'samaccountname',
		'cn',
		'givenname',
		'sn',
		'displayname',
	]

	def disable(self):
		'''Method to disable User in Active Directory'''
		self.useraccountcontrol = ["NORMAL_ACCOUNT","ACCOUNTDISABLE"]
		self.save()

	def enable(self):
		'''Method to enable User in Active Directory'''
		self.useraccountcontrol = ["NORMAL_ACCOUNT"]
		self.save()
	
	def setPassword(self,password):
		'''Set User password'''
		self.unicodePwd = password
		self.save()

	def PasswordExpiry(self):
		'''Get when the user password is expired'''
		pwdLastSet = self.pwdlastset.raw[0]

		if self.useraccountcontrol == '66048':
			return "Does not expire"

		if (pwdLastSet == 0):
			return "Password has expired"
		try:
			maxPwdAge = self.adldap.getADmaxPwdAge()
			mod = int(maxPwdAge) % 4294967296
		except:
			mod = 0
		if mod == 0:
			return "Domain does not expire passwords"

		pwdExpire = decimal.Decimal(pwdLastSet) - decimal.Decimal(maxPwdAge)

		expiryts = int((pwdExpire / 10000000) - 11644473600)

		return datetime.datetime.fromtimestamp(expiryts)


class adGroup(adObj):
	'''
		adObj child object class to represent LDAP Groups
	'''
	objtype = {
		'objectClass' : ['top', 'group']
	}
	newobj = [
		'samaccountname',
		'objectclass',
		'cn',
	]

	def AddToGroup(self,obj):
		'''
			Method to add LDAP object to Group

			@params:
				(adOBJ|DN string)obj: adOBJ or Child or LDAP DN Object string

			@return: None
		'''
		if type(obj) != str:
			dn = str(obj.dn)
		else:
			dn = obj

		try:
			self.member.raw.index(dn)
			modify = False
		except:
			modify = True

		if modify:
			lst = self.member.raw
			lst.append(dn)
			self.member = lst
			self.save()

	def DelFromGroup(self,obj):
		'''
			Method to add LDAP object to Group

			@params:
				(adOBJ|DN string)obj: adOBJ or Child or LDAP DN Object string

			@return: None
		'''
		if type(obj) != str:
			dn = str(obj.dn)
		else:
			dn = obj

		try:
			pos = self.member.raw.index(dn)
			modify = True
		except:
			modify = False

		if modify:
			lst = self.member.raw
			del lst[pos]
			self.member = lst
			self.save()


class adComputer(adObj):
	'''
		adObj child object class to represent LDAP Computers
	'''	
	objtype = {
		'objectClass' : ['top','person', 'organizationalPerson', 'user', 'computer']
	}
	newobj = [
		'objectclass',
		'cn',
		'samaccountname',
		'useraccountcontrol',
	]

	def disable(self):
		self.useraccountcontrol = ["ACCOUNTDISABLE","PASSWD_NOTREQD","WORKSTATION_TRUST_ACCOUNT"]
		self.save()

	def enable(self):
		self.useraccountcontrol = ["PASSWD_NOTREQD","WORKSTATION_TRUST_ACCOUNT"]
		self.save()

class adOU(adObj):
	'''
		adObj child object class to represent LDAP OUs
	'''
	objtype = {
		'objectClass' : ['top', 'organizationalUnit']
	}
	newobj = [
		'ou',
		'objectclass',
	]


class adObjs(object):
	'''Class to create or get adOBjs and childs objects'''
	qryFilter = ''
	adObjType = adObj

	def __init__(self,adldap):
		'''Constructor method'''
		self.adldap = adldap

	def filter(self,query,attr=['*'],ldapscope=ldap.SCOPE_SUBTREE,control_type=True,baseDN=None):
		'''Get multiple adObjs and Childs objects from query ldap sententes

			@params:
				(string)query : LDAP query sentence format
				(list)attr : Attributes to get from LDAP. Default all attributes.
				(ldap.SCOPE_X)ldapscope : Set ldap SCOPE from pytho ldap class attribute
				(bool)control_type : set True if return objects must be especific adObj child or simple adObj object
				(string)baseDN : set baseDN string

			@return: adObj and/or Childs list objects
		'''
		if baseDN == None:
			baseDN = self.adldap.baseDN

		COOKIE = ''
		CRITICALY = True
		PAGE_SIZE=1000
		result = []
		first_pass = True
		pg_ctrl = ldap.controls.SimplePagedResultsControl(CRITICALY,PAGE_SIZE,COOKIE)

		if control_type:
			query = '(&%(filter)s%(query)s)' % {'filter': self.qryFilter, 'query': query}
		else:
			query = '(&%(query)s)' % {'query': query}

		while first_pass or pg_ctrl.cookie:
			first_pass = False
			msgid = self.adldap.ldapConnection.search_ext(baseDN,ldapscope,query,attr,serverctrls=[pg_ctrl])
			result_type, data, msgid, serverctrls = self.adldap.ldapConnection.result3(msgid)
			pg_ctrl.cookie = serverctrls[0].cookie
			for obj in data:
				if obj[0] == None:
					continue
				if adUser.is_type(obj[1]):
					result.append(adUser(self.adldap,obj[0],obj[1]))
					continue
				if adComputer.is_type(obj[1]):
					result.append(adComputer(self.adldap,obj[0],obj[1]))
					continue
				if adGroup.is_type(obj[1]):
					result.append(adGroup(self.adldap,obj[0],obj[1]))
					continue
				if adOU.is_type(obj[1]):
					result.append(adOU(self.adldap,obj[0],obj[1]))
					continue
				result.append(adObj(self.adldap,obj[0],obj[1]))

		return result

	def new(self):
		'''Method to create new adObj'''
		obj = self.adObjType(self.adldap,None,self.adObjType.objtype)
		obj.is_new = True

		return obj


	def get(self,query,attr=['*'],ldapscope=ldap.SCOPE_SUBTREE,control_type=True):
		'''Filter method Wrapper to return one result adObj or Child object'''
		result = self.filter(query,attr,ldapscope,control_type)
		if len(result) == 1:
			return result[0]
		elif len(result) > 1:
			raise self.adldap.MultipleResults("Multiple Results")
		else:
			raise self.adldap.ObjectNotExist("Object not exist")

class adGroups(adObjs):
	'''Child object from adObjs to manage only Groups LDAP Objects'''
	qryFilter = '(&(objectclass=top)(objectclass=group))'
	adObjType = adGroup


class adComputers(adObjs):
	'''Child object from adObjs to manage only Gomputers LDAP Objects'''
	qryFilter = '(&(objectclass=top)(objectclass=person)(objectclass=organizationalPerson)(objectclass=user)(objectclass=computer))'
	adObjType = adComputer


class adUsers(adObjs):
	'''Child object from adObjs to manage only Users LDAP Objects'''
	qryFilter = '(&(objectclass=top)(objectclass=person)(objectclass=organizationalPerson)(objectclass=user)(!(objectclass=computer)))'
	adObjType = adUser

class adOUs(adObjs):
	'''Child object from adObjs to manage only OUs LDAP Objects'''
	qryFilter = '(&(objectclass=top)(objectclass=organizationalUnit))'
	adObjType = adOU
