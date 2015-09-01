# -*- coding: utf-8 -*-

class adUtils(object):
	'''Class with useful tools to facilitate using the framework 
	'''

	class ForbidChangeDN(Exception):
		pass

	class ObjectNotHaveEnable(Exception):
		pass

	class MultipleResults(Exception):
		pass

	class ObjectNotExist(Exception):
		pass

	class NotDNDefinied(Exception):
		pass

	class EmptyAttrNewObj(Exception):
		pass

	class NotUACValueSelected(Exception):
		pass

	acControl = {
	'''text'''
		"SCRIPT" : 1,
		"ACCOUNTDISABLE" : 2,
		"HOMEDIR_REQUIRED" : 8,
		"LOCKOUT" : 16,
		"PASSWD_NOTREQD" : 32,
		"ENCRYPTED_TEXT_PWD_ALLOWED" : 128,
		"TEMP_DUPLICATE_ACCOUNT" : 256,
		"NORMAL_ACCOUNT" : 512,
		"INTERDOMAIN_TRUST_ACCOUNT" : 2048,
		"WORKSTATION_TRUST_ACCOUNT" : 4096,
		"SERVER_TRUST_ACCOUNT" : 8192,
		"DONT_EXPIRE_PASSWORD" : 65536,
		"MNS_LOGON_ACCOUNT" : 131072,
		"SMARTCARD_REQUIRED" : 262144,
		"TRUSTED_FOR_DELEGATION" : 524288,
		"NOT_DELEGATED" : 1048576,
		"USE_DES_KEY_ONLY" : 2097152,
		"DONT_REQ_PREAUTH" : 4194304,
		"PASSWORD_EXPIRED" : 8388608,
		"TRUSTED_TO_AUTH_FOR_DELEGATION" : 16777216
	}


	@classmethod
	def littleEndian(self,hex):
		'''Method like class to calculate the littleEndian from hexadecimal value
			@param:
				(string)hex : Hexadecimal value
			@return: (string)Little Endian value 
		'''
		result = '';
		xinit = len(hex) - 2
		for x in range(xinit,0-1,-2):
			result += hex[x:x+2]
		return result


	@classmethod
	def getTextSID(self,binsid):
		'''Method like class to get a SID value from binsid
			@param:
				(string)binsid: binary sid data
			@return: (string) Text SID
		'''
		hex_sid = binsid.encode("hex")
		rev = int(hex_sid[0:0+2],16)
		subcount = int(hex_sid[2:2+2],16)
		auth = int(hex_sid[4:4+12],16)
		result = str(rev)+'-'+str(auth)

		subauth = {}

		for x in range(0,subcount):
			le = hex_sid[16+(x*8):(16+(x*8))+8]
			subauth[x] = int(self.littleEndian(le),16)
			result += '-'+str(subauth[x])

		return 'S-'+result

	def accountControl(self,options):
		'''Method to calculate useraccountcontrol attribute value
			
			@params:
				(list)options: Options values list from acControl attribute keys

			@return: (int) useraccountconltrol value
		'''
		val= 0;
		for i in options:
			val = val + self.acControl.get(i,0)
		return val

	def setQuery(self,operator='&',**fields):
		'''Method to generate ldap query sentences from **fields param dict
			
			This method generate "AND" global sentence but also can generate NOT, LESS That, MORE That, and Equal subsentences using follow suffix:
				
				attrubute="value" -> (attribute=value)
				attribute__not="value" -> (!(attribute=value))
				attribute__gt="value" -> (attribute>value)
				attribute__lt="value" -> (attribute<value)
				attribute__gt__not="value" -> (!(attribute>value))

			If value is equal to LIST then method generate multiple subsentences:

				attribute=["value1","value2","value3"] -> (attribute=value1)(attribute=value2)(attribute=value3)
				attribute__not=["value1","value2","value3"] -> (!(attribute=value1))(!(attribute=value2))(!(attribute=value3))

			@params:
				(char)operator: set the operator global sentence. & -> AND, | -> OR. Default is AND value
				(bool)is_disable: this option create (userAccountControl:1.2.840.113556.1.4.803:=2) subsentence
				(dict)**fields: methods parameters
			
			@return: (string) ldap query sentence


			Example:
				Query = ad.setQuery(attr1="value1",attr2__not="value2",attr3__gt=["value3","value4","value5"])
				ad.objs.filter(Query)

				or

				ad.objs.filter(ad.setQuery(attr1="value1",attr2__not="value2",attr3__gt=["value3","value4","value5"])	)

				Query == '(&(!(attr2=value2))(attr3>value3)(attr3>value4)(attr3>value5)(attr1=value1))'
		'''
		qry = ''

		is_disable = fields.get('is_disable',None)

		if is_disable != None:
			if is_disable:
				qry += '(userAccountControl:1.2.840.113556.1.4.803:=2)'
			else:
				qry += '(!(userAccountControl:1.2.840.113556.1.4.803:=2))'
			del fields['is_disable']

		for i in fields:
			negative = False
			if i.find("__not") > -1:
				key = i.replace("__not","")
				negative = True
			else:
				key = i


			if key.find("__gt") > -1:
				field = key.replace("__gt","")
				optr = ">"
			elif i.find("__ge") > -1:
				field = key.replace("__ge","")
				optr = ">="
			elif i.find("__lt") > -1:
				field = key.replace("__lt","")
				optr = "<"
			elif i.find("__le") > -1:
				field = key.replace("__le","")
				optr = "<="
			else:
				field = key
				optr = "="

			grp = ''
			if type(fields[i]) == list:
				for j in fields[i]:
					filt = '(%(field)s%(optr)s%(value)s)' % {'field': field,'optr': optr, 'value': j}
					if negative:
						grp += '(!'+filt+')'
					else:
						grp += filt
						
			else:
				filt = '(%(field)s%(optr)s%(value)s)' % {'field': field,'optr': optr, 'value': fields[i]}
				if negative:
					grp = '(!'+filt+')'
				else:
					grp += filt

			qry += grp

		query = '(%(operator)s%(query)s)' % { 'operator':operator,'query': qry }
		return query
