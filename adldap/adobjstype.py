# -*- coding: utf-8 -*-
import json, uuid, datetime
from adutils import adUtils


class adGenericAttr(object):
	def __init__(self,adldap,value):
		self.adldap = adldap
		if type(value) != list:
			raise Exception("Value must be list")
		self.ValueToRaw(value)

	def __getitem__(self,item):
		return self.raw[item]

	def __setitem__(self,item,value):
		self.raw[item] = value
		self.is_modified = True

	def __delitem__(self,item):
		del self.raw[item]
		self.is_modified = True

	@property
	def value(self):
		return self.RawToValue()

	def ValueToRaw(self,value):
		self.raw = value

	def RawToValue(self):
		if len(self.raw) > 1:
			return self.raw
		else:
			if len(self.raw) == 0:
				return None
			else:
				return self.raw[0]

	def humanReadeable(self):
		return self.value

	def __repr__(self):
		return repr(self.value)

	def __str__(self):
		return str(self.humanReadeable())

class PrimaryGroupID(adGenericAttr):
	def humanReadeable(self):
		 gsid = self.adldap.getDomainRID()+'-'+self.raw[0]
		 return self.adldap.groups.get(self.adldap.setQuery(objectsid=gsid)).dn.value


class unicodePwd(adGenericAttr):
	def ValueToRaw(self,password):
		unicode_pass = unicode('\"' + str(password[0]) + '\"', 'iso-8859-1')
		super(unicodePwd,self).ValueToRaw([unicode_pass.encode("utf-16-le")])

class UserAccountControl(adGenericAttr):
	def ValueToRaw(self,value):
		if type(value) == list:
			acControl = self.adldap.accountControl(value)
			if acControl > 0:
				self.raw = [str(self.adldap.accountControl(value))]
			else:
				self.raw = value
		else:
			self.raw = [str(value)]

	def humanReadeable(self):
		if self.value == None:
			return str(self.value)
		binary = bin(int(self.value))[2:][::-1]
		values = []
		for bit in range(0,len(binary)):
			if binary[bit] == '1':
				decimal = int(binary[bit]+'0'*bit,2)
				try:
					position = self.adldap.acControl.values().index(decimal)
					value = self.adldap.acControl.keys()[position]
					values.append(value)
				except:
					values.append("UNKNOWN")
		return values


class dn(adGenericAttr):
	pass


class adTime0Z(adGenericAttr):	
	def humanReadeable(self):
		val = []
		for d in self.raw:
			human = "%(year)s-%(month)s-%(day)s %(hour)s:%(min)s:%(sec)s" % { "year":d[0:4],"month":d[4:6],"day":d[6:8],
																									"hour":d[8:10],"min": d[10:12],"sec": d[12:14]}
			val.append(human)
		return val


class WhenChanged(adTime0Z):
	pass


class WhenCreated(adTime0Z):
	pass


class dSCorePropagationData(adTime0Z):
	pass


class adWinTimeStamp(adGenericAttr):	
	def Win2UnixTimeStamp(self,wints):
		if (wints == 0) or (int(wints) == 9223372036854775807):
			return 0

		secsAfterADEpoch = int(wints) / float(10000000)
		AD2Unix = ((1970-1601) * 365 - 3 + (1970-1601)/4) * 86400
		return int(secsAfterADEpoch - AD2Unix)

	def humanReadeable(self):
		val = []
		for ts in self.raw:
			unixTimeStamp = self.Win2UnixTimeStamp(ts)
			if unixTimeStamp <= 0:
				val.append(0)
			else:
				d = datetime.datetime.fromtimestamp(unixTimeStamp)
				val.append(d.strftime("%Y-%m-%d %H:%M:%S"))
		return val


class badPasswordTime(adWinTimeStamp):
	pass


class lastLogon(adWinTimeStamp):
	pass


class pwdLastSet(adWinTimeStamp):
	pass


class lastLogonTimeStamp(adWinTimeStamp):
	pass


class accountExpires(adWinTimeStamp):
	pass


class mSMQSignCertificates(adGenericAttr):
	pass


class adGenericMember(adGenericAttr):
	def __getitem__(self,index):
		return self.adldap.objs.get(self.adldap.setQuery(distinguishedname=self.raw[index]))

	def __setitem__(self,index,item):
		pass

	def is_member(self,groupname):
		for i in self.value:
			grp = i.lower().split(',')[0].replace('cn=','')
			if grp.strip() == groupname.lower().strip():
				return True
		return False
			
class memberOf(adGenericMember):
	pass

class member(adGenericMember):
	pass


class sAMAccountName(adGenericAttr):
	pass


class ObjectGUID(adGenericAttr):
	def RawToValue(self):
		return str(uuid.UUID(bytes=self.raw[0]))


class adGenericSid(adGenericAttr):
	def RawToValue(self):
		return adUtils.getTextSID(self.raw[0])

class ObjectSid(adGenericSid):
	pass

class sIDHistory(adGenericSid):
	pass

class userWorkStations(adGenericAttr):
	pass

class logonHours(adGenericAttr):
	def __getitem__(self,item):
		return self.humanReadeable()[item]

	def RawToValue(self):
		return list(bytearray(self.raw[0]))

	def humanReadeable(self):
		value = self.value
		sun = bin(value[0])[2:].zfill(8)[::-1]+bin(value[1])[2:].zfill(8)[::-1]+bin(value[2])[2:].zfill(8)[::-1]
		mon = bin(value[3])[2:].zfill(8)[::-1]+bin(value[4])[2:].zfill(8)[::-1]+bin(value[5])[2:].zfill(8)[::-1]
		tue = bin(value[6])[2:].zfill(8)[::-1]+bin(value[7])[2:].zfill(8)[::-1]+bin(value[8])[2:].zfill(8)[::-1]
		wed = bin(value[9])[2:].zfill(8)[::-1]+bin(value[10])[2:].zfill(8)[::-1]+bin(value[11])[2:].zfill(8)[::-1]
		thu = bin(value[12])[2:].zfill(8)[::-1]+bin(value[13])[2:].zfill(8)[::-1]+bin(value[14])[2:].zfill(8)[::-1]
		fri = bin(value[15])[2:].zfill(8)[::-1]+bin(value[16])[2:].zfill(8)[::-1]+bin(value[17])[2:].zfill(8)[::-1]
		sat = bin(value[18])[2:].zfill(8)[::-1]+bin(value[19])[2:].zfill(8)[::-1]+bin(value[20])[2:].zfill(8)[::-1]

		week = {
			"sun" : sun,
			"mon" : mon,
			"tue" : tue,
			"wed" : wed,
			"thu" : thu,
			"fri" : fri,
			"sat" : sat,
		}
		return week


class manager(adGenericAttr):
	pass

class directreports(adGenericAttr):
	pass
