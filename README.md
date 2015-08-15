# PyADLdap
Python framework to managing Microsoft Active Directory from LDAP

## Index
- [Description](#description)
- [Requires](#requires)
- [Installation](#installation)
- [How to use](#how-to-use)
- [Documentation](#documentation)
- [TODO](#todo)

## Description
The essential purpose of this framework is to work with LDAP objects as objects python.

The object attributes in LDAP are processed as attributes of objects in python and manipulation objects (such as enable, disable, change password, etc.) using the methods of the object in python.

## Requires

- Python 2.7
  - python-ldap

## Installation

First you must install a python-ldap dependence:

  - On debian and derivative
  
        apt-get install python-ldap

  - Or, if you prefer, you need only install dependencies python-ldap with the following command
  
        apt-get build-dep python-ldap

Then you can use pip to install it:

        pip install pyadldap

Or you can download the source code and install it with the following command:

        python setup.py install

Once installed, you can import the adLDAP class:

        from pyadldap.adldap import adLDAP

## How to use

  First of all, you must initialize the object from adLDAP class:
  
        ad = adLDAP(dcs=list("dc1.fqdn","dcIP","domainfqdn"),username="ADusername",password="ADusernamepassword"))

    Example:
  
        ad = adLDAP(dcs=["dc.domain.ltd"],username="username@domain.ltd",password="secret")

    or:
  
        dataConnection = {
          "dcs" : ["dc.domain.ltd"],
          "username" : "username@domain.ltd",
          "password" : "secret"
        }
        
        ad = adLDAP(**dataConnection)

And to search an LDAP object, such as a user:

        user = ad.objs.get('(samaccountname=username)')
        
    or, with setQuery method:
  
        user = ad.objs.get(ad.setQuery(samaccountname="username"))
    
    or, with user especific property:
    
        user = ad.users.get(ad.setQuery(samaccountname="username"))
        
If user object exist, with print command you can see the object in human readeable format
    
       print user
       
       {
          "dn": "cn=fistname surname,dc=domain,dc=fqdn,dc=ltd", 
          "displayname": "fistname surname", 
          "samaccountname": "username", 
          "objectclass": [
            "organizationalPerson", 
            "person", 
            "top", 
            "user"
          ], 
          "useraccountcontrol": [
            "NORMAL_ACCOUNT"
          ], 
          "userprincipalname": "username@domain.fqdn.ltd", 
          "sn": "surname", 
          "givenname": "fistname", 
          "cn": "fistname surname"
        }

To modify any value you just modify the corresponding attributes and save it.

        user.displayname = "modify displayname value"
        user.description = "create description value"
        user.save()
        
To remove attributes set None value:

        user.description = None #This action remove attribute in Active Directory
        user.save()

Change user password:

        user.unicodePwd = "secret"
        user.save()
    
    or, the fast way:
    
        user.setPassword("secret") # this method call save()
        
Enable or disable user:

    Enable and disable user with decimal value
        user.useraccountcontrol = 512 #enable user
        user.save()
        
        user.useraccountcontrol = 514 #disable user
        user.save()
        
    The easy way:
    
        user.useraccountcontrol = ['NORMAL_USER'] #enable user
        user.save()
        
        user.useraccountcontrol = ['NORMAL_USER','ACCOUNTDISABLE'] #disable user
        user.save()
        
    Or, the fast way:
    
        user.enable() #method call save()
        user.disable()  #method call save()
        
If you want to find multiple Active Directory objects you can use the "filter" method instead of the "get" method:

    Get all enabled computers with Windows 7, whose name does not begin with HST and not by LTP:
    
        hosts = ad.objs.filter('(&(!(samaccountname=HST*))(!(samaccountname=LTP*))(operatingsystem=Windows 7*)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))')
        
    or the easy way:
      
        hosts = ad.objs.filter(ad.setQuery(samaccountname__not=['HST*','LTP*'],operatingsystem="Windows 7*",is_disable=False))
        
    or, with user especific property:
    
        hosts = ad.computers.filter(ad.setQuery(samaccountname__not=['HST*','LTP*'],operatingsystem="Windows 7*",is_disable=False))
  
And the hosts object will have a list of objects similar to the object user:

        print hosts
        
        {
          "cn=computer1,dc=domain,dc=fqdn,dc=ltd",
          "cn=computer2,dc=domain,dc=fqdn,dc=ltd",
          "cn=computer3,dc=domain,dc=fqdn,dc=ltd",
          "cn=computer4,dc=domain,dc=fqdn,dc=ltd",
          "cn=computer5,dc=domain,dc=fqdn,dc=ltd",
          "cn=computer6,dc=domain,dc=fqdn,dc=ltd",
          "cn=computer7,dc=domain,dc=fqdn,dc=ltd",
        }
        

To create a new LDAP object, like a group, then:

        group = ad.groups.new()
        
    view human readeable format
        
        print group
        
        {
          "dn": null, 
          "objectclass": [
            "group", 
            "top"
          ], 
          "cn": null, 
          "samaccountname": null
        }
        
    and you must set null attributes at least:
    
      group.dn = "cn=groupname,ou=ouname,dc=domain,dc=fqdn,dc=ltd"
      group.cn = "groupname"
      group.samaccountname = "groupname"
      group.save()
      
      

## Documentation

  - [Working on it](https://github.com/Wengex/PyADLdap/wiki)

## TODO

  - Create python3 version
  - Check on windows system clients ldaps (SSL) connection
  - Check with exchange system
  - Implement Ticket Kerberos authentication
  - More tests, more tests, more tests
