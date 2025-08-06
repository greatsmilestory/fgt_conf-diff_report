Compare FortiGate conf files consisting of multiple vdoms or a single vdom to compare and output the attribute values of address, address group, service, and service group objects.

The uuid and associated-interface properties of address objects are not compared.

If you want to compare the associated-interface property as well, 

if key.lower() in [“uuid”, “associated-interface”]:

you can delete “associated-interface” from the code section.
