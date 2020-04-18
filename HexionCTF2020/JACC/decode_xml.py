#!/usr/bin/env python3
"""
Used in order to check the lxml parsing of an XML.
"""
from lxml import etree
from io import BytesIO

data = BytesIO(b"""<!-- API Version: 1.0.0 -->
 <!DOCTYPE username[
 <!ELEMENT username ANY>
 <!ENTITY xxe SYSTEM "file:///etc/passwd2">
 ]>
 <!-- -->
<root>
    <data>
        <username>admin</username><is_admin>1</is_admin></data> <data><username> &xxe; </username>
        <is_admin>0</is_admin>
    </data>
</root>
""")

xml = etree.parse(data)
print(etree.tostring(xml))
