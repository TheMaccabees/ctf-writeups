# -*- coding: utf-8 -*-
# Generated by the protocol buffer compiler.  DO NOT EDIT!
# source: mount_tree.proto

from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from google.protobuf import reflection as _reflection
from google.protobuf import symbol_database as _symbol_database
# @@protoc_insertion_point(imports)

_sym_db = _symbol_database.Default()




DESCRIPTOR = _descriptor.FileDescriptor(
  name='mount_tree.proto',
  package='sandbox2',
  syntax='proto3',
  serialized_options=None,
  create_key=_descriptor._internal_create_key,
  serialized_pb=b'\n\x10mount_tree.proto\x12\x08sandbox2\"\xa4\x05\n\tMountTree\x12\x31\n\x07\x65ntries\x18\x01 \x03(\x0b\x32 .sandbox2.MountTree.EntriesEntry\x12+\n\x04node\x18\x02 \x01(\x0b\x32\x18.sandbox2.MountTree.NodeH\x00\x88\x01\x01\x1aP\n\x08\x46ileNode\x12\x14\n\x07outside\x18\x02 \x01(\tH\x00\x88\x01\x01\x12\x15\n\x08writable\x18\x03 \x01(\x08H\x01\x88\x01\x01\x42\n\n\x08_outsideB\x0b\n\t_writable\x1aO\n\x07\x44irNode\x12\x14\n\x07outside\x18\x02 \x01(\tH\x00\x88\x01\x01\x12\x15\n\x08writable\x18\x03 \x01(\x08H\x01\x88\x01\x01\x42\n\n\x08_outsideB\x0b\n\t_writable\x1a\x39\n\tTmpfsNode\x12\x1a\n\rtmpfs_options\x18\x01 \x01(\tH\x00\x88\x01\x01\x42\x10\n\x0e_tmpfs_options\x1a.\n\x08RootNode\x12\x15\n\x08writable\x18\x03 \x01(\x08H\x00\x88\x01\x01\x42\x0b\n\t_writable\x1a\xda\x01\n\x04Node\x12\x31\n\tfile_node\x18\x01 \x01(\x0b\x32\x1c.sandbox2.MountTree.FileNodeH\x00\x12/\n\x08\x64ir_node\x18\x02 \x01(\x0b\x32\x1b.sandbox2.MountTree.DirNodeH\x00\x12\x33\n\ntmpfs_node\x18\x03 \x01(\x0b\x32\x1d.sandbox2.MountTree.TmpfsNodeH\x00\x12\x31\n\troot_node\x18\x04 \x01(\x0b\x32\x1c.sandbox2.MountTree.RootNodeH\x00\x42\x06\n\x04node\x1a\x43\n\x0c\x45ntriesEntry\x12\x0b\n\x03key\x18\x01 \x01(\t\x12\"\n\x05value\x18\x02 \x01(\x0b\x32\x13.sandbox2.MountTree:\x02\x38\x01\x42\x07\n\x05_nodeb\x06proto3'
)




_MOUNTTREE_FILENODE = _descriptor.Descriptor(
  name='FileNode',
  full_name='sandbox2.MountTree.FileNode',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  create_key=_descriptor._internal_create_key,
  fields=[
    _descriptor.FieldDescriptor(
      name='outside', full_name='sandbox2.MountTree.FileNode.outside', index=0,
      number=2, type=9, cpp_type=9, label=1,
      has_default_value=False, default_value=b"".decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
    _descriptor.FieldDescriptor(
      name='writable', full_name='sandbox2.MountTree.FileNode.writable', index=1,
      number=3, type=8, cpp_type=7, label=1,
      has_default_value=False, default_value=False,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
  ],
  extensions=[
  ],
  nested_types=[],
  enum_types=[
  ],
  serialized_options=None,
  is_extendable=False,
  syntax='proto3',
  extension_ranges=[],
  oneofs=[
    _descriptor.OneofDescriptor(
      name='_outside', full_name='sandbox2.MountTree.FileNode._outside',
      index=0, containing_type=None,
      create_key=_descriptor._internal_create_key,
    fields=[]),
    _descriptor.OneofDescriptor(
      name='_writable', full_name='sandbox2.MountTree.FileNode._writable',
      index=1, containing_type=None,
      create_key=_descriptor._internal_create_key,
    fields=[]),
  ],
  serialized_start=140,
  serialized_end=220,
)

_MOUNTTREE_DIRNODE = _descriptor.Descriptor(
  name='DirNode',
  full_name='sandbox2.MountTree.DirNode',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  create_key=_descriptor._internal_create_key,
  fields=[
    _descriptor.FieldDescriptor(
      name='outside', full_name='sandbox2.MountTree.DirNode.outside', index=0,
      number=2, type=9, cpp_type=9, label=1,
      has_default_value=False, default_value=b"".decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
    _descriptor.FieldDescriptor(
      name='writable', full_name='sandbox2.MountTree.DirNode.writable', index=1,
      number=3, type=8, cpp_type=7, label=1,
      has_default_value=False, default_value=False,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
  ],
  extensions=[
  ],
  nested_types=[],
  enum_types=[
  ],
  serialized_options=None,
  is_extendable=False,
  syntax='proto3',
  extension_ranges=[],
  oneofs=[
    _descriptor.OneofDescriptor(
      name='_outside', full_name='sandbox2.MountTree.DirNode._outside',
      index=0, containing_type=None,
      create_key=_descriptor._internal_create_key,
    fields=[]),
    _descriptor.OneofDescriptor(
      name='_writable', full_name='sandbox2.MountTree.DirNode._writable',
      index=1, containing_type=None,
      create_key=_descriptor._internal_create_key,
    fields=[]),
  ],
  serialized_start=222,
  serialized_end=301,
)

_MOUNTTREE_TMPFSNODE = _descriptor.Descriptor(
  name='TmpfsNode',
  full_name='sandbox2.MountTree.TmpfsNode',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  create_key=_descriptor._internal_create_key,
  fields=[
    _descriptor.FieldDescriptor(
      name='tmpfs_options', full_name='sandbox2.MountTree.TmpfsNode.tmpfs_options', index=0,
      number=1, type=9, cpp_type=9, label=1,
      has_default_value=False, default_value=b"".decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
  ],
  extensions=[
  ],
  nested_types=[],
  enum_types=[
  ],
  serialized_options=None,
  is_extendable=False,
  syntax='proto3',
  extension_ranges=[],
  oneofs=[
    _descriptor.OneofDescriptor(
      name='_tmpfs_options', full_name='sandbox2.MountTree.TmpfsNode._tmpfs_options',
      index=0, containing_type=None,
      create_key=_descriptor._internal_create_key,
    fields=[]),
  ],
  serialized_start=303,
  serialized_end=360,
)

_MOUNTTREE_ROOTNODE = _descriptor.Descriptor(
  name='RootNode',
  full_name='sandbox2.MountTree.RootNode',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  create_key=_descriptor._internal_create_key,
  fields=[
    _descriptor.FieldDescriptor(
      name='writable', full_name='sandbox2.MountTree.RootNode.writable', index=0,
      number=3, type=8, cpp_type=7, label=1,
      has_default_value=False, default_value=False,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
  ],
  extensions=[
  ],
  nested_types=[],
  enum_types=[
  ],
  serialized_options=None,
  is_extendable=False,
  syntax='proto3',
  extension_ranges=[],
  oneofs=[
    _descriptor.OneofDescriptor(
      name='_writable', full_name='sandbox2.MountTree.RootNode._writable',
      index=0, containing_type=None,
      create_key=_descriptor._internal_create_key,
    fields=[]),
  ],
  serialized_start=362,
  serialized_end=408,
)

_MOUNTTREE_NODE = _descriptor.Descriptor(
  name='Node',
  full_name='sandbox2.MountTree.Node',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  create_key=_descriptor._internal_create_key,
  fields=[
    _descriptor.FieldDescriptor(
      name='file_node', full_name='sandbox2.MountTree.Node.file_node', index=0,
      number=1, type=11, cpp_type=10, label=1,
      has_default_value=False, default_value=None,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
    _descriptor.FieldDescriptor(
      name='dir_node', full_name='sandbox2.MountTree.Node.dir_node', index=1,
      number=2, type=11, cpp_type=10, label=1,
      has_default_value=False, default_value=None,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
    _descriptor.FieldDescriptor(
      name='tmpfs_node', full_name='sandbox2.MountTree.Node.tmpfs_node', index=2,
      number=3, type=11, cpp_type=10, label=1,
      has_default_value=False, default_value=None,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
    _descriptor.FieldDescriptor(
      name='root_node', full_name='sandbox2.MountTree.Node.root_node', index=3,
      number=4, type=11, cpp_type=10, label=1,
      has_default_value=False, default_value=None,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
  ],
  extensions=[
  ],
  nested_types=[],
  enum_types=[
  ],
  serialized_options=None,
  is_extendable=False,
  syntax='proto3',
  extension_ranges=[],
  oneofs=[
    _descriptor.OneofDescriptor(
      name='node', full_name='sandbox2.MountTree.Node.node',
      index=0, containing_type=None,
      create_key=_descriptor._internal_create_key,
    fields=[]),
  ],
  serialized_start=411,
  serialized_end=629,
)

_MOUNTTREE_ENTRIESENTRY = _descriptor.Descriptor(
  name='EntriesEntry',
  full_name='sandbox2.MountTree.EntriesEntry',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  create_key=_descriptor._internal_create_key,
  fields=[
    _descriptor.FieldDescriptor(
      name='key', full_name='sandbox2.MountTree.EntriesEntry.key', index=0,
      number=1, type=9, cpp_type=9, label=1,
      has_default_value=False, default_value=b"".decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
    _descriptor.FieldDescriptor(
      name='value', full_name='sandbox2.MountTree.EntriesEntry.value', index=1,
      number=2, type=11, cpp_type=10, label=1,
      has_default_value=False, default_value=None,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
  ],
  extensions=[
  ],
  nested_types=[],
  enum_types=[
  ],
  serialized_options=b'8\001',
  is_extendable=False,
  syntax='proto3',
  extension_ranges=[],
  oneofs=[
  ],
  serialized_start=631,
  serialized_end=698,
)

_MOUNTTREE = _descriptor.Descriptor(
  name='MountTree',
  full_name='sandbox2.MountTree',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  create_key=_descriptor._internal_create_key,
  fields=[
    _descriptor.FieldDescriptor(
      name='entries', full_name='sandbox2.MountTree.entries', index=0,
      number=1, type=11, cpp_type=10, label=3,
      has_default_value=False, default_value=[],
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
    _descriptor.FieldDescriptor(
      name='node', full_name='sandbox2.MountTree.node', index=1,
      number=2, type=11, cpp_type=10, label=1,
      has_default_value=False, default_value=None,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
  ],
  extensions=[
  ],
  nested_types=[_MOUNTTREE_FILENODE, _MOUNTTREE_DIRNODE, _MOUNTTREE_TMPFSNODE, _MOUNTTREE_ROOTNODE, _MOUNTTREE_NODE, _MOUNTTREE_ENTRIESENTRY, ],
  enum_types=[
  ],
  serialized_options=None,
  is_extendable=False,
  syntax='proto3',
  extension_ranges=[],
  oneofs=[
    _descriptor.OneofDescriptor(
      name='_node', full_name='sandbox2.MountTree._node',
      index=0, containing_type=None,
      create_key=_descriptor._internal_create_key,
    fields=[]),
  ],
  serialized_start=31,
  serialized_end=707,
)

_MOUNTTREE_FILENODE.containing_type = _MOUNTTREE
_MOUNTTREE_FILENODE.oneofs_by_name['_outside'].fields.append(
  _MOUNTTREE_FILENODE.fields_by_name['outside'])
_MOUNTTREE_FILENODE.fields_by_name['outside'].containing_oneof = _MOUNTTREE_FILENODE.oneofs_by_name['_outside']
_MOUNTTREE_FILENODE.oneofs_by_name['_writable'].fields.append(
  _MOUNTTREE_FILENODE.fields_by_name['writable'])
_MOUNTTREE_FILENODE.fields_by_name['writable'].containing_oneof = _MOUNTTREE_FILENODE.oneofs_by_name['_writable']
_MOUNTTREE_DIRNODE.containing_type = _MOUNTTREE
_MOUNTTREE_DIRNODE.oneofs_by_name['_outside'].fields.append(
  _MOUNTTREE_DIRNODE.fields_by_name['outside'])
_MOUNTTREE_DIRNODE.fields_by_name['outside'].containing_oneof = _MOUNTTREE_DIRNODE.oneofs_by_name['_outside']
_MOUNTTREE_DIRNODE.oneofs_by_name['_writable'].fields.append(
  _MOUNTTREE_DIRNODE.fields_by_name['writable'])
_MOUNTTREE_DIRNODE.fields_by_name['writable'].containing_oneof = _MOUNTTREE_DIRNODE.oneofs_by_name['_writable']
_MOUNTTREE_TMPFSNODE.containing_type = _MOUNTTREE
_MOUNTTREE_TMPFSNODE.oneofs_by_name['_tmpfs_options'].fields.append(
  _MOUNTTREE_TMPFSNODE.fields_by_name['tmpfs_options'])
_MOUNTTREE_TMPFSNODE.fields_by_name['tmpfs_options'].containing_oneof = _MOUNTTREE_TMPFSNODE.oneofs_by_name['_tmpfs_options']
_MOUNTTREE_ROOTNODE.containing_type = _MOUNTTREE
_MOUNTTREE_ROOTNODE.oneofs_by_name['_writable'].fields.append(
  _MOUNTTREE_ROOTNODE.fields_by_name['writable'])
_MOUNTTREE_ROOTNODE.fields_by_name['writable'].containing_oneof = _MOUNTTREE_ROOTNODE.oneofs_by_name['_writable']
_MOUNTTREE_NODE.fields_by_name['file_node'].message_type = _MOUNTTREE_FILENODE
_MOUNTTREE_NODE.fields_by_name['dir_node'].message_type = _MOUNTTREE_DIRNODE
_MOUNTTREE_NODE.fields_by_name['tmpfs_node'].message_type = _MOUNTTREE_TMPFSNODE
_MOUNTTREE_NODE.fields_by_name['root_node'].message_type = _MOUNTTREE_ROOTNODE
_MOUNTTREE_NODE.containing_type = _MOUNTTREE
_MOUNTTREE_NODE.oneofs_by_name['node'].fields.append(
  _MOUNTTREE_NODE.fields_by_name['file_node'])
_MOUNTTREE_NODE.fields_by_name['file_node'].containing_oneof = _MOUNTTREE_NODE.oneofs_by_name['node']
_MOUNTTREE_NODE.oneofs_by_name['node'].fields.append(
  _MOUNTTREE_NODE.fields_by_name['dir_node'])
_MOUNTTREE_NODE.fields_by_name['dir_node'].containing_oneof = _MOUNTTREE_NODE.oneofs_by_name['node']
_MOUNTTREE_NODE.oneofs_by_name['node'].fields.append(
  _MOUNTTREE_NODE.fields_by_name['tmpfs_node'])
_MOUNTTREE_NODE.fields_by_name['tmpfs_node'].containing_oneof = _MOUNTTREE_NODE.oneofs_by_name['node']
_MOUNTTREE_NODE.oneofs_by_name['node'].fields.append(
  _MOUNTTREE_NODE.fields_by_name['root_node'])
_MOUNTTREE_NODE.fields_by_name['root_node'].containing_oneof = _MOUNTTREE_NODE.oneofs_by_name['node']
_MOUNTTREE_ENTRIESENTRY.fields_by_name['value'].message_type = _MOUNTTREE
_MOUNTTREE_ENTRIESENTRY.containing_type = _MOUNTTREE
_MOUNTTREE.fields_by_name['entries'].message_type = _MOUNTTREE_ENTRIESENTRY
_MOUNTTREE.fields_by_name['node'].message_type = _MOUNTTREE_NODE
_MOUNTTREE.oneofs_by_name['_node'].fields.append(
  _MOUNTTREE.fields_by_name['node'])
_MOUNTTREE.fields_by_name['node'].containing_oneof = _MOUNTTREE.oneofs_by_name['_node']
DESCRIPTOR.message_types_by_name['MountTree'] = _MOUNTTREE
_sym_db.RegisterFileDescriptor(DESCRIPTOR)

MountTree = _reflection.GeneratedProtocolMessageType('MountTree', (_message.Message,), {

  'FileNode' : _reflection.GeneratedProtocolMessageType('FileNode', (_message.Message,), {
    'DESCRIPTOR' : _MOUNTTREE_FILENODE,
    '__module__' : 'mount_tree_pb2'
    # @@protoc_insertion_point(class_scope:sandbox2.MountTree.FileNode)
    })
  ,

  'DirNode' : _reflection.GeneratedProtocolMessageType('DirNode', (_message.Message,), {
    'DESCRIPTOR' : _MOUNTTREE_DIRNODE,
    '__module__' : 'mount_tree_pb2'
    # @@protoc_insertion_point(class_scope:sandbox2.MountTree.DirNode)
    })
  ,

  'TmpfsNode' : _reflection.GeneratedProtocolMessageType('TmpfsNode', (_message.Message,), {
    'DESCRIPTOR' : _MOUNTTREE_TMPFSNODE,
    '__module__' : 'mount_tree_pb2'
    # @@protoc_insertion_point(class_scope:sandbox2.MountTree.TmpfsNode)
    })
  ,

  'RootNode' : _reflection.GeneratedProtocolMessageType('RootNode', (_message.Message,), {
    'DESCRIPTOR' : _MOUNTTREE_ROOTNODE,
    '__module__' : 'mount_tree_pb2'
    # @@protoc_insertion_point(class_scope:sandbox2.MountTree.RootNode)
    })
  ,

  'Node' : _reflection.GeneratedProtocolMessageType('Node', (_message.Message,), {
    'DESCRIPTOR' : _MOUNTTREE_NODE,
    '__module__' : 'mount_tree_pb2'
    # @@protoc_insertion_point(class_scope:sandbox2.MountTree.Node)
    })
  ,

  'EntriesEntry' : _reflection.GeneratedProtocolMessageType('EntriesEntry', (_message.Message,), {
    'DESCRIPTOR' : _MOUNTTREE_ENTRIESENTRY,
    '__module__' : 'mount_tree_pb2'
    # @@protoc_insertion_point(class_scope:sandbox2.MountTree.EntriesEntry)
    })
  ,
  'DESCRIPTOR' : _MOUNTTREE,
  '__module__' : 'mount_tree_pb2'
  # @@protoc_insertion_point(class_scope:sandbox2.MountTree)
  })
_sym_db.RegisterMessage(MountTree)
_sym_db.RegisterMessage(MountTree.FileNode)
_sym_db.RegisterMessage(MountTree.DirNode)
_sym_db.RegisterMessage(MountTree.TmpfsNode)
_sym_db.RegisterMessage(MountTree.RootNode)
_sym_db.RegisterMessage(MountTree.Node)
_sym_db.RegisterMessage(MountTree.EntriesEntry)


_MOUNTTREE_ENTRIESENTRY._options = None
# @@protoc_insertion_point(module_scope)